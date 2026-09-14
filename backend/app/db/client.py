"""Supabase storage layer with a local in-memory fallback.

SupabaseStore persists scan rows + result JSON + reports via the service
role client and reads THROUGH the database (the in-memory dict is only a
request-local write cache), so scans survive Render restarts and spin-downs.
LocalStore mirrors the same interface in-memory so the API is fully
functional (and pytest-testable) without a live Supabase project.
"""
from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone

from ..config import settings

PCAP_RETENTION_HOURS = 24


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class LocalStore:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.scans: dict[str, dict] = {}
        self.results: dict[str, dict] = {}
        self.objects: dict[str, bytes] = {}          # storage objects by path

    # ---- scans ----
    def create_scan(self, user_id: str, name: str, size: int, path: str,
                    scan_id: str | None = None) -> dict:
        scan = {
            "id": scan_id or str(uuid.uuid4()), "user_id": user_id, "name": name,
            "file_size": size, "file_path": path, "status": "uploaded",
            "progress": 0, "error": None, "posture_score": None,
            "grade": None, "protocol_counts": {}, "session_count": None,
            "started_at": None, "completed_at": None, "created_at": utcnow(),
        }
        with self.lock:
            self.scans[scan["id"]] = scan
        return scan

    def get_scan(self, scan_id: str, user_id: str) -> dict | None:
        scan = self.scans.get(scan_id)
        return scan if scan and scan["user_id"] == user_id else None

    def list_scans(self, user_id: str, limit: int, offset: int) -> tuple[list[dict], int]:
        rows = [s for s in self.scans.values() if s["user_id"] == user_id]
        rows.sort(key=lambda s: s["created_at"], reverse=True)
        return rows[offset:offset + limit], len(rows)

    def update_scan(self, scan_id: str, **fields) -> None:
        with self.lock:
            scan = self.scans.get(scan_id)
            if scan:
                scan.update(fields)

    def delete_scan(self, scan_id: str, user_id: str) -> bool:
        with self.lock:
            scan = self.scans.get(scan_id)
            if not scan or scan["user_id"] != user_id:
                return False
            del self.scans[scan_id]
            self.results.pop(scan_id, None)
            for k in [k for k in self.objects if scan_id in k]:
                del self.objects[k]
            return True

    # ---- analysis results ----
    def put_result(self, scan_id: str, result: dict) -> None:
        with self.lock:
            self.results[scan_id] = result

    def get_result(self, scan_id: str) -> dict | None:
        return self.results.get(scan_id)

    # ---- objects (pcap bytes / reports) ----
    def put_object(self, path: str, data: bytes) -> None:
        with self.lock:
            self.objects[path] = data

    def get_object(self, path: str) -> bytes | None:
        return self.objects.get(path)

    def delete_object(self, path: str) -> None:
        with self.lock:
            self.objects.pop(path, None)

    # ---- retention ----
    def cleanup_expired_pcaps(self, now: datetime | None = None) -> int:
        """Delete pcap objects for scans that completed >24h ago. No-op in
        the in-memory store (objects die with the process anyway); the
        Supabase store does real work. Returns number of objects removed."""
        return 0


class SupabaseStore(LocalStore):
    """Persists to Supabase and reads through the database: the in-memory
    dicts act only as a write-side cache so a fresh instance (Render cold
    start) still serves every previously created scan. Pcap/report bytes
    go to Storage buckets. Pcaps are cleaned up ~24h after scan completion
    (opportunistic, on list requests — no cron on the free tier)."""

    def __init__(self) -> None:
        super().__init__()
        from supabase import create_client
        self.sb = create_client(settings.supabase_url,
                                settings.supabase_service_role_key)

    # ---- row normalization ----
    @staticmethod
    def _row_to_scan(row: dict) -> dict:
        scan = dict(row)
        scan.setdefault("progress", 0)
        scan.setdefault("error", None)
        scan.setdefault("posture_score", None)
        scan.setdefault("grade", None)
        scan.setdefault("protocol_counts", {})
        scan.setdefault("session_count", None)
        scan.setdefault("started_at", None)
        scan.setdefault("completed_at", None)
        return scan

    def create_scan(self, user_id: str, name: str, size: int, path: str,
                    scan_id: str | None = None) -> dict:
        scan = super().create_scan(user_id, name, size, path, scan_id)
        try:
            row = {k: scan[k] for k in
                   ("id", "user_id", "name", "file_size", "file_path",
                    "status", "progress", "created_at")}
            self.sb.table("scans").insert(row).execute()
        except Exception:
            pass
        return scan

    def get_scan(self, scan_id: str, user_id: str) -> dict | None:
        scan = super().get_scan(scan_id, user_id)
        if scan:
            return scan
        try:
            res = (self.sb.table("scans").select("*")
                   .eq("id", scan_id).eq("user_id", user_id)
                   .limit(1).execute())
            if res.data:
                row = self._row_to_scan(res.data[0])
                with self.lock:
                    self.scans[scan_id] = row
                return row
        except Exception:
            pass
        return None

    def list_scans(self, user_id: str, limit: int, offset: int) -> tuple[list[dict], int]:
        try:
            res = (self.sb.table("scans").select("*").eq("user_id", user_id)
                   .order("created_at", desc=True)
                   .range(offset, offset + limit - 1).execute())
            count_res = (self.sb.table("scans").select("id", count="exact")
                         .eq("user_id", user_id).execute())
            rows = [self._row_to_scan(r) for r in res.data]
            with self.lock:
                for r in rows:
                    self.scans[r["id"]] = r
            self.cleanup_expired_pcaps()
            return rows, count_res.count or len(rows)
        except Exception:
            return super().list_scans(user_id, limit, offset)

    def update_scan(self, scan_id: str, **fields) -> None:
        super().update_scan(scan_id, **fields)
        try:
            self.sb.table("scans").update(fields).eq("id", scan_id).execute()
        except Exception:
            pass

    def delete_scan(self, scan_id: str, user_id: str) -> bool:
        scan = self.get_scan(scan_id, user_id)
        if not scan:
            return False
        if scan["file_path"]:
            self.delete_object(scan["file_path"])
        ok = super().delete_scan(scan_id, user_id)
        try:
            self.sb.table("scans").delete().eq("id", scan_id).execute()
        except Exception:
            pass
        return ok

    # ---- analysis results ----
    def put_result(self, scan_id: str, result: dict) -> None:
        super().put_result(scan_id, result)
        try:
            self.sb.table("scan_results").upsert(
                {"scan_id": scan_id, "data": result}).execute()
        except Exception:
            pass

    def get_result(self, scan_id: str) -> dict | None:
        cached = super().get_result(scan_id)
        if cached is not None:
            return cached
        try:
            res = (self.sb.table("scan_results").select("data")
                   .eq("scan_id", scan_id).limit(1).execute())
            if res.data:
                result = res.data[0]["data"]
                with self.lock:
                    self.results[scan_id] = result
                return result
        except Exception:
            pass
        return None

    # ---- objects (pcap bytes / reports) ----
    def put_object(self, path: str, data: bytes) -> None:
        super().put_object(path, data)
        try:
            self.sb.storage.from_("pcaps").upload(path, data,
                                                  {"upsert": "true"})
        except Exception:
            pass

    def get_object(self, path: str) -> bytes | None:
        cached = super().get_object(path)
        if cached is not None:
            return cached
        try:
            res = self.sb.storage.from_("pcaps").download(path)
            if res:
                data = bytes(res)
                with self.lock:
                    self.objects[path] = data
                return data
        except Exception:
            pass
        return None

    def delete_object(self, path: str) -> None:
        super().delete_object(path)
        try:
            self.sb.storage.from_("pcaps").remove([path])
        except Exception:
            pass

    # ---- retention ----
    def cleanup_expired_pcaps(self, now: datetime | None = None) -> int:
        """Delete pcap storage objects for scans completed >24h ago (the
        documented retention window). Called opportunistically from
        list_scans — the free tier has no scheduler."""
        now = now or datetime.now(timezone.utc)
        removed = 0
        try:
            res = (self.sb.table("scans").select("id,file_path,completed_at")
                   .eq("status", "complete")
                   .not_.is_("completed_at", "null")
                   .order("completed_at", desc=False).limit(50).execute())
            for row in res.data:
                done = row.get("completed_at")
                if not done:
                    continue
                try:
                    done_dt = datetime.fromisoformat(
                        str(done).replace("Z", "+00:00"))
                    if done_dt.tzinfo is None:
                        done_dt = done_dt.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
                if (now - done_dt).total_seconds() < PCAP_RETENTION_HOURS * 3600:
                    continue
                if row.get("file_path"):
                    self.delete_object(row["file_path"])
                    removed += 1
        except Exception:
            pass
        return removed


def get_store() -> LocalStore:
    if settings.supabase_url and settings.supabase_service_role_key:
        try:
            return SupabaseStore()
        except Exception:
            pass
    return LocalStore()
