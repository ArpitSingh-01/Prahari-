"""Scan endpoints: upload, list, detail, analyze, status, sessions,
findings, certificates, anomalies, summary.

Open access model: the tool runs without user accounts — one shared
workspace where every visitor sees (and may delete) every scan. All
boundaries are capacity guards (upload cap, analysis concurrency), not
identity checks.
"""
from __future__ import annotations

import os
import re
import tempfile
import uuid

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import Response

from ..config import settings
from ..deps import store
from ..worker import start_analysis

router = APIRouter(prefix="/api/scans", tags=["scans"])

PCAP_MAGICS = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
               b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
               b"\x0a\x0d\x0d\x0a")

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
MAX_NAME_LEN = 120


def _scan_or_404(scan_id: str) -> dict:
    scan = store().get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    return scan


def _result_or_409(scan_id: str) -> tuple[dict, dict]:
    scan = _scan_or_404(scan_id)
    result = store().get_result(scan_id)
    if result is None:
        raise HTTPException(409, "scan analysis not available (status: %s)"
                            % scan["status"])
    return scan, result


@router.post("", status_code=201)
async def upload_scan(file: UploadFile = File(...)):
    # stream to disk rather than holding the whole capture in memory
    # (Render free tier: 512 MB — never load what you can stream)
    limit = settings.max_upload_mb * 1024 * 1024
    magic = b""
    total = 0
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    try:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            if not magic:
                magic = chunk[:4]
                if magic not in PCAP_MAGICS:
                    tmp.close()
                    os.unlink(tmp.name)
                    raise HTTPException(400, "not a pcap/pcapng file")
            total += len(chunk)
            if total > limit:
                tmp.close()
                os.unlink(tmp.name)
                raise HTTPException(413, "file exceeds %d MB limit"
                                    % settings.max_upload_mb)
            tmp.write(chunk)
        tmp.close()
        if total == 0 or magic not in PCAP_MAGICS:
            os.unlink(tmp.name)
            raise HTTPException(400, "not a pcap/pcapng file")
        with open(tmp.name, "rb") as fh:
            raw = fh.read()
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
    # sanitize the display name (keep the extension, drop path traversals)
    name = _SAFE_NAME.sub("_", os.path.basename(file.filename or "capture.pcap"))
    name = name.strip("._")[:MAX_NAME_LEN] or "capture.pcap"
    scan_id = str(uuid.uuid4())
    path = "%s.pcap" % scan_id
    store().put_object(path, raw)
    return store().create_scan(name, total, path, scan_id=scan_id)


@router.get("")
def list_scans(limit: int = 20, offset: int = 0):
    limit = min(max(limit, 1), 100)
    items, total = store().list_scans(limit, offset)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/{scan_id}")
def get_scan(scan_id: str):
    return _scan_or_404(scan_id)


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: str):
    scan = _scan_or_404(scan_id)
    store().delete_object(scan["file_path"])
    store().delete_scan(scan_id)
    return Response(status_code=204)


@router.post("/{scan_id}/analyze", status_code=202)
async def analyze(scan_id: str):
    scan = _scan_or_404(scan_id)
    if scan["status"] in ("parsing",):
        raise HTTPException(409, "analysis already running")
    if scan["status"] == "complete":
        return {"status": "complete", "progress": 100}
    data = store().get_object(scan["file_path"])
    if data is None:
        raise HTTPException(410, "capture file no longer stored (24h retention)")
    await start_analysis(scan_id, data)
    store().update_scan(scan_id, status="parsing", progress=1, error=None)
    return {"status": "parsing", "progress": 1}


@router.get("/{scan_id}/status")
def scan_status(scan_id: str):
    scan = _scan_or_404(scan_id)
    return {"status": scan["status"], "progress": scan["progress"],
            "error": scan["error"]}


@router.get("/{scan_id}/summary")
def scan_summary(scan_id: str):
    scan, result = _result_or_409(scan_id)
    from ..reports.builder import _summary_text
    return {"summary": _summary_text(result), "posture": result["posture"]}


@router.get("/{scan_id}/sessions")
def list_sessions(scan_id: str, protocol: str | None = None,
                  transport: str | None = None, grade: str | None = None,
                  anomaly: bool | None = None, limit: int = 50, offset: int = 0):
    _, result = _result_or_409(scan_id)
    items = result["sessions"]
    if protocol:
        items = [s for s in items if s["protocol"] == protocol]
    if transport:
        items = [s for s in items if s["transport"] == transport]
    if grade:
        items = [s for s in items if s["grade"] == grade]
    if anomaly is not None:
        items = [s for s in items if s["is_anomaly"] == anomaly]
    total = len(items)
    return {"items": items[offset:offset + min(limit, 200)],
            "total": total, "limit": limit, "offset": offset}


@router.get("/{scan_id}/sessions/{session_id}")
def get_session(scan_id: str, session_id: str):
    _, result = _result_or_409(scan_id)
    for s in result["sessions"]:
        if s["session_id"] == session_id:
            sess_findings = [f for f in result["findings"]
                             if f["session_id"] == session_id]
            sess_advisories = [a for a in result.get("advisories", [])
                               if a["session_id"] == session_id]
            return {"session": s, "findings": sess_findings,
                    "advisories": sess_advisories}
    raise HTTPException(404, "session not found")


@router.get("/{scan_id}/findings")
def list_findings(scan_id: str, severity: str | None = None,
                  category: str | None = None, limit: int = 100, offset: int = 0):
    _, result = _result_or_409(scan_id)
    items = result["findings"]
    if severity:
        items = [f for f in items if f["severity"] == severity]
    if category:
        items = [f for f in items if f["category"] == category]
    total = len(items)
    return {"items": items[offset:offset + min(limit, 500)],
            "total": total, "limit": limit, "offset": offset}


@router.get("/{scan_id}/advisories")
def list_advisories(scan_id: str, limit: int = 100, offset: int = 0):
    """Informational zero-weight posture advisories (e.g. PQC migration)."""
    _, result = _result_or_409(scan_id)
    items = result.get("advisories", [])
    return {"items": items[offset:offset + min(limit, 500)],
            "total": len(items), "limit": limit, "offset": offset}


@router.get("/{scan_id}/certificates")
def list_certificates(scan_id: str):
    _, result = _result_or_409(scan_id)
    return {"items": result["certificates"],
            "total": len(result["certificates"])}


@router.get("/{scan_id}/anomalies")
def list_anomalies(scan_id: str):
    _, result = _result_or_409(scan_id)
    flagged = [s for s in result["sessions"] if s["is_anomaly"]]
    explanations = {e["session_id"]: e for e in result["anomaly_explanations"]}
    items = [{**s, "explanation": explanations.get(s["session_id"], {})}
             for s in flagged]
    return {"items": items, "total": len(items)}
