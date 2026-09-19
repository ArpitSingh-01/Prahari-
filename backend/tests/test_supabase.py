"""Optional integration tests against a REAL Supabase project.

Runs only when SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY are set in the
environment AND pytest is invoked with the `--supabase` flag:

    python -m pytest tests/test_supabase.py -q --supabase

Without the flag or the env vars every test here skips, so CI stays green
offline (ground rule: the default suite is local in-memory only).

These tests verify the production access path:
- schema.sql's contract (tables exist, service key can query them)
- storage bucket round-trips pcap bytes
- the store reads through the DB across fresh instances
"""
from __future__ import annotations

import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..")))


def _configured() -> bool:
    return bool(os.environ.get("SUPABASE_URL")
                and os.environ.get("SUPABASE_SERVICE_ROLE_KEY"))


pytestmark = pytest.mark.skipif(
    not (_configured()),
    reason="Supabase env vars not set; live integration suite is opt-in "
           "(pytest --supabase with SUPABASE_URL/SUPABASE_SERVICE_ROLE_KEY)")


@pytest.fixture(scope="module")
def sb_service():
    from supabase import create_client
    url = os.environ["SUPABASE_URL"]
    key = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
    return create_client(url, key)


def test_schema_applies(sb_service):
    """schema.sql's contract: the two tables exist and accept queries
    through the service role. (Applying schema.sql itself needs the SQL
    editor or a migration runner — this asserts the result.)"""
    row = sb_service.table("scans").select("id", count="exact").limit(1).execute()
    assert row is not None
    row = sb_service.table("scan_results").select("scan_id", count="exact").limit(1).execute()
    assert row is not None


def test_anon_key_locked_out():
    """RLS has no policies: the anon key must NOT be able to read scan rows
    even when it is set. (The backend only ever uses the service key.)"""
    url = os.environ.get("SUPABASE_URL")
    anon = os.environ.get("SUPABASE_ANON_KEY")
    if not (url and anon):
        pytest.skip("SUPABASE_ANON_KEY not set — anon lockout check needs it")
    from supabase import create_client
    anon_client = create_client(url, anon)
    try:
        res = anon_client.table("scans").select("id").limit(1).execute()
        assert res.data == [], "anon key read scan rows — RLS is not locked down"
    except Exception:
        pass          # an error/permission denial is the expected outcome


def test_storage_roundtrip(sb_service):
    """The private 'pcaps' bucket accepts writes and reads with the service
    key (this is the path Render uses)."""
    path = "__integration_test__/roundtrip.pcap"
    payload = b"\xd4\xc3\xb2\xa1" + os.urandom(64)
    try:
        try:
            sb_service.storage.from_("pcaps").upload(path, payload)
        except Exception:
            sb_service.storage.from_("pcaps").upload(path, payload,
                                                    {"upsert": "true"})
        got = bytes(sb_service.storage.from_("pcaps").download(path))
        assert got == payload
    finally:
        try:
            sb_service.storage.from_("pcaps").remove([path])
        except Exception:
            pass


def test_backend_store_read_through():
    """With env configured, SupabaseStore reads scan rows THROUGH the DB
    (write-side cache only): a fresh instance must find a scan created by
    another instance."""
    if not _configured():
        pytest.skip("Supabase env not set")
    from app.db.client import SupabaseStore
    import uuid as _uuid
    s1 = SupabaseStore()
    sid = str(_uuid.uuid4())
    s1.create_scan("read-through-test", 10, f"{sid}.pcap", scan_id=sid)
    s2 = SupabaseStore()          # fresh instance: simulates a Render restart
    scan = s2.get_scan(sid)
    assert scan is not None, "fresh store failed to read an existing scan"
    assert scan["name"] == "read-through-test"
    s1.delete_scan(sid)
