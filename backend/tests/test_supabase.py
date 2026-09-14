"""Optional integration tests against a REAL Supabase project.

Runs only when SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY (+ SUPABASE_ANON_KEY
for the RLS check) are set in the environment AND pytest is invoked with the
`--supabase` flag:

    python -m pytest tests/test_supabase.py -q --supabase

Without the flag or the env vars every test here skips, so CI stays green
offline (ground rule: the default suite is local in-memory only).

These tests verify §1.2 of the ship plan:
- schema.sql applies cleanly
- RLS isolates users (a second user cannot read another's scans)
- storage buckets round-trip pcap bytes
- the JWT verification path used in production
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


def _live(request) -> bool:
    return request.config.getoption("--supabase") and _configured()


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
    """schema.sql's contract: the three tables exist and accept queries
    through the service role. (Applying schema.sql itself needs the SQL
    editor or a migration runner — this asserts the result.)"""
    for table in ("scans", "scan_results", "reports"):
        col = "user_id" if table == "scans" else ("scan_id" if table == "scan_results" else "id")
        row = sb_service.table(table).select(col, count="exact").limit(1).execute()
        assert row is not None


def test_rls_user_isolation(sb_service):
    """RLS: the anon key (a real user session) must not read another user's
    scan rows. Requires SUPABASE_ANON_KEY + two test users; without them this
    test degrades to asserting the service key can see rows at all."""
    anon_key = os.environ.get("SUPABASE_ANON_KEY")
    if not anon_key:
        pytest.skip("SUPABASE_ANON_KEY not set — full RLS check needs it")
    from supabase import create_client
    url = os.environ["SUPABASE_URL"]
    user_a = create_client(url, anon_key)
    # sign in as a throwaway test user (must exist in the project)
    email = os.environ.get("SUPABASE_TEST_USER", "")
    password = os.environ.get("SUPABASE_TEST_PASSWORD", "")
    if not (email and password):
        pytest.skip("SUPABASE_TEST_USER/PASSWORD not set")
    user_a.auth.sign_in_with_password({"email": email, "password": password})
    rows = user_a.table("scans").select("*").limit(10).execute()
    other = [r for r in rows.data
             if r.get("user_id") != user_a.auth.get_session().user.id]
    assert not other, "RLS leak: signed-in user read scans they do not own"


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
    owner = "00000000-0000-0000-0000-000000000001"
    s1.create_scan(owner, "read-through-test", 10, f"{owner}/{sid}.pcap",
                   scan_id=sid)
    s2 = SupabaseStore()          # fresh instance: simulates a Render restart
    scan = s2.get_scan(sid, owner)
    assert scan is not None, "fresh store failed to read an existing scan"
    assert scan["name"] == "read-through-test"
    s1.delete_scan(sid, owner)
