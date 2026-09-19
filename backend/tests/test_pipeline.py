"""Golden-file tests: every scenario pcap must fire exactly its expected
rules; clean scenarios must stay clean. Also end-to-end API tests via
TestClient (upload -> analyze -> poll -> reports).

Expected-rule sets use `expected <= fired` (extra fires are tolerated but
gold captures demand ZERO findings)."""
from __future__ import annotations

import os
import sys
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..")))

from app.pipeline.runner import analyze_pcap, result_to_dict  # noqa: E402

PCAPS = os.path.normpath(os.path.join(HERE, "..", "fixtures", "pcaps"))

EXPECTED = {
    "good-smtps.pcap": set(),
    "imaps-good.pcap": set(),
    "pop3s-good.pcap": set(),
    "smtp-tls10-rc4.pcap": {"TLS-001", "CPR-002", "CPR-004", "PFS-001"},
    "starttls-ok.pcap": set(),
    "pop3-cleartext.pcap": {"PRT-001", "CRE-001"},
    "starttls-stripped.pcap": {"CFG-004"},
    "imap-expired-cert.pcap": {"CRT-001", "CRT-004"},
    "pop3s-weak-nopfs.pcap": {"CRT-005", "CRT-004", "PFS-001", "CPR-003"},
    "imaps-sha1-selfsigned.pcap": {"CRT-004", "CRT-006", "PFS-001", "CPR-003"},
    "handshake-failure.pcap": {"ALR-001"},
    "insecure-reneg.pcap": {"CFG-007"},        # renegotiation w/o RFC 5746
    # differentiator scenarios
    "host-cert-swap.pcap": {"XSE-001"},
    "host-version-regression.pcap": {"XSE-002"},
    "smtp-cleartext-auth.pcap": {"CRE-001", "PRT-001", "CFG-005"},
    "smtp-no-starttls-advert.pcap": {"CFG-005", "PRT-001"},
    "imap-cleartext-login.pcap": {"CRE-001", "PRT-001"},
    "imap-expiring-soon.pcap": {"CRT-003"},
    "pop3s-not-yet-valid.pcap": {"CRT-002"},
    "imap-hostname-mismatch.pcap": {"CRT-007"},   # SAN does not match SNI
    # gold captures: ZERO findings tolerated
    "all-clean-gold.pcap": set(),
    "after-remediation.pcap": set(),
}


def fired_rules(path: str) -> set[str]:
    r = result_to_dict(analyze_pcap(open(path, "rb").read()))
    # all findings, including host-level cross-session ones (session_id=None)
    return {f["rule_id"] for f in r["findings"]}


@pytest.mark.parametrize("name,expected", sorted(EXPECTED.items()))
def test_scenario_rules(name, expected):
    path = os.path.join(PCAPS, name)
    if not os.path.exists(path):
        pytest.skip("corpus not generated (run scripts/gen_traffic.py)")
    fired = fired_rules(path)
    assert expected <= fired, "missing rules %s in %s (fired %s)" % (
        sorted(expected - fired), name, sorted(fired))


def test_gold_captures_fully_clean():
    for name in ("all-clean-gold.pcap", "after-remediation.pcap"):
        path = os.path.join(PCAPS, name)
        if not os.path.exists(path):
            pytest.skip("corpus not generated")
        r = result_to_dict(analyze_pcap(open(path, "rb").read()))
        assert r["findings"] == [], (
            "gold capture %s must produce zero findings, got %s"
            % (name, [f["rule_id"] for f in r["findings"]]))
        assert r["posture"]["score"] == 100
        assert r["posture"]["grade"] == "A"
        # fusion invariant: clean capture -> zero ML adjustment, score stays 100
        assert r["posture"]["ml_adjustment"] == 0
        assert r["posture"]["rule_score"] == 100


def test_clean_scenarios_score_100():
    for name in ("imaps-good.pcap", "pop3s-good.pcap"):
        path = os.path.join(PCAPS, name)
        if not os.path.exists(path):
            pytest.skip("corpus not generated")
        r = result_to_dict(analyze_pcap(open(path, "rb").read()))
        assert r["posture"]["score"] == 100
        assert r["posture"]["grade"] == "A"


# ---------------- P0 §1.5: genuine SHA-1 fixture ----------------
def test_sha1_fixture_is_real_sha1():
    from cryptography import x509
    path = os.path.join(HERE, "..", "fixtures", "certs", "sha1.der")
    if not os.path.exists(path):
        pytest.skip("certs not generated")
    c = x509.load_der_x509_certificate(open(path, "rb").read())
    assert c.signature_hash_algorithm.name == "sha1"
    assert c.signature_algorithm_oid.dotted_string == "1.2.840.113549.1.1.5"


def test_sha1_selfsigned_scenario_fires_crt006():
    """CRT-006 end-to-end: a real SHA-1-signed self-signed cert on the wire."""
    path = os.path.join(PCAPS, "imaps-sha1-selfsigned.pcap")
    if not os.path.exists(path):
        pytest.skip("corpus not generated")
    r = result_to_dict(analyze_pcap(open(path, "rb").read()))
    fired = {f["rule_id"] for f in r["findings"]}
    assert "CRT-006" in fired, "CRT-006 must fire on the real sha1 fixture"
    # and the self-signed detection still works (manual SHA-1 verify path)
    assert "CRT-004" in fired


def test_cfg005_no_starttls_advert_scenario():
    path = os.path.join(PCAPS, "smtp-no-starttls-advert.pcap")
    if not os.path.exists(path):
        pytest.skip("corpus not generated")
    r = result_to_dict(analyze_pcap(open(path, "rb").read()))
    fired = {f["rule_id"] for f in r["findings"]}
    assert "CFG-005" in fired, "CFG-005 must fire when EHLO omits STARTTLS"


def test_cfg005_does_not_fire_on_starttls_ok():
    path = os.path.join(PCAPS, "starttls-ok.pcap")
    if not os.path.exists(path):
        pytest.skip("corpus not generated")
    r = result_to_dict(analyze_pcap(open(path, "rb").read()))
    fired = {f["rule_id"] for f in r["findings"]}
    assert "CFG-005" not in fired, "CFG-005 must NOT fire on a healthy STARTTLS flow"
    assert r["findings"] == []


# ---------------- P0 §1.6: reassembly robustness ----------------
def test_reassembly_handles_retransmits():
    """Duplicate/out-of-order segments must reconstruct the same stream."""
    from app.pipeline.reassembly import DirectionStream, Segment
    ds = DirectionStream()
    payload = b"HELLO-SECUREMAILSCOPE"
    half = len(payload) // 2
    # second half arrives first (reordered), then a dup of it, then the first half
    ds.add(Segment(seq=100 + half, data=payload[half:], ts=2.0))
    ds.add(Segment(seq=100 + half, data=payload[half:], ts=2.1))   # retransmit
    ds.add(Segment(seq=100, data=payload[:half], ts=2.2))
    assert ds.reassemble() == payload
    assert not ds.reassembly_incomplete


def test_reassembly_wraparound():
    """Sequence numbers that wrap past 2^32 must still sort correctly."""
    from app.pipeline.reassembly import DirectionStream, Segment
    ds = DirectionStream()
    near = (1 << 32) - 10            # 10 bytes before the wrap
    ds.add(Segment(seq=near, data=b"AAAAAAAAAA", ts=1.0))
    ds.add(Segment(seq=0, data=b"BBBBBBBBBB", ts=1.1))     # after wrap
    ds.add(Segment(seq=10, data=b"CC", ts=1.2))
    out = ds.reassemble()
    assert out == b"A" * 10 + b"B" * 10 + b"CC"
    assert not ds.reassembly_incomplete


def test_reassembly_flags_missing_segment():
    """A hole in the middle must never be silently concatenated."""
    from app.pipeline.reassembly import DirectionStream, Segment
    ds = DirectionStream()
    ds.add(Segment(seq=100, data=b"HEAD", ts=1.0))
    ds.add(Segment(seq=116, data=b"TAIL", ts=1.1))     # bytes 104-116 never arrived
    out = ds.reassemble()
    assert out == b"HEAD", "stream must stop at the hole"
    assert ds.reassembly_incomplete
    assert ds.hole_at == 4


def test_reassembly_truncated_flag():
    """Bytes past the per-direction cap are dropped — but flagged."""
    from app.pipeline.reassembly import MAX_STREAM_BYTES, DirectionStream, Segment
    ds = DirectionStream()
    chunk = b"x" * 65536
    sent = 0
    seq = 1000
    while sent < MAX_STREAM_BYTES + 65536:
        ds.add(Segment(seq=seq, data=chunk, ts=1.0))
        sent += len(chunk)
        seq += len(chunk)
    out = ds.reassemble()
    assert len(out) <= MAX_STREAM_BYTES
    assert ds.truncated, "hitting the cap must set the truncated flag"


def test_reassembly_duplicate_and_reordered_combined():
    from app.pipeline.reassembly import DirectionStream, Segment
    ds = DirectionStream()
    payload = b"0123456789ABCDEFGH"
    ds.add(Segment(seq=110, data=payload[10:15], ts=3.0))      # reordered
    ds.add(Segment(seq=100, data=payload[:10], ts=3.1))
    ds.add(Segment(seq=110, data=payload[10:15], ts=3.2))     # duplicate
    ds.add(Segment(seq=115, data=payload[15:], ts=3.3))
    ds.add(Segment(seq=100, data=payload[:5], ts=3.4))        # stale retransmit
    assert ds.reassemble() == payload
    assert not ds.reassembly_incomplete


# ---------------- P0 §1.3: builders on raw pipeline output ----------------
def test_report_builders_accept_raw_output():
    """build_json/build_html/build_pdf must work on the raw analyze_pcap()
    return value (Session objects), not only on result_to_dict() output."""
    from app.reports.builder import build_html, build_json, build_pdf
    path = os.path.join(PCAPS, "mixed.pcap")
    if not os.path.exists(path):
        pytest.skip("corpus not generated")
    raw = analyze_pcap(open(path, "rb").read())
    assert not isinstance(raw["sessions"][0], dict), "test expects raw Session objects"
    j = build_json(raw)
    h = build_html(raw, "mixed.pcap")
    p = build_pdf(raw, "mixed.pcap")
    assert j.startswith(b"{") and b'"prahari.report/v1"' in j
    assert b"Prahari" in h and b"Compliance mapping" in h
    assert p[:4] == b"%PDF"
    # and the normalized dict form still works identically
    j2 = build_json(result_to_dict(raw))
    assert b'"prahari.report/v1"' in j2


def test_report_schema_and_naming():
    from app.reports.builder import build_json
    path = os.path.join(PCAPS, "imaps-good.pcap")
    if not os.path.exists(path):
        pytest.skip("corpus not generated")
    out = build_json(result_to_dict(analyze_pcap(open(path, "rb").read())))
    assert b'"schema": "prahari.report/v1"' in out


# ---------------- P1 §2.1: score fusion ----------------
def test_fusion_bounded_and_directional():
    from app.pipeline.score import fuse_scores, session_ml_adjustment

    class S:   # minimal session stand-in
        def __init__(self, label=None, proba=None, anomaly=False):
            self.ml_risk = {"label": label, "proba": proba} if label else None
            self.is_anomaly = anomaly

    # clean session: zero adjustment regardless
    clean = S("low", [0.0, 0.0, 0.0, 1.0], anomaly=False)
    assert session_ml_adjustment(clean) == 0.0
    # a "clean" session the classifier mislabels still adjusts 0 via the guard
    mislabeled = S("low", [0.0, 0.0, 0.0, 1.0], anomaly=True)
    assert session_ml_adjustment(mislabeled) == 0.0
    # dirty + confident + anomalous: full weight
    hot = S("critical", [0.9, 0.05, 0.05, 0.0], anomaly=True)
    assert session_ml_adjustment(hot, max_session=2.0) == pytest.approx(2.0)
    # dirty but not anomalous: reduced weight
    warm = S("high", [0.0, 0.8, 0.1, 0.1], anomaly=False)
    assert session_ml_adjustment(warm, max_session=2.0) == pytest.approx(2.0 * 0.35 * 0.9)
    # scan-level cap: 50 hot sessions can move the total by at most 10
    fused, adj = fuse_scores([hot] * 50, rule_score=60, ml_available=True)
    assert adj == 10.0
    assert fused == 50
    # clean scan: unchanged
    fused, adj = fuse_scores([clean] * 10, rule_score=100, ml_available=True)
    assert (fused, adj) == (100, 0.0)
    # ML unavailable: unchanged
    fused, adj = fuse_scores([hot] * 10, rule_score=60, ml_available=False)
    assert (fused, adj) == (60, 0.0)


def test_fusion_dirty_capture_scores_shift_and_clean_stays_100():
    """mixed.pcap: fused <= rule score; clean gold: fused == rule == 100."""
    mixed = os.path.join(PCAPS, "mixed.pcap")
    if os.path.exists(mixed):
        p = result_to_dict(analyze_pcap(open(mixed, "rb").read()))["posture"]
        assert p["score"] <= p["rule_score"]
        assert p["ml_adjustment"] >= 0
    gold = os.path.join(PCAPS, "all-clean-gold.pcap")
    if os.path.exists(gold):
        p = result_to_dict(analyze_pcap(open(gold, "rb").read()))["posture"]
        assert p["score"] == p["rule_score"] == 100
        assert p["ml_adjustment"] == 0
        assert p["grade"] == "A"


# ---------------- P1 §2.6: differentiator verification ----------------
def test_differentiators_end_to_end():
    """The claimed differentiators must actually fire on their scenarios."""
    checks = {
        "smtp-tls10-rc4.pcap": {"CPR-004"},          # weakest-suite selection
        "starttls-stripped.pcap": {"CFG-004"},        # STARTTLS stripping
        "host-cert-swap.pcap": {"XSE-001"},           # cross-session cert swap
        "host-version-regression.pcap": {"XSE-002"}, # version regression
        "pop3s-weak-nopfs.pcap": {"PQC-001"},         # PQC-vulnerable kex
        "smtp-cleartext-auth.pcap": {"CRE-001"},      # cleartext creds
    }
    for name, want in checks.items():
        path = os.path.join(PCAPS, name)
        if not os.path.exists(path):
            pytest.skip("corpus not generated")
        fired = fired_rules(path)
        if "PQC-001" in want:
            # PQC-001 is informational (zero weight) — it lives in the
            # advisories channel, not the scored findings
            r = result_to_dict(analyze_pcap(open(path, "rb").read()))
            adv = {a["rule_id"] for a in r["advisories"]}
            assert "PQC-001" in adv, (
                "%s missing PQC-001 advisory (advisories %s)" % (name, sorted(adv)))
            want = want - {"PQC-001"}
        assert want <= fired, "%s missing %s (fired %s)" % (name, want, sorted(fired))


def test_credentials_are_redacted():
    """CRE-001 evidence must never carry a usable secret: passwords appear
    only in bullet-redacted form (imap/pop3) or as lengths (smtp b64 tokens)."""
    path = os.path.join(PCAPS, "smtp-cleartext-auth.pcap")
    if not os.path.exists(path):
        pytest.skip("corpus not generated")
    r = result_to_dict(analyze_pcap(open(path, "rb").read()))
    n = 0
    for f in r["findings"]:
        if f["rule_id"] == "CRE-001":
            n += 1
            pw = f["evidence"].get("password")
            if pw is not None:
                assert set(pw) <= {chr(0x2022)}, "password must be bullets only"
            assert f["evidence"].get("redacted") is True
    assert n > 0, "CRE-001 must fire on the cleartext-auth scenario"
    for s in r["sessions"]:
        for c in s.get("cleartext_creds", []):
            pw = c.get("password")
            if pw is not None:
                assert set(pw) <= {chr(0x2022)}, "session creds must be redacted"
            assert c.get("redacted") is True
    # plaintext login scenarios carry the bullet form for imap/pop3
    for name in ("imap-cleartext-login.pcap", "pop3-cleartext.pcap"):
        p2 = os.path.join(PCAPS, name)
        if not os.path.exists(p2):
            continue
        r2 = result_to_dict(analyze_pcap(open(p2, "rb").read()))
        for s2 in r2["sessions"]:
            for c2 in s2.get("cleartext_creds", []):
                pw2 = c2.get("password")
                if pw2 is not None:
                    assert set(pw2) <= {chr(0x2022)}


def test_findings_sorted_by_severity_then_weight():
    path = os.path.join(PCAPS, "mixed.pcap")
    if not os.path.exists(path):
        pytest.skip("corpus not generated")
    r = result_to_dict(analyze_pcap(open(path, "rb").read()))
    order = ["critical", "high", "medium", "low", "info"]
    keys = [(order.index(f["severity"]), -f["weight"]) for f in r["findings"]]
    assert keys == sorted(keys), "findings must be ordered critical->info then weight desc"


def test_reassembly_flags_surface_in_result():
    path = os.path.join(PCAPS, "mixed.pcap")
    if not os.path.exists(path):
        pytest.skip("corpus not generated")
    r = result_to_dict(analyze_pcap(open(path, "rb").read()))
    for s in r["sessions"]:
        assert "reassembly_incomplete" in s
        assert "truncated" in s
    assert "reassembly_incomplete_sessions" in r["meta"]


# ---------------- API end-to-end (local in-memory mode) ----------------
@pytest.fixture()
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        yield c


def test_api_end_to_end(client):
    path = os.path.join(PCAPS, "mixed.pcap")
    if not os.path.exists(path):
        pytest.skip("corpus not generated")
    with open(path, "rb") as fh:
        up = client.post("/api/scans", files={"file": ("mixed.pcap", fh)})
    assert up.status_code == 201, up.text
    scan_id = up.json()["id"]

    assert client.post(f"/api/scans/{scan_id}/analyze").status_code == 202

    for _ in range(120):                      # up to ~60 s (CI slack)
        st = client.get(f"/api/scans/{scan_id}/status").json()
        if st["status"] in ("complete", "failed"):
            break
        time.sleep(0.5)
    assert st["status"] == "complete", st

    detail = client.get(f"/api/scans/{scan_id}").json()
    assert detail["posture_score"] is not None
    assert detail["session_count"] >= 8

    sess = client.get(f"/api/scans/{scan_id}/sessions").json()
    assert sess["total"] >= 8
    sid = sess["items"][0]["session_id"]
    one = client.get(f"/api/scans/{scan_id}/sessions/{sid}").json()
    assert one["session"]["session_id"] == sid

    fnd = client.get(f"/api/scans/{scan_id}/findings").json()
    assert fnd["total"] >= 5
    # differentiator rules present in mixed corpus
    rules_hit = {f["rule_id"] for f in fnd["items"]}
    assert "CRE-001" in rules_hit, "credential exposure must fire"
    # PQC-001 is informational — served by the advisories endpoint
    adv = client.get(f"/api/scans/{scan_id}/advisories").json()
    adv_hit = {a["rule_id"] for a in adv["items"]}
    assert "PQC-001" in adv_hit, "PQC advisory must fire"

    certs = client.get(f"/api/scans/{scan_id}/certificates").json()
    assert certs["total"] >= 3

    rj = client.get(f"/api/scans/{scan_id}/report.json")
    assert rj.status_code == 200 and rj.json()["posture"]["grade"]
    rh = client.get(f"/api/scans/{scan_id}/report.html")
    assert rh.status_code == 200 and b"Prahari" in rh.content
    rp = client.get(f"/api/scans/{scan_id}/report.pdf")
    assert rp.status_code == 200 and rp.content[:4] == b"%PDF"

    assert client.delete(f"/api/scans/{scan_id}").status_code == 204


def test_upload_rejects_non_pcap(client):
    r = client.post("/api/scans", files={"file": ("x.pcap", b"not a pcap")})
    assert r.status_code == 400


def test_upload_rejects_oversize(client):
    blob = b"\xd4\xc3\xb2\xa1" + b"\x00" * (26 * 1024 * 1024)   # 26 MB, valid magic
    r = client.post("/api/scans", files={"file": ("big.pcap", blob)})
    assert r.status_code == 413


def test_before_after_remediation_delta():
    """The headline before/after pair: mixed.pcap is dirty; after-remediation.pcap is 100/A."""
    mixed = os.path.join(PCAPS, "mixed.pcap")
    after = os.path.join(PCAPS, "after-remediation.pcap")
    if not (os.path.exists(mixed) and os.path.exists(after)):
        pytest.skip("corpus not generated")
    a = result_to_dict(analyze_pcap(open(mixed, "rb").read()))["posture"]
    b = result_to_dict(analyze_pcap(open(after, "rb").read()))["posture"]
    assert a["score"] < 60, "mixed corpus is expected to be badly scored"
    assert b["score"] == 100 and b["grade"] == "A"
    assert b["score"] > a["score"]


def test_frame_numbers_are_per_read_and_absolute():
    """Frame numbers must be 1-based positions in the capture file: fresh per
    read_pcap() call (no global carry-over) and counted before filtering, so
    non-TCP packets consume a number exactly like Wireshark's "No." column."""
    import dpkt

    from app.pipeline.ingest import read_pcap

    data = open(os.path.join(PCAPS, "starttls-ok.pcap"), "rb").read()

    # (a) reading the same capture twice must produce identical numbers
    first = [p[8] for p in read_pcap(data)]
    second = [p[8] for p in read_pcap(data)]
    assert first == second, "frame numbering leaked state across reads"

    # starttls-ok.pcap is 100% TCP, so the first yielded packet is packet 1
    assert first[0] == 1, "first TCP packet should be frame 1"

    # (b) build a synthetic capture: one UDP/DNS packet ahead of one TCP
    # packet. The TCP packet must get frame number 2 (absolute), not 1.
    import io as _io

    udp = dpkt.ip.IP()
    udp.src = b"\x0a\x00\x00\x01"
    udp.dst = b"\x0a\x00\x00\x02"
    udp.p = dpkt.ip.IP_PROTO_UDP
    udp.data = b"\x00\x35\x00\x35\x00\x20\x00\x00" + b"\x00" * 16
    udp.len = len(udp)

    tcp_pkt = dpkt.ip.IP()
    tcp_pkt.src = b"\x0a\x00\x00\x01"
    tcp_pkt.dst = b"\x0a\x00\x00\x02"
    tcp_pkt.p = dpkt.ip.IP_PROTO_TCP
    tcp_pkt.data = dpkt.tcp.TCP(
        sport=1234, dport=993, seq=1, flags=dpkt.tcp.TH_SYN,
        data=b"",
    )
    tcp_pkt.len = len(tcp_pkt)

    eth_udp = dpkt.ethernet.Ethernet(
        type=dpkt.ethernet.ETH_TYPE_IP, data=udp)
    eth_tcp = dpkt.ethernet.Ethernet(
        type=dpkt.ethernet.ETH_TYPE_IP, data=tcp_pkt)

    buf = _io.BytesIO()
    pcapw = dpkt.pcap.Writer(buf)
    pcapw.writepkt(bytes(eth_udp), ts=1.0)
    pcapw.writepkt(bytes(eth_tcp), ts=2.0)
    packets = list(read_pcap(buf.getvalue()))
    assert len(packets) == 1, "only the TCP packet should be yielded"
    assert packets[0][8] == 2, (
        "frame numbering must be absolute (TCP packet is packet 2 in the"
        " file, after the DNS packet), not compacted"
    )


# ---------------- PQC assessment (post-quantum readiness) ----------------
def test_tls13_x25519_is_quantum_vulnerable_not_pqc_ready():
    """Bare TLS 1.3 with X25519 is harvest-now-decrypt-later vulnerable:
    it must be counted quantum-vulnerable, NOT PQC-ready, and carry the
    PQC-001 advisory (informational, zero weight)."""
    path = os.path.join(PCAPS, "all-clean-gold.pcap")
    if not os.path.exists(path):
        pytest.skip("corpus not generated")
    r = result_to_dict(analyze_pcap(open(path, "rb").read()))
    pqc = r["posture"]["pqc"]
    tls13 = [s for s in r["sessions"]
             if s["tls_version"] == "TLSv1.3" and s["kex_mechanism"] == "(TLS1.3)"]
    assert tls13, "fixture must contain a TLS 1.3 session"
    assert all(s["negotiated_group"] == "x25519" for s in tls13)
    assert pqc["pqc_ready_sessions"] == 0, (
        "bare TLS 1.3 X25519 must never count as PQC-ready")
    assert pqc["quantum_vulnerable_sessions"] >= len(tls13)
    # zero weight: the advisory fires but nothing is deducted
    adv = [a for a in r["advisories"] if a["rule_id"] == "PQC-001"
           and a["session_id"] in {s["session_id"] for s in tls13}]
    assert adv, "TLS 1.3 X25519 sessions must carry the PQC-001 advisory"
    assert all(a["weight"] == 0 and a["severity"] == "info" for a in adv)
    assert r["posture"]["score"] == 100 and r["posture"]["rule_score"] == 100


def test_hybrid_mlkem_group_is_pqc_ready():
    """A session negotiating X25519MLKEM768 is PQC-ready: counted as such,
    not counted quantum-vulnerable, and carries no PQC-001 advisory."""
    path = os.path.join(PCAPS, "pqc-hybrid-kex.pcap")
    if not os.path.exists(path):
        pytest.skip("corpus not generated")
    r = result_to_dict(analyze_pcap(open(path, "rb").read()))
    pqc = r["posture"]["pqc"]
    assert pqc["pqc_ready_sessions"] == 1
    assert pqc["quantum_vulnerable_sessions"] == 0
    assert not [a for a in r["advisories"] if a["rule_id"] == "PQC-001"]
    sess = r["sessions"][0]
    assert sess["negotiated_group"] == "X25519MLKEM768"
    assert sess["key_exchange_group_size"] == 128


def test_group_parsing_known_and_unknown():
    """group_name returns the right name for known ids and None for
    unknown ids; a malformed extension never raises."""
    from app.pipeline.tls_parser import group_name, parse_stream
    assert group_name(0x0017) == "secp256r1"
    assert group_name(0x001d) == "x25519"
    assert group_name(0x11ec) == "X25519MLKEM768"
    assert group_name(0x11eb) == "SecP256r1MLKEM768"
    assert group_name(0xdead) is None
    assert group_name(None) is None
    # unknown group id in a real supported_groups list: parse survives
    # (supported_groups body: count=2, groups=[0xdead, 0xbeef])
    import struct as _struct
    sg = _struct.pack(">H", 4) + _struct.pack(">HH", 0xdead, 0xbeef)
    exts = (10).to_bytes(2, "big") + len(sg).to_bytes(2, "big") + sg
    ch_body = (0x0303).to_bytes(2, "big") + bytes(32) + b"\x00" + \
        (4).to_bytes(2, "big") + (0x1301).to_bytes(2, "big") + \
        (0x1302).to_bytes(2, "big") + b"\x01\x00" + \
        len(exts).to_bytes(2, "big") + exts
    hs = (1).to_bytes(1, "big") + len(ch_body).to_bytes(3, "big") + ch_body
    rec = bytes([22]) + (0x0303).to_bytes(2, "big") + \
        len(hs).to_bytes(2, "big") + hs
    info = parse_stream(rec)
    assert info.offered_groups == [0xdead, 0xbeef]


# ---------------- ERD fields: packet_offset + ml_confidence ----------------
def test_findings_carry_packet_offset_and_ml_confidence():
    """Every finding (and advisory) from mixed.pcap carries both §2.3 ERD
    fields: packet_offset (byte offset of the session's first evidence frame
    in the capture file, or None) and ml_confidence (the classifier's bad-class
    probability mass for the session, float in [0,1], or None for
    host-level findings with no session ML context)."""
    path = os.path.join(PCAPS, "mixed.pcap")
    if not os.path.exists(path):
        pytest.skip("corpus not generated")
    r = result_to_dict(analyze_pcap(open(path, "rb").read()))
    assert r["findings"], "mixed corpus must produce findings"
    for f in r["findings"] + r["advisories"]:
        assert "packet_offset" in f, f["rule_id"] + " missing packet_offset"
        assert "ml_confidence" in f, f["rule_id"] + " missing ml_confidence"
        off = f["packet_offset"]
        assert off is None or (isinstance(off, int) and off >= 0), (
            "packet_offset must be a non-negative int or None, got %r" % off)
        conf = f["ml_confidence"]
        assert conf is None or (isinstance(conf, (int, float))
                                and 0.0 <= conf <= 1.0), (
            "ml_confidence must be a float in [0,1] or None, got %r" % conf)
    # host-level findings have no session context -> both must be None
    for f in r["findings"]:
        if f["session_id"] is None:
            assert f["packet_offset"] is None
            assert f["ml_confidence"] is None
    # at least some session findings carry a real (non-null) offset
    session_findings = [f for f in r["findings"] if f["session_id"]]
    assert any(f["packet_offset"] is not None for f in session_findings)


# ---------------- renegotiation detection (CFG-007) ----------------
def test_renegotiation_detection_and_non_firing():
    """A second ClientHello on an established stream sets renegotiation_seen
    (and CFG-007 fires when RFC 5746 renegotiation_info is absent); a single
    ClientHello — including on TLS 1.3 sessions — must never flag."""
    path = os.path.join(PCAPS, "insecure-reneg.pcap")
    if not os.path.exists(path):
        pytest.skip("corpus not generated")
    r = result_to_dict(analyze_pcap(open(path, "rb").read()))
    assert any(f["rule_id"] == "CFG-007" for f in r["findings"])
    assert r["sessions"][0]["renegotiation_seen"] is True
    # every other scenario pcap: at most one ClientHello per stream
    for name in ("all-clean-gold.pcap", "imaps-good.pcap", "starttls-ok.pcap"):
        p = os.path.join(PCAPS, name)
        if not os.path.exists(p):
            continue
        rr = result_to_dict(analyze_pcap(open(p, "rb").read()))
        assert not any(s["renegotiation_seen"] for s in rr["sessions"]), name
        assert not any(f["rule_id"] == "CFG-007" for f in rr["findings"]), name
