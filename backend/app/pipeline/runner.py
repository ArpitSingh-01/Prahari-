"""Pipeline runner: pcap bytes -> full analysis result dict.

Pure-python, no I/O: safe to call from tests, scripts, or the API worker.

Score model (PS §1.3 "rules + ML fusion"):
- rule_score  — 100 − Σ rule weights; the compliance anchor, always reported.
- ml_adjustment — bounded AI adjustment derived from the per-session ML risk
  classifier + anomaly detector. Zero when a session is clean.
- score (fused) — rule_score + Σ session adjustments, clamped to [0, 100]
  and never allowed to exceed the ceiling implied by a critical finding.
A capture with zero findings and zero anomalies must score exactly 100/A.
"""
from __future__ import annotations

import datetime as dt

from . import ingest, rules, score
from . import certificates as certmod
from . import sessions as sessmod
from . import tls_parser
from .features import FEATURE_NAMES, extract as extract_features, to_vector
from .reassembly import FlowTable

ML_MAX_SESSION_ADJUSTMENT = 2.0    # per-session cap; 5+ sessions can reach ±10
ML_MAX_SCAN_ADJUSTMENT = 10.0      # hard ceiling on the total ML move


def analyze_pcap(data: bytes, progress=None):
    """Analyze a pcap. Returns dict:
    {sessions, findings, certificates, features, posture, protocol_counts,
     servers, meta}
    Session objects carry findings in-session (also aggregated in 'findings').
    """
    def tick(pct, stage):
        if progress:
            progress(pct, stage)

    tick(5, "ingest")
    packets = ingest.read_pcap(data)
    table = FlowTable()
    count = 0
    frame_offsets: dict[int, int] = {}    # frame number -> file byte offset
    for (ts, src, sport, dst, dport, seq, flags, payload, frame_no,
         file_offset) in packets:
        syn = bool(flags & 0x02) and not bool(flags & 0x10)
        fin = bool(flags & 0x01)
        rst = bool(flags & 0x04)
        table.add_packet(src, sport, dst, dport, seq, payload, ts, frame_no,
                         syn=syn, fin=fin, rst=rst)
        if file_offset >= 0:
            frame_offsets.setdefault(frame_no, file_offset)
        count += 1

    tick(25, "protocol-id")
    sessions: list = []
    for flow in table.finished_flows(min_bytes=4):
        sess = sessmod.build_session(flow)
        if sess is not None:
            sessions.append(sess)

    tick(45, "tls-analysis")
    findings: list[dict] = []
    advisories: list[dict] = []
    cert_records: list[dict] = []
    features: list[dict] = []

    for i, s in enumerate(sessions):
        s.session_id = "sess-%04d" % (i + 1)
        certs = sessmod.analyze_certificates(s)
        s._cert_records = certs
        issues: list[str] = []
        for chain in s.cert_chains:
            _, ch_issues = certmod.analyze_chain(chain, s.sni)
            issues.extend(ch_issues)
        s._chain_issues = sorted(set(issues))
        s._chain_issue_count = len(s._chain_issues)
        # surface chain-level issues on the leaf cert record for the rule engine
        for ci, c in enumerate(s._cert_records):
            c["is_leaf"] = (ci == 0)
            c.setdefault("chain_issues", [])
            if c["is_leaf"]:
                c["chain_issues"] = sorted(set(c["chain_issues"]) | set(s._chain_issues))

        fnd, adv = rules.evaluate_session(s)
        for f in fnd:
            f["session_id"] = s.session_id
        for a in adv:
            a["session_id"] = s.session_id
        s.findings = fnd
        s._advisories = adv
        findings.extend(fnd)
        advisories.extend(adv)

        for c in certs:
            c = dict(c)
            c["session_id"] = s.session_id
            cert_records.append(c)
        features.append(extract_features(s, certs))
        if progress and i % 20 == 0:
            tick(45 + int(25 * i / max(1, len(sessions))), "tls-analysis")

    tick(70, "cross-session")
    host_findings: list[dict] = []
    try:
        from .rules import RULES
        for rid, host, ev in score.cross_session_findings(sessions):
            meta = RULES[rid]
            host_findings.append({
                "rule_id": rid, "title": meta["title"],
                "severity": meta["severity"], "category": meta["category"],
                "weight": meta["weight"], "reference": meta["reference"],
                "remediation": meta["remediation"],
                "description": "%s on host %s" % (meta["title"], host),
                "evidence": ev, "session_id": None,
                "evidence_frames": [],
            })
    except Exception:
        pass

    tick(75, "scoring")
    findings_by_session: dict[str, list[dict]] = {}
    for s in sessions:
        # bind packet-level evidence: frames carrying this session's TLS stream
        frames = (s.frames_c2s or []) + (s.frames_s2c or [])
        first_frame = frames[0] if frames else None
        for f in list(s.findings) + list(getattr(s, "_advisories", [])):
            f["evidence_frames"] = frames[:12] if frames else []
            f["evidence_hex"] = _hex_window(s.raw_c2s, 96) if "CRE-001" in f["rule_id"] else None
            # byte offset of the session's first evidence frame in the capture
            # file (None when the frame's offset was not recorded)
            f["packet_offset"] = frame_offsets.get(first_frame) if first_frame else None
        findings_by_session[s.session_id] = s.findings
    findings.extend(host_findings)
    for f in host_findings:
        # host-level cross-session findings name no single packet
        f.setdefault("packet_offset", None)
    # prioritized ordering is a property of the core output: critical first,
    # then by descending weight (score.SEVERITY_ORDER is the canonical order)
    findings.sort(key=lambda f: (score.SEVERITY_ORDER.index(f["severity"])
                                if f["severity"] in score.SEVERITY_ORDER else 99,
                                -f["weight"]))
    for s in sessions:
        s.risk_score, s.grade = score.score_session(s.findings)

    proto_counts: dict[str, int] = {}
    for s in sessions:
        label = s.protocol + ("s" if s.transport == "implicit" and s.tls_version else "")
        proto_counts[label] = proto_counts.get(label, 0) + 1

    severity_counts: dict[str, int] = {}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    tick(85, "ml")
    anomaly_explanations: list[dict] = []
    ml_available = False
    try:
        from ..ml_runtime import predict as mlp
        ml_available = mlp.available()
        if ml_available:
            for s, feat in zip(sessions, features):
                vec = to_vector(feat)
                s.is_anomaly, s.anomaly_score, s.anomaly_explanation = \
                    mlp.predict_anomaly(vec, FEATURE_NAMES)
                _, label, proba = mlp.predict_risk(vec)
                s.ml_risk = {"label": label, "proba": proba}
                if s.is_anomaly:
                    anomaly_explanations.append({
                        "session_id": s.session_id,
                        "score": round(s.anomaly_score, 4),
                        "top_features": s.anomaly_explanation,
                        "ml_risk": s.ml_risk,
                    })
    except Exception:
        pass                     # ML is additive; rules/scoring must never fail

    # per-finding AI confidence: the classifier's probability mass on any bad
    # risk class for the session the finding belongs to — the same confidence
    # that drives the fused adjustment (score.ml_confidence). Host-level
    # findings (session_id None) have no session ML context: None.
    sess_by_id = {s.session_id: s for s in sessions}
    for f in findings + advisories:
        sess = sess_by_id.get(f.get("session_id"))
        conf = score.ml_confidence(sess) if (sess and ml_available) else None
        f["ml_confidence"] = round(conf, 4) if conf is not None else None

    tick(90, "score-fusion")
    # ---- rules + ML fusion (bounded, defensible, clean-invariant-safe) ----
    rule_score, _, servers = score.score_scan(sessions, findings_by_session)
    fused_score, ml_adjustment = score.fuse_scores(
        sessions, rule_score, ml_available,
        max_session=ML_MAX_SESSION_ADJUSTMENT, max_total=ML_MAX_SCAN_ADJUSTMENT)
    for s in sessions:
        s.rule_score, _ = score.score_session(s.findings)   # rule anchor
        adj = score.session_ml_adjustment(s) if ml_available else 0.0
        # a session the rules scored clean must stay exactly clean
        adj = 0.0 if s.rule_score >= 100 else adj
        s.ml_adjustment = round(adj, 1)
        fused = max(0, min(100, int(round(s.rule_score - adj))))
        s.risk_score, s.grade = fused, score.grade_of(fused)

    tick(95, "done")
    return {
        "sessions": sessions,
        "findings": findings,
        "advisories": advisories,
        "certificates": cert_records,
        "features": features,
        "anomaly_explanations": anomaly_explanations,
        "posture": {
            "rule_score": rule_score,
            "ml_adjustment": ml_adjustment,
            "score": fused_score,
            "grade": score.grade_of(fused_score),
            "ml": {
                "enabled": ml_available,
                "anomalous_sessions": sum(1 for s in sessions if s.is_anomaly),
                "risk_distribution": _risk_distribution(sessions),
            },
            "severity_counts": severity_counts,
            "servers": servers,
            "pqc": {
                "quantum_vulnerable_sessions": sum(
                    1 for s in sessions
                    if getattr(s, "kex_mechanism", None) in
                    ("RSA", "DHE", "ECDH", "DH_anon", "ECDHE", "(TLS1.3)")
                    and s.tls_version
                    and getattr(s, "negotiated_group", None) not in
                    tls_parser.PQC_HYBRID_GROUPS),
                # PQC-ready means a hybrid ML-KEM group was actually
                # negotiated — bare TLS 1.3 X25519 is NOT post-quantum.
                "pqc_ready_sessions": sum(
                    1 for s in sessions
                    if getattr(s, "negotiated_group", None) in
                    tls_parser.PQC_HYBRID_GROUPS),
            },
            "credential_exposure": sum(
                1 for s in sessions if getattr(s, "cleartext_creds", None)),
        },
        "protocol_counts": proto_counts,
        "meta": {
            "packet_count": count,
            "flow_count": len(table.flows),
            "flows_overflowed": table.overflowed,
            "reassembly_incomplete_sessions": sum(
                1 for s in sessions if getattr(s, "reassembly_incomplete", False)),
            "truncated_sessions": sum(
                1 for s in sessions if getattr(s, "truncated", False)),
            "analyzed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        },
    }


def _risk_distribution(sessions) -> dict[str, int]:
    dist: dict[str, int] = {}
    for s in sessions:
        label = (s.ml_risk or {}).get("label") if getattr(s, "ml_risk", None) else None
        if label:
            dist[label] = dist.get(label, 0) + 1
    return dist


def _hex_window(data: bytes, n: int) -> str:
    """First n bytes as hex dump evidence (bounded, redacted-safe)."""
    chunk = (data or b"")[:n]
    return chunk.hex()


def result_to_dict(result: dict) -> dict:
    """JSON-serializable version of analyze_pcap output (API + fixtures)."""
    return {
        "sessions": [s.to_dict() | {"session_id": s.session_id}
                     for s in result["sessions"]],
        "findings": result["findings"],
        "advisories": result.get("advisories", []),
        "certificates": result["certificates"],
        "features": result["features"],
        "anomaly_explanations": result["anomaly_explanations"],
        "posture": result["posture"],
        "protocol_counts": result["protocol_counts"],
        "meta": result["meta"],
    }
