"""Posture scoring: session grade and scan-level aggregate.

Fusion contract (documented in docs/backend.md and the report appendix):
- `rule_score` is the compliance anchor: 100 − Σ rule weights. Never lost.
- ML may move a session by at most `max_session` points (default 2), driven
  by anomaly confirmation and classifier confidence, and only in the
  direction the rule evidence already points (never upgrades a dirty
  session). The scan-level fused score moves at most `max_total` (10).
- A clean session (no findings, no anomaly) always adjusts 0 — so clean
  captures stay exactly 100/A (golden-test invariant).
"""
from __future__ import annotations

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def grade_of(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def score_session(findings: list[dict]) -> tuple[int, str]:
    deduction = sum(f["weight"] for f in findings)
    score = max(0, 100 - deduction)
    return score, grade_of(score)


def score_scan(sessions: list, findings_by_session: dict[str, list[dict]]) -> tuple[int, str, dict]:
    """Scan score weights sessions by their own risk (worse sessions count more)."""
    if not sessions:
        return 100, "A", {}
    total_weighted = 0.0
    total_w = 0.0
    by_server: dict[str, list[int]] = {}
    for s in sessions:
        s_score, _ = score_session(findings_by_session.get(s.session_id, []))
        w = 1.0 + (100 - s_score) / 50.0
        total_weighted += s_score * w
        total_w += w
        host = s.server_host or s.dst_ip or "unknown"
        by_server.setdefault(host, []).append(s_score)
    score = int(round(total_weighted / total_w)) if total_w else 100
    server_grades = {h: {"mean_score": sum(v) // len(v), "sessions": len(v)}
                     for h, v in by_server.items()}
    return score, grade_of(score), server_grades


# ---- rules + ML fusion (bounded) -------------------------------------------

_ML_LABEL_ORDER = ["critical", "high", "medium", "low"]   # training label order


def ml_confidence(s) -> float | None:
    """Probability mass the risk classifier puts on any bad risk class
    (critical/high/medium) for this session — in [0, 1], or None when the
    classifier produced no probabilities. The same value drives the fused
    adjustment and is published as per-finding `ml_confidence`."""
    ml_risk = getattr(s, "ml_risk", None) or {}
    proba = ml_risk.get("proba") or []
    if not proba:
        return None
    try:
        return min(1.0, max(0.0, sum(p for n, p in zip(_ML_LABEL_ORDER, proba)
                                     if n != "low")))
    except Exception:
        return None


def session_ml_adjustment(s, max_session: float = 2.0) -> float:
    """Bounded per-session ML score adjustment, in [0, max_session].

    Formula: adj = max_session × w_anom × w_conf where
      w_anom  — 1.0 when the IsolationForest flags the session, else 0.35
      w_conf  — probability mass the risk classifier puts on any bad class
                (critical/high/medium). A clean 'low' verdict gives 0, so a
                session with no findings and no anomaly adjusts exactly 0.
    Adjustments are non-negative (risk-side only): ML can deepen a verdict
    the rules already imply, never soften it, and never touches a clean one.
    """
    w_conf = ml_confidence(s)
    if not w_conf:
        return 0.0
    w_anom = 1.0 if getattr(s, "is_anomaly", False) else 0.35
    return max_session * w_anom * w_conf


def fuse_scores(sessions: list, rule_score: int, ml_available: bool,
                max_session: float = 2.0, max_total: float = 10.0,
                ) -> tuple[int, float]:
    """Fuse the rule-derived scan score with bounded ML adjustments.

    Returns (fused_score, total_adjustment). The fused score is clamped to
    [0, 100] and may never sit above the ceiling implied by a critical
    finding (rule_score <= 30 guarantees F-band; fusion respects band
    boundaries by only ever moving DOWN from rule_score).
    """
    if not ml_available or not sessions:
        return rule_score, 0.0
    # a capture the rules scored perfectly must stay exactly 100/A
    if rule_score >= 100:
        return rule_score, 0.0
    total = sum(session_ml_adjustment(s, max_session) for s in sessions)
    total = max(0.0, min(max_total, total))
    fused = max(0, min(100, int(round(rule_score - total))))
    return fused, round(total, 1)


_VER_ORDER = {"SSLv2": 0, "SSLv3": 1, "TLSv1.0": 2, "TLSv1.1": 3,
              "TLSv1.2": 4, "TLSv1.3": 5}


def cross_session_findings(sessions) -> list[dict]:
    """Host-level analysis across one capture: certificate swaps and TLS
    version regressions on the same server. Returns partial findings dicts;
    the runner attaches rule metadata via rules.RULES."""
    from .rules import RULES
    out: list[dict] = []
    hosts: dict[str, list] = {}
    for s in sessions:
        key = s.server_host or s.dst_ip or "unknown"
        hosts.setdefault(key, []).append(s)

    for host, ss in hosts.items():
        ss.sort(key=lambda s: s.start_time or 0)
        # certificate swap: DISTINCT leaf fingerprints across sessions of
        # this host (dedup by fingerprint — repeats of the same cert are normal)
        fingerprints: dict[str, str] = {}     # fingerprint -> session_id
        for s in ss:
            for c in getattr(s, "_cert_records", []):
                if c.get("is_leaf"):
                    fingerprints.setdefault(c["fingerprint_sha256"], s.session_id)
                    break
        if len(fingerprints) > 1:
            out.append(("XSE-001", host,
                        {"distinct_certs": len(fingerprints),
                         "sessions": list(fingerprints.values())}))
        # version regression: the same host DROPS below its own best negotiated
        # version in a later session. A host steadily serving its max supported
        # version (e.g. 1.3 then 1.2 for a legacy client) is normal; a
        # regression (1.2 then 1.0) signals downgrade interference.
        vers = [(s.session_id, s.tls_version) for s in ss
                 if s.tls_version and s.transport != "plaintext"]
        best = max((_VER_ORDER.get(v, 0) for _, v in vers), default=0)
        for (sid_a, v_a), (sid_b, v_b) in zip(vers, vers[1:]):
            order_b = _VER_ORDER.get(v_b, 0)
            if sid_a != sid_b and order_b < _VER_ORDER.get(v_a, 0) and order_b < best - 1:
                out.append(("XSE-002", host,
                            {"from": v_a, "to": v_b,
                             "host_best": [k for k, o in _VER_ORDER.items() if o == best],
                             "sessions": [sid_a, sid_b]}))
                break
    return out
