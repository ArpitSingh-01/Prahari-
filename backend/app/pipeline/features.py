"""Numeric feature vectors per session (inputs to both ML models)."""
from __future__ import annotations

from .tls_parser import cipher_strength

FEATURE_NAMES = [
    "tls_version_num", "cipher_strength_bits", "cipher_id",
    "kex_is_pfs", "cert_key_bits", "cert_sig_alg_id",
    "cert_days_valid", "cert_days_to_expiry", "cert_is_self_signed",
    "cert_chain_issues_count", "transport_id", "alert_count",
    "renegotiation_seen", "session_resumed", "duration_ms_log",
    "bytes_client_log", "bytes_server_log",
    # PS §1.4 features (task: wire the four missing ones)
    "cert_chain_length",       # certificates offered in the session's chain
    "hostname_match",          # 1 matched / 0 mismatched / -1 not checkable (no SNI)
    "cipher_mismatch_count",   # offered suites stronger than the selected one
    "plaintext_prelude_len_log",  # log10 of pre-STARTTLS plaintext bytes
]

_SIG_IDS = {"sha256": 1, "sha384": 2, "sha512": 3, "sha1": 4, "md5": 5}
_TRANSPORT_IDS = {"implicit": 2, "starttls": 1, "plaintext": 0}


def extract(sess, cert_records: list[dict] | None = None) -> dict[str, float]:
    import math
    # leaf = the record flagged is_leaf by the pipeline (runner sets
    # is_leaf on index 0); fall back to the same definition for raw lists
    leaf = next((c for c in (cert_records or []) if c.get("is_leaf")), None) or \
        (cert_records[0] if cert_records else None)

    ver = 0
    if sess.tls_version:
        table = {"SSLv2": 0x0200, "SSLv3": 0x0300, "TLSv1.0": 0x0301,
                 "TLSv1.1": 0x0302, "TLSv1.2": 0x0303, "TLSv1.3": 0x0304}
        ver = table.get(sess.tls_version, 0)

    def lg(n):
        return math.log10(n + 1) if n else 0.0

    # hostname/SNI match: tri-state — matched / mismatched / not checkable
    if not sess.sni or leaf is None:
        hostname_match = -1.0                   # no SNI sent: unknown, not clean
    else:
        mismatched = any(i.startswith("hostname mismatch")
                         for i in leaf.get("chain_issues", []))
        hostname_match = 0.0 if mismatched else 1.0

    # offered suites strictly stronger than the one the server chose
    mismatch = 0
    if sess.cipher_id and sess.offered_ciphers:
        chosen_strength = cipher_strength(sess.cipher_id)
        mismatch = sum(1 for c in sess.offered_ciphers
                       if cipher_strength(c) > chosen_strength)

    return {
        "tls_version_num": ver,
        "cipher_strength_bits": cipher_strength(sess.cipher_id) if sess.cipher_id else 0,
        "cipher_id": sess.cipher_id or 0,
        "kex_is_pfs": 1.0 if sess.pfs else 0.0,
        "cert_key_bits": (leaf["key_length"] if leaf else 0),
        "cert_sig_alg_id": _SIG_IDS.get(leaf["signature_hash"], 0) if leaf else 0,
        "cert_days_valid": (leaf["days_valid"] if leaf else 0),
        "cert_days_to_expiry": (leaf["days_to_expiry"] if leaf else 0),
        "cert_is_self_signed": 1.0 if (leaf and leaf["self_signed"]) else 0.0,
        "cert_chain_issues_count": float(getattr(sess, "_chain_issue_count", 0)),
        "transport_id": _TRANSPORT_IDS.get(sess.transport, 0),
        "alert_count": sess.alert_count,
        "renegotiation_seen": 1.0 if sess.reneg_seen else 0.0,
        "session_resumed": 1.0 if sess.resumed else 0.0,
        "duration_ms_log": lg(sess.duration_ms),
        "bytes_client_log": lg(sess.bytes_c2s),
        "bytes_server_log": lg(sess.bytes_s2c),
        # PS §1.4 features
        "cert_chain_length": float(sum(len(ch) for ch in sess.cert_chains)
                                   if sess.cert_chains else 0),
        "hostname_match": hostname_match,
        "cipher_mismatch_count": float(mismatch),
        "plaintext_prelude_len_log": lg(getattr(sess, "plaintext_prelude_len", 0)),
    }


def to_vector(feat: dict[str, float]) -> list[float]:
    return [feat[name] for name in FEATURE_NAMES]
