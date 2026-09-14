"""Deterministic weak-cryptography rule engine.

Each rule: id, title, severity, weight, category, reference (compliance
mapping), remediation. Session score = 100 - sum(weights of fired rules).
Seeded from NIST SP 800-52r2, BSI TR-02102-02, CERT-In advisories.
"""
from __future__ import annotations

from . import certificates as certmod
from . import tls_parser
from .tls_parser import cipher_strength, kex_of

RULES: dict[str, dict] = {}


def rule(rid, title, severity, weight, category, reference, remediation):
    RULES[rid] = {
        "rule_id": rid, "title": title, "severity": severity,
        "weight": weight, "category": category,
        "reference": reference, "remediation": remediation,
    }
    return rid


def F(rid, session=None, evidence=None, description=None):
    return {
        "rule_id": rid,
        "title": RULES[rid]["title"],
        "severity": RULES[rid]["severity"],
        "category": RULES[rid]["category"],
        "weight": RULES[rid]["weight"],
        "reference": RULES[rid]["reference"],
        "description": description or RULES[rid]["title"],
        "evidence": evidence or {},
        "remediation": RULES[rid]["remediation"],
    }


# ---- protocol / transport -------------------------------------------------
rule("PRT-001", "Cleartext email session (no TLS)", "critical", 40, "protocol",
     "NIST SP 800-52r2 §3.1; CERT-In CIAD-2020-04; PCI-DSS 4.0 Req 4.2.1",
     "Configure the mail service to require TLS on every port; reject or "
     "redirect plaintext sessions.")
rule("CFG-003", "Implicit-TLS port serving plaintext", "critical", 40, "config",
     "RFC 8314 §4.1; PCI-DSS 4.0 Req 4.2.1",
     "Serve implicit TLS on 993/995/465 or at minimum enforce STARTTLS on "
     "submission ports; never accept plaintext on a secure port.")
rule("CFG-004", "STARTTLS stripped / cleartext fallback", "critical", 35, "config",
     "RFC 8314 §5; STARTTLS-downgrade literature; PCI-DSS 4.0 Req 4.2.1",
     "Configure clients to refuse sending credentials after a failed STARTTLS "
     "upgrade; deploy MTA-STS/DANE where applicable.")
rule("CFG-005", "No STARTTLS capability advertised", "high", 15, "config",
     "RFC 3207; RFC 8314; PCI-DSS 4.0 Req 4.2.1",
     "Enable STARTTLS support on SMTP/IMAP/POP3 plaintext ports.")
rule("TLS-001", "Deprecated TLS version negotiated", "critical", 35, "tls",
     "NIST SP 800-52r2 §3.1 (TLS 1.2 min, 1.3 preferred); PCI-DSS 4.0 Req 4.2.1",
     "Disable SSLv3–TLS 1.1; support TLS 1.2 with AEAD suites and prefer "
     "TLS 1.3.")

# ---- ciphers -----------------------------------------------------------
rule("CPR-001", "NULL / EXPORT / anonymous cipher suite", "critical", 40, "cipher",
     "NIST SP 800-52r2 §3.2; RFC 9155; PCI-DSS 4.0 Req 4.2.1",
     "Remove all NULL, EXPORT, and anonymous (DH_anon/ECDH_anon) suites from "
     "the server cipher configuration.")
rule("CPR-002", "RC4 / 3DES / IDEA / SEED cipher suite", "critical", 35, "cipher",
     "RFC 7465 (prohibits RC4); NIST SP 800-52r2 §3.2; PCI-DSS 4.0 Req 4.2.1",
     "Disable RC4 and 3DES suites; use AES-GCM or ChaCha20-Poly1305.")
rule("CPR-003", "CBC-mode suite negotiated (Lucky13 surface)", "medium", 10, "cipher",
     "NIST SP 800-52r2 §3.2 (AEAD preferred)",
     "Prefer AEAD suites (AES-GCM/ChaCha20); if CBC must stay, ensure proper "
     "padding-oracle mitigations.")
rule("CPR-004", "Server selected the weakest mutually-offered suite", "high", 15,
     "cipher", "NIST SP 800-52r2 §3.2",
     "Configure server-side cipher preference order and enable server cipher "
     "selection.")

# ---- key exchange ------------------------------------------------------
rule("PFS-001", "No forward secrecy (RSA key exchange)", "medium", 15, "pfs",
     "NIST SP 800-52r2 §3.2; BSI TR-02102-2 §4",
     "Enable ECDHE/DHE suites so past sessions stay confidential if the "
     "private key leaks.")

# ---- TLS behaviour -----------------------------------------------------
rule("CFG-006", "Session resumption without extended master secret", "medium", 10,
     "config", "RFC 7627 (EMS); Triple-Handshake attack literature",
     "Require the extended_master_secret extension for resumption.")
rule("CFG-007", "Insecure renegotiation observed", "high", 20, "config",
     "RFC 5746",
     "Disable client-initiated renegotiation or enforce RFC 5746 secure "
     "renegotiation.")
rule("ALR-001", "TLS handshake failed (fatal alert)", "high", 20, "tls",
     "RFC 8446 §6",
     "Investigate client/server version or cipher mismatch; repeated "
     "failures can indicate interception or misconfiguration.")

# ---- certificates ------------------------------------------------------
rule("CRT-001", "Expired certificate", "critical", 30, "certificate",
     "CA/Browser Forum Baseline Requirements; NIST SP 800-52r2 §3.3",
     "Renew the certificate immediately; automate renewal (ACME) to prevent "
     "recurrence.")
rule("CRT-002", "Certificate not yet valid", "high", 20, "certificate",
     "CA/Browser Forum Baseline Requirements",
     "Check system clock and reissue the certificate with correct validity.")
rule("CRT-003", "Certificate expiring within 30 days", "low", 5, "certificate",
     "CA/Browser Forum Baseline Requirements (2026: ≤47-day validity)",
     "Renew soon; move to automated short-lived certificates.")
rule("CRT-004", "Self-signed certificate", "high", 20, "certificate",
     "NIST SP 800-52r2 §3.3",
     "Deploy CA-issued certificates; if internal, run a private CA with "
     "controlled trust distribution.")
rule("CRT-005", "Weak public key", "critical", 30, "certificate",
     "NIST SP 800-57 Part 1 (RSA ≥2048, ECDSA ≥256)",
     "Reissue with RSA-2048+ or ECDSA P-256+.")
rule("CRT-006", "Weak signature hash (MD5/SHA-1)", "high", 25, "certificate",
     "NIST SP 800-131A r2 (SHA-1 disallowed for signatures)",
     "Reissue the certificate signed with SHA-256 or stronger.")
rule("CRT-007", "Certificate hostname mismatch", "high", 20, "certificate",
     "RFC 6125",
     "Issue a certificate whose SAN matches the service hostname clients "
     "connect to.")
rule("CRT-008", "Incomplete or broken certificate chain", "medium", 10,
     "certificate", "CA/Browser Forum Baseline Requirements §7.1",
     "Serve the full chain (leaf + intermediates) in the correct order.")


# ---- evaluation ----------------------------------------------------------
def _add(sess, out: list[dict], rid, evidence=None, description=None):
    out.append(F(rid, sess, evidence, description))


def evaluate_session(sess) -> tuple[list[dict], list[dict]]:
    """Run all rules against one analyzed Session.

    Returns (findings, advisories): findings are scored (weight > 0) and
    drive the posture score; advisories are informational (weight 0,
    severity "info") — reported for planning but never penalising, because
    e.g. being quantum-vulnerable today is the 2026 status quo, not a
    misconfiguration."""
    out: list[dict] = []
    advisories: list[dict] = []

    # plaintext sessions: no-TLS (PRT-001) vs downgrade (CFG-004) vs
    # server that never advertised STARTTLS (CFG-005)
    if sess.transport == "plaintext" and not sess.started_plain:
        if sess.protocol == "smtp" and sess.dst_port in (25, 587) and \
                b"STARTTLS" not in getattr(sess, "_ehlo_blob", b""):
            _add(sess, out, "CFG-005",
                 {"port": sess.dst_port,
                  "detail": "EHLO response advertises no STARTTLS capability"})
        _add(sess, out, "PRT-001",
             {"dst": f"{sess.dst_ip}:{sess.dst_port}"})
    elif sess.transport == "plaintext" and sess.started_plain:
        _add(sess, out, "CFG-004",
             {"port": sess.dst_port,
              "detail": "STARTTLS requested; session stayed in cleartext"})
    if sess.transport != "plaintext":
        if sess.dst_port in (993, 995, 465) and sess.tls_parse_error:
            _add(sess, out, "CFG-003",
                 {"port": sess.dst_port, "detail": sess.tls_parse_error})
        if sess.tls_version and sess.tls_version in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"):
            _add(sess, out, "TLS-001", {"negotiated": sess.tls_version})
        cid = sess.cipher_id
        if cid:
            name = (sess.cipher_suite or "").upper()
            if "NULL" in name or "EXPORT" in name or "anon" in name or cipher_strength(cid) == 0:
                _add(sess, out, "CPR-001", {"cipher": sess.cipher_suite})
            elif "RC4" in name or "3DES" in name or "IDEA" in name or "SEED" in name:
                _add(sess, out, "CPR-002", {"cipher": sess.cipher_suite})
            elif "CBC" in name and sess.tls_version == "TLSv1.2":
                _add(sess, out, "CPR-003", {"cipher": sess.cipher_suite})
            # server chose weakest of mutually offered
            if sess.offered_ciphers:
                offered_ok = [c for c in sess.offered_ciphers
                              if cipher_strength(c) >= cipher_strength(cid)]
                if offered_ok and cipher_strength(cid) < 128:
                    _add(sess, out, "CPR-004",
                         {"chosen": sess.cipher_suite,
                          "stronger_available": len(offered_ok)})
            if sess.pfs is False:
                _add(sess, out, "PFS-001",
                     {"kex": sess.kex_mechanism})
            if sess.resumed and not sess.ems:
                _add(sess, out, "CFG-006", {})
            if sess.reneg_seen and not sess.secure_renegotiation:
                _add(sess, out, "CFG-007", {})
        if any(desc in (40, 70, 71) for _, desc in sess.alerts):
            descs = {sess_alert[1] for sess_alert in sess.alerts}
            _add(sess, out, "ALR-001",
                 {"alerts": sorted(d for d in descs if d in (40, 70, 71))})

    certs = getattr(sess, "_cert_records", [])
    for c in certs:
        if not c.get("is_leaf"):
            continue                      # expiry/self-signed rules are leaf-only
        ev = {"fingerprint": c["fingerprint_sha256"][:16], "subject": c["subject_cn"]}
        if c["is_expired"]:
            _add(sess, out, "CRT-001", ev,
                 "Certificate for '%s' expired on %s" % (c["subject_cn"], c["not_after"][:10]))
        if c.get("not_yet_valid"):
            _add(sess, out, "CRT-002", ev,
                 "Certificate for '%s' is not valid before %s" % (c["subject_cn"], c["not_before"][:10]))
        if 0 <= c["days_to_expiry"] <= 30:
            _add(sess, out, "CRT-003", ev,
                 "Certificate for '%s' expires in %d days" % (c["subject_cn"], c["days_to_expiry"]))
        if c["self_signed"]:
            _add(sess, out, "CRT-004", ev,
                 "Certificate for '%s' is self-signed" % c["subject_cn"])
        if certmod.weak_key(c):
            _add(sess, out, "CRT-005", ev,
                 "%s key of %d bits in certificate '%s'" %
                 (c["key_algorithm"], c["key_length"], c["subject_cn"]))
        if certmod.weak_signature(c):
            _add(sess, out, "CRT-006", ev,
                 "Certificate '%s' uses %s signatures" % (c["subject_cn"], c["signature_hash"]))
        if any(i.startswith("hostname mismatch") for i in c.get("chain_issues", [])):
            _add(sess, out, "CRT-007", ev)

    # cleartext credentials in the plaintext prelude
    for cred in getattr(sess, "cleartext_creds", []):
        ev = {"kind": cred["kind"], "redacted": True}
        if cred.get("user"):
            ev["user"] = cred["user"]
        if cred.get("password"):              # bullet-redacted form (imap/pop3)
            ev["password"] = cred["password"]
        if cred.get("token_len"):
            ev["token_len"] = cred["token_len"]          # b64 blob, length only
        if cred.get("user_b64_len"):
            ev["user_b64_len"] = cred["user_b64_len"]    # AUTH LOGIN, length only
        if cred.get("pass_b64_len"):
            ev["pass_b64_len"] = cred["pass_b64_len"]
        _add(sess, out, "CRE-001", ev,
             "Cleartext %s authentication observed (credentials redacted)"
             % cred["kind"].replace("-", " "))

    # PQC readiness advisory (informational, zero weight: classical-only key
    # exchange is the 2026 status quo, not a misconfiguration — but a
    # harvest-now-decrypt-later adversary records it today). Sessions that
    # negotiated a hybrid ML-KEM group are PQC-ready and not advised.
    if sess.kex_mechanism and sess.kex_mechanism in PQC_VULN_KEX and sess.tls_version \
            and getattr(sess, "negotiated_group", None) not in tls_parser.PQC_HYBRID_GROUPS:
        group = getattr(sess, "negotiated_group_name", None)
        ev = {"kex": sess.kex_mechanism, "tls": sess.tls_version}
        if group:
            ev["group"] = group
        _add(sess, advisories, "PQC-001", ev,
             "%s key exchange%s has no post-quantum migration path "
             "(harvest-now-decrypt-later risk)"
             % (sess.kex_mechanism,
                " on " + group if group else ""))

    for issue in getattr(sess, "_chain_issues", []):
        if issue.startswith("signature break") or \
           issue in ("no intermediates offered (incomplete chain)",
                     "chain does not reach a self-signed root"):
            _add(sess, out, "CRT-008", {"detail": issue})
    return out, advisories


# ---- credentials / PQC / cross-session (differentiators) -----------------
rule("CRE-001", "Cleartext credentials observed", "critical", 40, "protocol",
     "CERT-In CIAD-2020-04; NIST SP 800-52r2 §3.1; PCI-DSS 4.0 Req 2.2.7 & 4.2.1",
     "Require TLS before any authentication; reject credentials on plaintext "
     "channels and disable plaintext auth mechanisms entirely.")
rule("PQC-001", "Quantum-vulnerable key exchange (no PQC migration path)",
     "info", 0, "compliance",
     "NIST PQC final standards (FIPS 203/204/205, 2024); NTRO PQC guidance",
     "Plan migration to hybrid post-quantum key establishment (e.g. X25519+ML-KEM) "
     "when your TLS stack supports it; classical ECDH/RSA kex is breakable by a "
     "harvest-now-decrypt-later adversary.")
rule("XSE-001", "Certificate changed between sessions of the same host",
     "medium", 10, "certificate",
     "MITRE ATT&CK T1586.001; forensic practice",
     "Verify the certificate rotation was authorized; an unexpected swap on the "
     "same host within one capture can indicate interception.")
rule("XSE-002", "TLS version regression on the same host within the capture",
     "high", 20, "tls",
     "Downgrade-attack literature; RFC 8446 §4.1.3",
     "Investigate why the same server negotiated a weaker TLS version in a "
     "later session; can indicate downgrade interference or flaky config.")

# quantum-vulnerable key exchange assessment: every classical mechanism
# (including ECDHE and bare TLS 1.3 X25519) is harvest-now-decrypt-later
# vulnerable; only hybrid ML-KEM groups are PQC-ready (see tls_parser).
PQC_VULN_KEX = {"RSA", "DHE", "DH_anon", "ECDH", "ECDHE", "(TLS1.3)"}
