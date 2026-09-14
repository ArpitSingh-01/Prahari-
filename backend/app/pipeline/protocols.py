"""Application-layer email protocol identification (port-agnostic)."""
from __future__ import annotations

import re

SMTP_PORTS = {25, 465, 587}
IMAP_PORTS = {143, 993}
POP3_PORTS = {110, 995}

RE_SMTP_GREETING = re.compile(rb"^220[ -]")
RE_SMTP_CMD = re.compile(rb"^(EHLO|HELO|MAIL FROM|RCPT TO|AUTH|DATA|QUIT|STARTTLS) ", re.I)
RE_SMTP_CMD_NOTLS = re.compile(rb"^(EHLO|HELO|MAIL FROM|RCPT TO|DATA|QUIT) ", re.I)
RE_IMAP_GREETING = re.compile(rb"^\* (OK|PREAUTH|BYE)", re.I)
RE_IMAP_CMD = re.compile(rb"^[A-Za-z0-9$.-]+ (LOGIN|CAPABILITY|STARTTLS|SELECT|LIST|FETCH|LOGOUT|IDLE|AUTHENTICATE) ", re.I)
RE_IMAP_CMD_NOTLS = re.compile(rb"^[A-Za-z0-9$.-]+ (LOGIN|CAPABILITY|SELECT|LIST|FETCH|LOGOUT|IDLE|AUTHENTICATE) ", re.I)
RE_POP3_GREETING = re.compile(rb"^\+OK")
RE_POP3_CMD = re.compile(rb"^(USER|PASS|APOP|STAT|LIST|RETR|DELE|QUIT|UIDL|CAPA|STLS) ", re.I)
RE_POP3_CMD_NOTLS = re.compile(rb"^(USER|PASS|APOP|STAT|LIST|RETR|DELE|QUIT|UIDL|CAPA) ", re.I)

# First command in a client stream per protocol (used for STARTTLS matching)
RE_SMTP_STARTTLS = re.compile(rb"^STARTTLS\r?\n", re.I)
RE_IMAP_STARTTLS = re.compile(rb"^[A-Za-z0-9$.-]+ STARTTLS\r?\n", re.I)
RE_POP3_STLS = re.compile(rb"^STLS\r?\n", re.I)


def score_client(data: bytes, allow_tls_cmds: bool = True) -> dict[str, float]:
    """How much does this client payload look like each protocol?"""
    head = data[:256]
    if not head:
        return {}
    out = {}
    cmdre = {"smtp": RE_SMTP_CMD, "imap": RE_IMAP_CMD, "pop3": RE_POP3_CMD}
    ntlre = {"smtp": RE_SMTP_CMD_NOTLS, "imap": RE_IMAP_CMD_NOTLS, "pop3": RE_POP3_CMD_NOTLS}
    for proto in cmdre:
        s = 0.0
        if cmdre[proto].search(head):
            s += 2.0
            if not allow_tls_cmds and ntlre[proto].search(head):
                s += 0.5
        out[proto] = s
    return out


def score_server(data: bytes) -> dict[str, float]:
    head = data[:128]
    if not head:
        return {}
    out = {}
    if RE_SMTP_GREETING.match(head):
        out["smtp"] = 2.0
    if RE_IMAP_GREETING.match(head):
        out["imap"] = 2.0
    if RE_POP3_GREETING.match(head):
        out["pop3"] = 2.0
    return out


def identify(c2s: bytes, s2c: bytes, sport: int, dport: int,
             encrypted: bool) -> str | None:
    """Return 'smtp'|'imap'|'pop3' base protocol, or None.

    Port hints only tie-break; payload evidence wins. Encrypted sessions
    rely on ports alone (the PS's IMAPS/POP3S/SMTPS variants are derived
    from base protocol + transport).
    """
    if encrypted:
        for ports, proto in ((SMTP_PORTS, "smtp"), (IMAP_PORTS, "imap"),
                             (POP3_PORTS, "pop3")):
            if dport in ports or sport in ports:
                return proto
        return None

    scores: dict[str, float] = {}
    for data, weight in ((s2c[:256], 1.0), (c2s[:256], 1.0)):
        for proto, s in score_server(data).items():
            scores[proto] = scores.get(proto, 0.0) + s * weight
        for proto, s in score_client(data).items():
            scores[proto] = scores.get(proto, 0.0) + s * weight

    # tiny port bonus
    for ports, proto in ((SMTP_PORTS, "smtp"), (IMAP_PORTS, "imap"),
                         (POP3_PORTS, "pop3")):
        if dport in ports or sport in ports:
            scores[proto] = scores.get(proto, 0.0) + 0.3

    if not scores:
        return None
    proto, best = max(scores.items(), key=lambda kv: kv[1])
    return proto if best >= 2.0 else None
