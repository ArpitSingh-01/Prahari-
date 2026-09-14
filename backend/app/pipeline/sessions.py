"""Build analyzed mail sessions from reassembled TCP flows.

Handles: protocol identification, STARTTLS/transition detection, TLS
handshake parsing, certificate extraction — producing Session objects
ready for the rule engine and feature extraction.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from . import certificates as certmod
from . import protocols, tls_parser
from .reassembly import Flow

TLS_CLIENT_HELLO_MAGIC = b"\x16\x03"


@dataclass
class Session:
    protocol: str                      # smtp|imap|pop3
    transport: str                     # implicit|starttls|plaintext
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    server_host: str | None = None
    tls_version: str | None = None
    cipher_suite: str | None = None
    cipher_id: int = 0
    offered_ciphers: list[int] = field(default_factory=list)
    kex_mechanism: str | None = None
    pfs: bool | None = None
    offered_groups: list[int] = field(default_factory=list)   # supported_groups offered by client
    negotiated_group: int | None = None      # group the server selected (key_share / named curve)
    negotiated_group_name: str | None = None
    key_exchange_group_size: int | None = None   # classical strength in bits
    start_time: dt.datetime | None = None
    end_time: dt.datetime | None = None
    duration_ms: int = 0
    started_plain: bool = False
    plaintext_prelude_len: int = 0       # bytes sent before the TLS upgrade
    client_version: int = 0
    sni: str | None = None
    alerts: list[tuple[int, int]] = field(default_factory=list)
    alert_count: int = 0
    cert_chains: list[list[bytes]] = field(default_factory=list)
    reneg_seen: bool = False
    resumed: bool = False
    ems: bool = False
    secure_renegotiation: bool = False
    handshake_complete: bool = False
    tls13: bool = False
    tls_parse_error: str | None = None
    reassembly_incomplete: bool = False      # a TCP hole: stream stops there
    truncated: bool = False                  # stream hit the 4 MB/direction cap
    bytes_c2s: int = 0
    bytes_s2c: int = 0
    frames_c2s: list = field(default_factory=list)   # frame numbers per direction
    frames_s2c: list = field(default_factory=list)
    raw_c2s: bytes = b""        # trimmed raw stream copies for evidence hex dumps
    raw_s2c: bytes = b""
    cleartext_creds: list = field(default_factory=list)  # redacted credential hits
    handshake_events: list = field(default_factory=list)  # (kind, detail) wire order
    _ehlo_blob: bytes = b""       # plaintext SMTP server response head (CFG-005)
    # populated later
    findings: list[dict] = field(default_factory=list)
    risk_score: int = 100
    grade: str = "A"
    is_anomaly: bool = False
    anomaly_score: float = 0.0
    anomaly_explanation: list = field(default_factory=list)
    ml_risk: dict | None = None
    rule_score: int = 100          # rule-engine-only score (compliance anchor)
    ml_adjustment: float = 0.0     # bounded fusion delta applied on top
    session_id: str = ""

    def to_dict(self) -> dict:
        return {
            "protocol": self.protocol + ("s" if self.transport == "implicit" and
                                         self.tls_version else ""),
            "transport": self.transport,
            "src_ip": self.src_ip, "src_port": self.src_port,
            "dst_ip": self.dst_ip, "dst_port": self.dst_port,
            "server_host": self.server_host,
            "tls_version": self.tls_version,
            "cipher_suite": self.cipher_suite,
            "kex_mechanism": self.kex_mechanism,
            "pfs": self.pfs,
            "offered_groups": [tls_parser.group_name(g) for g in self.offered_groups],
            "negotiated_group": self.negotiated_group_name,
            "key_exchange_group_size": self.key_exchange_group_size,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_ms": self.duration_ms,
            "started_plain": self.started_plain,
            "sni": self.sni,
            "alert_count": self.alert_count,
            "renegotiation_seen": self.reneg_seen,
            "session_resumed": self.resumed,
            "extended_master_secret": self.ems,
            "handshake_complete": self.handshake_complete,
            "tls13": self.tls13,
            "reassembly_incomplete": self.reassembly_incomplete,
            "truncated": self.truncated,
            "bytes_c2s": self.bytes_c2s, "bytes_s2c": self.bytes_s2c,
            "frames_c2s": self.frames_c2s, "frames_s2c": self.frames_s2c,
            "cleartext_creds": self.cleartext_creds,
            "handshake_events": [{"kind": k, "detail": d} for k, d in self.handshake_events],
            "risk_score": self.risk_score, "grade": self.grade,
            "rule_score": self.rule_score, "ml_adjustment": self.ml_adjustment,
            "is_anomaly": self.is_anomaly, "anomaly_score": self.anomaly_score,
            "anomaly_explanation": self.anomaly_explanation,
            "ml_risk": self.ml_risk,
        }


def _looks_like_client_hello(data: bytes) -> bool:
    # record: 0x16, version 0x0300-0x0304, handshake type 0x01
    return (len(data) >= 6 and data[0] == 0x16 and
            0x0300 <= (data[1] << 8) + data[2] <= 0x0304 and data[5] == 0x01)


def _split_starttls_stream(c2s: bytes, s2c: bytes):
    """Split plaintext preambles from the TLS section of a STARTTLS flow.

    Returns (plain_c2s, plain_s2c, tls_c2s, tls_s2c, stripped).
    stripped=True when STARTTLS was requested but no ClientHello followed.
    """
    import re
    m = (re.search(rb"STARTTLS\r?\n", c2s, re.I) or
         (re.search(rb"STLS\r?\n", c2s, re.I)))
    if not m:
        return c2s, s2c, b"", b"", False
    tls_start_c = m.end()

    m2 = None
    for pat in (rb"220[ -][^\r\n]*[Rr]eady to start TLS", rb"220[ -]2\.0\.0[^\r\n]*",
                rb"\+OK[^\r\n]*(Begin TLS|STLS)"):
        m2 = re.search(pat, s2c[:2048], re.I)
        if m2:
            break
    if m2 is None:
        m2 = re.search(rb"220[^\r\n]*\r\n", s2c[:2048])     # best effort
    tls_start_s = m2.end() if m2 else len(s2c)

    tls_c2s, tls_s2c = c2s[tls_start_c:], s2c[tls_start_s:]
    # some servers emit the response CRLF before switching to TLS records
    tls_c2s = tls_c2s.lstrip(b"\r\n ")
    tls_s2c = tls_s2c.lstrip(b"\r\n ")
    stripped = not _looks_like_client_hello(tls_c2s)
    return c2s[:tls_start_c], s2c[:tls_start_s], tls_c2s, tls_s2c, stripped


def _server_of(flow: Flow) -> tuple[str, int]:
    """Heuristic: the server is the side that did NOT send the first SYN
    and typically owns the well-known port."""
    if flow.saw_syn_from_src and not flow.saw_synack_from_dst:
        return flow.dst, flow.dport
    if flow.dport in (25, 110, 143, 465, 587, 993, 995) or \
       flow.sport not in (25, 110, 143, 465, 587, 993, 995):
        return flow.dst, flow.dport
    return flow.src, flow.sport


def _dt(ts: float) -> dt.datetime:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc)


def build_session(flow: Flow) -> Session | None:
    # capture frame evidence BEFORE reassemble() frees the segment list
    frames_c2s = sorted({seg.frame_no for seg in flow.c2s.segments if seg.frame_no})
    frames_s2c = sorted({seg.frame_no for seg in flow.s2c.segments if seg.frame_no})
    c2s = flow.c2s.reassemble()
    s2c = flow.s2c.reassemble()
    if not c2s and not s2c:
        return None
    # TCP-level forensics flags: never silently fabricate contiguity
    reassembly_incomplete = flow.c2s.reassembly_incomplete or flow.s2c.reassembly_incomplete
    truncated = flow.c2s.truncated or flow.s2c.truncated

    srv_ip, srv_port = _server_of(flow)
    cli_ip, cli_port = (flow.src, flow.sport) if srv_ip == flow.dst else \
                       (flow.dst, flow.dport)
    c2s_is_client = (cli_ip, cli_port) == (flow.src, flow.sport)
    if not c2s_is_client:
        c2s, s2c = s2c, c2s

    hello_c = _looks_like_client_hello(c2s)
    if hello_c:
        base = protocols.identify(c2s, s2c, cli_port, srv_port, encrypted=True)
        if base is None:
            return None                      # TLS but not a mail port/protocol
        sess = Session(protocol=base, transport="implicit")
        info = tls_parser.parse_stream(c2s)
        info_s = tls_parser.parse_stream(s2c)
        _merge_tls(sess, info, info_s)
        sess.server_host = info.sni
    else:
        base = protocols.identify(c2s, s2c, cli_port, srv_port, encrypted=False)
        if base is None:
            return None
        p_c2s, p_s2c, t_c2s, t_s2c, stripped = _split_starttls_stream(c2s, s2c)
        if stripped:
            sess = Session(protocol=base, transport="plaintext", started_plain=True)
            sess.tls_parse_error = "STARTTLS requested but no ClientHello followed"
        elif t_c2s:
            sess = Session(protocol=base, transport="starttls", started_plain=True)
            sess.plaintext_prelude_len = len(p_c2s)    # pre-upgrade plaintext bytes
            info = tls_parser.parse_stream(t_c2s)
            info_s = tls_parser.parse_stream(t_s2c)
            _merge_tls(sess, info, info_s)
            sess.server_host = info.sni
            # plaintext upgrade exchange is part of the session story
            # (_merge_tls stored tuples; normalize everything to dicts)
            pre = []
            if base == "smtp" and b"STARTTLS" in p_c2s:
                pre.append((("starttls_command"), {"proto": "smtp"}))
            elif base == "pop3" and b"STLS" in p_c2s:
                pre.append((("starttls_command"), {"proto": "pop3"}))
            elif base == "imap" and b"STARTTLS" in p_c2s:
                pre.append((("starttls_command"), {"proto": "imap"}))
            pre.append((("starttls_accepted"), {}))
            merged = list(pre) + [(k, d) for k, d in sess.handshake_events]
            sess.handshake_events = merged
        else:
            sess = Session(protocol=base, transport="plaintext")

    sess.src_ip, sess.src_port = cli_ip, cli_port
    sess.dst_ip, sess.dst_port = srv_ip, srv_port
    sess.reassembly_incomplete = reassembly_incomplete
    sess.truncated = truncated
    if flow.c2s.start_ts:
        sess.start_time = _dt(flow.start_ts)
        sess.end_time = _dt(flow.end_ts)
        sess.duration_ms = flow.duration_ms
    sess.bytes_c2s, sess.bytes_s2c = len(c2s), len(s2c)
    sess.frames_c2s, sess.frames_s2c = frames_c2s, frames_s2c
    sess.raw_c2s = c2s[:4096]           # evidence window (bounded)
    sess.raw_s2c = s2c[:4096]
    sess.cleartext_creds = scan_cleartext_credentials(c2s)
    sess.alert_count = len(sess.alerts)
    # capture the server's greeting/EHLO response head for capability
    # analysis (CFG-005: does a plaintext SMTP session advertise STARTTLS?)
    if sess.protocol == "smtp" and sess.transport in ("plaintext",):
        sess._ehlo_blob = s2c[:1024]

    return sess


def _merge_tls(sess: Session, info: tls_parser.HandshakeInfo,
               info_s: tls_parser.HandshakeInfo) -> None:
    sess.tls_version = info_s.negotiated_version_name or info.negotiated_version_name
    if not sess.tls_version:
        sess.tls_version = info.client_version_name
    sess.client_version = info.client_version
    sess.cipher_id = info_s.chosen_cipher or info.chosen_cipher
    if sess.cipher_id:
        sess.cipher_suite = tls_parser.cipher_name(sess.cipher_id)
        sess.kex_mechanism = tls_parser.kex_of(sess.cipher_id)
        sess.pfs = tls_parser.pfs_of(sess.kex_mechanism)
    sess.offered_ciphers = info.offered_ciphers
    sess.offered_groups = info.offered_groups
    sess.negotiated_group = info_s.negotiated_group or info.negotiated_group
    sess.negotiated_group_name = tls_parser.group_name(sess.negotiated_group)
    sess.key_exchange_group_size = tls_parser.GROUP_BITS.get(
        sess.negotiated_group) if sess.negotiated_group is not None else None
    sess.sni = info.sni
    sess.alerts = list(dict.fromkeys(info.alerts + info_s.alerts))
    sess.ems = info.extended_master_secret and info_s.extended_master_secret
    # RFC 5746 secure renegotiation is only established when BOTH sides
    # signalled the renegotiation_info extension
    sess.secure_renegotiation = info.secure_renegotiation and \
        info_s.secure_renegotiation
    sess.reneg_seen = info.renegotiation_seen or info_s.renegotiation_seen
    sess.resumed = info.is_resumption
    sess.handshake_complete = info.handshake_complete or info_s.handshake_complete
    sess.tls13 = info.tls13 or info_s.tls13
    sess.tls_parse_error = info.parse_error or info_s.parse_error
    # handshake event timeline (client then server, wire order preserved)
    sess.handshake_events = [(k, d) for k, d in info.events] + \
                            [(k, d) for k, d in info_s.events]
    # certificates come from the server stream
    if info_s.cert_der_chain:
        sess.cert_chains.append(info_s.cert_der_chain)
    elif info.cert_der_chain:
        sess.cert_chains.append(info.cert_der_chain)


def analyze_certificates(sess: Session) -> list[dict]:
    """Full certificate records for a session (dedup by fingerprint)."""
    seen: dict[str, dict] = {}
    for chain in sess.cert_chains:
        records, _issues = certmod.analyze_chain(chain, sess.sni)
        for rec in records:
            seen.setdefault(rec["fingerprint_sha256"], rec)
    return list(seen.values())


# --- cleartext credential scanner (redacted) -------------------------------
# Detects credentials sent in the plaintext pre-TLS portion of a session.
# Passwords are NEVER stored; only lengths and bullet redactions.
import re as _re

_CRED_PATTERNS = [
    ("smtp-auth-plain-b64", _re.compile(rb"AUTH PLAIN ([A-Za-z0-9+/=]{8,})", _re.I)),
    ("imap-login", _re.compile(rb"^[A-Za-z0-9$.-]+ LOGIN (\S+) (\S+)", _re.I | _re.M)),
    ("pop3-user-pass", _re.compile(rb"USER (\S+)[\r\n]+PASS (\S+)", _re.I | _re.S)),
    ("smtp-auth-login", _re.compile(rb"AUTH LOGIN", _re.I)),
]


def scan_cleartext_credentials(c2s: bytes) -> list[dict]:
    hits: list[dict] = []
    head = c2s[:2048]
    for kind, rx in _CRED_PATTERNS:
        m = rx.search(head)
        if not m:
            continue
        entry = {"kind": kind, "redacted": True}
        if kind in ("pop3-user-pass", "imap-login"):
            entry["user"] = m.group(1).decode("ascii", "replace")
            entry["password"] = chr(0x2022) * len(m.group(2))
        elif kind == "smtp-auth-plain-b64":
            entry["token_len"] = len(m.group(1))
        elif kind == "smtp-auth-login":
            lines = head.split(b"\r\n")
            for i, ln in enumerate(lines):
                if ln.strip().upper() == b"AUTH LOGIN" and i + 2 < len(lines):
                    entry["user_b64_len"] = len(lines[i + 1].strip())
                    entry["pass_b64_len"] = len(lines[i + 2].strip())
                    break
        hits.append(entry)
    return hits
