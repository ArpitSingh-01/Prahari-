"""Synthetic secure-email traffic generator -> real pcap files (pure Python).

Builds complete Ethernet/IP/TCP conversations with realistic SMTP/IMAP/POP3
payloads and hand-constructed TLS handshakes (ClientHello, ServerHello,
Certificate, CCS, Finished), then serializes them as classic pcap. This
works on any OS with no capture driver and lets us "negotiate" TLS 1.0/RC4
that modern OpenSSL stacks refuse to emit.

Usage:
    python scripts/gen_certs.py      # first: mint the cert corpus
    python scripts/gen_traffic.py    # then: write scenario pcaps
"""
from __future__ import annotations

import os
import struct
import sys

import dpkt

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..")))
from app.pipeline.tls_parser import CIPHER_NAMES  # noqa: E402
CERT_DIR = os.path.normpath(os.path.join(HERE, "..", "fixtures", "certs"))
OUT_DIR = os.path.normpath(os.path.join(HERE, "..", "fixtures", "pcaps"))

CLIENT_IP, SERVER_IP = "192.168.10.50", "192.168.10.10"
CLIENT_MAC = bytes.fromhex("020055555555")
SERVER_MAC = bytes.fromhex("0200aaaaaaaa")
BASE_TS = 1725400000.0

# ---------------------------------------------------------------- pcap ----
class Pcap:
    def __init__(self) -> None:
        self.packets: list[tuple[float, bytes]] = []

    def add(self, ts_off: float, frame: bytes) -> None:
        self.packets.append((BASE_TS + ts_off, frame))


def write_pcap(path: str, pcap: Pcap) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for ts, buf in sorted(pcap.packets, key=lambda p: p[0]):
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            fh.write(struct.pack("<IIII", sec, usec, len(buf), len(buf)))
            fh.write(buf)


def frame(src_mac: bytes, dst_mac: bytes, ip: bytes) -> bytes:
    eth = dpkt.ethernet.Ethernet(src_mac=src_mac, dst_mac=dst_mac,
                                 type=dpkt.ethernet.ETH_TYPE_IP)
    eth.data = ip
    return bytes(eth)


def tcp_packet(src: str, sport: int, dst: str, dport: int, seq: int,
               ack: int, flags: int, payload: bytes = b"", ts_off: float = 0.0) -> bytes:
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, ack=ack,
                       flags=flags, win=64240)
    tcp.data = payload
    ip = dpkt.ip.IP()
    ip.src = bytes(map(int, src.split(".")))
    ip.dst = bytes(map(int, dst.split(".")))
    ip.p = 6
    ip.data = tcp
    ip.len = len(ip)
    ip.ttl = 64
    return frame(CLIENT_MAC if src == CLIENT_IP else SERVER_MAC,
                 SERVER_MAC if src == CLIENT_IP else CLIENT_MAC, ip)


# --------------------------------------------------------- TLS builders ----
def _hs(htype: int, body: bytes) -> bytes:
    return bytes([htype]) + len(body).to_bytes(3, "big") + body


def _rec(ctype: int, version: int, payload: bytes) -> bytes:
    return bytes([ctype]) + version.to_bytes(2, "big") + \
        len(payload).to_bytes(2, "big") + payload


def ext(etype: int, body: bytes) -> bytes:
    return etype.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body


def sni_ext(host: str) -> bytes:
    name = host.encode()
    return ext(0, (len(name) + 3).to_bytes(2, "big") + b"\x00" +
               len(name).to_bytes(2, "big") + name)


def client_hello(versions: list[int], ciphers: list[int], host: str | None = None,
                 ems: bool = True, ticket: bool = True, session_id: bytes = b"",
                 groups: list[int] | None = None, reneg_info: bool = True) -> bytes:
    random = bytes(range(32))
    suites = b"".join(c.to_bytes(2, "big") for c in ciphers)
    exts = b""
    if host:
        exts += sni_ext(host)
    if ems:
        exts += ext(23, b"")
    if ticket:
        exts += ext(35, b"")
    if groups:
        body = (len(groups) * 2).to_bytes(2, "big") + \
               b"".join(g.to_bytes(2, "big") for g in groups)
        exts += ext(10, body)
    if versions and max(versions) >= 0x0304:
        vers = b"".join(v.to_bytes(2, "big") for v in versions)
        exts += ext(43, bytes([len(vers)]) + vers)
    if reneg_info:
        exts += ext(0xff01, b"\x00")
    body = (max(versions).to_bytes(2, "big") + random +
            len(session_id).to_bytes(1, "big") + session_id +
            len(suites).to_bytes(2, "big") + suites +
            b"\x01\x00" +
            len(exts).to_bytes(2, "big") + exts)
    return _hs(1, body)


def server_hello(version: int, cipher: int, session_id: bytes = b"",
                ems: bool = True, tls13: bool = False,
                group: int | None = None, reneg_info: bool = False) -> bytes:
    random = bytes(reversed(range(32)))
    exts = b""
    if ems:
        exts += ext(23, b"")
    if tls13:
        exts += ext(43, 0x0304.to_bytes(2, "big"))
    if group is not None:
        # TLS 1.3 ServerHello key_share: selected group + length-prefixed key
        key = bytes(range(32))
        exts += ext(51, group.to_bytes(2, "big") + len(key).to_bytes(2, "big") + key)
    if reneg_info:
        exts += ext(0xff01, b"\x00")
    body = (version.to_bytes(2, "big") + random +
            len(session_id).to_bytes(1, "big") + session_id +
            cipher.to_bytes(2, "big") + b"\x00" +
            len(exts).to_bytes(2, "big") + exts)
    return _hs(2, body)


def certificate_msg(ders: list[bytes]) -> bytes:
    inner = b"".join(len(d).to_bytes(3, "big") + d for d in ders)
    return _hs(11, len(inner).to_bytes(3, "big") + inner)


def alert(level: int, desc: int, version: int = 0x0303) -> bytes:
    return _rec(21, version, bytes([level, desc]))


def load_cert(name: str) -> bytes:
    with open(os.path.join(CERT_DIR, name + ".der"), "rb") as fh:
        return fh.read()


# -------------------------------------------------------- conversation ----
class Conv:
    """One TCP conversation with sequence tracking, appended to a Pcap."""

    def __init__(self, pcap: Pcap, sport: int, dport: int, t0: float,
                 cip: str = CLIENT_IP, sip: str = SERVER_IP) -> None:
        self.p, self.sport, self.dport, self.t = pcap, sport, dport, t0
        self.cip, self.sip = cip, sip
        self.cseq, self.sseq = 1000, 5000

    def _pkt(self, from_client: bool, flags: int, payload: bytes) -> None:
        if from_client:
            pkt = tcp_packet(self.cip, self.sport, self.sip, self.dport,
                             self.cseq, self.sseq, flags, payload, self.t)
        else:
            pkt = tcp_packet(self.sip, self.dport, self.cip, self.sport,
                             self.sseq, self.cseq, flags, payload, self.t)
        self.p.add(self.t, pkt)
        self.t += 0.004
        if from_client:
            self.cseq += len(payload) + (1 if flags & 0x02 or flags & 0x01 else 0)
        else:
            self.sseq += len(payload) + (1 if flags & 0x02 or flags & 0x01 else 0)

    def connect(self) -> None:
        self._pkt(True, dpkt.tcp.TH_SYN, b"")
        self._pkt(False, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, b"")
        self._pkt(True, dpkt.tcp.TH_ACK, b"")

    def c2s(self, payload: bytes) -> None:
        for i in range(0, len(payload), 1400):
            self._pkt(True, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload[i:i + 1400])

    def s2c(self, payload: bytes) -> None:
        for i in range(0, len(payload), 1400):
            self._pkt(False, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload[i:i + 1400])

    def finish(self) -> None:
        self._pkt(True, dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK, b"")
        self._pkt(False, dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK, b"")
        self._pkt(True, dpkt.tcp.TH_ACK, b"")

    # ---- TLS flows ----
    def tls_handshake(self, ch: bytes, sh: bytes, certs: list[bytes] | None,
                      app_client: bytes, app_server: bytes,
                      ske_group: int | None = 0x0017) -> None:
        """ClientHello -> ServerHello [+ Cert + SKE] -> CCS/Finished -> app data.

        ske_group: named curve for the (TLS 1.2) ServerKeyExchange; None
        suppresses the message (e.g. RSA kex has no SKE)."""
        self.c2s(_rec(22, 0x0303, ch))
        self.s2c(_rec(22, 0x0303, sh))
        if certs:
            self.s2c(_rec(22, 0x0303, certificate_msg(certs)))
            if ske_group is not None:
                # ECParameters: curve_type named_curve(3) + group id + pubkey
                ske_body = bytes([3]) + ske_group.to_bytes(2, "big") + \
                    b"\x41" + bytes(64)
                self.s2c(_rec(22, 0x0303, _hs(12, ske_body)))
        self.c2s(_rec(22, 0x0303, _hs(16, b"\x01\x02" + bytes(64))))  # ClientKeyExchange
        self.c2s(_rec(20, 0x0303, b"\x01"))              # CCS
        self.s2c(_rec(20, 0x0303, b"\x01"))
        self.c2s(_rec(23, 0x0303, bytes(48)))            # Finished (encrypted)
        self.s2c(_rec(23, 0x0303, bytes(48)))
        if app_client:
            self.c2s(_rec(23, 0x0303, app_client))
        if app_server:
            self.s2c(_rec(23, 0x0303, app_server))


# ------------------------------------------------------------ scenarios ----
def rec_plain(payload: bytes) -> bytes:
    """Plaintext email protocol bytes (used inside/outside TLS equally)."""
    return payload


def smtp_session_inside_tls(conv: Conv, host: str) -> None:
    conv.c2s(_rec(23, 0x0303, b"EHLO client.lab.example\r\n"))
    conv.s2c(_rec(23, 0x0303,
                  b"250-" + host + b"\r\n250-8BITMIME\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 35882577\r\n"))
    conv.c2s(_rec(23, 0x0303, b"MAIL FROM:<alice@lab.example>\r\n"))
    conv.s2c(_rec(23, 0x0303, b"250 2.1.0 Ok\r\n"))
    conv.c2s(_rec(23, 0x0303, b"QUIT\r\n"))
    conv.s2c(_rec(23, 0x0303, b"221 2.0.0 Bye\r\n"))


def imap_session_inside_tls(conv: Conv) -> None:
    conv.s2c(_rec(23, 0x0303, b"* OK [CAPABILITY IMAP4rev1] server ready\r\n"))
    conv.c2s(_rec(23, 0x0303, b"a1 LOGIN alice s3cret\r\n"))
    conv.s2c(_rec(23, 0x0303, b"a1 OK [CAPABILITY IMAP4rev1] Logged in\r\n"))
    conv.c2s(_rec(23, 0x0303, b"a2 SELECT INBOX\r\n"))
    conv.s2c(_rec(23, 0x0303, b"* 4 EXISTS\r\na2 OK [READ-WRITE] done\r\n"))
    conv.c2s(_rec(23, 0x0303, b"a3 LOGOUT\r\n"))
    conv.s2c(_rec(23, 0x0303, b"* BYE\r\na3 OK\r\n"))


def pop3_session_inside_tls(conv: Conv) -> None:
    conv.s2c(_rec(23, 0x0303, b"+OK POP3 server ready\r\n"))
    conv.c2s(_rec(23, 0x0303, b"USER alice\r\n"))
    conv.s2c(_rec(23, 0x0303, b"+OK\r\n"))
    conv.c2s(_rec(23, 0x0303, b"PASS hunter2\r\n"))
    conv.s2c(_rec(23, 0x0303, b"+OK logged in\r\n"))
    conv.c2s(_rec(23, 0x0303, b"LIST\r\n"))
    conv.s2c(_rec(23, 0x0303, b"+OK 2 messages\r\n1 320\r\n2 512\r\n.\r\n"))
    conv.c2s(_rec(23, 0x0303, b"QUIT\r\n"))
    conv.s2c(_rec(23, 0x0303, b"+OK bye\r\n"))


def sc_good_smtps(p: Pcap, t0: float) -> None:
    """Implicit TLS on 465, TLS 1.2 ECDHE AES-GCM, good cert."""
    c = Conv(p, 50123, 465, t0)
    c.connect()
    ch = client_hello([0x0303], [0xc02f, 0xc027, 0x002f], "mail.lab.example",
                      groups=[0x0017])
    sh = server_hello(0x0303, 0xc02f)
    c.tls_handshake(ch, sh, [load_cert("mail-leaf"), load_cert("ca")], b"", b"")
    smtp_session_inside_tls(c, b"mail.lab.example")
    c.finish()


def sc_imaps_good(p: Pcap, t0: float) -> None:
    """Implicit TLS on 993, TLS 1.3-style via supported_versions, CA chain."""
    c = Conv(p, 50200, 993, t0)
    c.connect()
    ch = client_hello([0x0304, 0x0303], [0x1301, 0x1302, 0xc02f], "mail.lab.example",
                      groups=[0x001d])
    sh = server_hello(0x0303, 0x1301, tls13=True, group=0x001d)
    c.tls_handshake(ch, sh, [load_cert("chain-leaf"), load_cert("ca")], b"", b"")
    imap_session_inside_tls(c)
    c.finish()


def sc_pop3s_good(p: Pcap, t0: float) -> None:
    c = Conv(p, 50300, 995, t0)
    c.connect()
    ch = client_hello([0x0303], [0xc02f, 0xc013], "mail.lab.example", groups=[0x0017])
    sh = server_hello(0x0303, 0xc02f)
    c.tls_handshake(ch, sh, [load_cert("mail-leaf"), load_cert("ca")], b"", b"")
    pop3_session_inside_tls(c)
    c.finish()


def sc_smtp_tls10_rc4(p: Pcap, t0: float) -> None:
    """TLS 1.0 with RC4 (deprecated + weak cipher)."""
    c = Conv(p, 50400, 465, t0)
    c.connect()
    ch = client_hello([0x0301], [0x0005, 0x0004], "old.lab.example")
    sh = server_hello(0x0301, 0x0005)
    c.tls_handshake(ch, sh, [load_cert("mail-leaf"), load_cert("ca")], b"", b"",
                    ske_group=None)
    smtp_session_inside_tls(c, b"old.lab.example")
    c.finish()


def sc_starttls_ok(p: Pcap, t0: float) -> None:
    """SMTP 587 plaintext -> STARTTLS -> TLS 1.2 (healthy upgrade)."""
    c = Conv(p, 50500, 587, t0)
    c.connect()
    c.s2c(b"220 mail.lab.example ESMTP ready\r\n")
    c.c2s(b"EHLO client.lab.example\r\n")
    c.s2c(b"250-mail.lab.example\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
    c.c2s(b"STARTTLS\r\n")
    c.s2c(b"220 2.0.0 Ready to start TLS\r\n")
    ch = client_hello([0x0303], [0xc02f, 0x0035], "mail.lab.example")
    sh = server_hello(0x0303, 0xc02f)
    c.tls_handshake(ch, sh, [load_cert("mail-leaf"), load_cert("ca")], b"", b"")
    smtp_session_inside_tls(c, b"mail.lab.example")
    c.finish()


def sc_pop3_cleartext(p: Pcap, t0: float) -> None:
    """POP3 110 fully plaintext with credentials."""
    c = Conv(p, 50600, 110, t0)
    c.connect()
    c.s2c(b"+OK POP3 mail.lab.example ready\r\n")
    c.c2s(b"USER alice\r\n")
    c.s2c(b"+OK\r\n")
    c.c2s(b"PASS hunter2\r\n")
    c.s2c(b"+OK logged in\r\n")
    c.c2s(b"LIST\r\n")
    c.s2c(b"+OK 1 messages\r\n1 400\r\n.\r\n")
    c.c2s(b"QUIT\r\n")
    c.s2c(b"+OK bye\r\n")
    c.finish()


def sc_starttls_stripped(p: Pcap, t0: float) -> None:
    """SMTP 25: STARTTLS offered, client requests, server refuses, session
    continues in cleartext -> downgrade/strip finding."""
    c = Conv(p, 50700, 25, t0)
    c.connect()
    c.s2c(b"220 mail.lab.example ESMTP ready\r\n")
    c.c2s(b"EHLO client.lab.example\r\n")
    c.s2c(b"250-mail.lab.example\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
    c.c2s(b"STARTTLS\r\n")
    c.s2c(b"454 4.7.0 TLS not available temporarily\r\n")
    c.c2s(b"MAIL FROM:<bob@lab.example>\r\n")
    c.s2c(b"250 2.1.0 Ok\r\n")
    c.c2s(b"RCPT TO:<carol@lab.example>\r\n")
    c.s2c(b"250 2.1.5 Ok\r\n")
    c.c2s(b"QUIT\r\n")
    c.s2c(b"221 2.0.0 Bye\r\n")
    c.finish()


def sc_imap_expired_cert(p: Pcap, t0: float) -> None:
    c = Conv(p, 50800, 993, t0)
    c.connect()
    ch = client_hello([0x0303], [0xc02f, 0x0035], "old.lab.example", groups=[0x0017])
    sh = server_hello(0x0303, 0xc02f)
    c.tls_handshake(ch, sh, [load_cert("expired")], b"", b"")
    imap_session_inside_tls(c)
    c.finish()


def sc_pop3s_weak_nopfs(p: Pcap, t0: float) -> None:
    """TLS 1.2 with RSA key exchange (no PFS) + weak 1024-bit cert key."""
    c = Conv(p, 50900, 995, t0)
    c.connect()
    ch = client_hello([0x0303], [0x0035, 0x002f], "weak.lab.example")
    sh = server_hello(0x0303, 0x0035)
    c.tls_handshake(ch, sh, [load_cert("weak-key")], b"", b"", ske_group=None)
    pop3_session_inside_tls(c)
    c.finish()


def sc_imaps_sha1_selfsigned(p: Pcap, t0: float) -> None:
    c = Conv(p, 51000, 993, t0)
    c.connect()
    ch = client_hello([0x0303], [0x002f], "self.lab.example")
    sh = server_hello(0x0303, 0x002f)
    c.tls_handshake(ch, sh, [load_cert("sha1")], b"", b"", ske_group=None)
    imap_session_inside_tls(c)
    c.finish()


def sc_handshake_failure(p: Pcap, t0: float) -> None:
    """Client offers only modern TLS 1.3; old server answers fatal alert."""
    c = Conv(p, 51100, 993, t0)
    c.connect()
    ch = client_hello([0x0304, 0x0303], [0x1301, 0x1302, 0x1303], "mail.lab.example",
                      groups=[0x001d, 0x0017])
    c.c2s(_rec(22, 0x0303, ch))
    c.s2c(alert(2, 40))            # fatal handshake_failure
    c.finish()


def sc_insecure_reneg(p: Pcap, t0: float) -> None:
    """SMTPS TLS 1.2 session where the client sends a SECOND ClientHello on
    the established connection (renegotiation) and neither side signals
    RFC 5746 renegotiation_info -> CFG-007 (insecure renegotiation)."""
    c = Conv(p, 52901, 465, t0)
    c.connect()
    ch = client_hello([0x0303], [0xc02f], "mail.lab.example", groups=[0x0017],
                      reneg_info=False)
    sh = server_hello(0x0303, 0xc02f, ems=True, reneg_info=False)
    c.tls_handshake(ch, sh, [load_cert("mail-leaf"), load_cert("ca")],
                    b"", b"", ske_group=0x0017)
    # mid-connection renegotiation: another ClientHello on the same stream,
    # again without renegotiation_info (the pre-RFC-5746 behaviour)
    reneg_ch = client_hello([0x0303], [0xc02f], None, ems=True, ticket=False,
                            reneg_info=False)
    c.c2s(_rec(22, 0x0303, reneg_ch))
    reneg_sh = server_hello(0x0303, 0xc02f, ems=True, reneg_info=False)
    c.s2c(_rec(22, 0x0303, reneg_sh))
    c.c2s(_rec(23, 0x0303, bytes(48)))       # application data continues
    c.finish()


SCENARIOS = {
    "good-smtps": sc_good_smtps,
    "imaps-good": sc_imaps_good,
    "pop3s-good": sc_pop3s_good,
    "smtp-tls10-rc4": sc_smtp_tls10_rc4,
    "starttls-ok": sc_starttls_ok,
    "pop3-cleartext": sc_pop3_cleartext,
    "starttls-stripped": sc_starttls_stripped,
    "imap-expired-cert": sc_imap_expired_cert,
    "pop3s-weak-nopfs": sc_pop3s_weak_nopfs,
    "imaps-sha1-selfsigned": sc_imaps_sha1_selfsigned,
    "handshake-failure": sc_handshake_failure,
    "insecure-reneg": sc_insecure_reneg,
}


def build_mixed() -> Pcap:
    p = Pcap()
    t = 0.0
    for name, fn in SCENARIOS.items():
        if name == "handshake-failure":
            continue
        fn(p, t)
        t += 2.5
    return p


# ----------------------------------------------------- XSE / demo scenarios ---
def sc_host_cert_swap(p: Pcap, t0: float) -> None:
    """Same host presents DIFFERENT leaf certificates in two sessions ->
    XSE-001 (certificate changed between sessions of the same host)."""
    # session 1: CA-signed good leaf on 993
    c = Conv(p, 52001, 993, t0)
    c.connect()
    ch = client_hello([0x0303], [0xc02f, 0xc030], "mail.lab.example", groups=[0x0017])
    sh = server_hello(0x0303, 0xc02f)
    c.tls_handshake(ch, sh, [load_cert("mail-leaf"), load_cert("ca")], b"", b"")
    imap_session_inside_tls(c)
    c.finish()
    # session 2 (later, same host): a DIFFERENT self-signed cert appears
    c = Conv(p, 52002, 993, t0 + 2.0)
    c.connect()
    ch = client_hello([0x0303], [0xc02f], "mail.lab.example", groups=[0x0017])
    sh = server_hello(0x0303, 0xc02f)
    c.tls_handshake(ch, sh, [load_cert("self-signed")], b"", b"")
    imap_session_inside_tls(c)
    c.finish()


def sc_host_version_regression(p: Pcap, t0: float) -> None:
    """Same host negotiates TLS 1.2 first, then DROPS to TLS 1.0 later ->
    XSE-002 (version regression on the same host: downgrade interference)."""
    c = Conv(p, 52101, 993, t0)
    c.connect()
    ch = client_hello([0x0303], [0xc02f, 0xc013], "mail.lab.example", groups=[0x0017])
    sh = server_hello(0x0303, 0xc02f)
    c.tls_handshake(ch, sh, [load_cert("mail-leaf"), load_cert("ca")], b"", b"")
    imap_session_inside_tls(c)
    c.finish()
    # later session: same host suddenly answers TLS 1.0 RC4
    c = Conv(p, 52102, 993, t0 + 2.0)
    c.connect()
    ch = client_hello([0x0303, 0x0301], [0xc02f, 0x0005], "mail.lab.example")
    sh = server_hello(0x0301, 0x0005)
    c.tls_handshake(ch, sh, [load_cert("mail-leaf"), load_cert("ca")], b"", b"",
                    ske_group=None)
    imap_session_inside_tls(c)
    c.finish()


def sc_smtp_cleartext_auth(p: Pcap, t0: float) -> None:
    """SMTP 25 plaintext with AUTH LOGIN + base64 credentials in the clear ->
    CRE-001 + PRT-001 + CFG-005 (no STARTTLS in the EHLO response at all)."""
    import base64 as _b64
    c = Conv(p, 52201, 25, t0)
    c.connect()
    c.s2c(b"220 mail.lab.example ESMTP ready\r\n")
    c.c2s(b"EHLO client.lab.example\r\n")
    c.s2c(b"250-mail.lab.example\r\n250-8BITMIME\r\n250-AUTH LOGIN PLAIN\r\n250 SIZE 35882577\r\n")
    c.c2s(b"AUTH LOGIN\r\n")
    c.s2c(b"334 VXNlcm5hbWU6\r\n")                       # "Username:"
    c.c2s(_b64.b64encode(b"alice@lab.example") + b"\r\n")
    c.s2c(b"334 UGFzc3dvcmQ6\r\n")                        # "Password:"
    c.c2s(_b64.b64encode(b"Sup3rS3cret!") + b"\r\n")
    c.s2c(b"235 2.7.0 Authentication successful\r\n")
    c.c2s(b"MAIL FROM:<alice@lab.example>\r\n")
    c.s2c(b"250 2.1.0 Ok\r\n")
    c.c2s(b"QUIT\r\n")
    c.s2c(b"221 2.0.0 Bye\r\n")
    c.finish()


def sc_smtp_no_starttls_advert(p: Pcap, t0: float) -> None:
    """SMTP 25 plaintext whose EHLO response never advertises STARTTLS and
    no upgrade is attempted -> CFG-005 only (server offers no TLS path)."""
    c = Conv(p, 52701, 25, t0)
    c.connect()
    c.s2c(b"220 mail.lab.example ESMTP ready\r\n")
    c.c2s(b"EHLO client.lab.example\r\n")
    c.s2c(b"250-mail.lab.example\r\n250-8BITMIME\r\n250 SIZE 35882577\r\n")
    c.c2s(b"MAIL FROM:<dave@lab.example>\r\n")
    c.s2c(b"250 2.1.0 Ok\r\n")
    c.c2s(b"QUIT\r\n")
    c.s2c(b"221 2.0.0 Bye\r\n")
    c.finish()


def sc_pqc_hybrid(p: Pcap, t0: float) -> None:
    """SMTPS implicit TLS 1.3 negotiating the hybrid ML-KEM group
    X25519MLKEM768 (0x11ec) — the only genuinely post-quantum-ready kex.
    Demonstrates the PQC-ready session count + no PQC-001 advisory."""
    c = Conv(p, 52801, 465, t0)
    c.connect()
    ch = client_hello([0x0304, 0x0303], [0x1301, 0x1302], "mail.lab.example",
                      groups=[0x11ec, 0x001d])
    sh = server_hello(0x0303, 0x1301, tls13=True, group=0x11ec)
    c.tls_handshake(ch, sh, [load_cert("mail-leaf"), load_cert("ca")], b"", b"",
                    ske_group=None)
    smtp_session_inside_tls(c, b"mail.lab.example")
    c.finish()


def sc_hostname_mismatch(p: Pcap, t0: float) -> None:
    """IMAPS 993: client sends SNI mail.lab.example but the server presents
    a CA-signed cert for other.lab.example -> CRT-007 (hostname mismatch)."""
    c = Conv(p, 52811, 993, t0)
    c.connect()
    ch = client_hello([0x0303], [0xc02f, 0x0035], "mail.lab.example", groups=[0x0017])
    sh = server_hello(0x0303, 0xc02f)
    c.tls_handshake(ch, sh, [load_cert("mismatch-leaf"), load_cert("ca")], b"", b"")
    imap_session_inside_tls(c)
    c.finish()


def sc_imap_cleartext_login(p: Pcap, t0: float) -> None:
    """IMAP 143 plaintext LOGIN with credentials -> CRE-001 + PRT-001."""
    c = Conv(p, 52301, 143, t0)
    c.connect()
    c.s2c(b"* OK [CAPABILITY IMAP4rev1 STARTTLS] IMAP ready\r\n")
    c.c2s(b"a1 LOGIN bob P@ssw0rd123\r\n")
    c.s2c(b"a1 OK [CAPABILITY IMAP4rev1] Logged in\r\n")
    c.c2s(b"a2 SELECT INBOX\r\n")
    c.s2c(b"* 12 EXISTS\r\na2 OK [READ-WRITE] done\r\n")
    c.c2s(b"a3 LOGOUT\r\n")
    c.s2c(b"* BYE\r\na3 OK\r\n")
    c.finish()


def sc_all_clean_gold(p: Pcap, t0: float) -> None:
    """A 'should score 100' gold capture: healthy sessions across all three
    protocols, good chains, TLS 1.2/1.3, forward secrecy, STARTTLS working."""
    # SMTPS implicit, TLS 1.2 ECDHE-GCM
    c = Conv(p, 52401, 465, t0)
    c.connect()
    ch = client_hello([0x0303], [0xc02f, 0xc030, 0x009e], "mail.lab.example",
                      groups=[0x0017])
    sh = server_hello(0x0303, 0xc02f)
    c.tls_handshake(ch, sh, [load_cert("mail-leaf"), load_cert("ca")], b"", b"")
    smtp_session_inside_tls(c, b"mail.lab.example")
    c.finish()
    # IMAPS implicit, TLS 1.3
    c = Conv(p, 52402, 993, t0 + 1.5)
    c.connect()
    ch = client_hello([0x0304, 0x0303], [0x1301, 0x1302, 0xc02f], "mail.lab.example",
                      groups=[0x001d])
    sh = server_hello(0x0303, 0x1301, tls13=True, group=0x001d)
    c.tls_handshake(ch, sh, [load_cert("mail-leaf"), load_cert("ca")], b"", b"")
    imap_session_inside_tls(c)
    c.finish()
    # POP3S implicit, TLS 1.2 ECDHE-GCM
    c = Conv(p, 52403, 995, t0 + 3.0)
    c.connect()
    ch = client_hello([0x0303], [0xc02f, 0xc013], "mail.lab.example", groups=[0x0017])
    sh = server_hello(0x0303, 0xc02f)
    c.tls_handshake(ch, sh, [load_cert("mail-leaf"), load_cert("ca")], b"", b"")
    pop3_session_inside_tls(c)
    c.finish()
    # SMTP 587 STARTTLS upgrade, healthy
    c = Conv(p, 52404, 587, t0 + 4.5)
    c.connect()
    c.s2c(b"220 mail.lab.example ESMTP ready\r\n")
    c.c2s(b"EHLO client.lab.example\r\n")
    c.s2c(b"250-mail.lab.example\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
    c.c2s(b"STARTTLS\r\n")
    c.s2c(b"220 2.0.0 Ready to start TLS\r\n")
    ch = client_hello([0x0303], [0xc02f, 0x0035], "mail.lab.example")
    sh = server_hello(0x0303, 0xc02f)
    c.tls_handshake(ch, sh, [load_cert("mail-leaf"), load_cert("ca")], b"", b"")
    smtp_session_inside_tls(c, b"mail.lab.example")
    c.finish()


def sc_expiring_soon_cert(p: Pcap, t0: float) -> None:
    """Certificate expiring within 30 days -> CRT-003 (low)."""
    c = Conv(p, 52501, 993, t0)
    c.connect()
    ch = client_hello([0x0303], [0xc02f, 0x0035], "soon.lab.example", groups=[0x0017])
    sh = server_hello(0x0303, 0xc02f)
    c.tls_handshake(ch, sh, [load_cert("expiring-soon")], b"", b"")
    imap_session_inside_tls(c)
    c.finish()


def sc_not_yet_valid_cert(p: Pcap, t0: float) -> None:
    """Certificate whose validity window starts in the future -> CRT-002."""
    c = Conv(p, 52601, 995, t0)
    c.connect()
    ch = client_hello([0x0303], [0xc02f], "future.lab.example", groups=[0x0017])
    sh = server_hello(0x0303, 0xc02f)
    c.tls_handshake(ch, sh, [load_cert("not-yet-valid")], b"", b"")
    pop3_session_inside_tls(c)
    c.finish()


def build_after_remediation() -> Pcap:
    """The 'after' capture for the before/after demo: same traffic shape as
    mixed but every server fixed — pairs with mixed.pcap for the score-delta
    story (different client ports so sessions are distinct)."""
    p = Pcap()
    t = 0.0
    # SMTPS + IMAPS + POP3S clean
    for port, proto_app in ((465, lambda c: smtp_session_inside_tls(c, b"mail.lab.example")),
                            (993, imap_session_inside_tls),
                            (995, pop3_session_inside_tls)):
        c = Conv(p, 53000 + port % 100, port, t)
        c.connect()
        ch = client_hello([0x0304, 0x0303], [0x1301, 0xc02f, 0xc030], "mail.lab.example",
                          groups=[0x0017])
        sh = server_hello(0x0303, 0xc02f)
        c.tls_handshake(ch, sh, [load_cert("mail-leaf"), load_cert("ca")], b"", b"")
        proto_app(c)
        c.finish()
        t += 1.5
    # STARTTLS upgrades now honored
    c = Conv(p, 53100, 587, t)
    c.connect()
    c.s2c(b"220 mail.lab.example ESMTP ready\r\n")
    c.c2s(b"EHLO client.lab.example\r\n")
    c.s2c(b"250-mail.lab.example\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
    c.c2s(b"STARTTLS\r\n")
    c.s2c(b"220 2.0.0 Ready to start TLS\r\n")
    ch = client_hello([0x0303], [0xc02f, 0x0035], "mail.lab.example")
    sh = server_hello(0x0303, 0xc02f)
    c.tls_handshake(ch, sh, [load_cert("mail-leaf"), load_cert("ca")], b"", b"")
    smtp_session_inside_tls(c, b"mail.lab.example")
    c.finish()
    # plaintext POP3 fixed to POP3S
    c = Conv(p, 53200, 995, t + 1.5)
    c.connect()
    ch = client_hello([0x0303], [0xc02f], "mail.lab.example", groups=[0x0017])
    sh = server_hello(0x0303, 0xc02f)
    c.tls_handshake(ch, sh, [load_cert("mail-leaf"), load_cert("ca")], b"", b"")
    pop3_session_inside_tls(c)
    c.finish()
    return p


DEMO_SCENARIOS = {
    "host-cert-swap": sc_host_cert_swap,
    "host-version-regression": sc_host_version_regression,
    "smtp-cleartext-auth": sc_smtp_cleartext_auth,
    "smtp-no-starttls-advert": sc_smtp_no_starttls_advert,
    "imap-cleartext-login": sc_imap_cleartext_login,
    "all-clean-gold": sc_all_clean_gold,
    "imap-expiring-soon": sc_expiring_soon_cert,
    "pop3s-not-yet-valid": sc_not_yet_valid_cert,
    "pqc-hybrid-kex": sc_pqc_hybrid,
    "imap-hostname-mismatch": sc_hostname_mismatch,
}


# ------------------------------------------------- randomized ML corpus ----
import random as _random

VERSION_CIPHERS = {
    0x0301: [0x0005, 0x0004, 0x000a, 0x002f, 0x0035, 0x0002],
    0x0302: [0x0005, 0x000a, 0x002f, 0x0035, 0x0033, 0x0039],
    0x0303: [0xc02f, 0xc027, 0xc030, 0x009e, 0x002f, 0x0035, 0x0005, 0x000a,
             0xc013, 0x009f],
    0x0304: [0x1301, 0x1302, 0x1303],
}
CERT_POOLS = [
    ["mail-leaf", "ca"],                    # clean
    ["good"],                               # self-signed single
    ["expired"], ["not-yet-valid"], ["expiring-soon"],
    ["weak-key"], ["sha1"], ["chain-leaf", "ca"], ["self-signed"],
]
MAIL_PORT = {"smtp": [25, 465, 587], "imap": [143, 993], "pop3": [110, 995]}
SECURE_PORT = {"smtp": 465, "imap": 993, "pop3": 995}
PLAIN_PORT = {"smtp": 587, "imap": 143, "pop3": 110}
CERT_HOST = {"expired": "old.lab.example", "not-yet-valid": "future.lab.example",
             "expiring-soon": "soon.lab.example", "weak-key": "weak.lab.example",
             "sha1": "sha1.lab.example", "self-signed": "self.lab.example"}
PROTO_APP = {"smtp": lambda c: smtp_session_inside_tls(c, b"mail.lab.example"),
             "imap": lambda c: imap_session_inside_tls(c),
             "pop3": lambda c: pop3_session_inside_tls(c)}


def random_mail_session(p: Pcap, t0: float, rng) -> None:
    proto = rng.choice(["smtp", "imap", "pop3"])
    mode = rng.choices(["implicit", "starttls", "plaintext"], weights=[55, 25, 20])[0]
    cport = rng.randint(49000, 65000)

    if mode == "plaintext":
        c = Conv(p, cport, PLAIN_PORT[proto], t0)
        c.connect()
        s2c = b"+OK POP3 ready\r\n" if proto == "pop3" else \
              b"* OK IMAP4rev1 ready\r\n" if proto == "imap" else \
              b"220 mail.lab.example ESMTP\r\n"
        c2s = b"USER alice\r\nPASS xxx\r\nQUIT\r\n" if proto == "pop3" else \
              b"a1 LOGIN alice xx\r\na2 LOGOUT\r\n" if proto == "imap" else \
              b"EHLO c.lab.example\r\nMAIL FROM:<a@lab.example>\r\nQUIT\r\n"
        c.c2s(c2s)
        c.s2c(s2c)
        c.finish()
        return

    if mode == "starttls":
        c = Conv(p, cport, PLAIN_PORT[proto], t0)
        c.connect()
        banner = {  # per-protocol greeting + STARTTLS exchange
            "smtp": (b"220 mail.lab.example ESMTP\r\n",
                     b"EHLO c.lab.example\r\n", b"250-STARTTLS\r\n250 8BITMIME\r\n",
                     b"STARTTLS\r\n", b"220 2.0.0 Ready to start TLS\r\n"),
            "imap": (b"* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\n",
                     b"a1 STARTTLS\r\n", b"a1 OK Begin TLS\r\n", None, None),
            "pop3": (b"+OK POP3 ready\r\nCAPA\r\n", b"STLS\r\n",
                     b"+OK Begin TLS\r\n", None, None),
        }[proto]
        c.s2c(banner[0])
        c.c2s(banner[1])
        if banner[3] is not None:
            c.s2c(banner[2])
            c.c2s(banner[3])
            c.s2c(banner[4])
        else:
            c.s2c(banner[2])
    else:
        c = Conv(p, cport, SECURE_PORT[proto], t0)
        c.connect()

    ver = rng.choices([0x0301, 0x0302, 0x0303, 0x0304], weights=[12, 8, 55, 25])[0]
    offered = rng.sample(VERSION_CIPHERS[ver], k=min(len(VERSION_CIPHERS[ver]), rng.randint(1, 4)))
    # server either picks the best or the worst of what's offered
    pick_best = rng.random() < 0.6
    chosen = max(offered) if pick_best else min(offered)
    host = rng.choice(["mail.lab.example", "old.lab.example", "self.lab.example"])
    cert_names = rng.choice(CERT_POOLS)
    if cert_names[0] in CERT_HOST and rng.random() < 0.7:
        host = CERT_HOST[cert_names[0]]
    # medium-band shape: a CBC suite on TLS 1.2 with an otherwise clean cert
    # fires CPR-003 only — keeps the 'medium' risk class populated
    if rng.random() < 0.15:
        ver, offered, chosen = 0x0303, [0x002f, 0xc02f], 0x002f
        host = "mail.lab.example"
        cert_names = ["mail-leaf", "ca"]
    ch = client_hello([ver], offered, host,
                      groups=[0x001d, 0x0017] if ver == 0x0304 else [0x0017])
    sh = server_hello(0x0303 if ver == 0x0304 else ver, chosen,
                      tls13=(ver == 0x0304),
                      group=0x001d if ver == 0x0304 else None)
    # RSA / DH_anon key exchange sends no ServerKeyExchange message
    cipher_name = CIPHER_NAMES.get(chosen, "")
    ske = None if (cipher_name.startswith("TLS_RSA_") or
                   cipher_name.startswith("TLS_DH_anon")) else 0x0017
    c.tls_handshake(ch, sh, [load_cert(n) for n in cert_names], b"", b"",
                    ske_group=ske)
    if rng.random() < 0.9:
        PROTO_APP[proto](c)
    c.finish()


def build_training_pcap(seed: int, count: int) -> Pcap:
    rng = _random.Random(seed)
    p = Pcap()
    t = 0.0
    for _ in range(count):
        random_mail_session(p, t, rng)
        t += rng.uniform(1.5, 4.0)
    return p


def main() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    for name, fn in SCENARIOS.items():
        p = Pcap()
        fn(p, 0.0)
        path = os.path.join(OUT_DIR, name + ".pcap")
        write_pcap(path, p)
        print("wrote %-28s %4d packets" % (name + ".pcap", len(p.packets)))
    mixed = build_mixed()
    write_pcap(os.path.join(OUT_DIR, "mixed.pcap"), mixed)
    print("wrote %-28s %4d packets" % ("mixed.pcap", len(mixed.packets)))

    for name, fn in DEMO_SCENARIOS.items():
        p = Pcap()
        fn(p, 0.0)
        write_pcap(os.path.join(OUT_DIR, name + ".pcap"), p)
        print("wrote %-28s %4d packets" % (name + ".pcap", len(p.packets)))
    fixed = build_after_remediation()
    write_pcap(os.path.join(OUT_DIR, "after-remediation.pcap"), fixed)
    print("wrote %-28s %4d packets" % ("after-remediation.pcap", len(fixed.packets)))

    train_dir = os.path.join(OUT_DIR, "train")
    os.makedirs(train_dir, exist_ok=True)
    for seed in (1, 2, 3, 4):
        p = build_training_pcap(seed, 45)
        write_pcap(os.path.join(train_dir, "train-%d.pcap" % seed), p)
        print("wrote train/train-%d.pcap %4d packets" % (seed, len(p.packets)))
    print("done ->", OUT_DIR)


if __name__ == "__main__":
    sys.exit(main())
