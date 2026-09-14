"""TLS record + handshake parsing over reassembled TCP byte streams.

Supports parsing of ClientHello, ServerHello, Certificate (TLS <= 1.2),
alerts, and ChangeCipherSpec. TLS 1.3 handshakes are encrypted after
ServerHello; we degrade gracefully and record what is visible.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# TLS content types
CT_CHANGE_CIPHER_SPEC = 20
CT_ALERT = 21
CT_HANDSHAKE = 22
CT_APPLICATION_DATA = 23

# Handshake types
HS_HELLO_REQUEST = 0
HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
HS_CERTIFICATE = 11
HS_SERVER_KEY_EXCHANGE = 12
HS_CLIENT_KEY_EXCHANGE = 16
HS_FINISHED = 20

TLS_VERSIONS = {
    0x0200: "SSLv2",
    0x0300: "SSLv3",
    0x0301: "TLSv1.0",
    0x0302: "TLSv1.1",
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3",
}

ALERT_LEVELS = {1: "warning", 2: "fatal"}
ALERT_DESCS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
    40: "handshake_failure", 47: "illegal_parameter", 48: "unknown_ca",
    49: "access_denied", 50: "decode_error", 51: "decrypt_error",
    70: "protocol_version", 71: "insufficient_security",
    42: "bad_certificate", 43: "unsupported_certificate",
    44: "certificate_revoked", 45: "certificate_expired",
    46: "certificate_unknown", 46 + 100: "unknown_psk_identity",
}

EXT_SNI = 0
EXT_EMS = 23                     # extended_master_secret
EXT_SESSION_TICKET = 35
EXT_SUPPORTED_VERSIONS = 43
EXT_RENEGOTIATION_INFO = 0xff01
EXT_SUPPORTED_GROUPS = 10
EXT_KEY_SHARE = 51

# Named groups (IANA TLS Supported Groups registry subset)
GROUP_NAMES: dict[int, str] = {
    0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1",
    0x001d: "x25519", 0x001e: "x448",
    0x0100: "ffdhe2048", 0x0101: "ffdhe3072",
    0x11ec: "X25519MLKEM768",     # hybrid post-quantum (X25519 + ML-KEM-768)
    0x11eb: "SecP256r1MLKEM768",  # hybrid post-quantum (P-256 + ML-KEM-768)
}
# Approximate classical security strength of the group in bits
GROUP_BITS: dict[int, int] = {
    0x0017: 128, 0x0018: 192, 0x0019: 256,
    0x001d: 128, 0x001e: 224,
    0x0100: 103, 0x0101: 125,
    0x11ec: 128, 0x11eb: 128,
}
# Hybrid ML-KEM groups: the only genuinely post-quantum-ready key exchange
PQC_HYBRID_GROUPS = {0x11ec, 0x11eb}


def group_name(gid: int | None) -> str | None:
    return GROUP_NAMES.get(gid) if gid is not None else None

CIPHER_NAMES: dict[int, str] = {
    0x0000: "TLS_NULL_WITH_NULL_NULL", 0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x0002: "TLS_RSA_WITH_NULL_SHA", 0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA", 0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", 0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA", 0x003b: "TLS_RSA_WITH_NULL_SHA256",
    0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256", 0x003d: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", 0x006b: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x009e: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 0x009f: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x00ba: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0x0040: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", 0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    0x0018: "TLS_DH_anon_WITH_RC4_128_MD5", 0x001a: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
    0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA", 0x006a: "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
    0x008c: "TLS_PSK_WITH_RC4_128_SHA", 0x0094: "TLS_PSK_WITH_NULL_SHA256",
    0x0017: "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
    0x0062: "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
    0x0063: "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
    0x0064: "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
    0x0065: "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA",
    0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xc023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xc028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xc077: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xc007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", 0xc011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    0xc006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA", 0x0066: "TLS_DHE_DSS_WITH_RC4_128_SHA",
}

KEX_NAMES = {0xc001: "ECDH_anon", 0xc00e: "ECDH_anon"}


def cipher_name(cid: int) -> str:
    if cid in CIPHER_NAMES:
        return CIPHER_NAMES[cid]
    return "TLS_UNKNOWN_0x%04x" % cid


def kex_of(cid: int) -> str:
    hi = cid >> 8
    if cid in KEX_NAMES:
        return KEX_NAMES[cid]
    name = CIPHER_NAMES.get(cid, "")
    if name.startswith("TLS_ECDHE_") or name.startswith("TLS_ECDH_"):
        return "ECDHE" if name.startswith("TLS_ECDHE_") else "ECDH"
    if name.startswith("TLS_DHE_") or name.startswith("TLS_DH_anon"):
        return "DHE" if name.startswith("TLS_DHE_") else "DH_anon"
    if name.startswith("TLS_RSA_"):
        return "RSA"
    if name.startswith("TLS_PSK_"):
        return "PSK"
    if 0x13_00 <= cid <= 0x13_ff:
        return "(TLS1.3)"      # always ECDHE-based
    if hi == 0xc0:
        return "ECDHE"
    if hi == 0x00 and (cid & 0xff) >= 0x0c:
        return "DHE"
    return "unknown"


def pfs_of(kex: str | None) -> bool | None:
    if kex is None:
        return None
    return kex in ("ECDHE", "DHE", "(TLS1.3)")


def cipher_strength(cid: int) -> int:
    """Approximate symmetric strength in bits."""
    name = CIPHER_NAMES.get(cid, "")
    if "NULL" in name or "EXPORT" in name or "anon" in name:
        return 0
    if "RC4" in name or "DES40" in name:
        return 40 if "EXPORT" in name else 64
    if "_DES_" in name or "3DES" in name:
        return 112 if "3DES" in name else 56
    if "128" in name:
        return 128
    if "256" in name or "384" in name:
        return 256
    return 128


@dataclass
class HandshakeInfo:
    """Everything extracted from one client/server hello exchange."""
    client_version: int = 0              # legacy_version field of ClientHello
    negotiated_version: int = 0          # from ServerHello / supported_versions
    offered_ciphers: list[int] = field(default_factory=list)
    chosen_cipher: int = 0
    sni: str | None = None
    session_id: bytes = b""
    session_ticket: bool = False
    extended_master_secret: bool = False
    secure_renegotiation: bool = False
    is_resumption: bool = False
    cert_der_chain: list[bytes] = field(default_factory=list)
    offered_groups: list[int] = field(default_factory=list)   # supported_groups (client)
    negotiated_group: int | None = None      # server's key_share group / named curve
    alerts: list[tuple[int, int]] = field(default_factory=list)   # (level, desc)
    saw_key_exchange: bool = False
    saw_client_key_exchange: bool = False
    saw_ccs: bool = False
    saw_application_data: bool = False
    handshake_complete: bool = False
    client_hello_count: int = 0     # >1 on one stream = renegotiation attempt
    renegotiation_seen: bool = False
    tls13: bool = False
    parse_error: str | None = None
    # event timeline: (kind, detail) tuples in wire order (frames attached later
    # by sessions.py using the flow's segment frame mapping)
    events: list = field(default_factory=list)

    @property
    def negotiated_version_name(self) -> str | None:
        if not self.negotiated_version:
            return None
        return TLS_VERSIONS.get(self.negotiated_version, "0x%04x" % self.negotiated_version)

    @property
    def client_version_name(self) -> str | None:
        if not self.client_version:
            return None
        return TLS_VERSIONS.get(self.client_version, "0x%04x" % self.client_version)


def _read_vec(data: memoryview, off: int, len_bytes: int) -> tuple[bytes, int]:
    if off + len_bytes > len(data):
        raise ValueError("truncated vector length")
    n = int.from_bytes(data[off:off + len_bytes], "big")
    off += len_bytes
    if off + n > len(data):
        raise ValueError("truncated vector body")
    return bytes(data[off:off + n]), off + n


def parse_client_hello(body: memoryview, info: HandshakeInfo) -> None:
    off = 0
    info.client_version = int.from_bytes(body[0:2], "big")
    off = 2 + 32                                    # version + random
    sid, off = _read_vec(body, off, 1)
    info.session_id = sid
    if info.session_id:
        info.is_resumption = True                   # heuristic; confirmed by server
    suites, off = _read_vec(body, off, 2)
    for i in range(0, len(suites) - 1, 2):
        cid = int.from_bytes(suites[i:i + 2], "big")
        if cid != 0x00ff:                           # reneg scsv
            info.offered_ciphers.append(cid)
    comp, off = _read_vec(body, off, 1)
    exts, off = _read_vec(body, off, 2)
    _parse_extensions(exts, info, client=True)


def parse_server_hello(body: memoryview, info: HandshakeInfo) -> None:
    off = 0
    info.negotiated_version = int.from_bytes(body[0:2], "big")
    off = 2 + 32
    sid, off = _read_vec(body, off, 1)
    if sid and sid == info.session_id and sid:
        info.is_resumption = True
    elif not sid and info.session_id:
        info.is_resumption = False
    chosen = int.from_bytes(body[off:off + 2], "big")
    info.chosen_cipher = chosen
    off += 2
    off += 1                                        # compression
    exts, off = _read_vec(body, off, 2)
    _parse_extensions(exts, info, client=False)


def _parse_extensions(exts: bytes, info: HandshakeInfo, client: bool) -> None:
    mv = memoryview(exts)
    off = 0
    while off + 4 <= len(mv):
        etype = int.from_bytes(mv[off:off + 2], "big")
        elen = int.from_bytes(mv[off + 2:off + 4], "big")
        body = mv[off + 4:off + 4 + elen]
        if off + 4 + elen > len(mv):
            break
        off += 4 + elen
        if etype == EXT_SNI and client:
            # RFC 6066: list_len(2) + entries of type(1)+len(2)+name;
            # type 0 = DNS hostname
            try:
                if len(body) >= 5 and body[2] == 0:
                    namelen = int.from_bytes(body[3:5], "big")
                    if 5 + namelen <= len(body):
                        info.sni = bytes(body[5:5 + namelen]).decode(
                            "ascii", "replace")
            except Exception:
                pass
        elif etype == EXT_EMS:
            info.extended_master_secret = True
        elif etype == EXT_SESSION_TICKET and client:
            info.session_ticket = True
        elif etype == EXT_RENEGOTIATION_INFO:
            info.secure_renegotiation = True
        elif etype == EXT_SUPPORTED_GROUPS and client:
            # SupportedGroups: 2-byte count + 2 bytes per group id
            try:
                mv_body = memoryview(bytes(body))
                if len(mv_body) >= 2:
                    n = int.from_bytes(mv_body[0:2], "big")
                    if n % 2 == 0 and 2 + n <= len(mv_body):
                        info.offered_groups = [
                            int.from_bytes(mv_body[i:i + 2], "big")
                            for i in range(2, 2 + n, 2)
                        ]
            except Exception:
                pass                     # one malformed extension never kills the parse
        elif etype == EXT_KEY_SHARE and not client:
            # ServerHello key_share: 2-byte selected group, then a length-
            # prefixed key exchange (whose bytes we don't need)
            try:
                mv_body = memoryview(bytes(body))
                if len(mv_body) >= 2:
                    info.negotiated_group = int.from_bytes(mv_body[0:2], "big")
            except Exception:
                pass
        elif etype == EXT_SUPPORTED_VERSIONS:
            if client:
                vers = bytes(body[1:])
                for i in range(0, len(vers) - 1, 2):
                    v = int.from_bytes(vers[i:i + 2], "big")
                    if v > (info.client_version or 0):
                        info.client_version = v        # real max offer
            else:
                info.negotiated_version = int.from_bytes(body[0:2], "big")
                if info.negotiated_version == 0x0304:
                    info.tls13 = True


def parse_server_key_exchange(body: memoryview, info: HandshakeInfo) -> None:
    """TLS 1.2 ECDHE ServerKeyExchange: curve_type(1) + named_curve(2).
    For finite-field DHE the first field is a length, not a curve type —
    we only claim a group when it looks like an EC named curve."""
    try:
        if len(body) >= 3 and body[0] == 3:       # EC named_curve
            gid = int.from_bytes(body[1:3], "big")
            info.negotiated_group = gid
    except Exception:
        pass


def parse_certificate(body: memoryview, info: HandshakeInfo) -> None:
    try:
        chain, off = _read_vec(body, 0, 3)
        o = 0
        while o + 3 <= len(chain):
            der, o = _read_vec(chain, o, 3)
            info.cert_der_chain.append(der)
    except Exception:
        pass


def parse_stream(data: bytes) -> HandshakeInfo:
    """Parse a reassembled one-direction-ordered concatenation of TLS
    records (client->server or server->client stream)."""
    info = HandshakeInfo()
    mv = memoryview(data)
    off = 0
    hs_buf = b""
    try:
        while off + 5 <= len(mv):
            ctype = mv[off]
            # length must be sane
            rlen = int.from_bytes(mv[off + 3:off + 5], "big")
            if ctype not in (20, 21, 22, 23) or rlen > 0x4000 + 2048:
                if not info.handshake_complete and not info.parse_error:
                    info.parse_error = "not a TLS stream"
                break
            if off + 5 + rlen > len(mv):
                break                                   # truncated tail (mid-capture)
            payload = bytes(mv[off + 5:off + 5 + rlen])
            off += 5 + rlen
            if ctype == CT_ALERT and payload:
                info.alerts.append((payload[0], payload[1] if len(payload) > 1 else 0))
                info.events.append(("alert",
                    {"level": ALERT_LEVELS.get(payload[0], str(payload[0])),
                     "desc": ALERT_DESCS.get(payload[1] if len(payload) > 1 else 0,
                                            str(payload[1] if len(payload) > 1 else 0))}))
            elif ctype == CT_CHANGE_CIPHER_SPEC:
                info.saw_ccs = True
                info.events.append(("ccs", {}))
                if not info.tls13 and info.chosen_cipher:
                    info.handshake_complete = True
            elif ctype == CT_APPLICATION_DATA:
                info.saw_application_data = True
                if info.tls13:
                    info.handshake_complete = True
            elif ctype == CT_HANDSHAKE:
                hs_buf += payload
                hs = memoryview(hs_buf)
                pos = 0
                while pos + 4 <= len(hs):
                    htype = hs[pos]
                    hlen = int.from_bytes(hs[pos + 1:pos + 4], "big")
                    if pos + 4 + hlen > len(hs):
                        break                            # wait for more records
                    body = hs[pos + 4:pos + 4 + hlen]
                    if htype == HS_CLIENT_HELLO and body[:1] not in (b"",):
                        info.client_hello_count += 1
                        if info.client_hello_count > 1:
                            # a repeated ClientHello on the same established
                            # c2s stream is a renegotiation. TLS 1.3 rekeying
                            # sends KeyUpdate, never a plaintext ClientHello,
                            # so this does not flag it.
                            info.renegotiation_seen = True
                        parse_client_hello(body, info)
                        info.events.append(("client_hello",
                            {"version": info.client_version_name or "",
                             "ciphers": len(info.offered_ciphers)}))
                    elif htype == HS_SERVER_HELLO:
                        parse_server_hello(body, info)
                        info.events.append(("server_hello",
                            {"version": info.negotiated_version_name or "",
                             "cipher": cipher_name(info.chosen_cipher) if info.chosen_cipher else ""}))
                    elif htype == HS_CERTIFICATE and not info.tls13:
                        n_certs = len(info.cert_der_chain)
                        parse_certificate(body, info)
                        info.events.append(("certificate",
                            {"count": len(info.cert_der_chain) or n_certs}))
                    elif htype == HS_SERVER_KEY_EXCHANGE:
                        info.saw_key_exchange = True
                        if not info.tls13:
                            parse_server_key_exchange(body, info)
                        info.events.append(("server_key_exchange", {}))
                    elif htype == HS_CLIENT_KEY_EXCHANGE:
                        info.saw_client_key_exchange = True
                        info.events.append(("client_key_exchange", {}))
                    elif htype == HS_FINISHED:
                        if info.tls13:
                            pass                          # encrypted; handshake ends on app data
                        else:
                            info.handshake_complete = True
                    pos += 4 + hlen
                hs_buf = b""
    except Exception as exc:                              # never let one bad stream kill a scan
        info.parse_error = str(exc)
    if info.alerts:
        for _, desc in info.alerts:
            if desc in (40, 70, 71):
                info.handshake_complete = False
    return info
