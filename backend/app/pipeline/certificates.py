"""X.509 certificate extraction and validation."""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

MIN_RSA_BITS = 2048
MIN_EC_BITS = 256
EXPIRY_WARN_DAYS = 30


def _name_str(name: x509.Name) -> tuple[str, str]:
    cn = org = None
    for attr in name:
        if attr.oid == NameOID.COMMON_NAME:
            cn = attr.value
        elif attr.oid == NameOID.ORGANIZATION_NAME:
            org = attr.value
    return (cn or "unknown", org or "-")


def fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def analyze_chain(cert_ders: list[bytes], sni: str | None, now: dt.datetime | None = None):
    """Analyze one offered certificate chain. Returns list of cert dicts +
    chain-level issues list."""
    now = now or dt.datetime.now(dt.timezone.utc)
    certs: list[x509.Certificate] = []
    for der in cert_ders[:5]:
        try:
            certs.append(x509.load_der_x509_certificate(der))
        except Exception:
            continue
    if not certs:
        return [], ["chain unreadable"]

    leaf = certs[0]
    issues: list[str] = []

    # chain signature verification along offered order
    for i in range(len(certs) - 1):
        if not _verify_cert_signature(certs[i], certs[i + 1]):
            issues.append("signature break between chain position %d and %d" % (i, i + 1))
            break

    self_signed = False
    if _self_signed_and_valid(certs[0]):
        leaf = certs[0]
        self_signed = (leaf.issuer == leaf.subject)
    if self_signed:
        issues.append("self-signed")
    if len(certs) == 1 and not self_signed:
        issues.append("no intermediates offered (incomplete chain)")

    # trust anchors: can't do full PKI validation passively/offline; we check
    # whether the chain terminates in a self-issued cert.
    root = certs[-1]
    if root.issuer != root.subject and len(certs) > 1:
        issues.append("chain does not reach a self-signed root")

    # hostname vs SNI
    if sni:
        names = []
        try:
            san = leaf.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            names = [str(n) for n in san.get_values_for_type(x509.DNSName)]
            ips = san.get_values_for_type(x509.IPAddress)
            names += [str(i) for i in ips]
        except Exception:
            names = []
        cn, _ = _name_str(leaf.subject)
        names.append(cn)
        if not _host_matches(sni, names):
            issues.append("hostname mismatch (SNI %s)" % sni)

    out = []
    from cryptography.hazmat.primitives import serialization
    for cert in certs:
        cn, org = _name_str(cert.subject)
        icn, iorg = _name_str(cert.issuer)
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            key_alg, key_bits = "RSA", pub.key_size
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            key_alg, key_bits = "ECDSA", pub.curve.key_size
        elif isinstance(pub, dsa.DSAPublicKey):
            key_alg, key_bits = "DSA", pub.key_size
        else:
            key_alg, key_bits = type(pub).__name__, 0
        try:
            san_list = [str(n) for n in cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)]
        except Exception:
            san_list = []
        nb = cert.not_valid_before_utc
        na = cert.not_valid_after_utc
        der = cert.public_bytes(serialization.Encoding.DER)
        out.append({
            "fingerprint_sha256": fingerprint(der),
            "subject_cn": cn,
            "subject_org": org,
            "issuer_cn": icn,
            "issuer_org": iorg,
            "self_signed": cert.issuer == cert.subject,
            "not_before": nb.isoformat(),
            "not_after": na.isoformat(),
            "is_expired": na < now,
            "not_yet_valid": nb > now,
            "days_to_expiry": int((na - now).total_seconds() // 86400),
            "days_valid": int((na - nb).total_seconds() // 86400),
            "key_algorithm": key_alg,
            "key_length": key_bits,
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "signature_hash": cert.signature_hash_algorithm.name
                              if cert.signature_hash_algorithm else "unknown",
            "san_entries": san_list,
            "pem": pem_of(der),
        })

    return out, issues


def weak_key(cert_dict: dict) -> bool:
    if cert_dict["key_algorithm"] == "RSA":
        return cert_dict["key_length"] < MIN_RSA_BITS
    if cert_dict["key_algorithm"] in ("ECDSA",):
        return cert_dict["key_length"] < MIN_EC_BITS
    if cert_dict["key_algorithm"] == "DSA":
        return True
    return cert_dict["key_algorithm"] not in ("RSA", "ECDSA")


def weak_signature(cert_dict: dict) -> bool:
    return cert_dict["signature_hash"] in ("md5", "sha1")


def _verify_cert_signature(child: x509.Certificate, parent: x509.Certificate) -> bool:
    """True if parent's key verifies child's signature.

    SHA-1 fallback: some `cryptography` builds silently refuse SHA-1
    verification (InvalidSignature even for valid signatures). For
    sha1WithRSAEncryption we recover the DigestInfo from the signature via
    textbook RSA and compare hashes directly — the fixture corpus contains a
    genuine SHA-1 certificate (rule CRT-006) that must still verify.
    """
    from cryptography.hazmat.primitives.asymmetric import ed448, ed25519, padding
    pub = parent.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            if child.signature_algorithm_oid == _OID_SHA1_RSA:
                return _verify_sha1_rsa(child, pub)
            try:
                params = child.signature_algorithm_parameters   # PSS vs PKCS1v15
            except Exception:
                params = padding.PKCS1v15()
            pub.verify(child.signature, child.tbs_certificate_bytes,
                       params, child.signature_hash_algorithm)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes,
                       ec.ECDSA(child.signature_hash_algorithm))
        elif isinstance(pub, dsa.DSAPublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes,
                       child.signature_hash_algorithm)
        elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pub.verify(child.signature, child.tbs_certificate_bytes)
        else:
            return False
        return True
    except Exception:
        return False


# 1.2.840.113549.1.1.5 — sha1WithRSAEncryption
_OID_SHA1_RSA = x509.ObjectIdentifier("1.2.840.113549.1.1.5")


def _verify_sha1_rsa(child: x509.Certificate, pub: rsa.RSAPublicKey) -> bool:
    """Manual PKCS#1 v1.5 verification for SHA-1 certificates."""
    import hashlib
    e = pub.public_numbers().e
    n = pub.public_numbers().n
    k = (n.bit_length() + 7) // 8
    if len(child.signature) != k:
        return False
    m = pow(int.from_bytes(child.signature, "big"), e, n)
    recovered = m.to_bytes(k, "big")
    # DigestInfo(SHA-1) prefix: SEQ{SEQ{OID 1.3.14.3.2.26, NULL}, OCTET STRING(20)}
    prefix = bytes.fromhex("3021300906052b0e03021a05000414")
    if not recovered.startswith(b"\x00\x01") or prefix not in recovered:
        return False
    digest_start = recovered.find(prefix) + len(prefix)
    return recovered[digest_start:digest_start + 20] == \
        hashlib.sha1(child.tbs_certificate_bytes).digest()


def _self_signed_and_valid(cert: x509.Certificate) -> bool:
    """True if the cert signs itself successfully (genuine self-signed)."""
    return cert.issuer == cert.subject and _verify_cert_signature(cert, cert)


def _host_matches(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    try:
        addr = ipaddress.ip_address(host)
        return str(addr) in names
    except ValueError:
        pass
    for n in names:
        n = n.lower().rstrip(".")
        if n == host:
            return True
        if n.startswith("*."):
            suffix = n[1:]
            if host.endswith(suffix) and host.count(".") >= n.count("."):
                return True
    return False


def pem_of(der: bytes) -> str:
    import base64
    b64 = base64.encodebytes(der).decode().replace("\n", "")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"
