"""Mint X.509 certificates for the synthetic corpus (pure Python).

Variants: good (RSA-2048+SHA256), expired, not-yet-valid, expiring-soon,
self-signed, weak-key (RSA-1024, below the NIST 2048-bit floor), a
genuine sha1-signed certificate, and a CA + leaves for chains.

The SHA-1 variant is signed for real: modern `cryptography` refuses
SHA-1 signing, so the TBSCertificate is built with the builder, its
signature-algorithm OID is rewritten to sha1WithRSAEncryption
(1.2.840.113549.1.1.5), and the RSA signature over DigestInfo(SHA-1 ||
tbs) is computed directly from the private numbers (RFC 8017). The
resulting DER parses as a true sha1WithRSAEncryption certificate.

Usage:  python scripts/gen_certs.py  -> writes DER files to backend/fixtures/certs/
"""
from __future__ import annotations

import datetime as dt
import hashlib
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

OUT = os.path.join(os.path.dirname(__file__), "..", "fixtures", "certs")

# DER: SEQ { OID 1.2.840.113549.1.1.5 (sha1WithRSAEncryption), NULL }
_ALG_SHA1_RSA = bytes.fromhex("300d06092a864886f70d0101050500")
_OID_SHA256_RSA = bytes.fromhex("06092a864886f70d01010b")
_OID_SHA1_RSA = bytes.fromhex("06092a864886f70d010105")
# DigestInfo prefix: SEQ { SEQ { OID 1.3.14.3.2.26 (SHA-1), NULL }, OCTET STRING(20) }
_SHA1_DIGESTINFO_PREFIX = bytes.fromhex("3021300906052b0e03021a05000414")


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _key(kind: str):
    if kind == "weak1024":          # NIST floor is 2048; 1024 trips the weak-key rule
        return rsa.generate_private_key(public_exponent=65537, key_size=1024)
    if kind == "ec256":
        return ec.generate_private_key(ec.SECP256R1())
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn: str, org: str = "Prahari Lab") -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def _sha1_sign_rsa(key: rsa.RSAPrivateKey, tbs_der: bytes) -> bytes:
    """Raw RSA signature over DigestInfo(SHA-1(tbs)) computed from the
    private numbers — bypasses the library's refusal to sign SHA-1 while
    producing a fully standard sha1WithRSAEncryption signature."""
    digest_info = _SHA1_DIGESTINFO_PREFIX + hashlib.sha1(tbs_der).digest()
    nums = key.private_numbers()
    n, d = nums.public_numbers.n, nums.d
    k = (n.bit_length() + 7) // 8
    m = int.from_bytes(digest_info, "big")
    return pow(m, d, n).to_bytes(k, "big")


def mint_sha1(cn: str, days_valid: int = 365, days_ago: int = 30) -> bytes:
    """Mint a genuine SHA-1-signed self-signed certificate (CRT-006 fixture).

    Builds the TBSCertificate with the standard builder (SHA-256, for its
    DER encoding only), rewrites both signature-algorithm OIDs to
    sha1WithRSAEncryption, and signs the TBS bytes with manual RSA-SHA1.
    """
    key = _key("rsa2048")
    subject = _name(cn)
    now = dt.datetime.now(dt.timezone.utc)
    nb = now - dt.timedelta(days=days_ago)
    na = nb + dt.timedelta(days=days_valid)
    scaffold = (x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(nb)
                .not_valid_after(na)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]),
                               critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                               critical=True)
                .sign(key, hashes.SHA256()))
    tbs = scaffold.tbs_certificate_bytes
    i = tbs.find(_OID_SHA256_RSA)
    if i < 0:
        raise RuntimeError("could not locate inner signature OID in TBS")
    tbs_sha1 = tbs[:i] + _OID_SHA1_RSA + tbs[i + len(_OID_SHA256_RSA):]
    sig = _sha1_sign_rsa(key, tbs_sha1)
    return _tlv(0x30, tbs_sha1 + _ALG_SHA1_RSA + _tlv(0x03, b"\x00" + sig))


def mint(cn: str, kind: str = "good", ca_key=None, ca_cert=None,
         days_valid: int = 365, days_ago: int = 30,
         org: str = "Prahari Lab") -> bytes:
    """Returns cert DER. If ca_key/ca_cert given, leaf is signed by CA."""
    if kind == "sha1":
        return mint_sha1(cn, days_valid, days_ago)
    key = _key("ec256" if kind in ("good", "self-signed", "chain") else
               ("weak1024" if kind == "weak-key" else "rsa2048"))
    subject = _name(cn, org)
    # all validity windows are anchored to NOW, not to a backdated "now" —
    # expiring-soon must expire in the future, not-yet-valid must start there
    real_now = dt.datetime.now(dt.timezone.utc)
    issued = real_now - dt.timedelta(days=days_ago)

    if kind == "expired":
        nb = issued - dt.timedelta(days=days_valid)
        na = real_now - dt.timedelta(days=10)
    elif kind == "not-yet-valid":
        nb = real_now + dt.timedelta(days=7)
        na = nb + dt.timedelta(days=365)
    elif kind == "expiring-soon":
        nb = issued
        na = real_now + dt.timedelta(days=20)
    else:
        nb, na = issued, issued + dt.timedelta(days=days_valid)

    builder = (x509.CertificateBuilder()
               .subject_name(subject)
               .issuer_name(ca_cert.subject if ca_cert is not None else subject)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(nb)
               .not_valid_after(na)
               .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]),
                              critical=False)
               .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                              critical=True))
    signer_key = ca_key if ca_key is not None else key
    cert = builder.sign(signer_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def mint_ca(cn: str = "Prahari Lab CA") -> tuple[bytes, object]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
    cert = (x509.CertificateBuilder()
            .subject_name(_name(cn))
            .issuer_name(_name(cn))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.DER), key)


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    ca_der, ca_key = mint_ca()
    made = {"ca": ca_der}
    for kind in ("good", "expired", "not-yet-valid", "expiring-soon",
                 "self-signed", "weak-key", "sha1"):
        cn = {"good": "mail.lab.example", "expired": "old.lab.example",
              "not-yet-valid": "future.lab.example", "expiring-soon": "soon.lab.example",
              "self-signed": "self.lab.example", "weak-key": "weak.lab.example",
              "sha1": "sha1.lab.example"}[kind]
        made[kind] = mint(cn, kind)
    # CA-signed leaves for clean-chain scenarios (SNI hostname matches)
    ca_cert = x509.load_der_x509_certificate(ca_der)
    leaf_der = mint("chain.lab.example", "good", ca_key=ca_key, ca_cert=ca_cert)
    made["chain-leaf"] = leaf_der
    mail_der = mint("mail.lab.example", "good", ca_key=ca_key, ca_cert=ca_cert)
    made["mail-leaf"] = mail_der
    # CRT-007 fixture: CA-signed, perfectly valid — but its SAN names a
    # DIFFERENT host than the one clients connect to (SNI mismatch)
    mismatch_der = mint("other.lab.example", "good", ca_key=ca_key, ca_cert=ca_cert)
    made["mismatch-leaf"] = mismatch_der

    for name, der in made.items():
        with open(os.path.join(OUT, name + ".der"), "wb") as fh:
            fh.write(der)
        c = x509.load_der_x509_certificate(der)
        print("wrote %s.der (%d bytes, %s-signed)" %
              (name, len(der), c.signature_hash_algorithm.name))
    print("done ->", os.path.abspath(OUT))


if __name__ == "__main__":
    sys.exit(main())
