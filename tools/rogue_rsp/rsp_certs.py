"""Attacker RSP certificate and ServerSigned1 crafting for the rogue SM-DS.

The rogue SM-DS must hand the eUICC an ES9+/ES11 ``initiateAuthentication``
response that the eUICC's ``AuthenticateServer`` step will process far enough to
exercise the CI-trust gate (SGP.22 v2.x §5.7.13). To get there the response must:

1. Echo the FRESH ``euiccChallenge`` the eUICC just issued into ``serverSigned1``
   (challenge binding), otherwise the eUICC rejects before it ever looks at the
   certificate chain.
2. Carry a ``serverSignature1`` that actually verifies against the public key in
   ``serverCertificate`` (so a rejection is provably the CI-trust check, not a
   broken signature).
3. Carry a ``serverCertificate`` whose issuer is NOT a GSMA production CI.

This module builds all three with an attacker-controlled ECDSA P-256 key. The
expected eUICC verdict is REJECT at the CI-trust gate. An ACCEPT is a CI-trust
bypass — CRITICAL.

Wire references (real captures):
- ``serverSigned1``     b64 ``MECACAAAAAAch...`` -> ``30 40 80 08 <txid> 81 10 <chal> 83 .. 84 ..``
- ``serverSignature1``  b64 ``XzdAQ867...``       -> ``5F 37 40 <64-byte ECDSA r||s>``
- ``euiccCiPKIdToBeUsed`` b64 ``BBSBNw9R...``      -> ``04 14 <20-byte CI SKI>``
- ``serverCertificate`` b64 ``MIICgz...``          -> X.509 DER (``30 82 ..``)
(from ``.sessions/betterroaming-live-rsp-20260629/handshake_capture.txt``)

Nothing here touches a device or the network. It is pure key/byte crafting.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.x509.oid import NameOID

import ber

# ServerSigned1 inner tags (SGP.22 rsp.asn ServerSigned1 / AuthenticateServerRequest).
TAG_SERVER_SIGNED1 = 0x30
TAG_TRANSACTION_ID = 0x80
TAG_EUICC_CHALLENGE = 0x81
TAG_SERVER_ADDRESS = 0x83
TAG_SERVER_CHALLENGE = 0x84

# serverSignature1 is [APPLICATION 55] OCTET STRING, tag 5F37.
TAG_SERVER_SIGNATURE1 = 0x5F37
# euiccCiPKIdToBeUsed is an OCTET STRING (SubjectKeyIdentifier), tag 04.
TAG_EUICC_CI_PKID = 0x04

# The production GSMA RSP2 Root CI1 SKI the Pixel eUICC trusts. The attacker cert
# is deliberately NOT chained to this; a forged-CI mutation may still CLAIM it.
PROD_GSMA_CI_PKID = bytes.fromhex("81370F5125D0B1D408D4C3B232E6D25E795BEBFB")


class CertCraftError(ValueError):
    """Raised when a certificate or signature cannot be crafted."""


@dataclass(frozen=True)
class AttackerIdentity:
    """An attacker key plus its SGP.22-style server certificate.

    ``server_certificate`` is DER-encoded X.509. ``ci_pkid`` is the 20-byte CI
    SubjectKeyIdentifier the response advertises as ``euiccCiPKIdToBeUsed`` — for a
    rogue SM-DS this is an untrusted synthetic CI (or a forged production value in
    the forged-CI mutation), never a real production CI whose key signed the cert.
    ``trusted`` is always False here: no attacker identity chains to a GSMA CI.
    """

    private_key: ec.EllipticCurvePrivateKey
    server_certificate: bytes
    ci_pkid: bytes
    label: str
    trusted: bool = False

    @property
    def public_key(self) -> ec.EllipticCurvePublicKey:
        return self.private_key.public_key()

    def ci_pkid_tlv(self) -> bytes:
        """``euiccCiPKIdToBeUsed`` as a full ``04 14 <ski>`` TLV."""
        return ber.tlv(TAG_EUICC_CI_PKID, self.ci_pkid)

    def server_certificate_tlv(self) -> bytes:
        """The X.509 DER cert. Already a ``30 ..`` SEQUENCE TLV on the wire."""
        return self.server_certificate


def generate_keypair() -> ec.EllipticCurvePrivateKey:
    """A fresh ECDSA P-256 (secp256r1) private key — the SGP.22 RSP curve."""
    return ec.generate_private_key(ec.SECP256R1())


def _ski_from_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """The 20-byte SHA-1 SubjectKeyIdentifier the CI-PKId field carries."""
    return x509.SubjectKeyIdentifier.from_public_key(public_key).digest


def _build_cert(
    subject_key: ec.EllipticCurvePrivateKey,
    issuer_key: ec.EllipticCurvePrivateKey,
    subject_cn: str,
    issuer_cn: str,
) -> bytes:
    """Build a P-256 ECDSA X.509 cert signed by ``issuer_key``. Returns DER."""
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
            critical=False,
        )
    )
    cert = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())
    from cryptography.hazmat.primitives.serialization import Encoding

    return cert.public_bytes(Encoding.DER)


def build_self_signed_identity(label: str = "self_signed") -> AttackerIdentity:
    """An attacker cert signed by its own key — no CI in the chain at all."""
    key = generate_keypair()
    cert = _build_cert(key, key, "ROGUE SM-DS DSauth", "ROGUE SM-DS DSauth")
    return AttackerIdentity(
        private_key=key,
        server_certificate=cert,
        ci_pkid=_ski_from_public_key(key.public_key()),
        label=label,
    )


def build_untrusted_ci_identity(label: str = "untrusted_ci") -> AttackerIdentity:
    """An attacker cert signed by a SYNTHETIC untrusted CI key.

    The cert chains to a CI, but a CI the eUICC has never heard of. ``ci_pkid``
    advertises that synthetic CI's SKI. This is the primary CI-trust probe: a
    well-formed chain to the wrong root.
    """
    ci_key = generate_keypair()
    leaf_key = generate_keypair()
    cert = _build_cert(leaf_key, ci_key, "ROGUE SM-DS DSauth", "ROGUE UNTRUSTED CI")
    return AttackerIdentity(
        private_key=leaf_key,
        server_certificate=cert,
        ci_pkid=_ski_from_public_key(ci_key.public_key()),
        label=label,
    )


def build_forged_ci_pkid_identity(
    forged_pkid: bytes = PROD_GSMA_CI_PKID, label: str = "forged_ci_pkid"
) -> AttackerIdentity:
    """Attacker cert (untrusted key) but ``euiccCiPKIdToBeUsed`` FORGED.

    Advertises a real production CI PKId while the cert is not signed by it. Tests
    whether the eUICC trusts the advertised PKId over the actual signer.
    """
    ci_key = generate_keypair()
    leaf_key = generate_keypair()
    cert = _build_cert(leaf_key, ci_key, "ROGUE SM-DS DSauth", "ROGUE FORGED CI")
    return AttackerIdentity(
        private_key=leaf_key,
        server_certificate=cert,
        ci_pkid=forged_pkid,
        label=label,
    )


def build_server_signed1(
    transaction_id: bytes,
    euicc_challenge: bytes,
    server_address: str,
    server_challenge: bytes,
) -> bytes:
    """The ``serverSigned1`` SEQUENCE bound to the FRESH euiccChallenge.

    ``30 { 80 <txid>  81 <euiccChallenge>  83 <serverAddress>  84 <serverChallenge> }``
    matching the real capture. ``euicc_challenge`` MUST be the value the eUICC just
    issued, or the eUICC rejects at the binding check before reaching CI-trust.
    """
    body = (
        ber.tlv(TAG_TRANSACTION_ID, transaction_id)
        + ber.tlv(TAG_EUICC_CHALLENGE, euicc_challenge)
        + ber.tlv(TAG_SERVER_ADDRESS, server_address.encode("ascii"))
        + ber.tlv(TAG_SERVER_CHALLENGE, server_challenge)
    )
    return ber.tlv(TAG_SERVER_SIGNED1, body)


def _der_sig_to_raw(der_sig: bytes) -> bytes:
    """DER ECDSA signature -> raw 64-byte r||s (P1363), as SGP.22 carries it."""
    r, s = decode_dss_signature(der_sig)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _raw_sig_to_der(raw_sig: bytes) -> bytes:
    if len(raw_sig) != 64:
        raise CertCraftError(f"raw ECDSA signature must be 64 bytes, got {len(raw_sig)}")
    r = int.from_bytes(raw_sig[:32], "big")
    s = int.from_bytes(raw_sig[32:], "big")
    return encode_dss_signature(r, s)


def sign_server_signed1(
    private_key: ec.EllipticCurvePrivateKey, server_signed1: bytes
) -> bytes:
    """Sign ``serverSigned1`` with the attacker key; return the full 5F37 TLV.

    ECDSA-P256-SHA256 over the DER ``serverSigned1`` bytes, converted to the raw
    64-byte r||s SGP.22 expects, wrapped as ``5F 37 40 <sig>``. The signature
    verifies against ``private_key``'s public key (see :func:`verify_server_signature1`),
    so a device rejection is attributable to CI-trust, not signature failure.
    """
    der = private_key.sign(server_signed1, ec.ECDSA(hashes.SHA256()))
    raw = _der_sig_to_raw(der)
    return ber.tlv(TAG_SERVER_SIGNATURE1, raw)


def verify_server_signature1(
    public_key: ec.EllipticCurvePublicKey,
    server_signed1: bytes,
    server_signature1_tlv: bytes,
) -> bool:
    """True if the ``5F37`` signature verifies over ``server_signed1``.

    Used by unit tests and by the response builder's self-check. Raises nothing on
    a bad signature — returns False (the caller decides).
    """
    from cryptography.exceptions import InvalidSignature

    raw = ber.first(server_signature1_tlv, TAG_SERVER_SIGNATURE1).value
    try:
        der = _raw_sig_to_der(raw)
        public_key.verify(der, server_signed1, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, CertCraftError):
        return False
