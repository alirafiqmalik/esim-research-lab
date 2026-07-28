"""Custom GSMA-style PKI for the simulated ecosystem.

Builds the certificate hierarchy SGP.22 relies on, using real NIST P-256 keys:

    CI (root, self-signed)
      |-- EUM cert         -> signs each eUICC cert
      |     `-- eUICC cert (ECDSA auth key, per-eUICC)
      |-- SM-DP+ DPauth cert  (server authentication)
      `-- SM-DP+ DPpb cert    (profile-binding / ES8+)

Everything is generated locally and written under pki/, so the testbed owns all
private keys and can decrypt or forge any channel. This is what makes plaintext
inspection of the protected parts possible.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_CURVE = ec.SECP256R1()
# Deterministic validity window so cross-run log diffs stay stable (no wall clock).
_NOT_BEFORE = _dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc)
_NOT_AFTER = _dt.datetime(2036, 1, 1, tzinfo=_dt.timezone.utc)

# SGP.22 SS2.4a.1.0 carries certificate role in `certificatePolicies` (the
# id-rspRole OID arc), NOT keyUsage alone -- CERT.DPauth.SIG and CERT.DPpb.SIG
# are distinct, non-interchangeable keypairs even for the same SM-DP+. We mirror
# that with our own private OID arc (not the real GSMA arc) so a verifier can
# reject a validly-CI-signed-but-wrong-role certificate with the same "invalidOid"
# semantics §5.7.13 mandates, rather than accepting anything that merely chains.
_ROLE_OIDS: dict[str, x509.ObjectIdentifier] = {
    "ci": x509.ObjectIdentifier("2.25.1"),
    "eum": x509.ObjectIdentifier("2.25.2"),
    "euicc": x509.ObjectIdentifier("2.25.3"),
    "dp_auth": x509.ObjectIdentifier("2.25.4"),
    "dp_pb": x509.ObjectIdentifier("2.25.5"),
}
_OID_TO_ROLE = {oid.dotted_string: role for role, oid in _ROLE_OIDS.items()}


def certificate_role(cert: x509.Certificate) -> str:
    """Read back the role this certificate was issued for. Raises ValueError if
    the certificatePolicies extension is missing or names an unknown role."""
    try:
        ext = cert.extensions.get_extension_for_class(x509.CertificatePolicies)
    except x509.ExtensionNotFound as exc:
        raise ValueError("certificate has no certificatePolicies (role) extension") from exc
    if not ext.value:
        raise ValueError("certificate's certificatePolicies extension is empty")
    oid = ext.value[0].policy_identifier.dotted_string
    role = _OID_TO_ROLE.get(oid)
    if role is None:
        raise ValueError(f"certificate names an unrecognized role OID {oid}")
    return role


def require_role(cert: x509.Certificate, *expected: str) -> None:
    """Raise ValueError (the invalidOid case, SGP.22 SS5.7.13) unless cert's role is one of expected."""
    role = certificate_role(cert)
    if role not in expected:
        raise ValueError(f"invalidOid: certificate role {role!r} not in expected {expected}")


def certificate_registered_oid(cert: x509.Certificate) -> str | None:
    """Read the SM-DP+/SM-DS OID from subjectAltName.registeredID (SGP.22
    SS4.5.2.1.0.4), the value SS3.0.1 step 10's conditional OID-pin check
    compares an activation code's OID field against. None if absent."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return None
    for name in san.value:
        if isinstance(name, x509.RegisteredID):
            return name.value.dotted_string
    return None


@dataclass
class KeyPair:
    name: str
    private_key: ec.EllipticCurvePrivateKey
    certificate: x509.Certificate

    def cert_der(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.DER)

    def public_point(self) -> bytes:
        return self.certificate.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )


def _name(cn: str, serial_number: str | None = None) -> x509.Name:
    attrs = [
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ecosim"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ]
    if serial_number is not None:
        # SGP.22 SS4.3.1: the EID lives in CERT.EUICC.SIG.subject.serialNumber.
        # This is exactly why the EID leaks over C1: the eUICC certificate is
        # sent in AuthenticateClient.req, so anyone observing that message
        # recovers the EID without any GetEID/local-bus access.
        attrs.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, serial_number))
    return x509.Name(attrs)


def _issue(
    subject_cn: str,
    subject_key: ec.EllipticCurvePrivateKey,
    issuer_cn: str,
    issuer_key: ec.EllipticCurvePrivateKey,
    *,
    ca: bool,
    serial: int,
    role: str,
    registered_oid: str | None = None,
    eid: str | None = None,
) -> x509.Certificate:
    policy = x509.CertificatePolicies([x509.PolicyInformation(_ROLE_OIDS[role], policy_qualifiers=None)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject_cn, serial_number=eid))
        .issuer_name(_name(issuer_cn))
        .public_key(subject_key.public_key())
        .serial_number(serial)
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(policy, critical=False)
    )
    if registered_oid is not None:
        # SGP.22 SS4.5.2.1.0.4: CERT.DPauth.SIG/CERT.DPpb.SIG carry the SM-DP+ OID
        # in subjectAltName.registeredID -- what an activation code's optional OID
        # field is pinned against (SS3.0.1 step 10, conditional on it being present).
        san = x509.SubjectAlternativeName([x509.RegisteredID(x509.ObjectIdentifier(registered_oid))])
        builder = builder.add_extension(san, critical=False)
    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())


@dataclass
class PKI:
    ci: KeyPair
    eum: KeyPair
    euicc: KeyPair
    dp_auth: KeyPair
    dp_pb: KeyPair

    def ci_public_key_id(self) -> bytes:
        """The GSMA "CI Public Key Identifier" the eUICC advertises in EUICCInfo1."""
        spki = self.ci.certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest = hashes.Hash(hashes.SHA1())
        digest.update(spki)
        return digest.finalize()


def _selfsigned(cn: str, key: ec.EllipticCurvePrivateKey, serial: int, role: str) -> x509.Certificate:
    return _issue(cn, key, cn, key, ca=True, serial=serial, role=role)


def eid_from_certificate(cert: x509.Certificate) -> str:
    """Recover the EID from an eUICC certificate's subject.serialNumber
    (SGP.22 SS4.3.1). Raises ValueError if absent."""
    attrs = cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
    if not attrs:
        raise ValueError("certificate carries no serialNumber/EID")
    return attrs[0].value


def _generate_eid() -> str:
    # 32 decimal digits (SGP.22 SS4.3.1). Unseeded on purpose: the EID is a fixed
    # device identity, one per build_pki, not a per-run-varying value.
    import random as _random
    return "".join(str(_random.randrange(10)) for _ in range(32))


def build_pki(smdp_oid: str = "2.999.100.1", eid: str | None = None) -> PKI:
    """Generate the full hierarchy in memory. `smdp_oid` is baked into the
    DPauth/DPpb certs' subjectAltName so the AC's optional OID-pin field
    (SS3.0.1 step 10) has something real to check against; pass a different
    value to model a distinguishably-different SM-DP+ operator. `eid` is baked
    into the eUICC cert's serialNumber (SS4.3.1); a fixed one lets a test pin a
    specific device identity."""
    device_eid = eid if eid is not None else _generate_eid()
    ci_key = ec.generate_private_key(_CURVE)
    ci_cert = _selfsigned("ecosim-CI-root", ci_key, serial=1, role="ci")
    ci = KeyPair("ci", ci_key, ci_cert)

    eum_key = ec.generate_private_key(_CURVE)
    eum_cert = _issue("ecosim-EUM", eum_key, "ecosim-CI-root", ci_key, ca=True, serial=2, role="eum")
    eum = KeyPair("eum", eum_key, eum_cert)

    euicc_key = ec.generate_private_key(_CURVE)
    euicc_cert = _issue("ecosim-eUICC", euicc_key, "ecosim-EUM", eum_key, ca=False, serial=3,
                         role="euicc", eid=device_eid)
    euicc = KeyPair("euicc", euicc_key, euicc_cert)

    dp_auth_key = ec.generate_private_key(_CURVE)
    dp_auth_cert = _issue("ecosim-SMDP-auth", dp_auth_key, "ecosim-CI-root", ci_key, ca=False, serial=4,
                           role="dp_auth", registered_oid=smdp_oid)
    dp_auth = KeyPair("dp_auth", dp_auth_key, dp_auth_cert)

    dp_pb_key = ec.generate_private_key(_CURVE)
    dp_pb_cert = _issue("ecosim-SMDP-pb", dp_pb_key, "ecosim-CI-root", ci_key, ca=False, serial=5,
                         role="dp_pb", registered_oid=smdp_oid)
    dp_pb = KeyPair("dp_pb", dp_pb_key, dp_pb_cert)

    return PKI(ci=ci, eum=eum, euicc=euicc, dp_auth=dp_auth, dp_pb=dp_pb)


def write_pki(pki: PKI, out_dir: Path) -> None:
    """Persist every key + cert as PEM under out_dir."""
    out_dir.mkdir(parents=True, exist_ok=True)
    for kp in (pki.ci, pki.eum, pki.euicc, pki.dp_auth, pki.dp_pb):
        (out_dir / f"{kp.name}.key.pem").write_bytes(
            kp.private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        (out_dir / f"{kp.name}.cert.pem").write_bytes(
            kp.certificate.public_bytes(serialization.Encoding.PEM)
        )


def verify_chain(leaf: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Verify ``leaf`` was signed by ``issuer`` (single hop, ECDSA/SHA-256)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed  # noqa: F401

    try:
        issuer.public_key().verify(
            leaf.signature,
            leaf.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except InvalidSignature:
        return False
