"""rsp_certs: parseable ECDSA cert + a signature that verifies with its pubkey."""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

import ber
import rsp_certs


def test_untrusted_ci_cert_is_parseable_ecdsa_p256():
    identity = rsp_certs.build_untrusted_ci_identity()
    cert = x509.load_der_x509_certificate(identity.server_certificate)
    assert isinstance(cert.public_key(), ec.EllipticCurvePublicKey)
    assert cert.public_key().curve.name == "secp256r1"
    assert identity.trusted is False


def test_self_signed_and_forged_identities_build():
    self_signed = rsp_certs.build_self_signed_identity()
    forged = rsp_certs.build_forged_ci_pkid_identity()
    x509.load_der_x509_certificate(self_signed.server_certificate)
    x509.load_der_x509_certificate(forged.server_certificate)
    # Forged mutation advertises the real production CI PKId it is NOT signed by.
    assert forged.ci_pkid == rsp_certs.PROD_GSMA_CI_PKID


def test_ci_pkid_tlv_is_octet_string_20_bytes():
    identity = rsp_certs.build_untrusted_ci_identity()
    field = ber.first(identity.ci_pkid_tlv(), rsp_certs.TAG_EUICC_CI_PKID)
    assert field.tag == 0x04
    assert len(field.value) == 20


def test_server_signed1_binds_challenge_and_txid():
    challenge = bytes.fromhex("0AE5502D276DA170928AB33246923A35")
    signed1 = rsp_certs.build_server_signed1(
        transaction_id=bytes.fromhex("A1B2C3D4"),
        euicc_challenge=challenge,
        server_address="rogue.local",
        server_challenge=bytes(16),
    )
    inner = ber.first(signed1, rsp_certs.TAG_SERVER_SIGNED1).value
    assert ber.first(inner, rsp_certs.TAG_EUICC_CHALLENGE).value == challenge
    assert ber.first(inner, rsp_certs.TAG_TRANSACTION_ID).value == bytes.fromhex("A1B2C3D4")


def test_signature_verifies_with_generated_public_key():
    identity = rsp_certs.build_untrusted_ci_identity()
    signed1 = rsp_certs.build_server_signed1(
        transaction_id=bytes.fromhex("A1B2C3D4"),
        euicc_challenge=bytes(16),
        server_address="rogue.local",
        server_challenge=bytes(16),
    )
    sig_tlv = rsp_certs.sign_server_signed1(identity.private_key, signed1)
    assert rsp_certs.verify_server_signature1(identity.public_key, signed1, sig_tlv)


def test_signature_is_full_5f37_tlv_with_64_byte_body():
    identity = rsp_certs.build_untrusted_ci_identity()
    signed1 = rsp_certs.build_server_signed1(
        transaction_id=bytes(4), euicc_challenge=bytes(16),
        server_address="x", server_challenge=bytes(16),
    )
    sig_tlv = rsp_certs.sign_server_signed1(identity.private_key, signed1)
    field = ber.first(sig_tlv, rsp_certs.TAG_SERVER_SIGNATURE1)
    assert field.tag == 0x5F37
    assert len(field.value) == 64  # raw r||s, P1363


def test_tampered_signed1_fails_verification():
    identity = rsp_certs.build_untrusted_ci_identity()
    signed1 = rsp_certs.build_server_signed1(
        transaction_id=bytes(4), euicc_challenge=bytes(16),
        server_address="x", server_challenge=bytes(16),
    )
    sig_tlv = rsp_certs.sign_server_signed1(identity.private_key, signed1)
    tampered = bytearray(signed1)
    tampered[-1] ^= 0x01
    assert not rsp_certs.verify_server_signature1(identity.public_key, bytes(tampered), sig_tlv)
