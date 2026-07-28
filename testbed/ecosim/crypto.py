"""Signing, verification, and ES8+/SCP03t session-key derivation.

Kept deliberately thin: raw ECDSA over the signed byte blobs and an ECDH-derived
AES-GCM key for the profile package. The point is not spec-perfect SCP03t framing
but that these bytes are genuinely integrity/confidentiality protected, so the
fuzzer can prove which fields it *cannot* usefully mutate.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def sign(key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    return key.sign(data, ec.ECDSA(hashes.SHA256()))


def verify(pub: ec.EllipticCurvePublicKey, signature: bytes, data: bytes) -> bool:
    try:
        pub.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def ephemeral_keypair() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def derive_session_key(
    private_key: ec.EllipticCurvePrivateKey,
    peer_public: ec.EllipticCurvePublicKey,
    info: bytes,
) -> bytes:
    shared = private_key.exchange(ec.ECDH(), peer_public)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)


def aead_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aead_open(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """Decrypt; raises cryptography.exceptions.InvalidTag on tamper."""
    return AESGCM(key).decrypt(nonce, ciphertext, aad)
