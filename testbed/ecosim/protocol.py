"""Shared crypto/byte-layout linchpin for the ES8+/ES9+ handshake.

Both the eUICC and the SM-DP+ import these functions so the signed blobs and the
session-key derivation are byte-identical on each side. Keeping the layouts here
(not duplicated in each component) removes the only real integration risk.

Signed blobs use length-prefixed concatenation (2-byte big-endian length + body)
so the ordering/framing is deterministic and stable across runs.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import crypto

SESSION_INFO = b"ecosim/es8+/scp03t/v1"


def concat_len(*parts: bytes) -> bytes:
    out = b""
    for p in parts:
        out += len(p).to_bytes(2, "big") + p
    return out


def read_len_fields(data: bytes) -> list[bytes]:
    """Inverse of concat_len: split a 2-byte-length-prefixed blob into its fields."""
    fields: list[bytes] = []
    i = 0
    n = len(data)
    while i < n:
        if i + 2 > n:
            raise ValueError("truncated length prefix")
        length = int.from_bytes(data[i:i + 2], "big")
        i += 2
        if i + length > n:
            raise ValueError("field overruns buffer")
        fields.append(data[i:i + length])
        i += length
    return fields


def point_bytes(key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey) -> bytes:
    pub = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    return pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def load_point(data: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)


# --- Signed structures ------------------------------------------------------
def server_signed1(transaction_id: bytes, euicc_challenge: bytes,
                   smdp_address: bytes, server_otpk: bytes) -> bytes:
    """ServerSigned1: what the SM-DP+ signs with its DPauth key (ES9+ step 1)."""
    return concat_len(transaction_id, euicc_challenge, smdp_address, server_otpk)


def euicc_signed1(transaction_id: bytes, euicc_challenge: bytes,
                  euicc_otpk: bytes, euicc_info1: bytes, ctx_params1: bytes = b"") -> bytes:
    """EuiccSigned1: what the eUICC signs with its per-card key (ES10 AuthServer).

    ctx_params1 (matchingId/deviceInfo, built by the LPA) is included here because
    SGP.22 v3.1 SS5.7.13 has the eUICC sign it verbatim WITHOUT validating its
    contents -- the SM-DP+ is the sole backstop. Carrying it as the 5th field lets
    the SM-DP+ recover the eUICC-attested matchingId the way the real ES9+ flow does."""
    return concat_len(transaction_id, euicc_challenge, euicc_otpk, euicc_info1, ctx_params1)


# --- ES8+ session key + profile sealing ------------------------------------
def session_key(local_ephemeral: ec.EllipticCurvePrivateKey,
                peer_otpk: ec.EllipticCurvePublicKey,
                transaction_id: bytes) -> bytes:
    return crypto.derive_session_key(local_ephemeral, peer_otpk, SESSION_INFO + transaction_id)


# 12-byte fixed nonce: this is a simulation, not production SCP03t counter logic.
BPP_NONCE = bytes(range(12))


def seal_profile(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return crypto.aead_seal(key, BPP_NONCE, plaintext, aad)


def open_profile(key: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return crypto.aead_open(key, BPP_NONCE, ciphertext, aad)
