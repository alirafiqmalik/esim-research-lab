"""Mutation generator for ES10b.AuthenticateServer (BF38) certificate/signature fuzzing.

Given one real, valid AuthenticateServer command (the seed), produce mutated BF38
commands that each SHOULD be rejected by the eUICC's in-SE verification. Every
mutation attacks the certificate/signature gate that SGP.22 §5.7.13 defines: the
server certificate must chain to a trusted CI and ServerSignature1 must verify.

Four attack classes:

- signature: ServerSignature1 bit-flipped, zeroed, truncated, wrong length, or a
  valid-looking-but-wrong random signature.
- certificate: the CI signature on serverCertificate corrupted; the cert swapped
  for an untrusted/self-signed one; the cert ASN.1 malformed (over/under-declared
  length, truncated, reordered).
- ci_id: euiccCiPKIdToBeUsed forged/unknown, or a different valid CI than the one
  that signed the cert.
- binding: stale/replayed euiccChallenge, or a mismatched transactionId inside
  serverSigned1.

Every mutation stays a BF38-tagged store-data command. The generator re-verifies
this through ``safety.classify`` before returning any mutation: a mutation that
did not classify ALLOWED as AuthenticateServer is dropped and reported, so the
campaign can never emit a non-BF38 or destructive APDU.

Nothing here sends anything. It builds candidate commands.
"""

from __future__ import annotations

from dataclasses import dataclass

import ber
from authsrv_seed import (
    TAG_EUICC_CHALLENGE,
    TAG_EUICC_CI_PKID,
    TAG_SERVER_SIGNATURE1,
    TAG_SERVER_SIGNED1,
    TAG_TRANSACTION_ID,
    AuthCommand,
)
from safety import Classification, classify

# A well-known GSMA TEST CI SubjectKeyIdentifier — a real CI SKI that is NOT the
# production CI this eUICC trusts. Used for the "different valid CI" attack.
GSMA_TEST_CI_PKID = bytes.fromhex("F54172BDF98A95D65CBEB88A38A1C11D800A85C3")

# Signature class attacks.
SIG_CATEGORY = "signature"
CERT_CATEGORY = "certificate"
CI_ID_CATEGORY = "ci_id"
BINDING_CATEGORY = "binding"


class MutationError(ValueError):
    """Raised when a generated mutation fails its own BF38/ALLOWED self-check."""


@dataclass(frozen=True)
class Mutation:
    """One mutated AuthenticateServer command.

    ``expected_reject`` is True for every mutation here: each is an invalid
    signature / untrusted CI / broken binding, so the safe eUICC outcome is a
    reject. An ACCEPT of any of these is a candidate bypass.
    """

    label: str
    category: str
    command: AuthCommand
    description: str
    expected_reject: bool = True

    @property
    def apdu_hex(self) -> str:
        return self.command.to_store_data_apdu()


# --------------------------------------------------------------------------- #
# Low-level component editors.
# --------------------------------------------------------------------------- #


def _replace_field(container_tlv: bytes, container_tag: int, inner_tag: int, new_value: bytes) -> bytes:
    """Re-encode ``container_tlv`` with the value of ``inner_tag`` replaced."""
    outer = ber.first(container_tlv, container_tag)
    inner_fields = ber.walk(outer.value)
    rebuilt = bytearray()
    replaced = False
    for field in inner_fields:
        if field.tag == inner_tag and not replaced:
            rebuilt += ber.tlv(inner_tag, new_value)
            replaced = True
        else:
            rebuilt += field.raw
    if not replaced:
        raise MutationError(f"inner tag 0x{inner_tag:X} not found for replacement")
    return ber.tlv(container_tag, bytes(rebuilt))


def _with_signature(seed: AuthCommand, new_sig_value: bytes) -> AuthCommand:
    return AuthCommand(
        server_signed1=seed.server_signed1,
        server_signature1=ber.tlv(TAG_SERVER_SIGNATURE1, new_sig_value),
        euicc_ci_pkid=seed.euicc_ci_pkid,
        server_certificate=seed.server_certificate,
        ctx_params1=seed.ctx_params1,
    )


def _with_certificate(seed: AuthCommand, new_cert_tlv: bytes) -> AuthCommand:
    return AuthCommand(
        server_signed1=seed.server_signed1,
        server_signature1=seed.server_signature1,
        euicc_ci_pkid=seed.euicc_ci_pkid,
        server_certificate=new_cert_tlv,
        ctx_params1=seed.ctx_params1,
    )


def _with_ci_pkid(seed: AuthCommand, new_pkid_value: bytes) -> AuthCommand:
    return AuthCommand(
        server_signed1=seed.server_signed1,
        server_signature1=seed.server_signature1,
        euicc_ci_pkid=ber.tlv(TAG_EUICC_CI_PKID, new_pkid_value),
        server_certificate=seed.server_certificate,
        ctx_params1=seed.ctx_params1,
    )


def _with_signed1(seed: AuthCommand, new_signed1_tlv: bytes) -> AuthCommand:
    return AuthCommand(
        server_signed1=new_signed1_tlv,
        server_signature1=seed.server_signature1,
        euicc_ci_pkid=seed.euicc_ci_pkid,
        server_certificate=seed.server_certificate,
        ctx_params1=seed.ctx_params1,
    )


# --------------------------------------------------------------------------- #
# Attack classes.
# --------------------------------------------------------------------------- #


def signature_attacks(seed: AuthCommand) -> list[Mutation]:
    sig = seed.server_signature1_value
    out: list[Mutation] = []

    flipped = bytearray(sig)
    flipped[0] ^= 0x01
    out.append(Mutation(
        "sig_bitflip", SIG_CATEGORY, _with_signature(seed, bytes(flipped)),
        "ServerSignature1 with one bit flipped; ECDSA verify must fail",
    ))
    out.append(Mutation(
        "sig_zeroed", SIG_CATEGORY, _with_signature(seed, bytes(len(sig))),
        "ServerSignature1 all-zero",
    ))
    out.append(Mutation(
        "sig_truncated", SIG_CATEGORY, _with_signature(seed, sig[:-8]),
        "ServerSignature1 truncated by 8 bytes (short length)",
    ))
    out.append(Mutation(
        "sig_wrong_length_short", SIG_CATEGORY, _with_signature(seed, sig[: len(sig) // 2]),
        "ServerSignature1 halved to a wrong length",
    ))
    out.append(Mutation(
        "sig_wrong_length_long", SIG_CATEGORY, _with_signature(seed, sig + bytes(16)),
        "ServerSignature1 padded to a wrong (over-long) length",
    ))
    out.append(Mutation(
        "sig_replaced_valid_looking", SIG_CATEGORY,
        _with_signature(seed, bytes((b ^ 0xA5) for b in sig)),
        "ServerSignature1 replaced with valid-looking-but-wrong 64-byte data",
    ))
    return out


def certificate_attacks(seed: AuthCommand) -> list[Mutation]:
    cert = seed.server_certificate
    out: list[Mutation] = []

    # Corrupt the CI signature on the cert: flip a bit in its LAST inner field
    # (the signatureValue BIT STRING), leaving the TLV framing intact.
    cert_fields = ber.walk(ber.first(cert, 0x30).value)
    if cert_fields:
        inner = list(cert_fields)
        last = inner[-1]
        corrupted_value = bytearray(last.value)
        corrupted_value[-1] ^= 0x01
        inner[-1] = ber.Field(last.tag, bytes(corrupted_value), b"")
        new_inner = b"".join(
            f.raw if f.raw else ber.tlv(f.tag, f.value) for f in inner
        )
        out.append(Mutation(
            "cert_ci_sig_corrupt", CERT_CATEGORY,
            _with_certificate(seed, ber.tlv(0x30, new_inner)),
            "serverCertificate CI signatureValue bit-flipped; CI-chain verify must fail",
        ))

    # Swap for an untrusted / self-signed certificate (synthetic, not CI-signed).
    untrusted = ber.tlv(
        0x30,
        ber.tlv(0x30, b"UNTRUSTED-SELF-SIGNED-TBS" + bytes(16))
        + ber.tlv(0x30, bytes.fromhex("06082A8648CE3D040302"))
        + ber.tlv(0x03, b"\x00" + bytes(64)),
    )
    out.append(Mutation(
        "cert_swapped_untrusted", CERT_CATEGORY, _with_certificate(seed, untrusted),
        "serverCertificate replaced with an untrusted self-signed cert",
    ))

    # Over-declared outer length: claim more bytes than present.
    cert_ba = bytearray(cert)
    over = _bump_first_length(cert_ba, +0x10)
    out.append(Mutation(
        "cert_asn1_overdeclared_len", CERT_CATEGORY, _with_certificate(seed, over),
        "serverCertificate outer length over-declared by 16 bytes",
    ))

    under = _bump_first_length(bytearray(cert), -0x08)
    out.append(Mutation(
        "cert_asn1_underdeclared_len", CERT_CATEGORY, _with_certificate(seed, under),
        "serverCertificate outer length under-declared by 8 bytes",
    ))

    out.append(Mutation(
        "cert_truncated", CERT_CATEGORY, _with_certificate(seed, cert[:-16]),
        "serverCertificate truncated by 16 bytes",
    ))

    # Reorder the cert's top-level components (tbs / sigAlg / sigValue).
    if len(cert_fields) >= 2:
        reordered_inner = cert_fields[1].raw + cert_fields[0].raw + b"".join(
            f.raw for f in cert_fields[2:]
        )
        out.append(Mutation(
            "cert_reordered", CERT_CATEGORY,
            _with_certificate(seed, ber.tlv(0x30, reordered_inner)),
            "serverCertificate first two components swapped",
        ))

    # A structurally valid prod cert reused for the wrong transaction: cert kept,
    # but the bound transactionId in serverSigned1 is changed, so the signed data
    # no longer matches this session's cert/challenge pairing.
    wrong_txn = _mutate_transaction_id(seed)
    out.append(Mutation(
        "cert_valid_wrong_transaction", CERT_CATEGORY, wrong_txn,
        "valid serverCertificate but transactionId changed (wrong-transaction reuse)",
    ))
    return out


def ci_id_attacks(seed: AuthCommand) -> list[Mutation]:
    out: list[Mutation] = []
    out.append(Mutation(
        "ci_pkid_forged_unknown", CI_ID_CATEGORY, _with_ci_pkid(seed, bytes.fromhex("00") * 20),
        "euiccCiPKIdToBeUsed set to an all-zero unknown/forged PKID",
    ))
    out.append(Mutation(
        "ci_pkid_random_unknown", CI_ID_CATEGORY,
        _with_ci_pkid(seed, bytes((b ^ 0xFF) for b in seed.euicc_ci_pkid_value)),
        "euiccCiPKIdToBeUsed set to an unknown (inverted) PKID",
    ))
    out.append(Mutation(
        "ci_pkid_different_valid_ci", CI_ID_CATEGORY, _with_ci_pkid(seed, GSMA_TEST_CI_PKID),
        "euiccCiPKIdToBeUsed points at a different valid CI than the one that signed the cert",
    ))
    return out


def binding_attacks(seed: AuthCommand) -> list[Mutation]:
    out: list[Mutation] = []
    stale = seed.euicc_challenge
    stale_flipped = bytearray(stale)
    stale_flipped[0] ^= 0xFF
    out.append(Mutation(
        "binding_stale_challenge", BINDING_CATEGORY,
        _with_signed1(seed, _replace_field(
            seed.server_signed1, TAG_SERVER_SIGNED1, TAG_EUICC_CHALLENGE, bytes(stale_flipped),
        )),
        "euiccChallenge in serverSigned1 no longer matches the fresh GetEUICCChallenge",
    ))
    out.append(Mutation(
        "binding_replayed_challenge", BINDING_CATEGORY,
        _with_signed1(seed, _replace_field(
            seed.server_signed1, TAG_SERVER_SIGNED1, TAG_EUICC_CHALLENGE, bytes(len(stale)),
        )),
        "euiccChallenge replaced with a fixed replayed all-zero nonce",
    ))
    out.append(Mutation(
        "binding_mismatched_txid", BINDING_CATEGORY, _mutate_transaction_id(seed),
        "transactionId in serverSigned1 mismatched against the session",
    ))
    return out


def _mutate_transaction_id(seed: AuthCommand) -> AuthCommand:
    txid = bytearray(seed.transaction_id)
    txid[0] ^= 0xFF
    return _with_signed1(seed, _replace_field(
        seed.server_signed1, TAG_SERVER_SIGNED1, TAG_TRANSACTION_ID, bytes(txid),
    ))


def _bump_first_length(data: bytearray, delta: int) -> bytes:
    """Adjust the first TLV's declared length by ``delta`` without changing bytes.

    Handles short-form and long-form (0x81/0x82) length encodings. The value bytes
    are left untouched, so the declared length no longer matches the content.
    """
    tag_end = 1
    if (data[0] & 0x1F) == 0x1F:
        tag_end = 2
        while data[tag_end - 1] & 0x80:
            tag_end += 1
    len_byte = data[tag_end]
    if len_byte & 0x80:
        n = len_byte & 0x7F
        current = int.from_bytes(data[tag_end + 1 : tag_end + 1 + n], "big")
        new = max(0, current + delta)
        data[tag_end + 1 : tag_end + 1 + n] = new.to_bytes(n, "big")
    else:
        data[tag_end] = max(0, min(0x7F, len_byte + delta))
    return bytes(data)


# --------------------------------------------------------------------------- #
# Top-level generator with self-check.
# --------------------------------------------------------------------------- #


def generate_mutations(seed: AuthCommand) -> list[Mutation]:
    """All mutations across the four classes, each verified BF38/ALLOWED.

    A mutation whose logical store-data APDU does not classify ALLOWED as
    AuthenticateServer is a generator bug; this raises rather than returning an
    unsendable or misclassified command.
    """
    mutations: list[Mutation] = []
    mutations += signature_attacks(seed)
    mutations += certificate_attacks(seed)
    mutations += ci_id_attacks(seed)
    mutations += binding_attacks(seed)

    for mutation in mutations:
        verdict = classify(mutation.apdu_hex)
        if verdict.classification is not Classification.ALLOWED or verdict.tag != 0xBF38:
            raise MutationError(
                f"mutation {mutation.label!r} did not classify as allowlisted BF38: "
                f"{verdict.classification.value} tag={verdict.tag}"
            )
    return mutations


CATEGORIES = (SIG_CATEGORY, CERT_CATEGORY, CI_ID_CATEGORY, BINDING_CATEGORY)
