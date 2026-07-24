"""Unit tests for the AuthenticateServer (BF38) verification fuzzer.

Mock-only. No device is touched. Covers the seed parser, the four mutation
classes, the BF38/BF41 safety change, and the bypass detector.
"""

from __future__ import annotations

import pytest

import ber
from authsrv_fuzz import (
    CATEGORIES,
    binding_attacks,
    certificate_attacks,
    ci_id_attacks,
    generate_mutations,
    signature_attacks,
)
from authsrv_seed import (
    TAG_BF38,
    AuthCommand,
    build_synthetic_command,
    parse_bf38_tlv,
    reassemble_blocks,
)
from run_authsrv import Severity, classify_outcome
from safety import Classification, classify


# --------------------------------------------------------------------------- #
# Seed parser.
# --------------------------------------------------------------------------- #


def test_seed_parser_splits_four_constructs() -> None:
    seed = build_synthetic_command()
    tlv = seed.to_command_tlv()
    parsed = parse_bf38_tlv(tlv)

    # serverSigned1 (SEQUENCE), serverSignature1 (5F37), euiccCiPKIdToBeUsed (04),
    # serverCertificate (30) all recovered, byte-identical.
    assert ber.walk(parsed.server_signed1)[0].tag == 0x30
    assert ber.walk(parsed.server_signature1)[0].tag == 0x5F37
    assert ber.walk(parsed.euicc_ci_pkid)[0].tag == 0x04
    assert ber.walk(parsed.server_certificate)[0].tag == 0x30
    assert parsed == seed


def test_seed_parser_exposes_inner_values() -> None:
    seed = build_synthetic_command()
    assert len(seed.server_signature1_value) == 64
    assert len(seed.euicc_ci_pkid_value) == 20
    assert len(seed.euicc_challenge) == 16
    assert len(seed.transaction_id) == 16


def test_seed_parser_rejects_non_bf38() -> None:
    # A GetEID TLV, not a BF38 command.
    with pytest.raises(ValueError):
        parse_bf38_tlv(bytes.fromhex("BF3E035C015A"))


def test_reassemble_block_chain() -> None:
    seed = build_synthetic_command()
    tlv = seed.to_command_tlv()
    # Split the TLV into two 255-ish blocks with STORE DATA headers: first block
    # P1=0x11 (more), last P1=0x91.
    half = len(tlv) // 2
    block0 = bytes([0x81, 0xE2, 0x11, 0x00, min(half, 0xFF)]) + tlv[:half]
    block1 = bytes([0x81, 0xE2, 0x91, 0x01, min(len(tlv) - half, 0xFF)]) + tlv[half:]
    assert reassemble_blocks([block0, block1]) == tlv
    assert parse_bf38_tlv(reassemble_blocks([block0, block1])) == seed


# --------------------------------------------------------------------------- #
# Mutation classes: each stays a BF38-tagged, ALLOWED command.
# --------------------------------------------------------------------------- #

_SEED = build_synthetic_command()
_ALL = generate_mutations(_SEED)


def test_every_category_present() -> None:
    seen = {m.category for m in _ALL}
    assert seen == set(CATEGORIES)


@pytest.mark.parametrize("mutation", _ALL, ids=[m.label for m in _ALL])
def test_mutation_is_allowed_bf38(mutation) -> None:
    verdict = classify(mutation.apdu_hex)
    assert verdict.classification is Classification.ALLOWED, mutation.label
    assert verdict.tag == 0xBF38, mutation.label
    assert mutation.expected_reject is True


@pytest.mark.parametrize(
    "builder", [signature_attacks, certificate_attacks, ci_id_attacks, binding_attacks]
)
def test_each_class_nonempty_and_bf38(builder) -> None:
    mutations = builder(_SEED)
    assert mutations
    for mutation in mutations:
        # Never a non-BF38 or destructive APDU.
        assert ber.walk(mutation.command.to_command_tlv())[0].tag == TAG_BF38
        assert classify(mutation.apdu_hex).classification is Classification.ALLOWED


def test_mutations_actually_change_the_seed() -> None:
    for mutation in _ALL:
        assert mutation.command != _SEED, mutation.label


# --------------------------------------------------------------------------- #
# Safety change: BF38 and BF41 ALLOWED; writes / destructive still not sendable.
# --------------------------------------------------------------------------- #


def test_bf38_authenticate_server_allowed() -> None:
    verdict = classify("81E2910003BF3800")
    assert verdict.classification is Classification.ALLOWED
    assert verdict.tag == 0xBF38


def test_bf41_cancel_session_allowed() -> None:
    verdict = classify("81E2910003BF4100")
    assert verdict.classification is Classification.ALLOWED
    assert verdict.tag == 0xBF41


@pytest.mark.parametrize("apdu,name", [
    ("81E2910003BF3700", "LoadBoundProfilePackage BF37"),
    ("81E2910003BF2100", "PrepareDownload BF21"),
    ("81E2910003BF3400", "eUICCMemoryReset BF34"),
    ("81E2910003BF3300", "DeleteProfile BF33"),
    ("80E4000002AABB", "GP DELETE 80E4"),
    ("00D6000001FF", "UPDATE BINARY write"),
    ("80DA00A002AABB", "PUT DATA write"),
])
def test_dangerous_ops_never_allowed(apdu: str, name: str) -> None:
    assert classify(apdu).classification is not Classification.ALLOWED, name


def test_bf37_and_bf21_not_sendable_so_no_install_after_accept() -> None:
    # Even if AuthenticateServer were accepted, the next RSP steps stay blocked,
    # so nothing can be installed.
    assert classify("81E2910003BF3700").classification is Classification.BLOCKED  # BF37
    assert classify("81E2910003BF2100").classification is Classification.UNKNOWN  # BF21


# --------------------------------------------------------------------------- #
# Bypass detector.
# --------------------------------------------------------------------------- #


def _ok_response() -> str:
    # BF38 { A0 authenticateResponseOk { ...euicc-signed... } } 9000
    inner = ber.tlv(0xA0, bytes(8))
    return (ber.tlv(TAG_BF38, inner) + b"\x90\x00").hex().upper()


def _error_response(code: int) -> str:
    # BF38 { A1 authenticateResponseError { transactionId, errorCode } } 9000
    err = ber.tlv(0x80, bytes(16)) + ber.tlv(0x02, bytes([code]))
    inner = ber.tlv(0xA1, err)
    return (ber.tlv(TAG_BF38, inner) + b"\x90\x00").hex().upper()


def test_accept_of_invalid_is_critical() -> None:
    mutation = signature_attacks(_SEED)[0]  # sig_bitflip, expected_reject=True
    outcome = classify_outcome(mutation, _ok_response(), "9000")
    assert outcome.accepted is True
    assert outcome.severity == Severity.CRITICAL.value
    assert "BYPASS" in outcome.detail


def test_error_response_is_expected_safe() -> None:
    mutation = signature_attacks(_SEED)[0]
    # code 7 = ciPKUnknown, an 8.8.x-mapped reject.
    outcome = classify_outcome(mutation, _error_response(7), "9000")
    assert outcome.accepted is False
    assert outcome.severity == Severity.INFO.value
    assert outcome.error_code == "ciPKUnknown"
    assert "safe" in outcome.detail


@pytest.mark.parametrize("sw", ["6A80", "6985", "6988"])
def test_sw_error_is_expected_safe(sw: str) -> None:
    mutation = certificate_attacks(_SEED)[0]
    outcome = classify_outcome(mutation, sw, sw)
    assert outcome.accepted is False
    assert outcome.severity == Severity.INFO.value


def test_every_mutation_accepted_would_be_critical() -> None:
    ok = _ok_response()
    for mutation in _ALL:
        outcome = classify_outcome(mutation, ok, "9000")
        assert outcome.severity == Severity.CRITICAL.value, mutation.label
