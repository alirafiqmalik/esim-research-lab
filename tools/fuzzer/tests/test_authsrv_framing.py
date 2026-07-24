"""Unit tests for the AuthenticateServer (BF38) malleable-framing fuzzer.

Mock-only. No device is touched. Covers the framing mutation generator (every
mutation stays a guarded BF38), the block-chaining re-split invariant, the
anomaly detector, and the CI-PKID-value-intact guarantee.
"""

from __future__ import annotations

import pytest

import ber
from authsrv_framing_fuzz import (
    BF38_TAG_BYTES,
    CLASS_BLOCKS,
    CLASS_CTX,
    CLASSES,
    FramingMutation,
    block_chaining_mutations,
    cert_wrapper_mutations,
    ci_pkid_framing_mutations,
    combinatorial_mutations,
    counts_by_class,
    ctx_params_mutations,
    generate_mutations,
    outer_framing_mutations,
    replay_mutations,
)
from authsrv_seed import TAG_BF38, build_synthetic_command, reassemble_blocks
from run_authsrv import chunk_store_data
from run_authsrv_framing import (
    Verdict,
    _guard_and_build,
    classify_framing_outcome,
)
from safety import Classification, classify

_SEED = build_synthetic_command()
_ALL = generate_mutations(_SEED)


# --------------------------------------------------------------------------- #
# Generator: volume, classes, and the guarded-BF38 invariant.
# --------------------------------------------------------------------------- #


def test_generator_hits_target_volume() -> None:
    # The campaign aims for a large mutation set (~500-2000).
    assert 500 <= len(_ALL) <= 2000


def test_every_class_present() -> None:
    seen = {m.mutation_class for m in _ALL}
    assert seen == set(CLASSES)


def test_counts_by_class_sums_to_total() -> None:
    counts = counts_by_class(_ALL)
    assert sum(counts.values()) == len(_ALL)


def test_no_duplicate_wire_inputs() -> None:
    keys = {(m.command_tlv, m.blocks) for m in _ALL}
    assert len(keys) == len(_ALL)


@pytest.mark.parametrize(
    "builder",
    [ctx_params_mutations, outer_framing_mutations, ci_pkid_framing_mutations,
     cert_wrapper_mutations, block_chaining_mutations, replay_mutations,
     combinatorial_mutations],
)
def test_each_builder_nonempty(builder) -> None:
    assert builder(_SEED)


def test_every_mutation_is_allowed_bf38() -> None:
    # The core safety invariant: no mutation ever becomes a non-BF38 INS/tag or a
    # destructive APDU. The outer tag is always BF38, so the guard says ALLOWED.
    for mutation in _ALL:
        assert mutation.command_tlv[:2] == BF38_TAG_BYTES, mutation.label
        verdict = classify(mutation.apdu_hex)
        assert verdict.classification is Classification.ALLOWED, mutation.label
        assert verdict.tag == 0xBF38, mutation.label


def test_no_wire_block_is_blocked() -> None:
    # Every individual block-chaining wire block classifies not-BLOCKED (ALLOWED or
    # UNKNOWN for a mid-tag split), never a destructive command.
    for mutation in _ALL:
        if mutation.blocks is None:
            continue
        for block in mutation.blocks:
            assert classify(block).classification is not Classification.BLOCKED, mutation.label


@pytest.mark.parametrize("apdu,name", [
    ("81E2910003BF3700", "LoadBoundProfilePackage BF37"),
    ("81E2910003BF2100", "PrepareDownload BF21"),
    ("81E2910003BF3400", "eUICCMemoryReset BF34"),
    ("81E2910003BF3300", "DeleteProfile BF33"),
    ("80E4000002AABB", "GP DELETE 80E4"),
])
def test_destructive_ops_stay_blocked(apdu: str, name: str) -> None:
    # The framing campaign does not weaken the blocklist; BF37/BF21/destructive
    # remain non-ALLOWED so no accepted AuthenticateServer can install/modify.
    assert classify(apdu).classification is not Classification.ALLOWED, name


# --------------------------------------------------------------------------- #
# Block-chaining re-split invariant.
# --------------------------------------------------------------------------- #


def test_standard_chunk_reassembles_exactly() -> None:
    # For non-block-chaining mutations the runner uses standard chunking, which
    # must reassemble byte-for-byte to the guarded BF38 TLV.
    for mutation in _ALL:
        if mutation.blocks is not None:
            continue
        blocks = chunk_store_data(mutation.command_tlv)
        reassembled = reassemble_blocks([bytes.fromhex(b) for b in blocks])
        assert reassembled == mutation.command_tlv, mutation.label


def test_guard_and_build_accepts_every_mutation() -> None:
    from run_authsrv import _cancel_session_apdu
    cancel = _cancel_session_apdu(b"\x00" * 16)
    for mutation in _ALL:
        seq = _guard_and_build(mutation, cancel)
        # challenge + at least one block + cancel
        assert seq[0] == "81E2910003BF2E00"
        assert len(seq) >= 3


# --------------------------------------------------------------------------- #
# CI-PKID value intact where the class promises it.
# --------------------------------------------------------------------------- #


def test_ctx_mutations_keep_ci_pkid_value_intact() -> None:
    # ctxParams1 mutations never touch euiccCiPKIdToBeUsed: the seed's exact
    # CI-PKID TLV bytes remain present in the mutated command.
    ci_pkid_tlv = _SEED.euicc_ci_pkid
    for mutation in ctx_params_mutations(_SEED):
        assert mutation.keeps_ci_pkid_valid is True, mutation.label
        assert ci_pkid_tlv in mutation.command_tlv, mutation.label


def test_ci_pkid_framing_keeps_value_but_fuzzes_wrapper() -> None:
    # Class 3 fuzzes the 04 14 wrapper but keeps the 20-byte VALUE valid.
    value = _SEED.euicc_ci_pkid_value
    for mutation in ci_pkid_framing_mutations(_SEED):
        assert mutation.keeps_ci_pkid_valid is True, mutation.label
        assert value in mutation.command_tlv, mutation.label


def test_all_generated_keep_ci_pkid_valid_flag() -> None:
    assert all(m.keeps_ci_pkid_valid for m in _ALL)


# --------------------------------------------------------------------------- #
# Anomaly detector.
# --------------------------------------------------------------------------- #


def _ok_response() -> str:
    inner = ber.tlv(0xA0, bytes(8))
    return (ber.tlv(TAG_BF38, inner) + b"\x90\x00").hex().upper()


def _error_response(code: int, pad: int = 0) -> str:
    err = ber.tlv(0x80, bytes(16)) + ber.tlv(0x02, bytes([code])) + bytes(pad)
    inner = ber.tlv(0xA1, err)
    return (ber.tlv(TAG_BF38, inner) + b"\x90\x00").hex().upper()


def _mut(mutation_class: str = CLASS_CTX) -> FramingMutation:
    return FramingMutation(
        label="synthetic", mutation_class=mutation_class, perturbs="test",
        command_tlv=BF38_TAG_BYTES + b"\x00",
    )


def test_accept_is_critical_bypass() -> None:
    outcome = classify_framing_outcome(_mut(), _ok_response(), "9000")
    assert outcome.verdict == Verdict.CRITICAL_BYPASS.value
    assert outcome.is_critical


def test_timeout_is_parser_anomaly() -> None:
    outcome = classify_framing_outcome(_mut(), "", "", responsive=False)
    assert outcome.verdict == Verdict.PARSER_ANOMALY.value


def test_6f00_is_parser_anomaly() -> None:
    outcome = classify_framing_outcome(_mut(), "6F00", "6F00")
    assert outcome.verdict == Verdict.PARSER_ANOMALY.value


def test_oversized_error_is_info_leak() -> None:
    canonical = _error_response(2)  # invalidSignature, small
    canonical_len = len(bytes.fromhex(canonical))
    oversized = _error_response(2, pad=128)
    outcome = classify_framing_outcome(
        _mut(), oversized, "9000", canonical_reject_len=canonical_len
    )
    assert outcome.verdict == Verdict.INFO_LEAK.value


def test_normal_error_is_expected_reject() -> None:
    canonical = _error_response(2)
    canonical_len = len(bytes.fromhex(canonical))
    outcome = classify_framing_outcome(
        _mut(), canonical, "9000", canonical_reject_len=canonical_len
    )
    assert outcome.verdict == Verdict.EXPECTED_REJECT.value


def test_sw_reject_is_expected_reject() -> None:
    outcome = classify_framing_outcome(_mut(), "6A80", "6A80")
    assert outcome.verdict == Verdict.EXPECTED_REJECT.value


def test_state_change_is_critical_and_takes_precedence() -> None:
    # Even an otherwise-clean reject is CRITICAL if card state changed.
    outcome = classify_framing_outcome(
        _mut(), "6A80", "6A80", state_changed=True
    )
    assert outcome.verdict == Verdict.STATE_CHANGE.value
    assert outcome.is_critical


def test_accept_precedes_leak_but_state_precedes_accept() -> None:
    # state_changed wins over an accept.
    outcome = classify_framing_outcome(
        _mut(), _ok_response(), "9000", state_changed=True
    )
    assert outcome.verdict == Verdict.STATE_CHANGE.value
