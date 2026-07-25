"""Safety + generation tests for the deep/oversized eUICC-parser fuzzer.

No device. The safety-critical invariants (verified manually in review) are
encoded here: every generated command is a guarded ALLOWED store-data command,
no wire block classifies BLOCKED, standard-chunk chains reassemble to the guarded
command, and the massive-chain class faithfully reassembles to the guarded ALLOWED
command with no early-final chaining trick.
"""
from __future__ import annotations

import pytest

import safety
from authsrv_seed import build_synthetic_command, reassemble_blocks
import deepbig_fuzz as D
import run_deepbig as R

CANCEL = "81E2910003BF4100"


@pytest.fixture(scope="module")
def mutations():
    seed = build_synthetic_command()
    return list(D.generate_mutations(seed))


def test_generates_all_classes(mutations):
    classes = {m.mutation_class.split("_")[0] for m in mutations}
    assert {"oversized", "deep", "huge", "massive", "read", "length"} <= classes
    assert len(mutations) >= 40


def test_every_outer_command_is_allowed(mutations):
    for m in mutations:
        v = safety.classify(m.apdu_hex)
        assert v.classification is safety.Classification.ALLOWED, m.label
        assert v.tag == m.target_tag, m.label


def test_no_wire_block_classifies_blocked(mutations):
    for m in mutations:
        blocks = R._wire_blocks(m)
        for b in blocks:
            assert safety.classify(b).classification is not safety.Classification.BLOCKED, m.label


def test_massive_chain_faithfully_reassembles_guarded_command(mutations):
    massive = [m for m in mutations if m.blocks is not None]
    assert massive, "expected massive-chain mutations"
    for m in massive:
        blocks = [bytes.fromhex(b) for b in m.blocks]
        assert reassemble_blocks(blocks) == m.command_tlv, m.label  # -> guarded ALLOWED command
        p1s = [b[2] for b in blocks]
        assert not any(p == 0x91 for p in p1s[:-1]), f"{m.label}: early-final chaining trick"


def test_runner_guard_accepts_all(mutations):
    for m in mutations:
        R._guard_command(m, CANCEL)  # raises SafetyError on any violation


def test_guard_rejects_injected_blocked_block(mutations):
    m = mutations[0]
    evil = D.DeepBigMutation(
        label="evil", mutation_class="massive_chain", target=m.target,
        target_tag=m.target_tag, perturbs="test", command_tlv=m.command_tlv,
        blocks=["81E2910006BF380100AA", "81E2910003BF3400"],  # BF34 reset block
        depth=0, size=0, keeps_ci_pkid_valid=True, expected_reject=True,
    )
    with pytest.raises(safety.SafetyError):
        R._guard_command(evil, CANCEL)


def test_deep_and_oversized_reach_scale(mutations):
    assert max((m.depth for m in mutations), default=0) >= 512
    assert max((m.size for m in mutations), default=0) >= 16384
