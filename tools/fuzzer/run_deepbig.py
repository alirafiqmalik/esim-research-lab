"""Campaign runner for the deep/big eUICC SE-parser fuzzer.

Default is DRY-RUN: build every deep/big mutation from the seed, guard each
through the safety chokepoint (outer tag ALLOWED, no wire block BLOCKED), and
send NOTHING. ``--live`` (gated behind ``--i-have-safety-review``) sends each
mutation through the on-device LARGE transport and runs the anomaly detector,
including the new UNRESPONSIVE/HANG verdict.

Per live attempt (``testing-handbook-skills:coverage-analysis`` closed-SE proxy —
response/SW diversity, reached stage, AND card responsiveness):

1. snapshot profiles (before)
2. BF38 target: GetEUICCChallenge (BF2E) -> mutated command (large transport) ->
   CancelSession (BF41). READ target: the mutated command alone.
3. canary GetEID (BF3E) responsiveness check on a fresh sequence.
4. if the canary fails -> HANG candidate: attempt recovery (channel RESET +
   re-canary) and record whether the card recovered.
5. snapshot profiles (after) -> STATE_CHANGE if changed.

Detector verdicts (``classify_deepbig_outcome``):

- STATE_CHANGE  : profiles/card state changed (CRITICAL).
- CRITICAL_BYPASS: an A0 accept (SW 9000) to a malformed/oversized input.
- HANG          : the post-attempt canary GetEID failed -> candidate SE DoS/crash.
- PARSER_ANOMALY: no response / timeout / abnormal SW while the card stays live.
- INFO_LEAK     : an error response over-large vs the canonical reject.
- EXPECTED_REJECT: a clean reject (safe baseline).

No profile can be installed by any accepted response: PrepareDownload (BF21) and
LoadBoundProfilePackage (BF37) stay BLOCKED in ``safety``. A huge/deep input may
CRASH or HANG the card — that is the finding — but it is transient and writes
nothing; the runner records recovery.

    # dry-run (no device): build + guard + report, send nothing
    tools/fuzzer/.venv/bin/python -m run_deepbig --seed-log <captured>/logcat.txt

    # live (device, gated; needs independent safety review first)
    tools/fuzzer/.venv/bin/python -m run_deepbig --live --i-have-safety-review \
        --seed-log .sessions/esimctl/<ts>-authenticate/logcat.txt \
        --out .sessions/fuzzer/deepbig/outcomes.jsonl \
        --max-attempts 200 --max-seconds 3600
"""

from __future__ import annotations

import argparse
import datetime as dt
import enum
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from authsrv_seed import (
    AuthCommand,
    build_synthetic_command,
    load_seed,
    reassemble_blocks,
)
from deepbig_fuzz import (
    DeepBigMutation,
    chunk_command,
    counts_by_class,
    generate_mutations,
    max_blocks_reached,
    max_depth_reached,
    max_size_reached,
)
from run_authsrv import GET_CHALLENGE_APDU, STORE_DATA_CHUNK, _cancel_session_apdu
from run_authsrv_framing import ANOMALY_SWS, LEAK_ABS_MARGIN, LEAK_RATIO, _decode_response
from safety import Classification, SafetyError, classify, guard_send
from seq_transport import LargeSeqTransport, SeqStepResult, SeqTransport, SeqTransportError

# Canary: GetEID (BF3E), read-only, used as the post-attempt responsiveness probe.
GET_EID_APDU = "81E2910003BF3E00"
RESET_TOKEN = "RESET"

RESP_OK_TAG = 0xA0  # authenticateResponseOk


class Verdict(enum.Enum):
    CRITICAL_BYPASS = "CRITICAL_BYPASS"
    STATE_CHANGE = "STATE_CHANGE"
    HANG = "HANG"
    PARSER_ANOMALY = "PARSER_ANOMALY"
    INFO_LEAK = "INFO_LEAK"
    EXPECTED_REJECT = "EXPECTED_REJECT"


CRITICAL_VERDICTS = frozenset({Verdict.CRITICAL_BYPASS, Verdict.STATE_CHANGE})
STOP_VERDICTS = frozenset({Verdict.CRITICAL_BYPASS, Verdict.STATE_CHANGE})
NOTABLE_VERDICTS = frozenset(
    {Verdict.CRITICAL_BYPASS, Verdict.STATE_CHANGE, Verdict.HANG,
     Verdict.PARSER_ANOMALY, Verdict.INFO_LEAK}
)


@dataclass(frozen=True)
class DeepBigOutcome:
    """Classified result of one deep/big attempt."""

    label: str
    mutation_class: str
    target: str
    verdict: str
    stage: str
    sw: str
    inner_tag: str | None
    resp_len: int
    depth: int
    size: int
    canary_ok: bool
    recovered: bool | None
    detail: str

    @property
    def is_critical(self) -> bool:
        return self.verdict in (v.value for v in CRITICAL_VERDICTS)

    @property
    def is_notable(self) -> bool:
        return self.verdict in (v.value for v in NOTABLE_VERDICTS)


def classify_deepbig_outcome(
    mutation: DeepBigMutation,
    response_hex: str,
    sw: str,
    *,
    canary_ok: bool = True,
    recovered: bool | None = None,
    responsive: bool = True,
    state_changed: bool = False,
    canonical_reject_len: int | None = None,
) -> DeepBigOutcome:
    """Anomaly detector for one deep/big attempt (extends the framing detector).

    Precedence: STATE_CHANGE and CRITICAL_BYPASS first (both CRITICAL), then the
    new HANG verdict (the post-attempt canary GetEID failed -> the SE stopped
    responding, a candidate DoS/crash), then PARSER_ANOMALY (odd SW / no response
    while the card is still live), then INFO_LEAK, then EXPECTED_REJECT.
    """
    accepted, stage, inner_tag, resp_len = _decode_response(response_hex, sw)
    sw_norm = (sw or "").upper().replace(" ", "")
    inner_hex = f"{inner_tag:X}" if inner_tag is not None else None

    def outcome(verdict: Verdict, detail: str) -> DeepBigOutcome:
        return DeepBigOutcome(
            label=mutation.label, mutation_class=mutation.mutation_class,
            target=mutation.target, verdict=verdict.value, stage=stage,
            sw=sw_norm, inner_tag=inner_hex, resp_len=resp_len,
            depth=mutation.depth, size=mutation.size,
            canary_ok=canary_ok, recovered=recovered, detail=detail,
        )

    if state_changed:
        return outcome(Verdict.STATE_CHANGE, "profiles/card state changed after the attempt")

    if accepted:
        return outcome(Verdict.CRITICAL_BYPASS,
                       "eUICC accepted a malformed/oversized/deep command")

    if not canary_ok:
        rec = "recovered" if recovered else ("not recovered" if recovered is False else "recovery not attempted")
        return outcome(Verdict.HANG,
                       f"post-attempt canary GetEID failed — candidate SE DoS/crash ({rec})")

    if not responsive or stage == "no_response" or sw_norm in ANOMALY_SWS:
        return outcome(Verdict.PARSER_ANOMALY,
                       "no response / timeout / abnormal SW — possible parser fault")

    if canonical_reject_len is not None and resp_len > 0:
        if resp_len >= canonical_reject_len * LEAK_RATIO and resp_len >= canonical_reject_len + LEAK_ABS_MARGIN:
            return outcome(Verdict.INFO_LEAK,
                           f"error response {resp_len} B vs canonical {canonical_reject_len} B — "
                           "possible memory/state disclosure")

    return outcome(Verdict.EXPECTED_REJECT, "clean reject (safe baseline)")


# --------------------------------------------------------------------------- #
# Guarding + wire assembly.
# --------------------------------------------------------------------------- #


def _wire_blocks(mutation: DeepBigMutation) -> list[str]:
    """Explicit wire blocks for the massive-chain class, else standard chunking."""
    if mutation.blocks is not None:
        return list(mutation.blocks)
    return chunk_command(mutation.command_tlv, STORE_DATA_CHUNK)


def _guard_command(mutation: DeepBigMutation, cancel_apdu: str) -> list[str]:
    """Guard one attempt through the safety chokepoint and build its command sequence.

    Every APDU that will reach the card is guarded BEFORE any send: the canary
    (GetEID), and — for BF38 targets — the GetEUICCChallenge and CancelSession
    wrappers; the logical command (must be ALLOWED on its own outer tag); and every
    individual wire block (none may classify BLOCKED). For the standard-chunk
    classes the chain is asserted to reassemble byte-for-byte to the guarded command
    TLV; the massive-chain class deliberately uses explicit blocks, whose
    per-block not-BLOCKED check is the invariant there. Raises SafetyError on any
    violation. Returns the command sequence WITHOUT the canary (sent separately).
    """
    guard_send(GET_EID_APDU, live=True)
    verdict = guard_send(mutation.apdu_hex, live=True)
    if verdict.classification is not Classification.ALLOWED or verdict.tag != mutation.target_tag:
        raise SafetyError(
            f"{mutation.label}: logical command classified {verdict.classification.value} "
            f"tag={verdict.tag}, expected ALLOWED/0x{mutation.target_tag:04X}"
        )

    blocks = _wire_blocks(mutation)
    for block in blocks:
        if classify(block).classification is Classification.BLOCKED:
            raise SafetyError(f"{mutation.label}: a wire block classified BLOCKED")

    if mutation.blocks is None:
        reassembled = reassemble_blocks([bytes.fromhex(b) for b in blocks])
        if reassembled != mutation.command_tlv:
            raise SafetyError(
                f"{mutation.label}: standard chunk chain does not reassemble to the guarded command"
            )

    if mutation.target_tag == 0xBF38:
        guard_send(GET_CHALLENGE_APDU, live=True)
        guard_send(cancel_apdu, live=True)
        return [GET_CHALLENGE_APDU, *blocks, cancel_apdu]
    return list(blocks)


# --------------------------------------------------------------------------- #
# Live helpers.
# --------------------------------------------------------------------------- #


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _load_seed_or_synthetic(seed_log: Path | None) -> tuple[AuthCommand, bool]:
    if seed_log is None:
        return build_synthetic_command(), True
    return load_seed(seed_log), False


def _sw_indicates_live(sw: str) -> bool:
    """A canary SW that proves the SE is still parsing commands."""
    s = (sw or "").upper().replace(" ", "")
    return s == "9000" or s.startswith("61") or s.startswith("62") or s.startswith("63")


def _channel_responsive(steps: list[SeqStepResult]) -> bool:
    return any(s.sw for s in steps if not s.is_reset)


def _pick_response_step(block_steps: list[SeqStepResult]) -> SeqStepResult | None:
    if not block_steps:
        return None
    for step in block_steps:
        if "BF38" in step.resp_hex.replace(" ", "").upper():
            return step
    return block_steps[-1]


def _run_canary(transport: SeqTransport) -> bool:
    """Fresh GetEID sequence. True only if the SE returns a live SW."""
    try:
        steps = transport.send_sequence([GET_EID_APDU])
    except SeqTransportError:
        return False
    return any(_sw_indicates_live(s.sw) for s in steps if not s.is_reset)


def _attempt_recovery(transport: SeqTransport) -> bool:
    """Non-destructive recovery: channel RESET (re-SELECT ISD-R) + re-canary.

    RESET is a channel close/reopen — never eUICCMemoryReset. Returns True if the
    SE answers the canary after the reset.
    """
    try:
        steps = transport.send_sequence([RESET_TOKEN, GET_EID_APDU])
    except SeqTransportError:
        return False
    return any(_sw_indicates_live(s.sw) for s in steps if not s.is_reset)


def _snapshot_profiles(repo_root: Path) -> frozenset[str] | None:
    """Read the current profile ICCID set via the project CLI. None on failure."""
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "esim.cli", "euicc", "list"],
            cwd=repo_root, capture_output=True, text=True, timeout=30,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    profiles = data.get("profiles") if isinstance(data, dict) else None
    if not isinstance(profiles, list):
        return None
    return frozenset(str(p.get("iccid")) for p in profiles if isinstance(p, dict))


def _run_one(
    transport: SeqTransport,
    mutation: DeepBigMutation,
    cancel_apdu: str,
    canonical_reject_len: int | None,
    before: frozenset[str] | None,
    repo_root: Path,
) -> tuple[DeepBigOutcome, SeqStepResult | None]:
    cmd_seq = _guard_command(mutation, cancel_apdu)

    # Send the mutated command. A timeout/transport failure mid-chain is itself a
    # candidate parser DoS signal (responsive=False), not a runner error.
    responsive = True
    resp_hex = ""
    sw = ""
    step: SeqStepResult | None = None
    try:
        results = transport.send_sequence(cmd_seq)
        offset = 1 if mutation.target_tag == 0xBF38 else 0
        nblocks = len(cmd_seq) - (2 if mutation.target_tag == 0xBF38 else 0)
        block_steps = results[offset : offset + nblocks]
        step = _pick_response_step(block_steps)
        resp_hex = step.resp_hex if step else ""
        sw = step.sw if step else ""
        responsive = _channel_responsive(results)
    except SeqTransportError:
        responsive = False

    # Canary responsiveness probe + recovery on failure.
    canary_ok = _run_canary(transport)
    recovered: bool | None = None
    if not canary_ok:
        recovered = _attempt_recovery(transport)

    state_changed = False
    if before is not None:
        after = _snapshot_profiles(repo_root)
        state_changed = after is not None and after != before

    outcome = classify_deepbig_outcome(
        mutation, resp_hex, sw,
        canary_ok=canary_ok, recovered=recovered,
        responsive=responsive, state_changed=state_changed,
        canonical_reject_len=canonical_reject_len,
    )
    return outcome, step


# --------------------------------------------------------------------------- #
# Dry-run / live drivers.
# --------------------------------------------------------------------------- #


def _dry_run(mutations: list[DeepBigMutation], synthetic: bool) -> int:
    cancel_apdu = _cancel_session_apdu(b"\x00" * 16)
    guarded = 0
    for mutation in mutations:
        _guard_command(mutation, cancel_apdu)
        guarded += 1
    print(json.dumps({
        "mode": "dry-run",
        "ts": _now(),
        "seed": "synthetic" if synthetic else "captured",
        "mutations": len(mutations),
        "guarded_allowed": guarded,
        "by_class": counts_by_class(mutations),
        "max_depth": max_depth_reached(mutations),
        "max_size_bytes": max_size_reached(mutations),
        "max_blocks": max_blocks_reached(mutations),
        "detector_verdicts": [v.value for v in Verdict],
        "note": "every mutation guarded ALLOWED on its outer tag; no wire block "
                "BLOCKED; BF37/BF21/writes stay blocked; nothing sent",
    }, indent=2))
    return 0


def _live_run(mutations: list[DeepBigMutation], args: argparse.Namespace) -> int:
    repo_root = _repo_root()
    transport = LargeSeqTransport(repo_root, python_executable="python3")
    cancel_apdu = _cancel_session_apdu(b"\x00" * 16)

    before = _snapshot_profiles(repo_root)
    out_path: Path = args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)

    summary = {"total": 0, "expected_reject": 0, "parser_anomaly": 0,
               "info_leak": 0, "hang": 0, "hang_recovered": 0, "critical": 0, "errors": 0}
    seen_shapes: set[tuple[str, str, str | None]] = set()
    canonical_reject_len: int | None = None
    stop_reason: str | None = None
    started = time.monotonic()

    with out_path.open("w") as fh:
        for mutation in mutations:
            if args.max_attempts and summary["total"] >= args.max_attempts:
                stop_reason = "max-attempts"
                break
            if args.max_seconds and (time.monotonic() - started) >= args.max_seconds:
                stop_reason = "max-seconds"
                break
            summary["total"] += 1

            try:
                outcome, step = _run_one(
                    transport, mutation, cancel_apdu, canonical_reject_len, before, repo_root
                )
            except SafetyError as exc:
                summary["errors"] += 1
                fh.write(json.dumps({
                    "ts": _now(), "label": mutation.label,
                    "mutation_class": mutation.mutation_class, "error": str(exc),
                }) + "\n")
                fh.flush()
                continue

            if canonical_reject_len is None and outcome.verdict == Verdict.EXPECTED_REJECT.value and outcome.resp_len:
                canonical_reject_len = outcome.resp_len

            shape = (outcome.stage, outcome.sw, outcome.inner_tag)
            unique = shape not in seen_shapes
            seen_shapes.add(shape)

            if outcome.verdict == Verdict.EXPECTED_REJECT.value:
                summary["expected_reject"] += 1
            elif outcome.verdict == Verdict.PARSER_ANOMALY.value:
                summary["parser_anomaly"] += 1
            elif outcome.verdict == Verdict.INFO_LEAK.value:
                summary["info_leak"] += 1
            elif outcome.verdict == Verdict.HANG.value:
                summary["hang"] += 1
                if outcome.recovered:
                    summary["hang_recovered"] += 1
            elif outcome.is_critical:
                summary["critical"] += 1

            if unique or outcome.is_notable:
                fh.write(json.dumps({
                    "ts": _now(), "label": outcome.label,
                    "mutation_class": outcome.mutation_class, "target": outcome.target,
                    "verdict": outcome.verdict, "stage": outcome.stage, "sw": outcome.sw,
                    "inner_tag": outcome.inner_tag, "resp_len": outcome.resp_len,
                    "depth": outcome.depth, "size": outcome.size,
                    "canary_ok": outcome.canary_ok, "recovered": outcome.recovered,
                    "unique_shape": unique, "detail": outcome.detail,
                    "resp_hex": (step.resp_hex if step else ""),
                }) + "\n")
                fh.flush()

            if outcome.is_critical:
                stop_reason = f"CRITICAL:{outcome.verdict}:{outcome.label}"
                break

        fh.write(json.dumps({
            "ts": _now(), "kind": "summary", "mode": "live",
            "seed_log": str(args.seed_log) if args.seed_log else "synthetic",
            "stop_reason": stop_reason, "unique_shapes": len(seen_shapes),
            "canonical_reject_len": canonical_reject_len, **summary,
        }) + "\n")

    print(json.dumps({
        "mode": "live", "out": str(out_path), "summary": summary,
        "unique_shapes": len(seen_shapes), "stop_reason": stop_reason,
    }, indent=2))
    return 2 if summary["critical"] else 0


def _parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="run_deepbig", description=__doc__)
    ap.add_argument("--live", action="store_true",
                    help="GATED: send guarded attempts to the device")
    ap.add_argument("--i-have-safety-review", action="store_true",
                    help="required with --live; asserts an independent safety review was done")
    ap.add_argument("--seed-log", type=Path, default=None,
                    help="captured authenticate session logcat.txt; omit to use the synthetic seed")
    ap.add_argument("--out", type=Path,
                    default=Path(".sessions/fuzzer/deepbig/outcomes.jsonl"),
                    help="unique outcomes + all CRITICAL/HANG/ANOMALY/LEAK JSONL (live only)")
    ap.add_argument("--max-attempts", type=int, default=0,
                    help="cap the number of live attempts (0 = no cap)")
    ap.add_argument("--max-seconds", type=float, default=0.0,
                    help="cap the live wall-clock seconds (0 = no cap)")
    return ap.parse_args(argv)


def main(argv: list[str]) -> int:
    args = _parse_args(argv)
    seed, synthetic = _load_seed_or_synthetic(args.seed_log)
    mutations = generate_mutations(seed)
    if not args.live:
        return _dry_run(mutations, synthetic)
    if not args.i_have_safety_review:
        raise SystemExit(
            "refusing --live without --i-have-safety-review: an independent safety "
            "review of this deep/big campaign is required first."
        )
    return _live_run(mutations, args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
