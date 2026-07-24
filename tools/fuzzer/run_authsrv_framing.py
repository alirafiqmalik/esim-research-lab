"""Campaign runner for the AuthenticateServer (BF38) malleable-framing fuzzer.

Default is DRY-RUN: build every framing/structural/replay mutation from the seed,
guard each through the safety chokepoint, classify a canonical-reject baseline, and
send NOTHING. ``--live`` (gated behind ``--i-have-safety-review``) sends each
mutation wrapped in GetEUICCChallenge (BF2E) -> block-chained mutated BF38 ->
CancelSession (BF41), snapshots profiles before/after, and runs the anomaly
detector on the eUICC's response(s) and SW(s).

Anomaly detector (``classify_framing_outcome``), per attempt:

- CRITICAL_BYPASS: authenticateResponseOk (inner A0, SW 9000) to a malformed input.
- PARSER_ANOMALY: no response / timeout / SW 6F00/6400/6581 / channel needs reset.
- INFO_LEAK: an error response unexpectedly larger than the canonical reject.
- STATE_CHANGE: profiles/card state differ after the attempt.
- EXPECTED_REJECT: an AuthenticateServerResponse error (A1 + 8.8.x) or clean SW error.

Coverage proxy (``testing-handbook-skills:coverage-analysis``): response/SW diversity
plus the reached parse stage stand in for line coverage on the closed SE. The runner
logs each unique (stage, sw, inner-tag) shape and every CRITICAL/ANOMALY/LEAK.

No profile can be installed by any accepted response: PrepareDownload (BF21) and
LoadBoundProfilePackage (BF37) stay BLOCKED in ``safety``, so the chain dead-ends at
the verify step regardless of the AuthenticateServer verdict.

    # dry-run (no device): build + guard + classify baseline, send nothing
    tools/fuzzer/.venv/bin/python -m run_authsrv_framing --seed-log <captured>/logcat.txt

    # live (device, gated; needs independent safety review first)
    tools/fuzzer/.venv/bin/python -m run_authsrv_framing --live --i-have-safety-review \
        --seed-log .sessions/esimctl/<ts>-authenticate/logcat.txt \
        --out .sessions/fuzzer/authsrv_framing/outcomes.jsonl \
        --max-attempts 600 --max-seconds 1800
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

import ber
from authsrv_framing_fuzz import (
    FramingMutation,
    counts_by_class,
    generate_mutations,
)
from authsrv_seed import (
    INS_STORE_DATA,
    AuthCommand,
    build_synthetic_command,
    load_seed,
    reassemble_blocks,
)
from run_authsrv import (
    GET_CHALLENGE_APDU,
    STORE_DATA_CHUNK,
    _cancel_session_apdu,
    chunk_store_data,
)
from safety import Classification, SafetyError, classify, guard_send
from seq_transport import SeqStepResult, SeqTransport, SeqTransportError

# BF38 response inner CHOICE tags (rsp.asn AuthenticateServerResponse).
RESP_OK_TAG = 0xA0  # authenticateResponseOk (euicc-signed)
RESP_ERROR_TAG = 0xA1  # authenticateResponseError

# SWs that indicate the parser aborted abnormally rather than cleanly rejecting.
ANOMALY_SWS = frozenset({"6F00", "6400", "6581", "6700", "6E00"})

# An error response this many bytes (and this ratio) larger than the canonical
# reject is treated as a candidate information leak.
LEAK_ABS_MARGIN = 16
LEAK_RATIO = 1.5


class Verdict(enum.Enum):
    CRITICAL_BYPASS = "CRITICAL_BYPASS"
    STATE_CHANGE = "STATE_CHANGE"
    PARSER_ANOMALY = "PARSER_ANOMALY"
    INFO_LEAK = "INFO_LEAK"
    EXPECTED_REJECT = "EXPECTED_REJECT"


CRITICAL_VERDICTS = frozenset({Verdict.CRITICAL_BYPASS, Verdict.STATE_CHANGE})
NOTABLE_VERDICTS = frozenset(
    {Verdict.CRITICAL_BYPASS, Verdict.STATE_CHANGE, Verdict.PARSER_ANOMALY, Verdict.INFO_LEAK}
)


@dataclass(frozen=True)
class FramingOutcome:
    """Classified result of one malleable-framing attempt."""

    label: str
    mutation_class: str
    verdict: str
    stage: str
    sw: str
    inner_tag: str | None
    resp_len: int
    detail: str

    @property
    def is_critical(self) -> bool:
        return self.verdict in (Verdict.CRITICAL_BYPASS.value, Verdict.STATE_CHANGE.value)

    @property
    def is_notable(self) -> bool:
        return self.verdict in (v.value for v in NOTABLE_VERDICTS)


def _decode_response(response_hex: str, sw: str) -> tuple[bool, str, int | None, int]:
    """Return (accepted, stage, inner_tag, response_byte_len) for a BF38 response.

    ``accepted`` is True only for an OK response (inner A0) with SW 9000.
    ``response_byte_len`` counts the full response APDU bytes (payload + SW).
    """
    sw = (sw or "").upper().replace(" ", "")
    cleaned = (response_hex or "").strip().replace(" ", "").upper()
    if not cleaned:
        return False, "no_response", None, 0
    try:
        data = bytes.fromhex(cleaned)
    except ValueError:
        return False, "unparseable_response", None, len(cleaned) // 2

    resp_len = len(data)
    trailing_sw = data[-2:].hex().upper() if len(data) >= 2 else ""
    if trailing_sw == "9000" and sw in ("", "9000"):
        sw = "9000"
        body = data[:-2]
    elif len(sw) == 4 and trailing_sw == sw:
        body = data[:-2]
    else:
        body = data

    if sw and sw != "9000":
        return False, f"rejected_sw_{sw}", None, resp_len

    try:
        fields = ber.walk(body)
    except ber.BerError:
        return False, "unparseable_response", None, resp_len
    if not fields or fields[0].tag != 0xBF38:
        return False, "no_bf38_response", None, resp_len

    try:
        inner = ber.walk(fields[0].value)
    except ber.BerError:
        return False, "unparseable_inner", None, resp_len
    if not inner:
        return False, "empty_bf38_response", None, resp_len

    inner_tag = inner[0].tag
    if inner_tag == RESP_OK_TAG:
        return True, "authenticateServer_accepted", inner_tag, resp_len
    if inner_tag == RESP_ERROR_TAG:
        return False, "authenticateServer_rejected", inner_tag, resp_len
    return False, f"unknown_inner_tag_{inner_tag:X}", inner_tag, resp_len


def classify_framing_outcome(
    mutation: FramingMutation,
    response_hex: str,
    sw: str,
    *,
    responsive: bool = True,
    state_changed: bool = False,
    canonical_reject_len: int | None = None,
) -> FramingOutcome:
    """Anomaly detector for one malleable-framing attempt.

    Precedence: STATE_CHANGE and CRITICAL_BYPASS first (both CRITICAL), then
    PARSER_ANOMALY (unresponsive / anomaly SW / no response), then INFO_LEAK
    (over-large error vs the canonical reject), then EXPECTED_REJECT.
    """
    accepted, stage, inner_tag, resp_len = _decode_response(response_hex, sw)
    sw_norm = (sw or "").upper().replace(" ", "")
    inner_hex = f"{inner_tag:X}" if inner_tag is not None else None

    def outcome(verdict: Verdict, detail: str) -> FramingOutcome:
        return FramingOutcome(
            label=mutation.label, mutation_class=mutation.mutation_class,
            verdict=verdict.value, stage=stage, sw=sw_norm,
            inner_tag=inner_hex, resp_len=resp_len, detail=detail,
        )

    if state_changed:
        return outcome(Verdict.STATE_CHANGE,
                       "profiles/card state changed after the attempt")

    if accepted:
        return outcome(Verdict.CRITICAL_BYPASS,
                       "eUICC accepted a malformed/framing-perturbed AuthenticateServer")

    if not responsive or stage == "no_response" or sw_norm in ANOMALY_SWS:
        return outcome(Verdict.PARSER_ANOMALY,
                       "no response / timeout / abnormal SW — possible parser crash or DoS")

    if canonical_reject_len is not None and resp_len > 0:
        if resp_len >= canonical_reject_len * LEAK_RATIO and resp_len >= canonical_reject_len + LEAK_ABS_MARGIN:
            return outcome(Verdict.INFO_LEAK,
                           f"error response {resp_len} B vs canonical {canonical_reject_len} B — "
                           "possible memory/state disclosure")

    return outcome(Verdict.EXPECTED_REJECT, "clean reject (safe baseline)")


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _load_seed_or_synthetic(seed_log: Path | None) -> tuple[AuthCommand, bool]:
    if seed_log is None:
        return build_synthetic_command(), True
    return load_seed(seed_log), False


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _wire_blocks(mutation: FramingMutation) -> list[str]:
    """Explicit wire blocks for the block-chaining class, else standard chunking."""
    if mutation.blocks is not None:
        return list(mutation.blocks)
    return chunk_store_data(mutation.command_tlv, STORE_DATA_CHUNK)


def _guard_and_build(mutation: FramingMutation, cancel_apdu: str) -> list[str]:
    """Guard one attempt through the safety chokepoint and build its wire sequence.

    Every APDU that will reach the card is guarded here BEFORE any send: the fresh
    GetEUICCChallenge (BF2E), the logical BF38 command (must be ALLOWED/BF38), the
    CancelSession (BF41) teardown, and every individual wire block (none may be
    BLOCKED). For the standard-chunk classes the chain is asserted to reassemble
    byte-for-byte to the guarded BF38 TLV; the block-chaining class deliberately
    breaks that reassembly, so the per-block not-BLOCKED check is the invariant
    there. Raises SafetyError on any violation.
    """
    guard_send(GET_CHALLENGE_APDU, live=True)
    verdict = guard_send(mutation.apdu_hex, live=True)
    if verdict.tag != 0xBF38:
        raise SafetyError(f"{mutation.label}: logical command is tag {verdict.tag}, not BF38")
    guard_send(cancel_apdu, live=True)

    blocks = _wire_blocks(mutation)
    for block in blocks:
        if classify(block).classification is Classification.BLOCKED:
            raise SafetyError(f"{mutation.label}: a wire block classified BLOCKED")

    if mutation.blocks is None:
        reassembled = reassemble_blocks([bytes.fromhex(b) for b in blocks])
        if reassembled != mutation.command_tlv:
            raise SafetyError(
                f"{mutation.label}: standard chunk chain does not reassemble to the guarded BF38"
            )

    return [GET_CHALLENGE_APDU, *blocks, cancel_apdu]


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


def _dry_run(mutations: list[FramingMutation], synthetic: bool) -> int:
    counts = counts_by_class(mutations)
    # Guard-check every mutation and every wire block without sending anything.
    cancel_apdu = _cancel_session_apdu(b"\x00" * 16)
    guarded = 0
    for mutation in mutations:
        _guard_and_build(mutation, cancel_apdu)
        guarded += 1
    print(json.dumps({
        "mode": "dry-run",
        "ts": _now(),
        "seed": "synthetic" if synthetic else "captured",
        "mutations": len(mutations),
        "guarded_allowed_bf38": guarded,
        "by_class": counts,
        "per_attempt_wire_sequence": [
            GET_CHALLENGE_APDU,
            "<mutated BF38 AuthenticateServer, block-chained>",
            "<CancelSession BF41>",
        ],
        "detector_verdicts": [v.value for v in Verdict],
        "note": "every mutation guarded ALLOWED as BF38; no wire block BLOCKED; nothing sent",
    }, indent=2))
    return 0


def _channel_responsive(steps: list[SeqStepResult]) -> bool:
    """The channel is responsive if at least one non-reset step returned an SW."""
    return any(s.sw for s in steps if not s.is_reset)


def _pick_response_step(block_steps: list[SeqStepResult]) -> SeqStepResult | None:
    if not block_steps:
        return None
    for step in block_steps:
        if "BF38" in step.resp_hex.replace(" ", "").upper():
            return step
    return block_steps[-1]


def _run_one(
    transport: SeqTransport,
    mutation: FramingMutation,
    cancel_apdu: str,
    canonical_reject_len: int | None,
    before: frozenset[str] | None,
    repo_root: Path,
) -> tuple[FramingOutcome, SeqStepResult | None]:
    seq = _guard_and_build(mutation, cancel_apdu)
    nblocks = len(seq) - 2  # minus challenge and cancel
    results = transport.send_sequence(seq)
    block_steps = results[1 : 1 + nblocks]
    step = _pick_response_step(block_steps)
    resp_hex = step.resp_hex if step else ""
    sw = step.sw if step else ""
    responsive = _channel_responsive(results)

    state_changed = False
    if before is not None:
        after = _snapshot_profiles(repo_root)
        state_changed = after is not None and after != before

    outcome = classify_framing_outcome(
        mutation, resp_hex, sw,
        responsive=responsive, state_changed=state_changed,
        canonical_reject_len=canonical_reject_len,
    )
    return outcome, step


def _live_run(mutations: list[FramingMutation], args: argparse.Namespace) -> int:
    repo_root = _repo_root()
    transport = SeqTransport(repo_root, python_executable="python3")
    cancel_apdu = _cancel_session_apdu(b"\x00" * 16)

    before = _snapshot_profiles(repo_root)

    out_path: Path = args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)

    summary = {"total": 0, "expected_reject": 0, "parser_anomaly": 0,
               "info_leak": 0, "critical": 0, "errors": 0}
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
            except (SeqTransportError, SafetyError) as exc:
                summary["errors"] += 1
                # A transport failure mid-chain can itself be a parser DoS signal.
                record = {"ts": _now(), "label": mutation.label,
                          "mutation_class": mutation.mutation_class, "error": str(exc)}
                fh.write(json.dumps(record) + "\n")
                fh.flush()
                continue

            # Learn the canonical reject size from the control's clean reject.
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
            elif outcome.is_critical:
                summary["critical"] += 1

            if unique or outcome.is_notable:
                record = {
                    "ts": _now(), "label": outcome.label,
                    "mutation_class": outcome.mutation_class, "verdict": outcome.verdict,
                    "stage": outcome.stage, "sw": outcome.sw, "inner_tag": outcome.inner_tag,
                    "resp_len": outcome.resp_len, "unique_shape": unique,
                    "detail": outcome.detail,
                    "resp_hex": (step.resp_hex if step else ""),
                }
                fh.write(json.dumps(record) + "\n")
                fh.flush()

            if outcome.is_critical:
                # CRITICAL_BYPASS or STATE_CHANGE: STOP immediately, no follow-on.
                stop_reason = f"CRITICAL:{outcome.verdict}:{outcome.label}"
                break

        summary_record = {
            "ts": _now(), "kind": "summary", "mode": "live",
            "seed_log": str(args.seed_log) if args.seed_log else "synthetic",
            "stop_reason": stop_reason, "unique_shapes": len(seen_shapes),
            "canonical_reject_len": canonical_reject_len, **summary,
        }
        fh.write(json.dumps(summary_record) + "\n")

    print(json.dumps({
        "mode": "live", "out": str(out_path), "summary": summary,
        "unique_shapes": len(seen_shapes), "stop_reason": stop_reason,
    }, indent=2))
    return 2 if summary["critical"] else 0


def _parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="run_authsrv_framing", description=__doc__)
    ap.add_argument("--live", action="store_true",
                    help="GATED: send guarded attempts to the device")
    ap.add_argument("--i-have-safety-review", action="store_true",
                    help="required with --live; asserts an independent safety review was done")
    ap.add_argument("--seed-log", type=Path, default=None,
                    help="captured authenticate session logcat.txt; omit to use the synthetic seed")
    ap.add_argument("--out", type=Path,
                    default=Path(".sessions/fuzzer/authsrv_framing/outcomes.jsonl"),
                    help="unique outcomes + all CRITICAL/ANOMALY/LEAK JSONL (live only)")
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
            "review of this superset framing campaign is required first."
        )
    return _live_run(mutations, args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
