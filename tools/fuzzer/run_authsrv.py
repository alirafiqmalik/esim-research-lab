"""Campaign runner for the AuthenticateServer (BF38) verification fuzzer.

Default is DRY-RUN: build every mutation from the seed, classify each through the
safety chokepoint, and send NOTHING. ``--live`` (gated) sends each mutated
AuthenticateServer wrapped in a GetEUICCChallenge -> AuthenticateServer ->
CancelSession triple and classifies the eUICC's outcome.

Per-attempt live protocol (run phase):

    1. GetEUICCChallenge (BF2E, fresh 16-byte nonce)   81E2910003BF2E00
    2. mutated AuthenticateServer (BF38, block-chained) mutation.apdu_hex
    3. CancelSession (BF41) to tear the transient session down

Bypass detector: the eUICC ACCEPTING a mutated (invalid-signature or untrusted-CI)
input is a CANDIDATE BYPASS (CRITICAL). Accept = an AuthenticateServerResponse OK
(inner tag A0, euicc-signed) with SW 9000. A reject — an AuthenticateResponseError
(inner A1, carrying an 8.8.x-mapped errorCode) or an SW error (69xx/6Axx) — is the
expected, safe outcome. Only unique outcomes and ALL CRITICAL candidates are
logged to JSONL.

No profile can be installed by any accepted response: PrepareDownload (BF21) and
LoadBoundProfilePackage (BF37) stay blocked in ``safety``, so the chain dead-ends
at the verify step regardless of the AuthenticateServer verdict.

    # dry-run (no device): build + classify, send nothing
    tools/fuzzer/.venv/bin/python -m run_authsrv --seed-log <captured>/logcat.txt

    # live (device, gated; needs independent safety review first)
    tools/fuzzer/.venv/bin/python -m run_authsrv --live \
        --seed-log .sessions/esimctl/<ts>-authenticate/logcat.txt \
        --out .sessions/fuzzer/authsrv/outcomes.jsonl
"""

from __future__ import annotations

import argparse
import datetime as dt
import enum
import json
import sys
from dataclasses import dataclass
from pathlib import Path

import ber
from authsrv_fuzz import generate_mutations, Mutation
from authsrv_seed import (
    INS_STORE_DATA,
    AuthCommand,
    build_synthetic_command,
    load_seed,
    reassemble_blocks,
)
from safety import Classification, SafetyError, classify, guard_send
from seq_transport import SeqStepResult, SeqTransport, SeqTransportError

GET_CHALLENGE_APDU = "81E2910003BF2E00"
CANCEL_SESSION_TAG = 0xBF41

# STORE DATA payload per block. 0x3F (63 bytes) reproduces the lpac chaining that
# produced the captured seed exactly (13 blocks, 81E211.. x12 + 81E2910C.. final).
STORE_DATA_CHUNK = 0x3F
P1_INTERMEDIATE = 0x11  # STORE DATA P1, more-blocks-follow
P1_LAST = 0x91  # STORE DATA P1, final block (bit 0x80 set)

# BF38 response inner CHOICE tags (rsp.asn AuthenticateServerResponse).
RESP_OK_TAG = 0xA0  # authenticateResponseOk (euicc-signed)
RESP_ERROR_TAG = 0xA1  # authenticateResponseError (carries authenticateErrorCode)

# rsp.asn AuthenticateErrorCode INTEGER values, for labelling a reject.
AUTH_ERROR_CODES = {
    1: "invalidCertificate",
    2: "invalidSignature",
    3: "unsupportedCurve",
    4: "noSessionContext",
    5: "invalidOid",
    6: "euiccChallengeMismatch",
    7: "ciPKUnknown",
    127: "undefinedError",
}


class Severity(enum.Enum):
    CRITICAL = "CRITICAL"
    INFO = "INFO"


@dataclass(frozen=True)
class Outcome:
    """Classified result of one AuthenticateServer attempt."""

    label: str
    category: str
    accepted: bool
    severity: str
    stage: str
    sw: str
    error_code: str | None
    detail: str


def _decode_response(response_hex: str, sw: str) -> tuple[bool, str, str | None]:
    """Return (accepted, stage, error_code_name) for a BF38 response.

    ``accepted`` is True only for an OK response (inner A0) with SW 9000.
    """
    sw = (sw or "").upper()
    cleaned = (response_hex or "").strip().replace(" ", "").upper()
    try:
        data = bytes.fromhex(cleaned)
    except ValueError:
        return False, "unparseable_response", None

    if data[-2:].hex().upper() in ("9000",) and sw in ("", "9000"):
        sw = "9000"
    body = data[:-2] if data[-2:].hex().upper() == "9000" else data

    if sw and sw not in ("9000",):
        return False, f"rejected_sw_{sw}", None

    try:
        fields = ber.walk(body)
    except ber.BerError:
        return False, "unparseable_response", None
    if not fields or fields[0].tag != 0xBF38:
        return False, "no_bf38_response", None

    inner = ber.walk(fields[0].value)
    if not inner:
        return False, "empty_bf38_response", None

    if inner[0].tag == RESP_OK_TAG:
        return True, "authenticateServer_accepted", None
    if inner[0].tag == RESP_ERROR_TAG:
        code = _extract_error_code(inner[0].value)
        name = AUTH_ERROR_CODES.get(code, f"code_{code}") if code is not None else None
        return False, "authenticateServer_rejected", name
    return False, f"unknown_response_tag_{inner[0].tag:X}", None


def _extract_error_code(error_body: bytes) -> int | None:
    for field in ber.walk(error_body):
        if field.tag == 0x02 and field.value:  # INTEGER authenticateErrorCode
            return int.from_bytes(field.value, "big")
    return None


def classify_outcome(mutation: Mutation, response_hex: str, sw: str) -> Outcome:
    """Bypass detector: label one mutated-AuthenticateServer outcome.

    An ACCEPT of a mutation that should have been rejected is a CANDIDATE BYPASS
    (CRITICAL). A reject (error response or SW error) is the expected safe result.
    """
    accepted, stage, error_code = _decode_response(response_hex, sw)
    if accepted and mutation.expected_reject:
        severity = Severity.CRITICAL
        detail = (
            "CANDIDATE BYPASS: eUICC accepted an invalid AuthenticateServer "
            f"({mutation.category}/{mutation.label}) instead of rejecting it"
        )
    elif accepted:
        severity = Severity.INFO
        detail = "accepted (mutation was not expected to be rejected)"
    else:
        severity = Severity.INFO
        detail = "rejected as expected (safe)"
    return Outcome(
        label=mutation.label,
        category=mutation.category,
        accepted=accepted,
        severity=severity.value,
        stage=stage,
        sw=(sw or "").upper(),
        error_code=error_code,
        detail=detail,
    )


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _load_seed_or_synthetic(seed_log: Path | None) -> tuple[AuthCommand, bool]:
    if seed_log is None:
        return build_synthetic_command(), True
    return load_seed(seed_log), False


def _build(seed: AuthCommand) -> list[Mutation]:
    return generate_mutations(seed)


def _dry_run(mutations: list[Mutation], synthetic: bool) -> int:
    by_category: dict[str, int] = {}
    for mutation in mutations:
        by_category[mutation.category] = by_category.get(mutation.category, 0) + 1
        verdict = classify(mutation.apdu_hex)
        assert verdict.classification is Classification.ALLOWED and verdict.tag == 0xBF38
    print(json.dumps({
        "mode": "dry-run",
        "ts": _now(),
        "seed": "synthetic" if synthetic else "captured",
        "mutations": len(mutations),
        "by_category": by_category,
        "per_attempt_wire_sequence": [
            GET_CHALLENGE_APDU,
            "<mutated BF38 AuthenticateServer, block-chained>",
            "<CancelSession BF41>",
        ],
        "note": "every mutation classified ALLOWED as BF38; nothing sent",
    }, indent=2))
    return 0


def chunk_store_data(bf38_tlv: bytes, chunk_size: int = STORE_DATA_CHUNK) -> list[str]:
    """Re-split a BF38 command TLV into block-chained STORE DATA APDUs.

    Intermediate blocks are ``81 E2 11 <p2> <Lc> <chunk>``; the final block is
    ``81 E2 91 <p2> <Lc> <chunk>``. ``p2`` is the zero-based block index, matching
    the lpac chaining that produced the captured seed. ``reassemble_blocks`` over
    the returned blocks reproduces ``bf38_tlv`` byte-for-byte.
    """
    if len(bf38_tlv) < 2 or bf38_tlv[:2] != b"\xbf\x38":
        raise ValueError("chunk_store_data requires a BF38-tagged command TLV")
    if not 1 <= chunk_size <= 0xFF:
        raise ValueError(f"chunk_size {chunk_size} out of 1..255 range")

    blocks: list[str] = []
    total = len(bf38_tlv)
    offset = 0
    index = 0
    while offset < total:
        chunk = bf38_tlv[offset : offset + chunk_size]
        last = offset + len(chunk) >= total
        p1 = P1_LAST if last else P1_INTERMEDIATE
        header = bytes([0x81, INS_STORE_DATA, p1, index & 0xFF, len(chunk)])
        blocks.append((header + chunk).hex().upper())
        offset += len(chunk)
        index += 1
    return blocks


def _bf38_response_step(block_steps: list[SeqStepResult]) -> SeqStepResult | None:
    """Pick the step carrying the AuthenticateServer response.

    In GP block chaining the response completes on the final block. This scans the
    block steps for the one whose response bytes carry the BF38 response TLV, and
    falls back to the last block step when none decode (a reject the classifier
    then labels safely).
    """
    if not block_steps:
        return None
    for step in block_steps:
        if "BF38" in step.resp_hex.replace(" ", "").upper():
            return step
    return block_steps[-1]


def _cancel_session_apdu(transaction_id: bytes) -> str:
    """Build a CancelSession (BF41) store-data APDU to tear down the session."""
    # reason 1 = postponed (SGP.22 CancelSessionReason); benign teardown value.
    body = ber.tlv(0x80, transaction_id) + ber.tlv(0x81, b"\x01")
    tlv = ber.tlv(CANCEL_SESSION_TAG, body)
    lc = len(tlv)
    return (bytes([0x81, 0xE2, 0x91, 0x00, lc]) + tlv).hex().upper()


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _guard_and_build(mutation: Mutation, cancel_apdu: str) -> tuple[list[str], int]:
    """Guard one attempt through the safety chokepoint and build its wire sequence.

    Every APDU that will reach the card is guarded ALLOWED here BEFORE any send:
    the fresh GetEUICCChallenge (BF2E), the logical BF38 command, and the
    CancelSession (BF41) teardown. The BF38 is then re-split into block-chained
    STORE DATA APDUs, and the chain is asserted to reassemble byte-for-byte to the
    exact BF38 TLV that was just guarded, so nothing but the guarded command can
    reach the card. Raises SafetyError if any invariant fails.
    """
    guard_send(GET_CHALLENGE_APDU, live=True)
    verdict = guard_send(mutation.apdu_hex, live=True)
    if verdict.tag != 0xBF38:
        raise SafetyError(
            f"{mutation.label}: logical command is tag {verdict.tag}, not BF38"
        )
    guard_send(cancel_apdu, live=True)

    bf38_tlv = mutation.command.to_command_tlv()
    blocks = chunk_store_data(bf38_tlv)
    reassembled = reassemble_blocks([bytes.fromhex(b) for b in blocks])
    if reassembled != bf38_tlv:
        raise SafetyError(
            f"{mutation.label}: block chain does not reassemble to the guarded BF38"
        )
    for block in blocks:
        if classify(block).classification is Classification.BLOCKED:
            raise SafetyError(f"{mutation.label}: a wire block classified BLOCKED")

    seq = [GET_CHALLENGE_APDU, *blocks, cancel_apdu]
    return seq, len(blocks)


def _run_one(
    transport: SeqTransport, mutation: Mutation, cancel_apdu: str
) -> tuple[Outcome, SeqStepResult | None]:
    seq, nblocks = _guard_and_build(mutation, cancel_apdu)
    results = transport.send_sequence(seq)
    # results: [challenge, block_0 .. block_{n-1}, cancel]
    block_steps = results[1 : 1 + nblocks]
    step = _bf38_response_step(block_steps)
    resp_hex = step.resp_hex if step else ""
    sw = step.sw if step else ""
    return classify_outcome(mutation, resp_hex, sw), step


def _live_run(mutations: list[Mutation], args: argparse.Namespace) -> int:
    transport = SeqTransport(_repo_root(), python_executable="python3")
    seed_txid = mutations[0].command.transaction_id if mutations else b"\x00"
    cancel_apdu = _cancel_session_apdu(seed_txid)

    out_path: Path = args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    summary: dict[str, int] = {"total": 0, "rejected": 0, "accepted_info": 0,
                               "critical": 0, "errors": 0}
    records: list[dict[str, object]] = []
    critical: Outcome | None = None

    with out_path.open("w") as fh:
        for mutation in mutations:
            summary["total"] += 1
            try:
                outcome, step = _run_one(transport, mutation, cancel_apdu)
            except (SeqTransportError, SafetyError) as exc:
                summary["errors"] += 1
                record = {
                    "ts": _now(), "label": mutation.label,
                    "category": mutation.category, "error": str(exc),
                }
                records.append(record)
                fh.write(json.dumps(record) + "\n")
                fh.flush()
                continue

            record = {
                "ts": _now(), "label": outcome.label, "category": outcome.category,
                "accepted": outcome.accepted, "severity": outcome.severity,
                "stage": outcome.stage, "sw": outcome.sw,
                "error_code": outcome.error_code, "detail": outcome.detail,
                "resp_hex": (step.resp_hex if step else ""),
            }
            records.append(record)
            fh.write(json.dumps(record) + "\n")
            fh.flush()

            if outcome.severity == Severity.CRITICAL.value:
                summary["critical"] += 1
                critical = outcome
                # A candidate bypass. STOP immediately; attempt no follow-on.
                break
            if outcome.accepted:
                summary["accepted_info"] += 1
            else:
                summary["rejected"] += 1

    summary_record = {
        "ts": _now(), "kind": "summary", "mode": "live",
        "seed_log": str(args.seed_log) if args.seed_log else "synthetic",
        "device_serial": None, **summary,
        "critical_bypass": critical.label if critical else None,
    }
    with out_path.open("a") as fh:
        fh.write(json.dumps(summary_record) + "\n")

    print(json.dumps({
        "mode": "live", "out": str(out_path), "summary": summary,
        "critical_bypass": critical.label if critical else None,
        "per_mutation": [
            {
                "label": r.get("label"), "category": r.get("category"),
                "sw": r.get("sw"), "stage": r.get("stage"),
                "error_code": r.get("error_code"),
                "severity": r.get("severity"), "error": r.get("error"),
            }
            for r in records
        ],
    }, indent=2))
    return 2 if critical else 0


def _parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="run_authsrv", description=__doc__)
    ap.add_argument("--live", action="store_true",
                    help="GATED: send guarded attempts to the device (needs safety review)")
    ap.add_argument("--seed-log", type=Path, default=None,
                    help="captured authenticate session logcat.txt; omit to use the synthetic seed")
    ap.add_argument("--out", type=Path,
                    default=Path(".sessions/fuzzer/authsrv/outcomes.jsonl"),
                    help="unique outcomes + all CRITICAL candidates JSONL (live only)")
    return ap.parse_args(argv)


def main(argv: list[str]) -> int:
    args = _parse_args(argv)
    seed, synthetic = _load_seed_or_synthetic(args.seed_log)
    mutations = _build(seed)
    if not args.live:
        return _dry_run(mutations, synthetic)
    return _live_run(mutations, args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
