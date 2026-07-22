"""Shared plumbing for the read-only discovery campaigns.

The four explore modules (SELECT, GET DATA, READ, timing) all build candidate
APDUs, route each one through the single ``engine.FuzzEngine.consider`` /
``safety.guard_send`` chokepoint, and dedup observed behaviour with
``novelty.NoveltyEngine``. This module holds the APDU builders they share and the
generic drive loop that feeds candidates to the engine and writes only
unique-or-unexpected rows via ``reporting.UniqueBehaviourReporter``.

Skills applied:

- ``coverage-analysis``: a black-box secure element exposes no in-process
  coverage, so the campaigns use a response/SW-diversity proxy (the novelty
  engine) plus an explicit discovery count (selectable AIDs, readable data
  objects, readable files) as the effectiveness signal.
- ``fuzzing-dictionary``: the AID and data-object token tables in the per-angle
  modules are the domain dictionary that steers the sweep toward the eUICC's
  GlobalPlatform / ISO-7816 grammar.

Nothing here sends anything on its own. It only builds candidates and drives them
through the existing safety-gated engine.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable
from dataclasses import dataclass

from dictionary import STORE_DATA_PREFIX, encode_lc
from engine import CandidateOutcome, FuzzEngine
from novelty import NoveltyEngine, ProbeResult
from reporting import BehaviourRecord, UniqueBehaviourReporter


@dataclass(frozen=True)
class Candidate:
    """One read-only APDU to probe, plus the metadata novelty/reporting need.

    ``command`` is a shared per-instruction label (``SELECT``, ``GETDATA``, ...)
    so the novelty engine dedups the boring "not found" responses by SW instead
    of logging one row per swept target. ``target`` is the human-readable thing
    being probed (an AID, a data-object tag, a file reference) and is what the
    discovery findings list records.
    """

    apdu_hex: str
    command: str
    tag: str | None
    target: str
    malformed: bool = False


# ---- APDU builders (all within the read-only allowlist) --------------------


def select_apdu(aid: bytes, *, p1: int = 0x04, p2: int = 0x00, le: int | None = 0x00) -> str:
    """Build an ISO SELECT (INS A4). Empty ``aid`` yields a next-occurrence probe."""
    apdu = bytes((0x00, 0xA4, p1 & 0xFF, p2 & 0xFF))
    if aid:
        apdu += bytes((len(aid) & 0xFF,)) + aid
    if le is not None:
        apdu += bytes((le & 0xFF,))
    return apdu.hex().upper()


def get_data_apdu(tag: int, *, odd: bool = False, le: int = 0x00) -> str:
    """Build a GET DATA (INS CA even / CB odd) for a 1- or 2-byte tag in P1-P2."""
    ins = 0xCB if odd else 0xCA
    return bytes((0x00, ins, (tag >> 8) & 0xFF, tag & 0xFF, le & 0xFF)).hex().upper()


def read_binary_apdu(*, sfi: int | None = None, offset: int = 0, le: int = 0x00) -> str:
    """Build a READ BINARY (INS B0). ``sfi`` set uses short-EF addressing in P1."""
    if sfi is not None:
        p1 = 0x80 | (sfi & 0x1F)
        p2 = offset & 0xFF
    else:
        p1 = (offset >> 8) & 0x7F
        p2 = offset & 0xFF
    return bytes((0x00, 0xB0, p1, p2, le & 0xFF)).hex().upper()


def read_record_apdu(*, record: int, sfi: int, mode: int = 0x04, le: int = 0x00) -> str:
    """Build a READ RECORD (INS B2). ``mode`` low bits select first/next/abs."""
    p2 = ((sfi & 0x1F) << 3) | (mode & 0x07)
    return bytes((0x00, 0xB2, record & 0xFF, p2, le & 0xFF)).hex().upper()


def get_response_apdu(*, le: int = 0x00) -> str:
    """Build a GET RESPONSE (INS C0) for ``le`` buffered bytes."""
    return bytes((0x00, 0xC0, 0x00, 0x00, le & 0xFF)).hex().upper()


def store_data_get(tag: int, body: bytes = b"") -> str:
    """Build an ES10x STORE DATA GET (INS E2) for an allowlisted BFxx read tag."""
    tag_bytes = bytes(((tag >> 8) & 0xFF, tag & 0xFF)) if tag > 0xFF else bytes((tag,))
    tlv = tag_bytes + bytes((len(body),)) + body
    lc = encode_lc(len(tlv), form="short")
    return (STORE_DATA_PREFIX + lc + tlv).hex().upper()


# ---- discovery predicate ----------------------------------------------------


def sw_indicates_data(sw: str | None) -> bool:
    """True when a status word means the target exists / returned content.

    9000 = success, 61xx = more data via GET RESPONSE, 62xx/63xx = selected or
    read with a warning. 6A82 (not found), 6A88, 6999, 6D00 fall through as
    absent and are not counted as discoveries.
    """
    if not sw:
        return False
    s = sw.upper()
    return s == "9000" or s.startswith("61") or s.startswith("62") or s.startswith("63")


# ---- shared drive loop ------------------------------------------------------


def _split_response(outcome: CandidateOutcome) -> tuple[str | None, str | None]:
    sw = outcome.sw
    resp = outcome.resp_hex
    if outcome.sent and resp and sw and resp.upper().endswith(sw.upper()):
        resp = resp[: -len(sw)] or None
    return sw, resp


def drive(
    *,
    angle: str,
    engine: FuzzEngine,
    novelty: NoveltyEngine,
    reporter: UniqueBehaviourReporter,
    candidates: Iterable[Candidate],
    phase: str,
    wall: int,
    send_cap: int | None,
) -> dict[str, object]:
    """Feed candidates through the safety-gated engine and record behaviour.

    Writes unique/unexpected rows via ``reporter`` and returns the summary dict
    enriched with a ``discovery`` list of every target that returned data.
    """
    deadline = time.monotonic() + wall
    findings: list[dict[str, object]] = []
    seen_targets: set[str] = set()

    for candidate in candidates:
        if time.monotonic() > deadline:
            break
        if send_cap is not None and engine.sent >= send_cap:
            # Stop transmitting once the live cap is hit; keep classifying.
            engine.live = False

        outcome = engine.consider(candidate.apdu_hex)
        sw, resp = _split_response(outcome)
        transport_error = (
            outcome.error
            if outcome.error and outcome.classification.value == "ALLOWED"
            else None
        )
        result = ProbeResult(
            apdu_hex=candidate.apdu_hex,
            command=candidate.command,
            classification=outcome.classification.value,
            malformed=candidate.malformed,
            sent=outcome.sent,
            sw=sw,
            resp_hex=resp,
            transport_error=transport_error,
        )
        verdict = novelty.evaluate(result)
        reporter.note_considered(sw, outcome.sent)
        reporter.report(
            BehaviourRecord(
                mode=f"explore_{angle}",
                phase=phase,
                apdu=candidate.apdu_hex,
                tag=candidate.tag,
                command=candidate.command,
                classification=outcome.classification.value,
                sent=outcome.sent,
                sw=sw,
                resp=resp,
                resp_fingerprint=verdict.fingerprint,
                novelty=list(verdict.novelty),
                repeat_consistency="not_tested",
                severity=verdict.severity,
            )
        )

        if outcome.sent and sw_indicates_data(sw) and candidate.target not in seen_targets:
            seen_targets.add(candidate.target)
            findings.append(
                {
                    "target": candidate.target,
                    "command": candidate.command,
                    "sw": sw,
                    "resp_fingerprint": verdict.fingerprint,
                }
            )

    summary = dict(reporter.finalize(distinct_signatures=novelty.distinct_signatures()))
    summary["angle"] = angle
    summary["discovery"] = findings
    reporter.summary_path.write_text(json.dumps(summary, indent=2) + "\n")
    return summary
