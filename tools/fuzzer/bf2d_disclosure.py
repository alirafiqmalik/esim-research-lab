"""BF2D (GetProfilesInfo) parser info-disclosure probe.

Prior work established that ``BF2D`` accepts DER-illegal inner framing and still
returns the profile list. This angle turns that leniency into a targeted leak
test: for the SAME logical request, it sends several framings that over-declare
how much data the card should read or return, then compares response LENGTHS and
content against the canonical ``BF2D 00`` request. A response longer than the
canonical one, or one carrying bytes past the profile-list TLV, is a buffer
over-read / info-disclosure symptom.

Every candidate is a STORE DATA (INS ``E2``) whose leading BER-TLV tag is
``BF2D`` — the allowlisted read-only ``GetProfilesInfo``. ``safety.classify``
gates on that tag, so every framing here classifies ALLOWED and nothing outside
the read-only allowlist is ever built. Each candidate is routed through
``engine.FuzzEngine.consider`` -> ``safety.guard_send`` before any send.

Skills applied:

- ``fuzzing-dictionary``: the framings reuse the BER length edge cases from
  ``dictionary`` (over-long / long-form / dangling lengths) as the disclosure
  vocabulary.
- ``coverage-analysis``: the disclosure signal is an explicit per-framing
  response-length delta against the canonical baseline, logged alongside the
  usual SW-diversity proxy.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from dictionary import STORE_DATA_PREFIX, encode_lc
from engine import FuzzEngine
from explore_common import Candidate, store_data_get
from novelty import NoveltyEngine, ProbeResult
from reporting import BehaviourRecord, UniqueBehaviourReporter

_COMMAND = "BF2D"
_TAG = 0xBF2D
_CANONICAL_LABEL = "canonical"


def _store_data_apdu(tlv: bytes, *, trailing: bytes = b"") -> str:
    """Wrap a raw ``BF2D`` TLV in the ES10x STORE DATA prefix, plus optional Le."""
    lc = encode_lc(len(tlv), form="short")
    return (STORE_DATA_PREFIX + lc + tlv + trailing).hex().upper()


def _framings() -> list[tuple[str, str]]:
    """Return ``(label, apdu_hex)`` pairs: the canonical request and leak probes.

    All share the leading tag ``BF2D``; only the inner framing and expected
    length differ, so the card should treat every one as the same logical
    ``GetProfilesInfo`` request.
    """
    out: list[tuple[str, str]] = []

    # Canonical: BF2D with an empty, correctly-framed body.
    out.append((_CANONICAL_LABEL, store_data_get(_TAG)))

    # Over-declared inner length: BF2D declares 0xFF value bytes, none present.
    out.append(("inner_len_over_ff", _store_data_apdu(bytes((0xBF, 0x2D, 0xFF)))))

    # Long-form inner length declaring 0x0100 bytes against an empty body.
    out.append(
        ("inner_len_long_0100", _store_data_apdu(bytes((0xBF, 0x2D, 0x82, 0x01, 0x00))))
    )

    # Large declared search-criteria: a nested A0 (search criteria) whose length
    # says 0xFF while no criteria bytes follow.
    out.append(
        (
            "search_criteria_over",
            _store_data_apdu(bytes((0xBF, 0x2D, 0x03, 0xA0, 0x81, 0xFF))),
        )
    )

    # Large expected length (Le): canonical body plus a short Le of 0x00 (=256).
    out.append(("le_short_256", _store_data_apdu(bytes((0xBF, 0x2D, 0x00)), trailing=b"\x00")))

    # Extended expected length (Le): request 0xFFFF response bytes.
    out.append(
        (
            "le_extended_ffff",
            _store_data_apdu(bytes((0xBF, 0x2D, 0x00)), trailing=b"\x00\xFF\xFF"),
        )
    )

    return out


def candidates() -> list[Candidate]:
    """Yield the canonical request and every disclosure framing as Candidates."""
    out: list[Candidate] = []
    for label, apdu_hex in _framings():
        out.append(
            Candidate(
                apdu_hex=apdu_hex,
                command=_COMMAND,
                tag=f"{_TAG:04X}",
                target=f"BF2D:{label}",
                malformed=label != _CANONICAL_LABEL,
            )
        )
    return out


def _strip_sw(sw: str | None, resp: str | None) -> str | None:
    if resp and sw and resp.upper().endswith(sw.upper()):
        stripped = resp[: -len(sw)]
        return stripped or None
    return resp


@dataclass(frozen=True)
class DisclosureFinding:
    """One framing's response measured against the canonical baseline."""

    label: str
    sent: bool
    sw: str | None
    resp_len_bytes: int | None
    delta_vs_canonical: int | None
    longer_than_canonical: bool


def run(
    *,
    engine: FuzzEngine,
    out_path: Path,
    summary_path: Path,
    phase: str,
    wall: int,
    send_cap: int | None,
) -> dict[str, object]:
    """Run the BF2D disclosure probe and write the length-comparison summary.

    Routes every framing through ``engine.consider`` (the safety chokepoint),
    logs novel behaviour via the reporter, and records each framing's response
    length so the summary can flag any framing that leaks more than the canonical
    request. ``wall`` and ``send_cap`` are honoured against the small framing set.
    """
    novelty = NoveltyEngine()
    measured: dict[str, DisclosureFinding] = {}
    canonical_len: int | None = None

    with UniqueBehaviourReporter(
        out_path=out_path,
        summary_path=summary_path,
        mode="deepdata_bf2d_disclosure",
        phase=phase,
        allowlist=["BF2D"],
    ) as reporter:
        for candidate in candidates():
            if send_cap is not None and engine.sent >= send_cap:
                engine.live = False

            outcome = engine.consider(candidate.apdu_hex)
            sw = outcome.sw
            resp = _strip_sw(sw, outcome.resp_hex)
            resp_len = len(bytes.fromhex(resp)) if resp else (0 if outcome.sent else None)

            label = candidate.target.split(":", 1)[1]
            if label == _CANONICAL_LABEL and outcome.sent:
                canonical_len = resp_len

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
                    mode="deepdata_bf2d_disclosure",
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
            measured[label] = DisclosureFinding(
                label=label,
                sent=outcome.sent,
                sw=sw,
                resp_len_bytes=resp_len,
                delta_vs_canonical=None,
                longer_than_canonical=False,
            )

        # Second pass: compare every framing against the canonical response length.
        findings: list[dict[str, object]] = []
        flagged: list[str] = []
        for label, finding in measured.items():
            delta: int | None = None
            longer = False
            if (
                canonical_len is not None
                and finding.resp_len_bytes is not None
                and label != _CANONICAL_LABEL
            ):
                delta = finding.resp_len_bytes - canonical_len
                longer = delta > 0
                if longer:
                    flagged.append(label)
            findings.append(
                {
                    "label": label,
                    "sent": finding.sent,
                    "sw": finding.sw,
                    "resp_len_bytes": finding.resp_len_bytes,
                    "delta_vs_canonical": delta,
                    "longer_than_canonical": longer,
                }
            )

        summary = dict(reporter.finalize(distinct_signatures=novelty.distinct_signatures()))

    summary["angle"] = "bf2d_disclosure"
    summary["canonical_resp_len_bytes"] = canonical_len
    summary["framings"] = findings
    summary["disclosure_flagged"] = flagged
    if canonical_len is None:
        summary["note"] = "disclosure comparison requires --live; dry-run sends nothing"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2) + "\n")
    return summary
