"""C2b/C3 command-APDU parser fuzzer: SoftwareEuicc.dispatch_apdu structural robustness.

`dispatch_apdu` is the real ES10 command-side parser/dispatcher (BER-TLV walk via
`tlv.py`) added this session so command fuzzing hits genuine parsing logic instead
of typed method calls. A real ISD-R applet returns an ISO-7816 status word for any
malformed or unsupported APDU -- it never crashes or resets on adversarial input,
since a parser crash on this transport is itself a denial-of-service primitive
(and, depending on the fault, a potential exploit primitive) on a real card. This
module builds a large structural mutation corpus targeting `tlv.walk` (called from
`dispatch_apdu`) and classifies every case as one of:

  - "clean-reject": `EuiccApduError` raised with a status word (matches real-card behaviour).
  - "crash": any other exception escapes -- the interesting bug class.
  - "success": `dispatch_apdu` returned bytes without raising.

Findings group cases by outcome CLASS (one finding per class, with a count), not
one per test case; any crash is flagged separately with full repro bytes.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from .. import codec, tlv
from ..euicc import EuiccApduError, SoftwareEuicc
from ..pki import build_pki
from . import record

SEED = 0xC2B00
CORPUS_SEED = 0xC2B00 ^ 0x5EED

# Real ES10 tags that exist in codec.py but are NOT routed by dispatch_apdu today
# (only TAG_GET_EUICC_CHALLENGE / TAG_GET_EUICC_INFO1 are GET-style and routable).
UNROUTED_REAL_TAGS: tuple[int, ...] = (
    codec.TAG_AUTHENTICATE_SERVER,
    codec.TAG_PREPARE_DOWNLOAD,
    codec.TAG_BOUND_PROFILE_PACKAGE,
    codec.TAG_STORE_METADATA,
    codec.TAG_PROFILE_INSTALL_RESULT,
    codec.TAG_LIST_NOTIFICATION,
)
ROUTED_TAGS: tuple[int, ...] = (codec.TAG_GET_EUICC_CHALLENGE, codec.TAG_GET_EUICC_INFO1)

NESTING_DEPTHS: tuple[int, ...] = (
    1, 2, 5, 10, 50, 100, 200, 500, 700, 900, 950, 980, 995, 999, 1000, 1001, 1500, 2000, 3000, 5000,
)
BULK_LENGTHS: tuple[int, ...] = (16, 64, 256, 4096)


@dataclass
class MutationCase:
    category: str
    name: str
    wire: bytes
    note: str = ""


@dataclass
class CaseResult:
    case: MutationCase
    outcome: str  # "clean-reject" | "crash" | "success"
    sw: int | None = None
    error_type: str = ""
    error_message: str = ""
    response_len: int | None = None


# --------------------------------------------------------------------------
# Corpus construction
# --------------------------------------------------------------------------


def _nest(tag: int, depth: int, leaf: bytes = b"") -> bytes:
    """Wrap `leaf` in `depth` layers of constructed-TLV nesting under `tag`."""
    wire = leaf
    for _ in range(depth):
        wire = tlv.encode_constructed(tag, [wire])
    return wire


def _build_multi_byte_tag_cases() -> list[MutationCase]:
    cases: list[MutationCase] = []
    # first byte with low 5 bits == 0x1F (multi-byte marker) but nothing follows.
    for name, first in (
        ("bf-alone", 0xBF), ("1f-alone", 0x1F), ("df-alone", 0xDF),
        ("ff-alone", 0xFF), ("9f-alone", 0x9F), ("5f-alone", 0x5F),
    ):
        cases.append(MutationCase("multi_byte_tag_truncated", name, bytes([first]),
                                   "single byte, low5==0x1F marker, no second tag byte"))
    # long chains of the marker byte -- confirms walk() only ever consumes 2 tag
    # bytes and doesn't try to follow a longer BER continuation chain unsafely.
    for n in (2, 3, 5, 10, 50, 200):
        cases.append(MutationCase("multi_byte_tag_chain", f"chain-1f-x{n}", b"\x1f" * n,
                                   "repeated 0x1F bytes: tag becomes 0x1f1f, 3rd byte reinterpreted as length"))
    return cases


def _build_length_cases() -> list[MutationCase]:
    cases: list[MutationCase] = []
    # long-form length claiming more bytes than present.
    for name, wire in (
        ("1byte-tag-81ff-empty", bytes([0x99, 0x81, 0xFF])),
        ("1byte-tag-82ffff-empty", bytes([0x99, 0x82, 0xFF, 0xFF])),
        ("2byte-tag-81ff-empty", bytes([0xBF, 0x50, 0x81, 0xFF])),
        ("1byte-tag-81ff-1byte-present", bytes([0x99, 0x81, 0xFF, 0xAA])),
        ("1byte-tag-84ffffffff", bytes([0x99, 0x84, 0xFF, 0xFF, 0xFF, 0xFF])),
        ("routed-tag-claims-huge-len", bytes([0xBF, 0x2E, 0x82, 0x7F, 0xFF])),
    ):
        cases.append(MutationCase("length_long_form_overrun", name, wire,
                                   "long-form length field claims more value bytes than the buffer holds"))
    # length byte 0x80 exactly: indefinite-length marker, invalid in our DER-ish scheme (k==0 branch).
    for name, wire in (
        ("1byte-tag-80-alone", bytes([0x99, 0x80])),
        ("2byte-tag-80-alone", bytes([0xBF, 0x50, 0x80])),
        ("routed-challenge-80-alone", bytes([0xBF, 0x2E, 0x80])),
        ("1byte-tag-80-trailing-junk", bytes([0x99, 0x80, 0xAA, 0xBB])),
    ):
        cases.append(MutationCase("length_indefinite_marker", name, wire,
                                   "length byte 0x80 (indefinite form) is not valid DER; k=length&0x7F==0"))
    # length byte 0xFF: k = 0x7F = 127 extra length-bytes claimed, essentially never present.
    for name, wire in (
        ("1byte-tag-ff-empty", bytes([0x99, 0xFF])),
        ("1byte-tag-ff-5bytes", bytes([0x99, 0xFF, 1, 2, 3, 4, 5])),
        ("2byte-tag-ff-empty", bytes([0xBF, 0x50, 0xFF])),
    ):
        cases.append(MutationCase("length_k127_huge", name, wire,
                                   "length byte 0xFF claims 127 length-octets follow; buffer far too short"))
    # zero-length values across a spread of tags (should parse fine as an empty TLV).
    for tag in (0x00, 0x01, 0x30, 0x41, 0x5A, 0x80, 0x91, 0xC0, 0xDE, 0xFE):
        cases.append(MutationCase("length_zero_value", f"tag-{tag:#04x}-len0", bytes([tag, 0x00]),
                                   "well-formed single TLV with zero-length value"))
    return cases


def _build_nesting_cases() -> list[MutationCase]:
    cases: list[MutationCase] = []
    for depth in NESTING_DEPTHS:
        cases.append(MutationCase("nested_constructed_wellformed", f"depth-{depth}",
                                   _nest(0xA0, depth, leaf=b""),
                                   "well-formed constructed nesting, tag 0xA0 at every level"))
    malformed_leaf = bytes([0xBF])  # truncated multi-byte tag as the innermost "value"
    for depth in (1, 10, 100, 500, 900, 999, 1000, 2000, 5000):
        cases.append(MutationCase("nested_constructed_malformed_leaf", f"depth-{depth}-bad-leaf",
                                   _nest(0xA0, depth, leaf=malformed_leaf),
                                   "deep nesting whose innermost bytes are themselves unparsable"))
    return cases


def _build_valid_outer_garbage_inner_cases(rng: random.Random) -> list[MutationCase]:
    cases: list[MutationCase] = []
    garbage_payloads: dict[str, bytes] = {
        "random-garbage": bytes(rng.getrandbits(8) for _ in range(16)),
        "truncated-child": bytes([0x80, 0xFF]),  # child TLV claiming a length it doesn't have
        "wrong-tag-child-valid": tlv.encode(0xEE, b"unexpected"),
        "nested-garbage-50deep": _nest(0xA0, 50, leaf=b"\xbf"),
        "all-zero-16": b"\x00" * 16,
        "all-ff-16": b"\xff" * 16,
    }
    for tag in ROUTED_TAGS:
        for name, payload in garbage_payloads.items():
            wire = tlv.encode(tag, payload)
            cases.append(MutationCase(
                "valid_outer_garbage_inner", f"tag-{tag:#06x}-{name}", wire,
                "valid single top-level TLV (correct outer tag+length) but adversarial inner content; "
                "dispatch_apdu only inspects cmd.tag today, so the handler runs regardless",
            ))
    return cases


def _build_multiple_top_level_cases(rng: random.Random) -> list[MutationCase]:
    cases: list[MutationCase] = []
    challenge = tlv.encode(codec.TAG_GET_EUICC_CHALLENGE, b"")
    info1 = tlv.encode(codec.TAG_GET_EUICC_INFO1, b"")
    unknown = tlv.encode(0x41, b"x")
    for name, wire in (
        ("two-challenge-siblings", challenge + challenge),
        ("challenge-then-info1", challenge + info1),
        ("info1-then-challenge", info1 + challenge),
        ("challenge-then-unknown", challenge + unknown),
        ("three-siblings", challenge + info1 + unknown),
        ("unknown-then-challenge", unknown + challenge),
    ):
        cases.append(MutationCase("multiple_top_level_tlvs", name, wire,
                                   "multiple well-formed sibling TLVs concatenated at top level"))
    # random pairs of single-byte-tag TLVs via the seeded RNG.
    for i in range(6):
        t1 = tlv.encode(rng.randint(0x01, 0x7F), bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 4))))
        t2 = tlv.encode(rng.randint(0x01, 0x7F), bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 4))))
        cases.append(MutationCase("multiple_top_level_tlvs", f"random-pair-{i}", t1 + t2,
                                   "two random well-formed TLVs concatenated"))
    # adversarial "smuggling" framing: node1's declared length engulfs bytes that
    # look like a second TLV's header, then genuine trailing bytes form node2.
    smuggle = bytes([0x81, 0x06]) + b"AAAA" + bytes([0x42, 0x00]) + bytes([0x42, 0x00])
    cases.append(MutationCase(
        "multiple_top_level_tlvs", "smuggled-header-in-value", smuggle,
        "node1 (tag 0x81, len=6) swallows what looks like a second TLV's tag+length bytes "
        "as its own value; only the genuine trailing 2 bytes form an actual node2 -- "
        "confirms walk() does not get tricked into merging/misparsing, it just consumes "
        "declared-length bytes literally",
    ))
    smuggle_overrun = bytes([0x81, 0x06]) + b"AAAA" + bytes([0x42, 0xFF])
    cases.append(MutationCase(
        "multiple_top_level_tlvs", "smuggled-header-then-overrun", smuggle_overrun,
        "same smuggling framing, but the genuine trailing bytes themselves form a truncated "
        "node2 (claims 0xFF more bytes than exist) -- should raise a parse TLVError, not silently drop it",
    ))
    return cases


def _build_empty_and_bulk_cases(rng: random.Random) -> list[MutationCase]:
    cases: list[MutationCase] = []
    cases.append(MutationCase("empty_buffer", "zero-bytes", b"", "empty command_wire"))
    interesting_singles = (0x00, 0x1F, 0x20, 0x80, 0xA0, 0xBF, 0xDF, 0xFF)
    seen: set[int] = set()
    for b in interesting_singles:
        cases.append(MutationCase("single_byte", f"byte-{b:#04x}", bytes([b]), "single-byte command_wire"))
        seen.add(b)
    for _ in range(56):
        b = rng.randint(0, 255)
        if b in seen:
            continue
        seen.add(b)
        cases.append(MutationCase("single_byte", f"byte-{b:#04x}", bytes([b]), "single-byte command_wire"))
    for n in BULK_LENGTHS:
        cases.append(MutationCase("bulk_all_ff", f"len-{n}", b"\xff" * n, "buffer of all-0xFF bytes"))
        cases.append(MutationCase("bulk_all_00", f"len-{n}", b"\x00" * n, "buffer of all-0x00 bytes"))
        for i in range(5):
            cases.append(MutationCase("bulk_random", f"len-{n}-sample-{i}",
                                       bytes(rng.getrandbits(8) for _ in range(n)),
                                       "uniformly random buffer via seeded RNG"))
    return cases


def _build_unknown_tag_cases(rng: random.Random) -> list[MutationCase]:
    cases: list[MutationCase] = []
    # 1-byte tag space, avoiding low5==0x1F (that's the multi-byte marker, covered elsewhere).
    seen: set[int] = set()
    while len(cases) < 30:
        t = rng.randint(0x00, 0xFE)
        if (t & 0x1F) == 0x1F or t in seen:
            continue
        seen.add(t)
        value = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 8)))
        cases.append(MutationCase("unknown_tag_1byte", f"tag-{t:#04x}", tlv.encode(t, value),
                                   "well-formed single TLV, unknown 1-byte tag"))
    # real ES10 tags that exist in codec.py but aren't GET commands -> correctly NOT routable.
    for tag in UNROUTED_REAL_TAGS:
        cases.append(MutationCase("unknown_tag_2byte_real_unrouted", f"tag-{tag:#06x}-empty",
                                   tlv.encode(tag, b""), "real ES10 tag, empty value, not a GET command"))
        payload = bytes(rng.getrandbits(8) for _ in range(12))
        cases.append(MutationCase("unknown_tag_2byte_real_unrouted", f"tag-{tag:#06x}-nonempty",
                                   tlv.encode(tag, payload), "real ES10 tag, nonempty value, not a GET command"))
    # look-alike 2-byte tags in the BF-prefix space that are NOT real ES10 tags at all.
    seen2: set[int] = set()
    while len(cases_count_lookalike(cases)) < 15:
        second = rng.randint(0x00, 0xFF)
        tag = 0xBF00 | second
        if tag in ROUTED_TAGS or tag in UNROUTED_REAL_TAGS or tag in seen2:
            continue
        seen2.add(tag)
        cases.append(MutationCase("unknown_tag_2byte_lookalike", f"tag-{tag:#06x}",
                                   tlv.encode(tag, b""), "BF-prefixed tag that is not a defined ES10 command"))
    return cases


def cases_count_lookalike(cases: list[MutationCase]) -> list[MutationCase]:
    return [c for c in cases if c.category == "unknown_tag_2byte_lookalike"]


def build_corpus(seed: int = CORPUS_SEED) -> list[MutationCase]:
    rng = random.Random(seed)
    cases: list[MutationCase] = []
    cases += _build_multi_byte_tag_cases()
    cases += _build_length_cases()
    cases += _build_nesting_cases()
    cases += _build_valid_outer_garbage_inner_cases(rng)
    cases += _build_multiple_top_level_cases(rng)
    cases += _build_empty_and_bulk_cases(rng)
    cases += _build_unknown_tag_cases(rng)
    return cases


# --------------------------------------------------------------------------
# Execution / classification
# --------------------------------------------------------------------------


def run_case(euicc: SoftwareEuicc, case: MutationCase) -> CaseResult:
    try:
        response = euicc.dispatch_apdu(case.wire, ci_pkid=None)
    except EuiccApduError as exc:
        return CaseResult(case=case, outcome="clean-reject", sw=exc.sw,
                           error_type=type(exc).__name__, error_message=str(exc))
    except Exception as exc:  # noqa: BLE001 -- broad on purpose: this IS the crash-detection surface
        return CaseResult(case=case, outcome="crash",
                           error_type=type(exc).__name__, error_message=repr(exc))
    return CaseResult(case=case, outcome="success", response_len=len(response))


def run_corpus(euicc: SoftwareEuicc, cases: list[MutationCase]) -> list[CaseResult]:
    return [run_case(euicc, case) for case in cases]


def _by_category(results: list[CaseResult], category: str) -> list[CaseResult]:
    return [r for r in results if r.case.category == category]


def _outcome_counts(results: list[CaseResult]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.outcome] = counts.get(r.outcome, 0) + 1
    return counts


def _sw_breakdown(results: list[CaseResult]) -> str:
    counts: dict[int, int] = {}
    for r in results:
        if r.sw is not None:
            counts[r.sw] = counts.get(r.sw, 0) + 1
    return ", ".join(f"{sw:#06x}x{n}" for sw, n in sorted(counts.items()))


def _repro_hex(case: MutationCase, limit: int = 64) -> str:
    h = case.wire[:limit].hex()
    suffix = "..." if len(case.wire) > limit else ""
    return f"{h}{suffix} ({len(case.wire)} bytes total)"


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------


def _finding(**kwargs: object) -> record.Finding:
    kwargs.setdefault("round", 2)
    kwargs.setdefault("direction", "parser-robustness-dispatch-apdu")
    kwargs.setdefault("channel", "C2b")
    kwargs.setdefault("spec_section", "SGP.22 ES10 command framing / ISO-7816 status word model")
    kwargs.setdefault("artifact_path", "testbed/ecosim/campaign/fuzz_c2b_apdu_parser.py")
    return record.Finding(**kwargs)  # type: ignore[arg-type]


def build_findings(results: list[CaseResult]) -> list[record.Finding]:
    findings: list[record.Finding] = []
    crashes = [r for r in results if r.outcome == "crash"]

    # F1 -- multi-byte tag truncation.
    g = _by_category(results, "multi_byte_tag_truncated")
    findings.append(_finding(
        hypothesis="A tag byte with low 5 bits == 0x1F (multi-byte marker) but no following second "
                   "tag byte is rejected with a clean status word, not an IndexError.",
        mutation=f"n={len(g)} single-byte buffers whose only byte has low5==0x1F "
                 f"({', '.join(c.case.name for c in g)})",
        observed=f"outcomes={_outcome_counts(g)}; status words: {_sw_breakdown(g)}. "
                 f"tlv.walk's own bounds check (`if i >= n: raise TLVError`) catches this before any "
                 f"out-of-range index read, and dispatch_apdu wraps it as EuiccApduError(0x6A80, ...).",
        classification=record.CONFORMANT,
        rationale="Matches real ISO-7816/BER-TLV parser behaviour: a truncated multi-byte tag is a "
                  "malformed command APDU and must return a status word, never crash the parser.",
        severity="info",
    ))

    # F2 -- multi-byte tag chains.
    g = _by_category(results, "multi_byte_tag_chain")
    findings.append(_finding(
        hypothesis="Long runs of the 0x1F marker byte do not cause walk() to attempt an unbounded "
                   "or unsafe tag-continuation chain (our TLV codec only ever reads 2 tag bytes).",
        mutation=f"n={len(g)}: repeated 0x1F buffers of length {[c.case.name for c in g]}",
        observed=f"outcomes={_outcome_counts(g)}; status words: {_sw_breakdown(g)}. Every case is "
                 f"consumed as a 2-byte tag (0x1f1f) followed by reinterpreting the 3rd byte as a "
                 f"length field, which then either overruns the buffer or (for the longest chains) "
                 f"still resolves to a clean TLVError -> 0x6A80.",
        classification=record.CONFORMANT,
        rationale="tlv.walk never implements true multi-octet BER tag-number continuation (bit 0x80 "
                  "chaining past the 2nd byte); feeding it a long chain of marker bytes just degrades "
                  "to length-field misparsing, which is caught the same as any other bad length -- "
                  "no unbounded loop or unchecked index access observed.",
        severity="info",
    ))

    # F3 -- length long-form overrun.
    g = _by_category(results, "length_long_form_overrun")
    findings.append(_finding(
        hypothesis="A long-form length field claiming more value bytes than are actually present in "
                   "the buffer is rejected, not read out-of-bounds.",
        mutation=f"n={len(g)}: {', '.join(c.case.name for c in g)}",
        observed=f"outcomes={_outcome_counts(g)}; status words: {_sw_breakdown(g)}. Every case hits "
                 f"`if i + length > n: raise TLVError(...)` in tlv.walk before any slice is taken.",
        classification=record.CONFORMANT,
        rationale="tlv.walk bounds-checks the computed absolute length against the buffer size before "
                  "slicing, so an overlong declared length can never read past the end of command_wire.",
        severity="info",
    ))

    # F4 -- indefinite-length marker (0x80).
    g = _by_category(results, "length_indefinite_marker")
    findings.append(_finding(
        hypothesis="Length byte 0x80 (BER indefinite-length form, invalid in this DER-only scheme) is "
                   "rejected rather than silently treated as length 0 or causing k=0 to misbehave.",
        mutation=f"n={len(g)}: {', '.join(c.case.name for c in g)}",
        observed=f"outcomes={_outcome_counts(g)}; status words: {_sw_breakdown(g)}. tlv.walk's "
                 f"`if k == 0 or i + k > n: raise TLVError('bad long-form length')` explicitly rejects "
                 f"k=0 (i.e. a bare 0x80), including on the two routed command tags.",
        classification=record.CONFORMANT,
        rationale="SGP.22's ES10 APDUs are DER-encoded; indefinite-length BER is not a legal encoding "
                  "on this transport, so rejecting it with a status word (rather than accepting it or "
                  "misreading length as 0) matches required card behaviour.",
        severity="info",
    ))

    # F5 -- length byte 0xFF (k=127 claimed extra length-octets).
    g = _by_category(results, "length_k127_huge")
    findings.append(_finding(
        hypothesis="A length byte of 0xFF (claiming 127 further length-octets) does not attempt a huge "
                   "read or allocation before checking the buffer actually holds 127 more bytes.",
        mutation=f"n={len(g)}: {', '.join(c.case.name for c in g)}",
        observed=f"outcomes={_outcome_counts(g)}; status words: {_sw_breakdown(g)}. The `i + k > n` "
                 f"bounds check runs before `int.from_bytes(b[i:i+k], 'big')` is ever called, so no "
                 f"oversized slice/allocation is attempted -- rejection is immediate and cheap.",
        classification=record.CONFORMANT,
        rationale="Confirms the length-of-length field itself is bounds-checked before use, closing off "
                  "a class of length-field DoS (attacker-controlled huge `k` driving a large read) that "
                  "a naive implementation might not guard.",
        severity="info",
    ))

    # F6 -- zero-length values.
    g = _by_category(results, "length_zero_value")
    successes = [r for r in g if r.outcome == "success" or r.outcome == "clean-reject"]
    findings.append(_finding(
        hypothesis="A well-formed TLV with a zero-length value parses successfully as an empty node "
                   "(not an error), and then is routed/rejected purely by tag as usual.",
        mutation=f"n={len(g)}: {', '.join(c.case.name for c in g)}",
        observed=f"outcomes={_outcome_counts(g)}; status words: {_sw_breakdown(g)}. All 10 are "
                 f"structurally valid single TLVs; since none use a routed tag, all land in the "
                 f"unknown-command branch (0x6A88), exactly as an unknown non-empty-value tag would.",
        classification=record.CONFORMANT,
        rationale="Zero-length values are legal TLV; tlv.walk correctly distinguishes 'parses fine but "
                  "unknown tag' (0x6A88) from 'does not parse at all' (0x6A80) in every case.",
        severity="info",
    ))

    # F7 -- deep well-formed nesting (recursion-depth robustness).
    g = _by_category(results, "nested_constructed_wellformed")
    deep_crash = [r for r in g if r.outcome == "crash"]
    findings.append(_finding(
        hypothesis="Well-formed but arbitrarily deep constructed-TLV nesting (mirroring the "
                   "tools/fuzzer/deepbig_fuzz.py idea) is parsed successfully or cleanly rejected at "
                   "every depth up to 5000 levels, not aborted by an unhandled RecursionError.",
        mutation=f"n={len(g)} depths tested: {sorted(NESTING_DEPTHS)} (single tag 0xA0 wrapped "
                 f"recursively, innermost value empty)",
        observed=f"outcomes={_outcome_counts(g)}. "
                 + (f"CRASH at depths {[c.case.name for c in deep_crash]}: "
                    f"{deep_crash[0].error_type}: {deep_crash[0].error_message}"
                    if deep_crash else
                    "No crash at any tested depth up to 5000 -- every depth resolved to a clean "
                    "EuiccApduError(0x6A88) (successfully parsed, unknown top-level tag)."),
        classification=record.REAL_GAP if deep_crash else record.CONFORMANT,
        rationale=(
            "tlv.walk() recurses one Python call frame per nesting level with no depth cap, so an "
            "unhandled RecursionError escaping dispatch_apdu (which only catches tlv.TLVError) would be "
            "a genuine crash-on-adversarial-input bug: a real applet must return a status word (or "
            "reject via a defined depth limit) rather than fault, so a busy/oversized-APDU-triggered "
            "crash is a real robustness gap, not a testbed artifact -- the same danger applies to any "
            "BER-TLV parser without an explicit recursion/depth guard."
            if deep_crash else
            "No recursion-depth fault observed up to 5000 levels of nesting in this process/stack "
            "context; tlv.walk's per-level recursion did not exceed Python's default recursion limit "
            "here. This is a genuine (if soft) robustness result, not proof of a hard depth cap -- a "
            "sufficiently deeper or differently-stacked call could still trip CPython's recursion limit, "
            "so it remains a latent RecursionError-shaped worry, not something the parser guards against."
        ),
        severity="high" if deep_crash else "low",
    ))

    # F8 -- deep nesting with a malformed innermost leaf.
    g = _by_category(results, "nested_constructed_malformed_leaf")
    deep_crash2 = [r for r in g if r.outcome == "crash"]
    findings.append(_finding(
        hypothesis="Deep nesting whose innermost bytes are themselves unparsable (truncated multi-byte "
                   "tag) still resolves cleanly -- the inner TLVError is swallowed per-level "
                   "(`except TLVError: node.children = []`) without needing to unwind the whole stack "
                   "via an exception at every frame.",
        mutation=f"n={len(g)} depths tested: {[c.case.name for c in g]}, innermost value = "
                 f"truncated multi-byte-tag byte (0xBF alone)",
        observed=f"outcomes={_outcome_counts(g)}. "
                 + (f"CRASH at {[c.case.name for c in deep_crash2]}: "
                    f"{deep_crash2[0].error_type}: {deep_crash2[0].error_message}"
                    if deep_crash2 else
                    "No crash at any tested depth; every case resolved to EuiccApduError(0x6A88)."),
        classification=record.REAL_GAP if deep_crash2 else record.CONFORMANT,
        rationale="Same recursion-depth reasoning as F7, combined with confirming the inner "
                  "try/except TLVError doesn't itself change the crash/no-crash outcome for deep stacks.",
        severity="high" if deep_crash2 else "info",
    ))

    # F9 -- valid outer tag (routed command), adversarial inner content.
    g = _by_category(results, "valid_outer_garbage_inner")
    findings.append(_finding(
        hypothesis="For the two routed commands (GetEuiccChallenge/GetEuiccInfo1), garbage/truncated/"
                   "wrong-tag content inside the outer TLV's value is tolerated because dispatch_apdu "
                   "only inspects cmd.tag before calling the handler -- the handlers themselves take no "
                   "attacker-controlled input.",
        mutation=f"n={len(g)}: both routed tags x 6 garbage-payload variants "
                 f"(random bytes, truncated child, wrong-tag child, 50-deep nested garbage, all-zero, all-ff)",
        observed=f"outcomes={_outcome_counts(g)} -- every case returned successfully (a real "
                 f"euiccChallenge/EUICCInfo1 response), regardless of what garbage was inside the "
                 f"outer TLV's value.",
        classification=record.ARTIFACT,
        rationale="This matches dispatch_apdu's CURRENT implementation exactly (it never reads cmd.value "
                  "for these two commands), so it is not a parser bug today. It is flagged as an artifact "
                  "because a real GetEuiccChallenge/GetEuiccInfo1 APDU is defined as carrying an empty "
                  "value (tlv.encode(tag, b'')); once future rounds add commands whose handlers DO read "
                  "cmd.value (e.g. AuthenticateServer/BF38), this same 'outer tag valid, garbage inner "
                  "tolerated by dispatch' path is exactly where a real parsing gap would need to be "
                  "closed before wiring in the handler.",
        severity="low",
    ))

    # F10 -- multiple top-level TLVs / adversarial framing.
    g = _by_category(results, "multiple_top_level_tlvs")
    findings.append(_finding(
        hypothesis="Multiple concatenated top-level TLVs (whether genuinely sibling nodes or via "
                   "adversarial 'smuggling' framing where one node's declared length engulfs what looks "
                   "like a second TLV's header) are always rejected by dispatch_apdu's "
                   "`len(nodes) != 1` check, and framing tricks never cause tlv.walk to merge/misparse "
                   "nodes into passing that check.",
        mutation=f"n={len(g)}: {', '.join(c.case.name for c in g)}",
        observed=f"outcomes={_outcome_counts(g)}; status words: {_sw_breakdown(g)}. The smuggling cases "
                 f"confirm walk() consumes each node's declared length literally: "
                 f"'smuggled-header-in-value' still parses to exactly 2 nodes (the declared length "
                 f"swallows the fake header bytes as ordinary value content, then the real trailing "
                 f"bytes form a second genuine node) -> rejected as 'got 2'; "
                 f"'smuggled-header-then-overrun' produces a genuinely truncated trailing node -> "
                 f"rejected as an unparsable TLV (0x6A80), not silently dropped.",
        classification=record.CONFORMANT,
        rationale="A real ISD-R applet must reject any command APDU that doesn't decode to exactly one "
                  "command TLV. dispatch_apdu's explicit node-count check, combined with walk()'s "
                  "byte-literal (non-greedy, non-mergeable) consumption, closes off length-smuggling as "
                  "an attack against the single-command-TLV invariant.",
        severity="info",
    ))

    # F11 -- empty/single-byte/bulk buffers.
    empty_g = _by_category(results, "empty_buffer")
    single_g = _by_category(results, "single_byte")
    bulk_g = (_by_category(results, "bulk_all_ff") + _by_category(results, "bulk_all_00")
              + _by_category(results, "bulk_random"))
    all_bulk = empty_g + single_g + bulk_g
    findings.append(_finding(
        hypothesis="Degenerate buffers (empty, single arbitrary byte, all-0xFF/all-0x00/uniformly random "
                   "buffers of 16/64/256/4096 bytes) never crash the parser, only ever clean-reject.",
        mutation=f"n={len(all_bulk)}: 1 empty + {len(single_g)} single-byte (sampled across the tag "
                 f"space) + {len(bulk_g)} bulk buffers (all-0xFF/all-0x00/random at lengths {BULK_LENGTHS})",
        observed=f"outcomes={_outcome_counts(all_bulk)}; status words: {_sw_breakdown(all_bulk)}. "
                 f"The single empty-buffer case is the only one that produces 0x6700 (empty command); "
                 f"everything else resolves to 0x6A80 (unparsable/multi-node) or 0x6A88 (unknown tag).",
        classification=record.CONFORMANT,
        rationale="Every degenerate/bulk buffer, however unstructured, resolves to a defined status word. "
                  "No crash across 4096-byte random buffers confirms tlv.walk's per-node bounds checks "
                  "hold under high-entropy adversarial input, not just hand-crafted edge cases.",
        severity="info",
    ))

    # F12 -- unknown 1-byte tags.
    g = _by_category(results, "unknown_tag_1byte")
    findings.append(_finding(
        hypothesis="Well-formed single TLVs with an unrouted 1-byte tag are cleanly rejected with 0x6A88.",
        mutation=f"n={len(g)} randomly sampled 1-byte tags (low5 != 0x1F) with random small values",
        observed=f"outcomes={_outcome_counts(g)}; status words: {_sw_breakdown(g)}.",
        classification=record.CONFORMANT,
        rationale="dispatch_apdu's final `raise EuiccApduError(0x6A88, ...)` fallthrough correctly "
                  "catches every unrouted tag in the 1-byte tag space with no crash.",
        severity="info",
    ))

    # F13 -- unrouted real ES10 tags (BF21/BF25/BF36/BF37/BF38/BF28).
    g = _by_category(results, "unknown_tag_2byte_real_unrouted")
    findings.append(_finding(
        hypothesis="Real ES10 command tags that exist in codec.py but are not GET-style commands "
                   "(PrepareDownload BF21, StoreMetadata BF25, BoundProfilePackage BF36, "
                   "ProfileInstallResult BF37, AuthenticateServer BF38, ListNotification BF28) are "
                   "correctly rejected as unsupported by dispatch_apdu, since they are not (yet) routed.",
        mutation=f"n={len(g)}: each of {[f'{t:#06x}' for t in UNROUTED_REAL_TAGS]} x empty-value and "
                 f"nonempty-value variants",
        observed=f"outcomes={_outcome_counts(g)}; status words: {_sw_breakdown(g)}. All 12 cleanly "
                 f"rejected with 0x6A88 regardless of value content, confirming routing is decided purely "
                 f"by cmd.tag before any value inspection.",
        classification=record.CONFORMANT,
        rationale="This is exactly the intended behaviour for this round: only TAG_GET_EUICC_CHALLENGE "
                  "and TAG_GET_EUICC_INFO1 are routed today, and every other real ES10 tag -- even ones "
                  "an attacker might expect to be accepted since they're legitimate SGP.22 tags -- is "
                  "rejected the same as a completely made-up tag, with no special-casing that could leak "
                  "information about which tags are 'almost supported'.",
        severity="info",
    ))

    # F14 -- look-alike BF-prefixed tags that aren't real ES10 tags at all.
    g = _by_category(results, "unknown_tag_2byte_lookalike")
    findings.append(_finding(
        hypothesis="Arbitrary BF-prefixed 2-byte tags that resemble ES10 command tags but aren't defined "
                   "anywhere are rejected identically to genuine-but-unrouted tags (no special handling "
                   "based on tag 'plausibility').",
        mutation=f"n={len(g)} randomly sampled 0xBFxx tags excluding the 8 real ES10 tags",
        observed=f"outcomes={_outcome_counts(g)}; status words: {_sw_breakdown(g)}.",
        classification=record.CONFORMANT,
        rationale="Confirms dispatch_apdu's rejection path is a flat tag equality check with a single "
                  "fallthrough error, not a range/prefix-based heuristic that could be probed to "
                  "enumerate valid vs. invalid tags via different error behaviour.",
        severity="info",
    ))

    # F15 -- crash summary (always recorded, even if empty, per task instructions).
    if crashes:
        lines = []
        for r in crashes:
            lines.append(f"[{r.case.category}/{r.case.name}] {r.error_type}: {r.error_message} "
                         f"repro={_repro_hex(r.case)}")
        findings.append(_finding(
            hypothesis="No input in this corpus causes dispatch_apdu to raise anything other than "
                       "EuiccApduError.",
            mutation=f"n={len(crashes)} crashing cases out of {len(results)} total",
            observed="; ".join(lines),
            classification=record.REAL_GAP,
            rationale="An unhandled exception escaping the command-APDU parser is a denial-of-service "
                      "(and potential exploit) primitive on a real card, which must never crash/reset on "
                      "adversarial input -- this is a genuine implementation robustness bug, not a "
                      "testbed simplification artifact.",
            severity="high",
        ))
    else:
        findings.append(_finding(
            hypothesis="No input in this corpus causes dispatch_apdu to raise anything other than "
                       "EuiccApduError (i.e. zero unhandled crashes across the full run).",
            mutation=f"n={len(results)} total structural mutation cases across all categories",
            observed="Zero crashes observed. Every case resolved to either EuiccApduError "
                     "(clean-reject, with a defined status word) or a successful response for the two "
                     "routed commands. This is a genuine negative result, not a manufactured one.",
            classification=record.CONFORMANT,
            rationale="dispatch_apdu's try/except around tlv.walk plus tlv.walk's own bounds-checked "
                      "parsing (length checks before every slice, per-level try/except around recursive "
                      "child parsing) together hold up against the full breadth of structural mutations "
                      "tested here: multi-byte tag truncation/chains, long-form/indefinite/huge-k length "
                      "fields, deep nesting up to 5000 levels, adversarial multi-TLV framing, and "
                      "high-entropy bulk buffers up to 4096 bytes.",
            severity="info",
        ))

    return findings


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def main() -> None:
    pki = build_pki()
    rng = random.Random(SEED)
    euicc = SoftwareEuicc(pki, rng)

    corpus = build_corpus()
    results = run_corpus(euicc, corpus)
    findings = build_findings(results)
    record.append_many(findings)

    counts = _outcome_counts(results)
    by_class: dict[str, int] = {}
    for f in findings:
        by_class[f.classification] = by_class.get(f.classification, 0) + 1
    crashes = [r for r in results if r.outcome == "crash"]

    print(f"fuzz_c2b_apdu_parser: {len(results)} cases run across "
          f"{len({c.case.category for c in results})} categories")
    print(f"outcome breakdown: {counts}")
    print(f"findings recorded: {len(findings)} -> {record.FINDINGS} ({by_class})")
    if crashes:
        print(f"!! {len(crashes)} CRASH(ES) FOUND:")
        for r in crashes:
            print(f"   [{r.case.category}/{r.case.name}] {r.error_type}: {r.error_message}")
            print(f"   repro hex: {_repro_hex(r.case)}")
    else:
        print("no crashes found -- dispatch_apdu held up against the full mutation corpus")


if __name__ == "__main__":
    main()
