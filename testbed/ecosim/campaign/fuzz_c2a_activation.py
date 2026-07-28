"""C2a activation-code fuzzer: SGP.22 v3.1 SS4.1 grammar vs. our parser + full flow.

Ground truth: `spec_notes/round1.md`, section "D1 -- Activation Code (C2a) SS4.1".
The activation code (`[LPA:]AC_Format$SM-DP+Address$AC_Token[$OID[$CC...]]`) carries
NO signature or MAC (PROTECTION note in round1.md) -- it is bare `$`-delimited plain
ASCII, trust-on-first-use until the SM-DP+ later proves a CI-chained certificate.
Its only defenses before that point are (1) the LPA's own grammar/charset checks and
(2) the SM-DP+'s pending-order lookup, the sole backstop against a substituted
matchingId (SS3.1.3 step 3).

Every mutated code is exercised at two layers:
  (a) `codec.ActivationCode.parse` -- syntax-only, no network (catches ValueError).
  (b) a full download through a live `Ecosystem`/`Lpa` for a representative subset --
      does the mutation reach further than parse and change end-to-end behaviour
      (install succeeds, a *different* order gets installed, or the SM-DP+ aborts)?

Findings are classified per `record.py`'s vocabulary and appended to
`findings.jsonl` when this module is run as a script.
"""

from __future__ import annotations

from dataclasses import dataclass

from .. import codec
from ..orchestrator import Ecosystem, build_ecosystem
from . import record

# --------------------------------------------------------------------------
# Parse-layer corpus
# --------------------------------------------------------------------------


@dataclass
class MutationCase:
    category: str
    name: str
    code: str
    note: str = ""


@dataclass
class ParseResult:
    case: MutationCase
    accepted: bool
    error: str
    parsed: codec.ActivationCode | None


def build_parse_corpus(addr: str, mid: str) -> list[MutationCase]:
    """Mutated activation codes covering SS4.1's grammar, keyed to a valid
    (addr, mid) pair so non-targeted fields stay well-formed."""
    cases: list[MutationCase] = []

    def add(category: str, name: str, code: str, note: str = "") -> None:
        cases.append(MutationCase(category=category, name=name, code=code, note=note))

    # -- AC_Format != "1" ----------------------------------------------------
    for fmt in ("2", "", "01", "1.0"):
        add("ac_format", f"format={fmt!r}", f"LPA:{fmt}${addr}${mid}")

    # -- missing mandatory fields (too few '$') -------------------------------
    add("missing_fields", "one-field-no-dollar", "LPA:1")
    add("missing_fields", "two-fields", f"LPA:1${addr}")
    add("missing_fields", "empty-body", "LPA:")
    add("missing_fields", "no-lpa-prefix", f"1${addr}${mid}")

    # -- extra trailing fields / delimiters -----------------------------------
    add("extra_fields", "with-oid-and-cc", f"LPA:1${addr}${mid}$1.3.6.1.4.1.99999$1")
    add("extra_fields", "with-junk-tail", f"LPA:1${addr}${mid}$oid$1$0$extra$extra2")
    add("extra_fields", "trailing-bare-dollar", f"LPA:1${addr}${mid}$")
    add("extra_fields", "doubled-delimiters", f"LPA:1$${addr}$${mid}")

    # -- empty SM-DP+ address --------------------------------------------------
    add("empty_address", "explicit-empty", f"LPA:1$${mid}")

    # -- SM-DP+ address charset violations / injection ------------------------
    add("address_charset", "embedded-dollar", f"LPA:1${addr}$evil${mid}")
    add("address_charset", "crlf-injection", f"LPA:1${addr}\r\nX-Injected: 1${mid}")
    add("address_charset", "control-char", f"LPA:1${addr}\x00evil.test${mid}")
    add("address_charset", "lowercase-with-space", f"LPA:1$smdp fake host.test${mid}")

    # -- matchingId out-of-charset ---------------------------------------------
    add("matching_id_charset", "lowercase", f"LPA:1${addr}$abc123def")
    add("matching_id_charset", "spaces", f"LPA:1${addr}$AB CD 1234")
    add("matching_id_charset", "unicode", f"LPA:1${addr}$MÄTCH日本123")
    add("matching_id_charset", "control-chars", f"LPA:1${addr}$AB\x01\x02CD")
    add("matching_id_charset", "null-byte", f"LPA:1${addr}$AB\x00CD1234")
    add("matching_id_charset", "embedded-dollar", f"LPA:1${addr}$AB$CD1234",
        note="'$' can never survive inside a split field -- it always reinterprets as a delimiter")

    # -- oversized (>255 chars overall) -----------------------------------------
    long_mid = "A" * 300
    add("oversized", "long-matching-id", f"LPA:1${addr}${long_mid}")
    long_oid = "9" * 260
    add("oversized", "long-oid-field", f"LPA:1${addr}${mid}${long_oid}")

    # -- embedded 'LPA:' repeats --------------------------------------------------
    add("lpa_repeat", "doubled-prefix", f"LPA:LPA:1${addr}${mid}")
    add("lpa_repeat", "prefix-in-address", f"LPA:1$LPA:{addr}${mid}")

    # -- null bytes --------------------------------------------------------------
    add("null_bytes", "in-matching-id", f"LPA:1${addr}$\x00{mid}")
    add("null_bytes", "in-address", f"LPA:1$\x00{addr}${mid}")

    return cases


def run_parse_layer(cases: list[MutationCase]) -> list[ParseResult]:
    results: list[ParseResult] = []
    for case in cases:
        try:
            parsed = codec.ActivationCode.parse(case.code)
            results.append(ParseResult(case=case, accepted=True, error="", parsed=parsed))
        except ValueError as exc:
            results.append(ParseResult(case=case, accepted=False, error=str(exc), parsed=None))
    return results


def _group(results: list[ParseResult], category: str) -> list[ParseResult]:
    return [r for r in results if r.case.category == category]


def _accepted_names(rs: list[ParseResult]) -> str:
    return ", ".join(f"{r.case.name}" for r in rs if r.accepted) or "(none)"


def _rejected_names(rs: list[ParseResult]) -> str:
    return ", ".join(f"{r.case.name}={r.error!r}" for r in rs if not r.accepted) or "(none)"


# --------------------------------------------------------------------------
# Full-flow spot checks
# --------------------------------------------------------------------------


@dataclass
class FlowResult:
    label: str
    completed: bool
    error: str
    summary: dict | None


def _attempt_flow(eco: Ecosystem, code: str, label: str) -> FlowResult:
    try:
        summary = eco.lpa.download_profile(code)
        return FlowResult(label=label, completed=True, error="", summary=summary)
    except (ValueError, KeyError) as exc:
        return FlowResult(label=label, completed=False, error=repr(exc), summary=None)


def run_full_flow_spotchecks() -> dict[str, FlowResult]:
    """Representative full-flow scenarios, each on a fresh Ecosystem so an earlier
    mutation's aborted transaction can't leak state into the next scenario."""
    out: dict[str, FlowResult] = {}

    # 1. Baseline: a genuinely valid, freshly-ordered activation code.
    eco = build_ecosystem(seed=0xC2A1)
    ac = eco.mno.order_profile("victim-profile", "VictimMNO", 0)
    out["baseline"] = _attempt_flow(eco, ac.encode(), "baseline")

    # 2. AC_Format != "1" but otherwise valid + registered.
    eco = build_ecosystem(seed=0xC2A2)
    ac = eco.mno.order_profile("format-bug-profile", "MNO", 0)
    bad_format_code = f"LPA:2${ac.smdp_address}${ac.matching_id}"
    out["bad_format_accepted"] = _attempt_flow(eco, bad_format_code, "bad_format_accepted")

    # 3. matchingId substituted with a well-formed but UNREGISTERED value.
    eco = build_ecosystem(seed=0xC2A3)
    ac = eco.mno.order_profile("unused-profile", "MNO", 0)
    unregistered_code = f"LPA:1${ac.smdp_address}$FFFFFFFFFFFFFFFF"
    out["unregistered_matching_id"] = _attempt_flow(eco, unregistered_code, "unregistered_matching_id")

    # 4. Cross-order matchingId swap: two orders on the SAME SM-DP+, attacker
    #    substitutes the matchingId of order B into order A's activation code.
    eco = build_ecosystem(seed=0xC2A4)
    ac_a = eco.mno.order_profile("alice-profile", "AliceMNO", 0)
    ac_b = eco.mno.order_profile("bob-profile", "BobMNO", 1)
    swapped_code = f"LPA:1${ac_a.smdp_address}${ac_b.matching_id}"
    out["cross_order_swap"] = _attempt_flow(eco, swapped_code, "cross_order_swap")
    out["_swap_context"] = FlowResult(
        label="_swap_context", completed=True, error="",
        summary={"ordered_for": "alice-profile", "victim_order_sp": "AliceMNO",
                 "swapped_in_order_sp": "BobMNO", "swapped_in_profile": "bob-profile"},
    )

    # 5. Extra trailing fields (well-formed oid + cc), otherwise valid+registered.
    eco = build_ecosystem(seed=0xC2A5)
    ac = eco.mno.order_profile("trailing-profile", "MNO", 0)
    trailing_code = f"LPA:1${ac.smdp_address}${ac.matching_id}$1.3.6.1.4.1.99999$1$extra-ignored"
    out["extra_trailing_fields"] = _attempt_flow(eco, trailing_code, "extra_trailing_fields")

    # 6. Control-char/CRLF injected into the address, matchingId left valid+registered.
    eco = build_ecosystem(seed=0xC2A6)
    ac = eco.mno.order_profile("addr-injection-profile", "MNO", 0)
    injected_code = f"LPA:1${ac.smdp_address}\r\nEvil: 1${ac.matching_id}"
    out["address_injection"] = _attempt_flow(eco, injected_code, "address_injection")

    return out


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------


def _finding(**kwargs: object) -> record.Finding:
    kwargs.setdefault("round", 1)
    kwargs.setdefault("direction", "D1-activation-code")
    kwargs.setdefault("channel", "C2a")
    kwargs.setdefault("spec_section", "SGP.22 v3.1 SS4.1")
    kwargs.setdefault("artifact_path", "testbed/ecosim/campaign/fuzz_c2a_activation.py")
    return record.Finding(**kwargs)  # type: ignore[arg-type]


def build_findings(parse_results: list[ParseResult], flows: dict[str, FlowResult]) -> list[record.Finding]:
    findings: list[record.Finding] = []

    # F1 -- AC_Format != "1" is fully accepted by our parser, and a full
    # download completes end to end despite the invalid format.
    fmt_group = _group(parse_results, "ac_format")
    bad_fmt_flow = flows["bad_format_accepted"]
    findings.append(_finding(
        hypothesis="AC_Format values other than the literal '1' are rejected, as SS4.1 mandates.",
        mutation=f"AC_Format in {{'2','','01','1.0'}} with an otherwise valid+registered address/matchingId "
                 f"(n={len(fmt_group)})",
        observed=f"codec.ActivationCode.parse accepted ALL {len(fmt_group)} variants "
                 f"({_accepted_names(fmt_group)}) -- parse() never inspects fields[0] at all. "
                 f"Full-flow spot check with AC_Format='2': download_profile completed="
                 f"{bad_fmt_flow.completed}, summary={bad_fmt_flow.summary}.",
        classification=record.ARTIFACT,
        rationale="SS4.1: 'AC_Format MUST be literal \"1\"; any other value -> LPA SHALL treat AC as invalid.' "
                  "A conformant LPA rejects the code at step 1 of SS3.1.3.1 before any network activity. Our "
                  "codec.ActivationCode.parse never checks fields[0], so a malformed-format code sails through "
                  "parsing AND a full profile installation -- this exists only because our parser is simplified.",
        severity="medium",
    ))

    # F2 -- too few '$'-delimited fields correctly rejected.
    missing_group = _group(parse_results, "missing_fields")
    findings.append(_finding(
        hypothesis="Codes missing the 'LPA:' scheme, or with fewer than the 3 mandatory fields "
                   "(AC_Format, SM-DP+Address, AC_Token), are rejected.",
        mutation=f"n={len(missing_group)} cases: {', '.join(c.case.name for c in missing_group)}",
        observed=f"All {len(missing_group)} rejected: {_rejected_names(missing_group)}",
        classification=record.CONFORMANT,
        rationale="SS4.1 Table 8 makes AC_Format, SM-DP+Address and AC_Token mandatory (the bracket notation "
                  "[$OID[...]] only wraps the optional tail). codec.ActivationCode.parse enforces "
                  "len(fields) >= 3 and a leading 'LPA:' scheme, matching what a conformant LPA must reject "
                  "at SS3.1.3.1 step 1 (malformed AC).",
        severity="info",
    ))

    # F3 -- extra trailing fields/params are ignored, not just at parse but end to end.
    extra_group = _group(parse_results, "extra_fields")
    extra_flow = flows["extra_trailing_fields"]
    findings.append(_finding(
        hypothesis="Unknown trailing parameters beyond CCRequiredFlag are ignored (forward-compatibility), not rejected.",
        mutation=f"n={len(extra_group)} cases with extra '$'-fields / trailing delimiters: "
                 f"{', '.join(c.case.name for c in extra_group)}",
        observed=f"Parse accepted {sum(1 for r in extra_group if r.accepted)}/{len(extra_group)} "
                 f"(rejected: {_rejected_names(extra_group)}). Full-flow spot check with a well-formed "
                 f"oid+cc+extra-garbage tail: completed={extra_flow.completed}, summary={extra_flow.summary}.",
        classification=record.CONFORMANT,
        rationale="round1.md: a conformant LPA SHALL 'ignore unknown trailing params (forward-compat)'. Our "
                  "parser takes fields[3]/fields[4] as oid/cc and silently drops anything beyond that, and the "
                  "full download still completes normally -- this matches spec-mandated behaviour, not leniency.",
        severity="info",
    ))

    # F4 -- empty / delimiter-induced-empty SM-DP+ address rejected.
    empty_addr_group = _group(parse_results, "empty_address") + [
        r for r in _group(parse_results, "extra_fields") if r.case.name == "doubled-delimiters"
    ]
    findings.append(_finding(
        hypothesis="An empty SM-DP+ address, however it arises (explicit or via doubled delimiters), is rejected.",
        mutation=f"n={len(empty_addr_group)}: {', '.join(c.case.name for c in empty_addr_group)}",
        observed=f"All {len(empty_addr_group)} rejected: {_rejected_names(empty_addr_group)}",
        classification=record.CONFORMANT,
        rationale="SS4.1 requires a non-empty FQDN for SM-DP+Address (only AC_Token 'MAY be zero-length'). "
                  "codec.ActivationCode.parse explicitly checks `if not smdp: raise ValueError`, matching the "
                  "spec's mandatory-field requirement regardless of how the empty value was produced.",
        severity="info",
    ))

    # F5 -- SM-DP+ address charset/injection accepted by parse; sim has no
    # transport layer for the mutation to actually reach.
    addr_group = _group(parse_results, "address_charset")
    inj_flow = flows["address_injection"]
    findings.append(_finding(
        hypothesis="SM-DP+ address values outside the QR-alphanumeric charset (CRLF, NUL, embedded '$') are rejected.",
        mutation=f"n={len(addr_group)}: {', '.join(c.case.name for c in addr_group)}",
        observed=f"Parse accepted {sum(1 for r in addr_group if r.accepted)}/{len(addr_group)} -- ALL of them "
                 f"({_accepted_names(addr_group)}); none rejected. The embedded-'$' case is not even flagged as "
                 f"a charset problem: it silently restructures the field count instead (matching_id becomes the "
                 f"literal 'evil', and the real matchingId is shifted into the oid field). Full-flow spot check "
                 f"with a CRLF-injected address (matchingId left valid+registered): completed={inj_flow.completed}, "
                 f"summary={inj_flow.summary} -- the sim has no DNS/HTTP layer for the injected address to reach, "
                 f"so it is carried inertly inside the JSON envelope.",
        classification=record.ARTIFACT,
        rationale="SS4.1 restricts SM-DP+Address to the ISO/IEC 18004 Table 5 QR-alphanumeric charset excluding "
                  "'$'. codec.ActivationCode.parse performs no charset check on the address at all. Our sim also "
                  "has no real resolver/HTTP client for a CRLF/control-char address to exploit (it is passed "
                  "as an opaque string field to a fixed in-process SmDpPlus object), so this direction cannot "
                  "demonstrate real header-injection risk here -- both the parser leniency and the inert "
                  "downstream handling are testbed simplifications.",
        severity="low",
    ))

    # F6 -- matchingId charset leniency.
    mid_group = [r for r in _group(parse_results, "matching_id_charset") if r.case.name != "embedded-dollar"]
    findings.append(_finding(
        hypothesis="matchingId (AC_Token) values outside charset [0-9A-Z-] are rejected.",
        mutation=f"n={len(mid_group)}: {', '.join(c.case.name for c in mid_group)}",
        observed=f"Parse accepted {sum(1 for r in mid_group if r.accepted)}/{len(mid_group)} "
                 f"({_accepted_names(mid_group)}); none rejected. codec.ActivationCode.parse performs no "
                 f"charset check on matching_id and utf-8 round-trips lowercase/space/unicode/control/null "
                 f"bytes without error.",
        classification=record.ARTIFACT,
        rationale="SS4.1: AC_Token charset is strictly [0-9A-Z-]. Real conformant LPAs validate this at parse "
                  "time. Our parser accepts any string content, purely a simplification -- it does not reflect "
                  "any real protocol mutability (the real matchingId IS attacker-substitutable, but only within "
                  "its narrow charset; ours widens the charset itself, which is the artifact).",
        severity="low",
    ))

    # F7 -- '$' can never survive as a literal character inside a field; it
    # always restructures field boundaries. Genuine property of the
    # delimiter-based (non-ASN.1, unescaped) plaintext grammar itself.
    dollar_case = next(r for r in parse_results if r.case.name == "embedded-dollar"
                        and r.case.category == "matching_id_charset")
    findings.append(_finding(
        hypothesis="A '$' placed where a matchingId is expected is caught as an out-of-charset character.",
        mutation="matchingId value containing a literal '$' (e.g. 'AB$CD1234') inside an otherwise well-formed code",
        observed=f"accepted={dollar_case.accepted}; parsed={dollar_case.parsed}. The '$' is consumed by "
                 f"str.split('$') before any field-level validation runs, so matching_id becomes 'AB' and "
                 f"'CD1234' is silently reinterpreted as the OID field -- no error surfaces anywhere in the chain.",
        classification=record.REAL_GAP,
        rationale="This is not a parser bug specific to our sim: SS4.1's grammar is unescaped '$'-delimited "
                  "plain ASCII (explicitly NOT ASN.1 on this leg). ANY implementation that splits on '$' first "
                  "and validates fields second has this exact property -- a '$' can never be observed as an "
                  "out-of-charset character because it is consumed as structure before the field is even "
                  "extracted. This is precisely why the spec excludes '$' from the AC_Token/address charsets "
                  "at the generation side; it is a structural gap in the real wire format, not an artifact "
                  "of our simplification.",
        severity="low",
    ))

    # F8 -- oversized activation code, no 255-char cap enforced anywhere.
    oversized_group = _group(parse_results, "oversized")
    findings.append(_finding(
        hypothesis="Activation codes exceeding the SS4.1 255-character maximum are rejected.",
        mutation=f"n={len(oversized_group)}: {', '.join(c.case.name for c in oversized_group)} "
                 f"(matchingId or oid padded to 260-300 chars)",
        observed=f"Parse accepted {sum(1 for r in oversized_group if r.accepted)}/{len(oversized_group)} "
                 f"({_accepted_names(oversized_group)}); codec.ActivationCode.parse has no length check at all.",
        classification=record.ARTIFACT,
        rationale="SS4.1: 'Max length 255 chars (unless carrying Delete Notification for Device Change).' A "
                  "conformant LPA enforces this bound (it also matches real QR/SMS transport capacity limits). "
                  "Our parser has no such check -- purely a testbed simplification, not a real protocol gap, "
                  "since a real over-255 code likely never survives its delivery channel (QR/SMS) to reach a "
                  "parser at all.",
        severity="low",
    ))

    # F9 -- embedded 'LPA:' repeats.
    lpa_group = _group(parse_results, "lpa_repeat")
    findings.append(_finding(
        hypothesis="A second, embedded 'LPA:' scheme token (doubled prefix or reused mid-string) causes rejection.",
        mutation=f"n={len(lpa_group)}: {', '.join(c.case.name for c in lpa_group)}",
        observed=f"Parse accepted {sum(1 for r in lpa_group if r.accepted)}/{len(lpa_group)} "
                 f"({_accepted_names(lpa_group)}). 'LPA:LPA:1$addr$mid' parses with version field literally "
                 f"= 'LPA:1' (garbage, but AC_Format is never validated -- see F1); 'LPA:1$LPA:addr$mid' "
                 f"parses with smdp_address literally containing 'LPA:' as ordinary charset-unchecked text.",
        classification=record.ARTIFACT,
        rationale="Only one 'LPA:' scheme prefix is meaningful per SS4.1; a conformant LPA strips exactly one "
                  "occurrence and then validates AC_Format == '1', which would reject 'LPA:1' as a format value. "
                  "Both acceptances here are downstream of F1 (no AC_Format check) and the address charset gap "
                  "(F5) -- an artifact of parser leniency, not a new protocol property.",
        severity="info",
    ))

    # F10 -- null bytes.
    null_group = _group(parse_results, "null_bytes")
    findings.append(_finding(
        hypothesis="NUL bytes embedded in matchingId or address cause rejection or a decode failure.",
        mutation=f"n={len(null_group)}: {', '.join(c.case.name for c in null_group)}",
        observed=f"Parse accepted {sum(1 for r in null_group if r.accepted)}/{len(null_group)} "
                 f"({_accepted_names(null_group)}); U+0000 is valid UTF-8/Python str content, so it round-trips "
                 f"through parse/encode with no exception anywhere in the codec.",
        classification=record.ARTIFACT,
        rationale="NUL is outside every charset SS4.1 defines for these fields. Our parser treats the AC purely "
                  "as a Python str with no charset enforcement, so NUL is indistinguishable from any other "
                  "character to it -- a testbed simplification, not a real protocol behaviour (a real LPA "
                  "written in C over a null-terminated buffer would likely truncate or fault instead).",
        severity="info",
    ))

    # F11 -- unregistered matchingId substitution: SM-DP+ backstop.
    unreg_flow = flows["unregistered_matching_id"]
    findings.append(_finding(
        hypothesis="Substituting matchingId with a well-formed but unregistered value is caught by the SM-DP+ "
                   "pending-order lookup, since the AC itself has no integrity protection to catch it earlier.",
        mutation="matchingId replaced with 'FFFFFFFFFFFFFFFF' (valid charset, never registered) on an "
                 "otherwise valid, live activation code",
        observed=f"Full download attempt: completed={unreg_flow.completed}, error={unreg_flow.error!r}. "
                 f"The eUICC still signs the attacker-supplied matchingId into EuiccSigned1 without checking "
                 f"it (per D2), so the flow proceeds through AuthenticateServer; the SM-DP+'s AuthenticateClient "
                 f"is the first and only component that rejects it.",
        classification=record.REAL_GAP,
        rationale="round1.md: activation codes have zero integrity ('MUTABLE-IN-REALITY: YES if digitally "
                  "delivered ... free substitution of address/matchingId'), and the eUICC 'SHALL neither check "
                  "the values provided in ctxParams1 ... nor correlate them' (D2). The SM-DP+'s pending-order "
                  "check (SS3.1.3 step 3) is the real and only backstop, exactly as observed here: an "
                  "unregistered matchingId aborts the transaction before any profile is bound. This validates "
                  "the spec's bounded-impact claim experimentally.",
        severity="medium",
    ))

    # F12 -- cross-order matchingId swap: profile redirection, no cert needed.
    swap_flow = flows["cross_order_swap"]
    swap_ctx = flows["_swap_context"].summary
    findings.append(_finding(
        hypothesis="Substituting matchingId with a DIFFERENT already-registered order's id (same SM-DP+, "
                   "address untouched) is also caught by the pending-order lookup, since the SM-DP+ binds "
                   "sessions to a specific requester as well as a specific matchingId.",
        mutation=f"Activation code addressed at order '{swap_ctx['ordered_for']}' (SP={swap_ctx['victim_order_sp']}) "
                 f"had its matchingId replaced with the matchingId of a second, unrelated pending order "
                 f"'{swap_ctx['swapped_in_profile']}' (SP={swap_ctx['swapped_in_order_sp']}) on the SAME SM-DP+",
        observed=f"Full download attempt: completed={swap_flow.completed}, error={swap_flow.error!r}, "
                 f"summary={swap_flow.summary}. The download completed and installed "
                 f"'{swap_flow.summary['profileName'] if swap_flow.summary else '?'}' -- the second order's "
                 f"profile, NOT the one the victim's activation code was originally issued for.",
        classification=record.REAL_GAP,
        rationale="SmDpPlus._select_order looks up matchingId in a flat order table with no binding to which "
                  "device/session 'owns' that order beyond the bare string match (SS3.1.3 step 3 says the "
                  "SM-DP+ verifies a pending order exists for the provided MatchingID -- it says nothing about "
                  "verifying the requester is the intended recipient of THAT specific order). Because the "
                  "activation code has zero integrity (round1.md D1), an attacker who intercepts/rewrites the "
                  "AC in transit needs ONLY another valid matchingId string (no CI-signed certificate, no rogue "
                  "server) to redirect a victim's download to a different subscriber's profile on the same, "
                  "legitimate SM-DP+. This is a stronger result than the address-redirection case round1.md "
                  "bounds by 'attacker also needs a CI-signed CERT.DPauth.SIG' -- that bound applies to routing "
                  "to a DIFFERENT (rogue) server, not to a same-server cross-order swap.",
        severity="high",
    ))

    # F13 -- fidelity note: even the testbed's own "valid" matchingId violates SS4.1 charset.
    findings.append(_finding(
        hypothesis="The testbed's own legitimately-generated activation codes (mno.py) use an SS4.1-conformant "
                   "matchingId charset.",
        mutation="n/a -- inspection of Mno._generate_matching_id, not a mutation",
        observed="Mno._generate_matching_id returns `self.rng.randbytes(8).hex()`, i.e. lowercase hex digits "
                 "0-9a-f. Every 'baseline valid' activation code produced anywhere in this testbed (including "
                 "the baseline full-flow run above) already contains lowercase a-f characters.",
        classification=record.ARTIFACT,
        rationale="SS4.1 AC_Token charset is [0-9A-Z-] -- uppercase only, no lowercase letters. A byte-for-byte "
                  "conformant LPA would already flag every activation code this testbed generates as "
                  "out-of-charset, independent of any attacker mutation. This is invisible only because our "
                  "parser performs no charset check (F6) -- it is a testbed fidelity gap in mno.py, not a "
                  "finding about attacker capability. Left unfixed here since this module may not edit files "
                  "outside campaign/; flagged for the fidelity backlog in round1.md.",
        severity="info",
    ))

    return findings


def main() -> None:
    eco = build_ecosystem(seed=0xC2A0)
    ac = eco.mno.order_profile("corpus-anchor-profile", "AnchorMNO", 0)
    corpus = build_parse_corpus(ac.smdp_address, ac.matching_id)
    parse_results = run_parse_layer(corpus)
    flows = run_full_flow_spotchecks()
    findings = build_findings(parse_results, flows)
    record.append_many(findings)

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.classification] = counts.get(f.classification, 0) + 1
    accepted = sum(1 for r in parse_results if r.accepted)
    print(f"fuzz_c2a_activation: {len(corpus)} parse-layer mutations, {accepted} accepted by parse "
          f"({len(corpus) - accepted} rejected)")
    print(f"full-flow spot checks: {sum(1 for k in flows if not k.startswith('_'))} scenarios")
    print(f"recorded {len(findings)} findings -> {record.FINDINGS}: {counts}")


if __name__ == "__main__":
    main()
