"""confirmation-code-control-absent (channel C2a): Confirmation Code is parsed
but never implemented anywhere downstream -- a distinct category from D1/D2/D4
(a control that exists and is bypassable). Here the control simply does not
exist in the testbed's flow at all, so it cannot be "found" as a bypass; it is
recorded once, by static inspection, so the report doesn't conflate "control
absent" with "control present but bypassable" (very different remediation and
very different claims about what the campaign actually demonstrated).

Ground truth (static inspection, re-verified at the time this module was
written):
  - codec.ActivationCode.cc_required: bool is parsed from the AC's optional
    trailing "$1" field (codec.py) but the field is never read by lpa.py or
    smdp.py's order-registration path (mno.Mno.order_profile/smdp.Order carry
    no cc_required at all).
  - smdp.py's authenticate_client() hardcodes `cc_required_flag = b"\\x00"`
    unconditionally when building smdpSigned2, regardless of the AC or order.
  - euicc.py's verify_smdp_signature2() unpacks that flag into
    `_cc_required_field` and discards it (leading underscore) -- it is
    verified as part of the signed blob's integrity, but its VALUE is never
    branched on.
  - No code path in lpa.py ever prompts for, collects, or forwards a
    confirmation code value to the SM-DP+.

Net effect: SGP.22's Confirmation Code anti-fraud mechanism (intended to
require explicit, out-of-band user confirmation before an order proceeds) is
entirely unwired in this testbed. This is a testbed completeness gap, not a
protocol/ecosystem finding -- there is nothing to bypass because nothing was
implemented. Recorded as TESTBED-ARTIFACT so it is not miscounted alongside
the bypass-class REAL-GAP findings elsewhere in the ledger.

Runnable: ./venv/bin/python -m testbed.ecosim.campaign.note_confirmation_code_absent
"""

from __future__ import annotations

import inspect

from .. import lpa, mno, smdp
from . import record

ARTIFACT_PATH = "testbed/ecosim/campaign/note_confirmation_code_absent.py"
SPEC_SECTION = "SGP.22 Confirmation Code Required Flag (SS3.1.1 / SS5.7.5 ccRequiredFlag)"


def _static_checks() -> dict[str, bool]:
    order_src = inspect.getsource(mno.Mno.order_profile)
    lpa_src = "".join(
        inspect.getsource(getattr(lpa.Lpa, name))
        for name, _ in inspect.getmembers(lpa.Lpa, predicate=inspect.isfunction)
    )
    smdp_src = inspect.getsource(smdp.SmDpPlus.authenticate_client)
    return {
        "order_profile_reads_cc_required": "cc_required" in order_src,
        "lpa_reads_or_prompts_cc_required": "cc_required" in lpa_src or "confirmation" in lpa_src.lower(),
        "smdp_hardcodes_cc_required_flag": 'cc_required_flag = b"\\x00"' in smdp_src,
    }


def main() -> None:
    checks = _static_checks()

    finding = record.Finding(
        round=2,
        direction="confirmation-code-control-absent",
        channel="C2a",
        spec_section=SPEC_SECTION,
        hypothesis=(
            "codec.ActivationCode.cc_required is parsed from the activation code but is never "
            "consulted anywhere downstream (order registration, AuthenticateClient's ccRequiredFlag, "
            "or an actual user-facing confirmation prompt), so the Confirmation Code anti-fraud "
            "control is entirely unimplemented rather than implemented-and-bypassable."
        ),
        mutation="none -- static inspection of mno.py/lpa.py/smdp.py, not a fuzz/attack scenario.",
        observed=(
            f"order_profile_reads_cc_required={checks['order_profile_reads_cc_required']} "
            f"(mno.Mno.order_profile and smdp.Order carry no cc_required field); "
            f"lpa_reads_or_prompts_cc_required={checks['lpa_reads_or_prompts_cc_required']} "
            f"(no prompt/forward path exists in lpa.Lpa); "
            f"smdp_hardcodes_cc_required_flag={checks['smdp_hardcodes_cc_required_flag']} "
            f"(smdp.py's authenticate_client always signs ccRequiredFlag=0x00 in smdpSigned2, "
            f"regardless of the activation code or order); euicc.py's verify_smdp_signature2 "
            f"unpacks that flag into `_cc_required_field` and discards it (never branched on)."
        ),
        classification=record.ARTIFACT,
        rationale=(
            "This is a testbed completeness gap, not a protocol-level finding: there is no "
            "implemented control here to bypass, so 'accepted' is not meaningful for it. Recording "
            "it as its own category so the final report does not present 'confirmation code missing' "
            "as equivalent evidence to the bypass-class findings (D1/D2/D4), which demonstrate an "
            "IMPLEMENTED, spec-mandated check failing to hold under attack. Whether real SM-DP+/LPA "
            "deployments correctly implement and enforce Confirmation Code is a separate, unanswered "
            "question this testbed cannot speak to until the control is actually built and then fuzzed."
        ),
        severity="low",
        artifact_path=ARTIFACT_PATH,
    )

    record.append(finding)
    print(f"recorded 1 finding: {finding.direction} / {finding.classification}")
    print(checks)


if __name__ == "__main__":
    main()
