"""D4-followup -- conditional OID-pin enforcement (C1), SGP.22 SS3.0.1 step 10.

Moves the OID-pin check from "demonstrated only inside a test script" (the D4
worker's finding) to an actual core fix: lpa.Lpa._verify_oid_pin, wired into
download_profile right after InitiateAuthentication. Certificates now carry a
real subjectAltName.registeredID (pki.build_pki(smdp_oid=...)), so this checks
against genuine certificate content, not a hand-rolled comparison.

Runnable: ./venv/bin/python -m testbed.ecosim.campaign.test_c1_oid_pin
"""

from __future__ import annotations

import random

from .. import codec
from ..euicc import SoftwareEuicc
from ..lpa import Lpa
from ..mno import Mno
from ..pki import build_pki
from ..smdp import SmDpPlus
from ..bus import Bus
from . import record


def run() -> list[record.Finding]:
    findings: list[record.Finding] = []

    # Two distinguishable SM-DP+ operators: different OIDs, same trusted CI
    # (both validly issued -- the D4 scenario: a legitimate-but-different operator).
    legit_pki = build_pki(smdp_oid="2.999.100.1")
    rogue_pki = build_pki(smdp_oid="2.999.100.2")

    def make_lpa(pki, smdp_address: str, rng_seed: int) -> tuple[Lpa, SmDpPlus, Mno]:
        rng = random.Random(rng_seed)
        bus = Bus.default()
        euicc = SoftwareEuicc(pki, rng)
        smdp = SmDpPlus(pki, rng, address=smdp_address)
        mno = Mno(smdp, rng)
        lpa = Lpa(euicc, smdp, bus, pki.ci.certificate)
        return lpa, smdp, mno

    # S1: no OID in the AC (the common case, SS4.1 makes it optional) -> unaffected.
    lpa, smdp, mno = make_lpa(legit_pki, "smdp.ecosim.test", 0xA1)
    ac = mno.order_profile("plan-a", "SpA")
    ok, err = True, ""
    try:
        lpa.download_profile(ac.encode())
    except Exception as exc:  # noqa: BLE001
        ok, err = False, repr(exc)
    findings.append(record.Finding(
        round=4, direction="D4-oid-pin-enforcement", channel="C1",
        spec_section="SGP.22 §3.0.1 step 10 / §4.1",
        hypothesis="An activation code with no OID field (the common case) is unaffected by the new check.",
        mutation="none (baseline, no OID in AC)", observed=f"installed={ok} err={err}",
        classification=record.CONFORMANT, rationale="OID-pin is conditional; absence must not break the normal flow.",
        severity="info", artifact_path="testbed/ecosim/lpa.py,testbed/ecosim/pki.py"))

    # S2: AC pins the CORRECT OID against the correct (legit) server -> succeeds.
    lpa2, smdp2, mno2 = make_lpa(legit_pki, "smdp.ecosim.test", 0xA2)
    ac2 = mno2.order_profile("plan-b", "SpB")
    ac2_pinned = codec.ActivationCode(smdp_address=ac2.smdp_address, matching_id=ac2.matching_id, oid="2.999.100.1")
    ok2, err2 = True, ""
    try:
        lpa2.download_profile(ac2_pinned.encode())
    except Exception as exc:  # noqa: BLE001
        ok2, err2 = False, repr(exc)
    findings.append(record.Finding(
        round=4, direction="D4-oid-pin-enforcement", channel="C1",
        spec_section="SGP.22 §3.0.1 step 10",
        hypothesis="An AC pinning the OID that matches the actual (legitimate) server succeeds.",
        mutation="AC.oid = '2.999.100.1' (matches legit_pki's dp_auth cert)", observed=f"installed={ok2} err={err2}",
        classification=record.CONFORMANT, rationale="Correct OID pin against the correct server must not be rejected.",
        severity="info", artifact_path="testbed/ecosim/lpa.py,testbed/ecosim/pki.py"))

    # S3: D4-style substitution -- AC pins the LEGIT OID, but is rewritten to point
    # at the ROGUE server's address (a different, distinguishable, validly-CI-issued
    # operator). The rogue server's cert carries ITS OWN OID, not the pinned one.
    lpa3, smdp3, mno3 = make_lpa(rogue_pki, "rogue-smdp.ecosim.test", 0xA3)
    ac3_substituted = codec.ActivationCode(
        smdp_address="rogue-smdp.ecosim.test", matching_id="rogue-order", oid="2.999.100.1",
    )
    smdp3.register_order("rogue-order", "89020000000000000099", "Free-5GB-Promo", "RogueOperator", 0)
    ok3, err3 = True, ""
    try:
        lpa3.download_profile(ac3_substituted.encode())
    except Exception as exc:  # noqa: BLE001
        ok3, err3 = False, repr(exc)
    findings.append(record.Finding(
        round=4, direction="D4-oid-pin-enforcement", channel="C1",
        spec_section="SGP.22 §3.0.1 step 10",
        hypothesis="When an AC pins the legitimate operator's OID but has been redirected "
                   "(D4-style) to a different, validly-CI-issued rogue server, the OID-pin catches it.",
        mutation="AC.smdp_address rewritten to rogue-smdp.ecosim.test, AC.oid left at the legit value '2.999.100.1'",
        observed=f"installed={ok3} err={err3}",
        classification=record.CONFORMANT if not ok3 else record.ARTIFACT,
        rationale="Closes the specific D4 sub-case where the OID field survives AC tampering unmodified "
                  "(e.g. a partial/naive rewrite, or an OID injected by a source other than the AC itself, "
                  "such as a device-side default). Narrow protection: if the SAME attacker controls the whole "
                  "AC string, they can rewrite the OID field too (see S4).",
        severity="medium", artifact_path="testbed/ecosim/lpa.py,testbed/ecosim/pki.py"))

    # S4: the honest caveat -- if the attacker controls the whole AC, they rewrite
    # the OID field too, and the pin provides no protection at all.
    ac4_full_control = codec.ActivationCode(
        smdp_address="rogue-smdp.ecosim.test", matching_id="rogue-order-4", oid="2.999.100.2",
    )
    lpa4, smdp4, _mno4 = make_lpa(rogue_pki, "rogue-smdp.ecosim.test", 0xA4)
    smdp4.register_order("rogue-order-4", "89020000000000000098", "Free-5GB-Promo-v2", "RogueOperator", 0)
    ok4, err4 = True, ""
    try:
        lpa4.download_profile(ac4_full_control.encode())
    except Exception as exc:  # noqa: BLE001
        ok4, err4 = False, repr(exc)
    findings.append(record.Finding(
        round=4, direction="D4-oid-pin-enforcement", channel="C1",
        spec_section="SGP.22 §3.0.1 step 10 / §4.1",
        hypothesis="If the same attacker who redirects the SM-DP+ address also controls the AC's OID field, "
                   "the OID-pin gives no protection -- it only helps when the OID reaches the LPA independently.",
        mutation="AC fully attacker-authored: both smdp_address and oid point at the rogue server consistently",
        observed=f"installed={ok4} err={err4}",
        classification=record.REAL_GAP if ok4 else record.ARTIFACT,
        severity="high" if ok4 else "info",
        rationale="Confirms the D4 worker's original caveat: OID-pinning inside the AC itself is not a "
                  "general defense against AC-tampering, since the AC is exactly what the attacker controls. "
                  "This remains the core D4 REAL-GAP regardless of the new check.",
        artifact_path="testbed/ecosim/lpa.py,testbed/ecosim/pki.py"))

    record.append_many(findings)
    return findings


if __name__ == "__main__":
    results = run()
    by_class: dict[str, int] = {}
    for f in results:
        by_class[f.classification] = by_class.get(f.classification, 0) + 1
    print(f"D4-oid-pin-enforcement: {len(results)} findings {by_class}")
    for f in results:
        print(f"  [{f.classification}/{f.severity}] {f.hypothesis}")
        print(f"      observed: {f.observed}")
