"""D12 -- post-install profile lifecycle authorization (C2b/C3): EnableProfile,
DisableProfile, DeleteProfile.

Every prior direction in this campaign concerned the download/install flow.
Nothing tested what happens AFTER a profile is installed: SGP.22's ES10c
EnableProfile/DisableProfile/DeleteProfile are local LPA<->eUICC commands with
no signature and no network round-trip, modeled here (added this round)
exactly like GetEID -- ICCID-keyed, no additional cryptographic authorization
beyond having local ES10c/APDU access at all, consistent with how every other
local ES10 command in this testbed (and, per the spec-verifier, the real
protocol) already behaves.

Runnable: ./venv/bin/python -m testbed.ecosim.campaign.test_c2b_profile_lifecycle
"""

from __future__ import annotations

from .. import codec
from ..orchestrator import build_ecosystem, run_flow
from . import record


def run() -> list[record.Finding]:
    findings: list[record.Finding] = []
    eco = build_ecosystem(seed=0xD12A)

    # Install two profiles on the same eUICC (two separate orders/downloads).
    summary_a, _ = run_flow(eco, profile_name="user-plan-A", sp_name="TelcoA")
    summary_b, _ = run_flow(eco, profile_name="user-plan-B", sp_name="TelcoB")
    iccid_a, iccid_b = summary_a["iccid"], summary_b["iccid"]

    # S1: user enables profile A (the one they intended).
    eco.lpa.enable_profile(iccid_a)
    enabled_after_a = [p.iccid for p in eco.euicc._installed if p.enabled]
    findings.append(record.Finding(
        round=5, direction="D12-profile-lifecycle-authorization", channel="C3",
        spec_section="SGP.22 ES10c EnableProfile (modeled; exact tag numbers ours, see codec.py comment)",
        hypothesis="EnableProfile with the correct ICCID enables the intended profile.",
        mutation="none (baseline)", observed=f"enabled after enabling A: {enabled_after_a}",
        classification=record.CONFORMANT, rationale="Sanity check.", severity="info",
        artifact_path="testbed/ecosim/campaign/test_c2b_profile_lifecycle.py"))

    # S2: THE KEY QUESTION -- can a local C2b/C3 attacker silently switch the
    # user's active profile to a DIFFERENT one on the SAME card, with zero
    # additional authorization (no PIN, no signature, no SM-DP+ round-trip)?
    eco.lpa.enable_profile(iccid_b)
    switched = any(p.iccid == iccid_b and p.enabled for p in eco.euicc._installed)
    a_now_disabled = not any(p.iccid == iccid_a and p.enabled for p in eco.euicc._installed)
    findings.append(record.Finding(
        round=5, direction="D12-profile-lifecycle-authorization", channel="C2b",
        spec_section="SGP.22 ES10c EnableProfile -- local command, no signature/PIN modeled",
        hypothesis="A local MITM on the modem/APDU transport (C2b) -- this project's exact threat "
                   "model -- can silently switch which profile is active, with zero additional "
                   "authorization beyond local ES10c access: no PIN, no user consent prompt "
                   "re-verification, no SM-DP+/network involvement, no signature to forge.",
        mutation="send EnableProfile(iccid_B) over C2b while the user believes profile A is active",
        observed=f"switched_to_B={switched} A_disabled={a_now_disabled} iccid_a={iccid_a} iccid_b={iccid_b}",
        classification=record.REAL_GAP if switched else record.ARTIFACT,
        severity="medium",
        rationale="Consistent with every other ES10 local command this campaign has modeled (GetEID, "
                  "GetEUICCChallenge, GetEUICCInfo1): SGP.22's local ES10x interface trusts whoever has "
                  "physical/APDU access to the ISD-R, with no additional per-command authorization layer. "
                  "For a rooted-device or compromised-baseband attacker (this project's threat model), "
                  "profile enable/disable is then a silent, undetectable-to-the-user operation -- distinct "
                  "from D1/D2/D4 (which required tricking a download flow) and from D10 (read-only EID "
                  "spoofing): this is direct WRITE access to the device's active-service state.",
        artifact_path="testbed/ecosim/campaign/test_c2b_profile_lifecycle.py"))

    # S3: can the attacker delete a profile the user still wants?
    eco.lpa.disable_profile(iccid_b)  # must disable before delete, per our model
    eco.lpa.delete_profile(iccid_b)
    still_present = any(p.iccid == iccid_b for p in eco.euicc._installed)
    findings.append(record.Finding(
        round=5, direction="D12-profile-lifecycle-authorization", channel="C2b",
        spec_section="SGP.22 ES10c DeleteProfile -- local command",
        hypothesis="A local attacker can also delete an installed profile outright (destructive, "
                   "not just a silent switch), again with no additional authorization.",
        mutation="DisableProfile(iccid_B) then DeleteProfile(iccid_B)",
        observed=f"profile_b_still_present={still_present} (expected False)",
        classification=record.REAL_GAP if not still_present else record.ARTIFACT,
        severity="medium",
        rationale="Same local-trust-boundary root cause as S2, but destructive/irreversible rather than "
                  "transient -- the user's profile B (and its ICCID/subscription binding on this eUICC) "
                  "is gone, not just deactivated.",
        artifact_path="testbed/ecosim/campaign/test_c2b_profile_lifecycle.py"))

    # S4: sanity -- our own model's one safety rail (can't delete the enabled profile) holds.
    # (A was disabled back in S2 when B was enabled; re-enable it so this actually
    # tests "delete while enabled", not "delete while already disabled".)
    eco.lpa.enable_profile(iccid_a)
    rejected = False
    try:
        eco.lpa.delete_profile(iccid_a)  # iccid_a is now the currently-enabled profile
    except ValueError:
        rejected = True
    findings.append(record.Finding(
        round=5, direction="D12-profile-lifecycle-authorization", channel="C2b",
        spec_section="n/a -- our own modeled safety rail, not a spec citation",
        hypothesis="Our model refuses to delete the currently-ENABLED profile (a real eUICC would "
                   "typically require disabling first too) -- confirms S3 required an explicit disable step.",
        mutation="attempt DeleteProfile on the currently-enabled iccid_a directly",
        observed=f"rejected={rejected}",
        classification=record.CONFORMANT, severity="info",
        rationale="This specific rail is real-behavior-consistent (can't yank the active profile out from "
                  "under a running session) but doesn't change S2/S3's core finding: DISABLE + ENABLE-a-"
                  "different-one, or DISABLE + DELETE, both proceed with zero extra authorization.",
        artifact_path="testbed/ecosim/campaign/test_c2b_profile_lifecycle.py"))

    record.append_many(findings)
    return findings


if __name__ == "__main__":
    results = run()
    by_class: dict[str, int] = {}
    for f in results:
        by_class[f.classification] = by_class.get(f.classification, 0) + 1
    print(f"D12 profile lifecycle authorization: {len(results)} findings {by_class}")
    for f in results:
        print(f"  [{f.classification}/{f.severity}] {f.hypothesis[:100]}")
        print(f"      observed: {f.observed}")
