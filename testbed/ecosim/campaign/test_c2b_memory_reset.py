"""D13 -- EuiccMemoryReset bypasses Profile Policy Rules entirely (C2b/C3).

SGP.22 SS5.7.19 (per spec-verifier round 5): EuiccMemoryReset deletes entire
profile categories "regardless of their enabled status or any Profile Policy
Rules" -- an explicit, spec-stated bypass of the one soft protection
DeleteProfile itself respects. This test shows the contrast directly: a
profile with PPR "no delete" set survives an ordinary DeleteProfile call, but
not an EuiccMemoryReset.

Runnable: ./venv/bin/python -m testbed.ecosim.campaign.test_c2b_memory_reset
"""

from __future__ import annotations

from ..orchestrator import build_ecosystem, run_flow
from . import record


def run() -> list[record.Finding]:
    findings: list[record.Finding] = []
    eco = build_ecosystem(seed=0xD13A)

    summary, _ = run_flow(eco, profile_name="carrier-locked-plan", sp_name="TelcoC")
    iccid = summary["iccid"]
    profile = next(p for p in eco.euicc._installed if p.iccid == iccid)
    profile.ppr_no_delete = True  # simulates a carrier-set "protected" profile
    eco.lpa.disable_profile(iccid)

    # S1: an ordinary DeleteProfile call respects the PPR and is rejected.
    rejected = False
    try:
        eco.lpa.delete_profile(iccid)
    except ValueError:
        rejected = True
    findings.append(record.Finding(
        round=5, direction="D13-memory-reset-bypasses-ppr", channel="C2b",
        spec_section="SGP.22 §5.7.18 DeleteProfile",
        hypothesis="An ordinary DeleteProfile call respects a profile's Profile Policy Rules (disallowedByPolicy).",
        mutation="attempt DeleteProfile on a profile with ppr_no_delete=True",
        observed=f"rejected={rejected} still_present={any(p.iccid == iccid for p in eco.euicc._installed)}",
        classification=record.CONFORMANT, severity="info",
        rationale="Confirms our PPR modeling actually blocks the normal path before testing the bypass.",
        artifact_path="testbed/ecosim/campaign/test_c2b_memory_reset.py",
    ))

    # S2: EuiccMemoryReset deletes it anyway, PPR notwithstanding.
    eco.lpa.memory_reset()
    still_present_after_reset = any(p.iccid == iccid for p in eco.euicc._installed)
    findings.append(record.Finding(
        round=5, direction="D13-memory-reset-bypasses-ppr", channel="C2b",
        spec_section="SGP.22 §5.7.19 EuiccMemoryReset",
        hypothesis="EuiccMemoryReset deletes a PPR-protected profile anyway -- an explicit spec-stated "
                   "bypass of the one soft protection DeleteProfile itself respects, on top of D12's "
                   "already-zero caller authentication.",
        mutation="call EuiccMemoryReset after the identical profile survived a direct DeleteProfile attempt",
        observed=f"still_present_after_memory_reset={still_present_after_reset} (expected False)",
        classification=record.REAL_GAP if not still_present_after_reset else record.ARTIFACT,
        severity="high",
        rationale="Same zero-caller-authentication root cause as D12 (local ES10c, no PIN/signature/network "
                  "involvement), escalated further: even a carrier's own explicit 'do not delete this "
                  "profile' policy flag provides no protection against this specific command. A local "
                  "attacker (this project's threat model) can wipe every profile category on the card in "
                  "one unauthenticated call, bypassing the only business-logic safeguard that exists.",
        artifact_path="testbed/ecosim/campaign/test_c2b_memory_reset.py",
    ))

    record.append_many(findings)
    return findings


if __name__ == "__main__":
    results = run()
    by_class: dict[str, int] = {}
    for f in results:
        by_class[f.classification] = by_class.get(f.classification, 0) + 1
    print(f"D13 memory-reset PPR bypass: {len(results)} findings {by_class}")
    for f in results:
        print(f"  [{f.classification}/{f.severity}] {f.hypothesis[:100]}")
        print(f"      observed: {f.observed}")
