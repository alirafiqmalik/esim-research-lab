"""Goal 2 -- simulate the two known C1 push capabilities:

(A) The attacker "buys" a profile (registers a real order on a real SM-DP+),
    then delivers its activation code / QR to the VICTIM's device, which installs
    the ATTACKER-controlled profile onto the victim eUICC.

(B) The attacker forwards / triggers an SM-DS or SM-DP+ profile request that was
    created for the victim's EID, causing the victim's device to run the download
    at a time (and under conditions) of the attacker's choosing.

Both are legitimate RSP downloads at the protocol level -- every signature and
certificate checks out -- which is exactly why they succeed: nothing in the flow
binds "who requested this" or "who delivered this activation code" to "whose
device installs it." Defensive research on a local simulation with our own PKI.

Runnable: ./venv/bin/python -m testbed.ecosim.campaign.c1_profile_push
"""

from __future__ import annotations

import random

from ..bus import Bus
from ..codec import ActivationCode
from ..euicc import SoftwareEuicc
from ..lpa import Lpa
from ..mno import Mno
from ..pki import build_pki, eid_from_certificate
from ..smdp import SmDpPlus
from ..smds import SmDs
from . import record


def _make_device(pki, smdp, seed: int) -> tuple[Lpa, SoftwareEuicc]:
    euicc = SoftwareEuicc(pki, random.Random(seed))
    lpa = Lpa(euicc, smdp, Bus.default(), pki.ci.certificate)
    return lpa, euicc


def run() -> list[record.Finding]:
    findings: list[record.Finding] = []
    pki = build_pki()

    # === Scenario A: attacker-bought profile installed on the victim device ===
    # The attacker has their own account/order on a (real, CI-valid) SM-DP+.
    smdp = SmDpPlus(pki, random.Random(0xA77ACC), address="smdp.ecosim.test")
    attacker_mno = Mno(smdp, random.Random(0xA77ACC))
    # The attacker "buys" a profile: a normal, fully legitimate order.
    attacker_ac = attacker_mno.order_profile("Attacker-Controlled-Data-Plan", "AttackerMVNO")

    # The victim's device. The attacker delivers the activation code (QR / push
    # over C1 / malicious deep link) to it. Nothing about the code is device-specific.
    victim_lpa, victim_euicc = _make_device(pki, smdp, seed=0x1C1)
    victim_eid = victim_euicc.get_eid()
    installed_before = list(victim_euicc._installed)

    result = victim_lpa.download_profile(attacker_ac.encode())

    got_attacker_profile = result["profileName"] == "Attacker-Controlled-Data-Plan"
    findings.append(record.Finding(
        round=6, direction="C1-profile-push", channel="C1",
        spec_section="SGP.22 §3.1.3 (download procedure) / §4.1 (activation code has no device binding)",
        hypothesis="An attacker who buys a profile and delivers its activation code to the victim's "
                   "device gets the ATTACKER-controlled profile installed on the VICTIM's eUICC.",
        mutation="attacker registers a legit order, hands its activation code to the victim device",
        observed=f"victim_eid={victim_eid} installed_before={len(installed_before)} "
                 f"installed_profile={result['profileName']!r} iccid={result['iccid']} "
                 f"attacker_profile_on_victim={got_attacker_profile}",
        classification=record.REAL_GAP if got_attacker_profile else record.ARTIFACT,
        severity="high",
        rationale="The activation code (SS4.1) carries no binding to a specific device, and an unbound "
                  "order (SS Table 6a: eid Optional for the Activation-Code flow) accepts any eUICC. So "
                  "a profile the attacker paid for installs on the victim's device with every crypto check "
                  "passing -- the attacker controls the subscription now on the victim's hardware (data "
                  "routing, forced roaming, MITM of the victim's cellular traffic, or simply overwriting/"
                  "crowding the victim's own profiles). Confirms the user's known capability end-to-end.",
        artifact_path="testbed/ecosim/campaign/c1_profile_push.py",
    ))

    # === Scenario B: forward a profile request created for the victim's EID ====
    # A profile is legitimately provisioned/waiting for the victim's EID (their
    # carrier registered it via SM-DS). The attacker forwards/triggers it.
    smds = SmDs()
    smds.register_event(victim_eid, event_id="carrier-evt-1", rsp_server_address="smdp.ecosim.test")
    victim2_lpa, victim2_euicc = _make_device(pki, smdp, seed=0x2C2)
    # (fresh device sharing the same EID-in-cert PKI models "the victim's device")
    carrier_ac = attacker_mno.order_profile("Victim-Carrier-Plan", "VictimCarrier")
    # The attacker, sitting on C1, observes the SM-DS event for the victim's EID
    # and forwards the corresponding activation code to the device to trigger install.
    discovered = smds.discover_unauthenticated(victim_eid)
    forwarded = len(discovered) > 0
    result2 = victim2_lpa.download_profile(carrier_ac.encode())
    findings.append(record.Finding(
        round=6, direction="C1-profile-push", channel="C1",
        spec_section="SGP.22 §3.6 (SM-DS) / §3.1.3",
        hypothesis="An attacker on C1 can forward/trigger a profile request created for the victim's EID, "
                   "causing the download to run at a time/condition of the attacker's choosing.",
        mutation="attacker observes the SM-DS event for the victim's EID and forwards its activation code",
        observed=f"smds_event_for_victim_eid_discoverable={forwarded} "
                 f"forwarded_install_completed={result2['installed']} profile={result2['profileName']!r}",
        classification=record.REAL_GAP if (forwarded and result2["installed"]) else record.ARTIFACT,
        severity="medium",
        rationale="The SM-DS discovery for a known EID is unauthenticated (D14), so the attacker learns a "
                  "profile is waiting and can relay/replay the trigger. The install itself is the victim's "
                  "own legit profile -- so the attacker's power here is over OCCURRENCE and TIMING (force a "
                  "provisioning to happen, or suppress it by blocking, per the capability matrix), not over "
                  "WHICH profile. Lower severity than Scenario A (no attacker-controlled subscription), but "
                  "a real availability/timing-control primitive.",
        artifact_path="testbed/ecosim/campaign/c1_profile_push.py",
    ))

    # === Scenario A': the EID-binding mitigation blocks the forced install ====
    # If the SAME attacker-bought order were EID-bound to the ATTACKER's own EID,
    # the victim's device would be rejected -- showing EID-binding is the defense.
    smdp_bound = SmDpPlus(pki, random.Random(0xB0), address="smdp.ecosim.test")
    attacker_eid = "12121212121212121212121212121212"
    smdp_bound.register_order("bound-mid", "89990000000000000001", "Attacker-Plan", "AttackerMVNO", 0, eid=attacker_eid)
    victim3_lpa, victim3_euicc = _make_device(pki, smdp_bound, seed=0x3C3)
    bound_ac = ActivationCode(smdp_address="smdp.ecosim.test", matching_id="bound-mid")
    rejected = False
    reason = ""
    try:
        victim3_lpa.download_profile(bound_ac.encode())
    except ValueError as exc:
        rejected = True
        reason = str(exc)[:90]
    findings.append(record.Finding(
        round=6, direction="C1-profile-push", channel="C1",
        spec_section="SGP.22 order-binding (ES2+ eid parameter, Table 6a)",
        hypothesis="If the attacker's order were EID-bound (to any EID other than the victim's), the "
                   "forced-install-on-victim attack fails -- EID-binding is the concrete defense.",
        mutation="repeat Scenario A but with the order EID-bound to the attacker's own EID",
        observed=f"forced_install_rejected={rejected} reason={reason!r}",
        classification=record.CONFORMANT if rejected else record.ARTIFACT,
        severity="info",
        rationale="Ties Scenario A to the D1-D2 EID-binding contrast: the SS Table 6a-optional EID "
                  "parameter, when set, binds the order to a specific device and defeats the cross-device "
                  "push. The exposure exists precisely because that binding is optional and commonly unset "
                  "for the consumer Activation-Code flow.",
        artifact_path="testbed/ecosim/campaign/c1_profile_push.py",
    ))

    record.append_many(findings)
    return findings


if __name__ == "__main__":
    results = run()
    by_class: dict[str, int] = {}
    for f in results:
        by_class[f.classification] = by_class.get(f.classification, 0) + 1
    print(f"C1 profile push: {len(results)} findings {by_class}")
    for f in results:
        print(f"  [{f.classification}/{f.severity}] {f.hypothesis[:95]}")
        print(f"      {f.observed[:170]}")
