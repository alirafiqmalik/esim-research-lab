"""D14 -- SM-DS discovery is pre-authentication, EID-only: EID-enumeration
privacy/reconnaissance primitive.

New actor/interface, untouched by every prior direction in this campaign:
SM-DS (Subscription Manager Discovery Server, SGP.22 SS3.6). Discovery lets
the LPA ask "is there a pending profile for my EID?" -- and it necessarily
happens BEFORE mutual authentication (the eUICC's identity isn't
cryptographically established until the actual SM-DP+ handshake runs). This
test asks whether that pre-auth query is bindable to an arbitrary caller-
supplied EID rather than the querying device's own, combining with D10
(GetEID is unsigned/spoofable) to ask: can a third party enumerate EIDs
against the SM-DS to learn who has a pending order, and from which operator?

Runnable: ./venv/bin/python -m testbed.ecosim.campaign.test_smds_enumeration
"""

from __future__ import annotations

import random

from ..bus import Bus
from ..euicc import SoftwareEuicc
from ..lpa import Lpa
from ..pki import build_pki
from ..smdp import SmDpPlus
from ..smds import SmDs
from . import record


def run() -> list[record.Finding]:
    findings: list[record.Finding] = []
    pki = build_pki()
    smds = SmDs()
    smdp = SmDpPlus(pki, random.Random(0xD14), address="smdp.ecosim.test")

    device_a = SoftwareEuicc(pki, random.Random(0xA1))
    device_b = SoftwareEuicc(pki, random.Random(0xB1))
    eid_a, eid_b = device_a.get_eid(), device_b.get_eid()

    # SM-DP+ registers pending events for both devices (e.g. two different
    # operators each pushed an order via the "Default SM-DP+/SM-DS" flow).
    smds.register_event(eid_a, event_id="evt-a-1", smdp_address="carrier-x-smdp.test")
    smds.register_event(eid_b, event_id="evt-b-1", smdp_address="carrier-y-smdp.test")

    # S1: device A discovers its own pending event (baseline, legitimate use).
    lpa_a = Lpa(device_a, smdp, Bus.default(), pki.ci.certificate)
    own_events = lpa_a.discover(smds)
    findings.append(record.Finding(
        round=5, direction="D14-smds-eid-enumeration", channel="C1",
        spec_section="SGP.22 §3.6 (SM-DS discovery, ES9+/ES11-shaped, pre-authentication)",
        hypothesis="A device can discover its own pending SM-DS event (baseline).",
        mutation="none (baseline, device A queries its own EID)",
        observed=f"found {len(own_events)} event(s): {[(e.event_id, e.smdp_address) for e in own_events]}",
        classification=record.CONFORMANT, severity="info",
        rationale="Sanity check.", artifact_path="testbed/ecosim/campaign/test_smds_enumeration.py"))

    # S2: THE KEY QUESTION -- can device A's LPA query B's EID and learn B's
    # pending-event info, purely by supplying B's EID string? No credential,
    # no signature, nothing that ties the query to device A's own identity.
    other_device_events = lpa_a.discover(smds, eid=eid_b)
    leaked = len(other_device_events) > 0 and other_device_events[0].smdp_address == "carrier-y-smdp.test"
    findings.append(record.Finding(
        round=5, direction="D14-smds-eid-enumeration", channel="C1",
        spec_section="SGP.22 §3.6",
        hypothesis="Discovery happens before mutual authentication, so nothing binds a query to the "
                   "querying device's own EID -- any caller who knows or guesses another device's EID "
                   "can learn whether it has a pending profile and which operator registered it.",
        mutation="device A's LPA queries device B's EID directly (no credential proving A is B)",
        observed=f"leaked_b_info_to_a={leaked} returned={[(e.event_id, e.smdp_address) for e in other_device_events]}",
        classification=record.REAL_GAP if leaked else record.ARTIFACT,
        severity="medium",
        rationale="Structural consequence of discovery necessarily preceding mutual authentication "
                  "(the eUICC's cryptographic identity isn't established until the subsequent SM-DP+ "
                  "handshake) -- this is a real architectural property, not a testbed shortcut. Combined "
                  "with D10 (GetEID is unsigned/spoofable, so an attacker doesn't even need to guess a "
                  "target's EID if they can read it locally, or with EID formats being non-secret 32-digit "
                  "identifiers per SGP.29), this is a reconnaissance/privacy primitive: learn if a specific "
                  "device has a pending order and which carrier registered it. It does NOT by itself allow "
                  "claiming or installing that device's profile (D2's matchingId-based order lookup is the "
                  "separate, actual claim-time gate) -- impact is information disclosure, not profile theft.",
        artifact_path="testbed/ecosim/campaign/test_smds_enumeration.py"))

    record.append_many(findings)
    return findings


if __name__ == "__main__":
    results = run()
    by_class: dict[str, int] = {}
    for f in results:
        by_class[f.classification] = by_class.get(f.classification, 0) + 1
    print(f"D14 SM-DS EID enumeration: {len(results)} findings {by_class}")
    for f in results:
        print(f"  [{f.classification}/{f.severity}] {f.hypothesis[:100]}")
        print(f"      observed: {f.observed}")
