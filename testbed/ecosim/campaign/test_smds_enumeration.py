"""D14 -- SM-DS discovery and the EID-enumeration question, CORRECTED by a
live finding.

New actor/interface, untouched by every prior direction in this campaign:
SM-DS (Subscription Manager Discovery Server, SGP.22 SS3.6). The original
hypothesis here was that discovery is a pre-authentication, EID-only query:
the LPA asks "is there a pending event for THIS EID?" before any mutual
authentication, so a caller could supply an arbitrary EID and enumerate who
has a pending order and from which operator -- a privacy/reconnaissance
primitive, compounding with D10 (GetEID unsigned/spoofable).

Live probing of three production SM-DS REFUTED that premise. Real ES11
discovery is `InitiateAuthentication` (body carries euiccChallenge +
euiccInfo1, NO EID field) followed by `AuthenticateClient`, whose input is the
eUICC-signed authenticateServerResponse. `eventEntries[]` come back only from
AuthenticateClient, and the queried EID rides inside CERT.EUICC, which the
eUICC signs. The EID is therefore auth-bound: a caller can only discover
events for an EID whose eUICC it holds. There is no pre-authentication
enumeration oracle. See testbed/ping-sm-ds/notes/03-eid-enumeration.md.

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
    eid_a = device_a.get_eid()
    # A DIFFERENT device's EID. ecosim's software eUICCs share one cert (no
    # per-device EID -- the same caveat smdp.authenticate_client documents), so
    # a second SoftwareEuicc would report the SAME EID. To model a genuinely
    # distinct device we use a separate EID string that no eUICC here attests.
    eid_other = "99999999999999999999999999999999"

    # An SM-DP+ (or a cascading SM-DS) registers pending events for both EIDs.
    # rspServerAddress may point at an SM-DP+ OR at another SM-DS.
    smds.register_event(eid_a, event_id="evt-a-1", rsp_server_address="carrier-x-smdp.test")
    smds.register_event(eid_other, event_id="evt-other-1", rsp_server_address="carrier-y-smds.test")

    # S1: device A discovers events for its OWN eUICC-attested EID. Real ES11
    # binds the discovered EID to the eUICC signature in AuthenticateClient, so
    # this is the only query a device can make -- for itself.
    lpa_a = Lpa(device_a, smdp, Bus.default(), pki.ci.certificate)
    own_events = lpa_a.discover(smds)
    findings.append(record.Finding(
        round=5, direction="D14-smds-eid-enumeration", channel="C1",
        spec_section="SGP.22 §3.6 (SM-DS discovery, ES11 InitiateAuthentication + AuthenticateClient)",
        hypothesis="A device discovers events for its OWN eUICC-attested EID (baseline).",
        mutation="none (baseline; device A queries via its own eUICC identity)",
        observed=f"found {len(own_events)} event(s): {own_events}",
        classification=record.CONFORMANT, severity="info",
        rationale="Sanity check: the authenticated discover returns eventEntries only for the "
                  "EID the eUICC attested to. rspServerAddress may be an SM-DP+ or another SM-DS.",
        artifact_path="testbed/ecosim/campaign/test_smds_enumeration.py"))

    # S2: THE CORRECTED FINDING. The historical hypothesis was that a caller
    # could hand the SM-DS an arbitrary EID pre-authentication and enumerate
    # another device's pending events. Live probing REFUTED it: on real
    # servers InitiateAuthentication carries no EID, and eventEntries come only
    # from the eUICC-signed AuthenticateClient, so the EID is auth-bound.
    #
    # The faithful authenticated path cannot even express "query B's EID from
    # A": lpa_a.discover(smds) queries A's attested EID and only ever returns
    # A's events. The refuted oracle survives only in discover_unauthenticated,
    # the historical bare lookup we keep for contrast -- it is NOT the faithful
    # model of a live SM-DS.
    faithful_a_sees = lpa_a.discover(smds)
    faithful_leaks_other = any(e["rspServerAddress"] == "carrier-y-smds.test" for e in faithful_a_sees)
    refuted_oracle = smds.discover_unauthenticated(eid_other)  # historical shortcut only
    findings.append(record.Finding(
        round=5, direction="D14-smds-eid-enumeration", channel="C1",
        spec_section="SGP.22 §3.6 (ES11); live: testbed/ping-sm-ds/notes/03-eid-enumeration.md",
        hypothesis="[REFUTED-by-live] Discovery is a pre-authentication EID-enumeration oracle: any "
                   "caller who supplies another device's EID learns whether it has a pending event "
                   "and which operator registered it.",
        mutation="device A attempts to learn another EID's events; faithful authenticated path vs. the "
                 "historical unauthenticated bare lookup",
        observed=f"faithful_authenticated_discover_leaks_other_eid={faithful_leaks_other} "
                 f"(A sees only its own attested EID's events {faithful_a_sees}); "
                 f"historical_unauthenticated_lookup_would_return={[(e.event_id, e.rsp_server_address) for e in refuted_oracle]}",
        classification=record.ARTIFACT, severity="info",
        rationale="REFUTED by live probing of three production SM-DS (lpa.live.esimdiscovery.com/.dev, "
                  "lpa.ds.gsma.com), logged in testbed/ping-sm-ds/notes/03-eid-enumeration.md. Real ES11 "
                  "InitiateAuthentication carries euiccChallenge + euiccInfo1 and NO EID field; "
                  "eventEntries[] are returned only by AuthenticateClient, whose input is the eUICC-signed "
                  "authenticateServerResponse, and the queried EID rides inside CERT.EUICC. The EID is "
                  "cryptographically auth-bound, so a caller can only discover events for an EID whose "
                  "eUICC it holds -- there is no pre-authentication enumeration oracle. The apparent leak "
                  "existed only in the earlier bare-EID model (kept as discover_unauthenticated for "
                  "contrast) and is a testbed artifact, not a real-network property. rspServerAddress may "
                  "also cascade to another SM-DS rather than an SM-DP+.",
        artifact_path="testbed/ecosim/campaign/test_smds_enumeration.py"))

    record.append_many(findings)
    return findings


if __name__ == "__main__":
    results = run()
    by_class: dict[str, int] = {}
    for f in results:
        by_class[f.classification] = by_class.get(f.classification, 0) + 1
    print(f"D14 SM-DS discovery (corrected): {len(results)} findings {by_class}")
    print("CORRECTED FINDING: no pre-authentication EID-enumeration oracle exists.")
    print("  The EID is auth-bound -- real ES11 InitiateAuthentication carries no EID, and")
    print("  eventEntries come only from the eUICC-signed AuthenticateClient (EID inside CERT.EUICC).")
    print("  A device can discover only its own attested EID's events. Historical bare-EID")
    print("  oracle REFUTED by live probing: testbed/ping-sm-ds/notes/03-eid-enumeration.md")
    for f in results:
        print(f"  [{f.classification}/{f.severity}] {f.hypothesis[:100]}")
        print(f"      observed: {f.observed}")
