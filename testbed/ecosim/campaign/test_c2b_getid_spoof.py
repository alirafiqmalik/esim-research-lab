"""D10 -- GetEID plaintext/unsigned local exposure (channel C2b/C3).

SGP.22 v3.1 SS5.7.20 / SS4.3.1 (per spec-verifier round 3, Q10): the EID is never
a field in EUICCInfo1/2; it only appears (a) inside CERT.EUICC.SIG.subject.serialNumber
(cryptographically bound, but only checked by a relying SM-DP+/SM-DS during a full
RSP session) and (b) as the raw, unsigned, unencrypted response to ES10c.GetEID.
A local MITM on the LPA<->eUICC bus -- exactly this project's threat model -- can
read or spoof this response with zero built-in protection.

Runnable: ./venv/bin/python -m testbed.ecosim.campaign.test_c2b_getid_spoof
"""

from __future__ import annotations

from dataclasses import replace

from .. import codec
from ..bus import C2B, Message
from ..orchestrator import build_ecosystem
from . import record


def run() -> list[record.Finding]:
    findings: list[record.Finding] = []

    # S1 -- baseline: honest GetEID read matches the card's real EID.
    eco = build_ecosystem(seed=0xD10A)
    real_eid = eco.euicc.get_eid()
    reported = eco.lpa.get_eid()
    findings.append(record.Finding(
        round=3, direction="D10-getid-plaintext-spoof", channel="C3",
        spec_section="SGP.22 §5.7.20",
        hypothesis="Honest GetEID over the ES10c-modelled path reports the card's real EID.",
        mutation="none (baseline)",
        observed=f"real_eid={real_eid} reported={reported} match={real_eid == reported}",
        classification=record.CONFORMANT, rationale="No tampering; sanity check.",
        severity="info", artifact_path="testbed/ecosim/campaign/test_c2b_getid_spoof.py",
    ))

    # S2 -- a C2b (modem/APDU transport) MITM rewrites the plaintext GetEID response.
    eco = build_ecosystem(seed=0xD10B)
    real_eid = eco.euicc.get_eid()
    spoofed_eid = "".join("9" if c != "9" else "1" for c in real_eid)

    def c2b_mutator(msg: Message) -> Message:
        if msg.kind == "GetEID.resp.resp":
            new_wire = codec.eid_response(spoofed_eid)
            return replace(msg, wire=new_wire)
        return msg

    eco.bus.set_mutator(C2B, c2b_mutator)
    try:
        reported = eco.lpa.get_eid()
    finally:
        eco.bus.clear_mutators()

    spoofed = reported == spoofed_eid and reported != real_eid
    findings.append(record.Finding(
        round=3, direction="D10-getid-plaintext-spoof", channel="C2b",
        spec_section="SGP.22 §5.7.20 / §4.3.1",
        hypothesis="A local MITM on the modem/APDU transport (C2b) can spoof the eUICC's "
                   "reported EID with zero detection, since GetEID is unsigned and unencrypted.",
        mutation="rewrite GetEID.resp payload to a different 32-digit EID",
        observed=f"real_eid={real_eid} spoofed_eid={spoofed_eid} lpa_reported={reported} spoofed_accepted={spoofed}",
        classification=record.REAL_GAP if spoofed else record.ARTIFACT,
        severity="medium",
        rationale="SGP.22 SS5.7.20's GetEuiccDataResponse carries eidValue with no signature or encryption "
                  "-- this is the real protocol's design, not a testbed simplification. The only "
                  "cryptographically-bound copy of the EID lives inside CERT.EUICC.SIG, which requires "
                  "a full RSP session (not a bare GetEID call) for any party to check. Any app/flow that "
                  "trusts a bare GetEID response for device identification is trusting an unauthenticated "
                  "value on exactly the channel this project's rooted-device threat model controls.",
        artifact_path="testbed/ecosim/campaign/test_c2b_getid_spoof.py",
    ))

    record.append_many(findings)
    return findings


if __name__ == "__main__":
    results = run()
    by_class: dict[str, int] = {}
    for f in results:
        by_class[f.classification] = by_class.get(f.classification, 0) + 1
    print(f"D10 GetEID spoof: {len(results)} findings {by_class}")
    for f in results:
        print(f"  [{f.classification}/{f.severity}] {f.hypothesis}")
        print(f"      observed: {f.observed}")
