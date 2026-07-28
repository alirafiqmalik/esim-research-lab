"""D4 -- SM-DP+ address/identity binding: rogue-but-CI-valid SM-DP+ substitution.

Ground truth (spec_notes/round2.md "D4", round1.md "D1"): the activation code (AC,
channel C2a) has zero integrity -- SGP.22 SS4.1 ships it as bare `$`-delimited
plaintext. `serverAddress` is carried inside `serverSigned1` (tamper-evident once
signed by the SM-DP+ that answers), but it is self-asserted by whichever server
answers, and the SM-DP+ OID check (subjectAltName.registeredID) is explicitly
CONDITIONAL: "if its OID was provided earlier, verify the OID" (SS3.0.1 step 10).
There is no `serverAddressMismatch`/`serverOidMismatch` reason code in the
normative v3.1 `CancelSessionReason` enum, and the eUICC itself never checks
`serverAddress` at all (testbed/ecosim/euicc.py's `authenticate_server` reads the
field into `_smdp_address_field` and discards it -- see the leading underscore).

So an attacker who controls AC delivery (a compromised QR-hosting page, a
malicious deep link, an SMS/email MITM -- channel C2a, NOT the local device) can
rewrite the AC's SM-DP+ address and matchingId to point the LPA at an entirely
DIFFERENT SM-DP+ operator that nonetheless holds a validly CI-issued certificate
(a rogue/compromised operator, or a misissued/socially-engineered cert -- either
way, the CI's trust decision is the only anchor SGP.22 gives the ecosystem). Every
cryptographic check the eUICC and SM-DP+ perform -- chain-to-CI, role/invalidOid,
signature -- passes, because those checks are about "is this a CI-trusted
DPauth/DPpb key" and never about "is this the address the user meant."

This module builds ONE shared PKI (one CI, via build_ecosystem) and a SECOND,
independent SmDpPlus ("rogue-smdp.ecosim.test") that reuses that same PKI's
dp_auth/dp_pb keypairs -- i.e. a legitimately CI-trusted operator, not a forged
cert. S1 is the honest baseline. S2 drives the full mutual-authentication
handshake against the rogue server using an attacker-substituted AC and shows it
completes cleanly. S3 checks whether an OID pin in the AC would have helped: the
shipped lpa.py never reads `ActivationCode.oid` at all, so it doesn't, but a
minimal enforcement written here (test-only, mirroring the spec's conditional
check) shows what conformant behavior would look like.

Runnable: ./venv/bin/python -m testbed.ecosim.campaign.test_c1_rogue_smdp
"""

from __future__ import annotations

from dataclasses import replace

from .. import codec, protocol
from ..bus import C1, Bus
from ..codec import ActivationCode
from ..euicc import SoftwareEuicc
from ..lpa import Lpa
from ..mno import Mno
from ..orchestrator import build_ecosystem
from ..smdp import SmDpPlus
from . import record

# Stand-in "SM-DP+ operator identity" OIDs for the S3 demonstration. Real SGP.22
# certs carry this as subjectAltName.registeredID, unique per operator. Our
# pki.py's CertificatePolicies OID only encodes CERT ROLE (dp_auth/dp_pb/euicc/
# eum/ci -- see pki._ROLE_OIDS), not per-operator identity, and the rogue/legit
# SmDpPlus instances here deliberately share the SAME dp_auth/dp_pb cert (per
# task design, modelling "same CI, different/compromised operator"). So there is
# no cert field to read a per-operator OID from; these constants are pure
# test-side bookkeeping used only to show what an OID-pin check WOULD compare
# against if our cert model carried that extra identity dimension.
_LEGIT_OPERATOR_OID = "1.3.6.1.4.1.99999.1.1"
_ROGUE_OPERATOR_OID = "1.3.6.1.4.1.99999.2.1"


def _enforce_oid_pin(ac: ActivationCode, actual_server_oid: str) -> None:
    """What a conformant LPA SHOULD do per SGP.22 SS3.0.1 step 10 / SS3.1.3.1 when
    the AC carries an OID: "if its OID was provided earlier, verify the OID [...]
    otherwise abort with reason CancelSession". NOT implemented anywhere in
    testbed/ecosim/lpa.py -- reproduced here, in the test script only, to show
    what the conditional check would catch if it existed.
    """
    if ac.oid and ac.oid != actual_server_oid:
        raise ValueError(
            f"serverOidMismatch: AC pinned OID {ac.oid!r} but the server that "
            f"answered presents operator OID {actual_server_oid!r}"
        )


def _server_signed1_address(messages: list, kind: str = "InitiateAuthentication.resp") -> str:
    """Pull the self-asserted smdp_address out of a logged serverSigned1, the way
    the eUICC would see it (and never check it) inside authenticate_server."""
    for msg in messages:
        if msg.channel == C1 and msg.kind == kind:
            obj = codec.from_json_wire(msg.wire)
            fields = protocol.read_len_fields(codec.unb64(obj["serverSigned1"]))
            return fields[2].decode("utf-8", "replace")
    raise ValueError(f"no {kind} observed")


def run() -> list[record.Finding]:
    findings: list[record.Finding] = []

    # --- shared PKI: one CI, reused by both the legitimate and rogue SM-DP+ ----
    eco = build_ecosystem(seed=0xD4C1)
    pki = eco.pki
    real_smdp = eco.smdp  # "smdp.ecosim.test", the user's intended operator

    rogue_smdp = SmDpPlus(pki, eco.rng, address="rogue-smdp.ecosim.test")
    rogue_mno = Mno(rogue_smdp, eco.rng)

    real_ac = eco.mno.order_profile("RealPlan-5GB", "RealTelco", profile_class=0)
    rogue_order_ac = rogue_mno.order_profile("Free-5GB-Promo", "RogueOperator", profile_class=0)

    # === S1: baseline -- honest AC, real order, real SM-DP+ ====================
    s1_result = eco.lpa.download_profile(real_ac.encode())
    s1_ok = s1_result.get("installed") is True and s1_result.get("profileName") == "RealPlan-5GB"
    findings.append(record.Finding(
        round=2, direction="D4-rogue-smdp-substitution", channel="C1",
        spec_section="SGP.22 §3.0.1 / §4.1",
        hypothesis="With an untampered AC, the LPA installs the user's real profile "
                   "from the legitimate SM-DP+.",
        mutation="none (baseline)",
        observed=f"result={s1_result}",
        classification=record.CONFORMANT if s1_ok else record.ARTIFACT,
        rationale="Sanity check that the shared-PKI, two-SM-DP+ setup behaves normally "
                  "before introducing the AC substitution.",
        severity="info",
        artifact_path="testbed/ecosim/campaign/test_c1_rogue_smdp.py",
    ))

    # === S2: substitution -- attacker rewrites AC address + matchingId =========
    # Models an on-path attacker on the AC-delivery channel (C2a: compromised
    # QR-hosting page / malicious deep link / SMS-or-email MITM) -- NOT the local
    # device. The user's real AC named smdp.ecosim.test + the real matchingId;
    # what the LPA actually receives is this:
    tampered_ac = ActivationCode(
        smdp_address=rogue_order_ac.smdp_address,
        matching_id=rogue_order_ac.matching_id,
        oid=real_ac.oid,  # empty in this testbed's ACs; carried through unchanged
    )

    rogue_bus = Bus.default()
    # Same physical eUICC/device as S1 (SoftwareEuicc built on the same pki.euicc
    # identity) -- only the AC the user was handed differs. The LPA is modelled as
    # dialing whichever SM-DP+ the AC names, exactly like a real LPAd opening TLS
    # to the FQDN it parsed out of the AC.
    rogue_lpa = Lpa(eco.euicc, rogue_smdp, rogue_bus, pki.ci.certificate)

    s2_exc = ""
    try:
        s2_result = rogue_lpa.download_profile(tampered_ac.encode())
    except Exception as exc:  # noqa: BLE001 - characterising, not asserting
        s2_result = {}
        s2_exc = repr(exc)

    s2_installed_rogue = (
        s2_result.get("installed") is True and s2_result.get("profileName") == "Free-5GB-Promo"
    )
    asserted_address = _server_signed1_address(rogue_bus.all_messages())
    findings.append(record.Finding(
        round=2, direction="D4-rogue-smdp-substitution", channel="C1",
        spec_section="SGP.22 §3.0.1 steps 8/10, §4.1",
        hypothesis="An AC with its SM-DP+ address and matchingId rewritten to point at a "
                   "DIFFERENT but still validly CI-issued SM-DP+ operator will pass every "
                   "cryptographic check and install that operator's (benign-sounding) "
                   "profile, with nothing in the protocol flagging the substitution.",
        mutation="AC.smdp_address: 'smdp.ecosim.test' -> 'rogue-smdp.ecosim.test'; "
                 "AC.matching_id: <real order id> -> <rogue order id registered on the "
                 "rogue SM-DP+>; smdpSignature2/euiccSignature1/cert chains untouched",
        observed=f"installed_rogue_profile={s2_installed_rogue} exc={s2_exc!r} "
                 f"result={s2_result} self_asserted_serverAddress_in_serverSigned1={asserted_address!r}",
        classification=record.REAL_GAP if s2_installed_rogue else record.ARTIFACT,
        rationale="Matches round2.md D4 exactly: serverAddress is self-asserted inside a "
                  "signed blob (tamper-evident to a MITM on C1, but useless once the AC "
                  "itself, on C2a, has already been redirected before any TLS/session ever "
                  "opens); the OID check is conditional and unused when the AC carries no "
                  "OID; there is no serverAddressMismatch reason code in the normative "
                  "v3.1 enum; and the eUICC never checks serverAddress at all. Because the "
                  "rogue server's DPauth/DPpb keys genuinely chain to the same trusted CI "
                  "with the correct role, every check that exists (chain, role, signature) "
                  "passes honestly. This is a real, spec-documented property rooted in D1 "
                  "(the AC has zero integrity), not a testbed simplification.",
        severity="high" if s2_installed_rogue else "info",
        artifact_path="testbed/ecosim/campaign/test_c1_rogue_smdp.py",
    ))

    # === S2, root cause: the field is read and explicitly discarded ============
    findings.append(record.Finding(
        round=2, direction="D4-rogue-smdp-substitution", channel="C3",
        spec_section="SGP.22 §5.7.13",
        hypothesis="testbed/ecosim/euicc.py's authenticate_server never compares "
                   "serverSigned1's smdp_address field against anything.",
        mutation="static inspection, not a mutation",
        observed="euicc.py authenticate_server() unpacks serverSigned1 as "
                 "`_tx_id_field, euicc_challenge_field, _smdp_address_field, server_otpk_field` "
                 "-- the leading underscore marks smdp_address as read-and-discarded; the "
                 "self-asserted address recovered above (%r) is never checked against the "
                 "AC's address, a dialed FQDN, or anything else." % asserted_address,
        classification=record.CONFORMANT,
        rationale="This is a FAITHFUL model of SGP.22, not a testbed bug: the spec gives the "
                  "eUICC no serverAddress-verification step at all (round2.md D4). Our code "
                  "correctly mirrors that absence rather than inventing a check the real "
                  "protocol doesn't have.",
        severity="high",
        artifact_path="testbed/ecosim/euicc.py",
    ))

    # === S3: does an OID pin in the AC help? ====================================
    pinned_ac = replace(tampered_ac, oid=_LEGIT_OPERATOR_OID)
    rogue_bus2 = Bus.default()
    rogue_lpa2 = Lpa(SoftwareEuicc(pki, eco.rng), rogue_smdp, rogue_bus2, pki.ci.certificate)

    s3_exc = ""
    try:
        s3_result = rogue_lpa2.download_profile(pinned_ac.encode())
    except Exception as exc:  # noqa: BLE001
        s3_result = {}
        s3_exc = repr(exc)
    s3_shipped_code_installed_anyway = (
        s3_result.get("installed") is True and s3_result.get("profileName") == "Free-5GB-Promo"
    )
    findings.append(record.Finding(
        round=2, direction="D4-rogue-smdp-substitution", channel="C1",
        spec_section="SGP.22 §3.0.1 step 10",
        hypothesis="Even when the AC carries an SM-DP+ OID pinned to the legitimate "
                   "operator, the shipped lpa.py performs no OID-vs-certificate check, so "
                   "the substitution still succeeds silently.",
        mutation="same address/matchingId substitution as S2, but AC.oid left populated "
                 f"with the legitimate operator's pinned OID ({_LEGIT_OPERATOR_OID!r})",
        observed=f"installed_rogue_profile={s3_shipped_code_installed_anyway} exc={s3_exc!r} "
                 f"result={s3_result}; codec.ActivationCode.oid is parsed but grep confirms "
                 f"it is never read anywhere in lpa.py or euicc.py",
        classification=record.ARTIFACT,
        rationale="SGP.22 SS3.0.1 step 10 makes the OID check CONDITIONAL ('if its OID was "
                  "provided earlier, verify the OID') -- here we DID provide an OID, so a "
                  "conformant implementation SHOULD have compared it and aborted. The "
                  "shipped testbed lpa.py has no code path that reads ActivationCode.oid at "
                  "all, so this specific absence is a genuine testbed limitation (distinct "
                  "from the underlying S2 finding, which holds regardless of any OID check).",
        severity="medium",
        artifact_path="testbed/ecosim/lpa.py",
    ))

    # === S3b: what conformant OID-pin enforcement WOULD look like (test-only) ==
    oid_check_err = ""
    oid_check_raised = False
    try:
        _enforce_oid_pin(pinned_ac, _ROGUE_OPERATOR_OID)
    except ValueError as exc:
        oid_check_raised = True
        oid_check_err = repr(exc)
    findings.append(record.Finding(
        round=2, direction="D4-rogue-smdp-substitution", channel="C1",
        spec_section="SGP.22 §3.0.1 step 10",
        hypothesis="A minimal, spec-shaped OID-pin check (added only in this test script, "
                   "NOT in lpa.py/euicc.py) would have caught this specific substitution, "
                   "since the attacker rewrote the address/matchingId but the AC's pinned "
                   "OID still names the legitimate operator.",
        mutation="post-hoc application of _enforce_oid_pin(pinned_ac, actual_server_oid) "
                 "against the same tampered_ac used in S3",
        observed=f"raised={oid_check_raised} err={oid_check_err}",
        classification=record.CONFORMANT,
        rationale="Demonstrates the ONE mitigation SGP.22 actually offers for this class of "
                  "attack: an AC-carried OID pin, if an LPA implemented the conditional "
                  "check. It does not generalize -- it only helps when the AC's issuer "
                  "bothered to populate the OID AND the attacker didn't also rewrite it "
                  "(nothing stops an attacker who controls the AC from rewriting the OID "
                  "field too, since the AC has zero integrity end to end, per D1). The "
                  "underlying OID values are test-side bookkeeping, not read from any cert "
                  "field, because our pki.py's OID extension encodes cert ROLE, not "
                  "per-operator identity -- see the module docstring.",
        severity="info",
        artifact_path="testbed/ecosim/campaign/test_c1_rogue_smdp.py",
    ))

    # === modeling-simplification note: rogue smdp shares the exact keypair =====
    same_dp_auth_key = rogue_smdp.pki.dp_auth is real_smdp.pki.dp_auth
    findings.append(record.Finding(
        round=2, direction="D4-rogue-smdp-substitution", channel="C1",
        spec_section="SGP.22 §3.0.1",
        hypothesis="(modeling note) the rogue SmDpPlus instance reuses the exact same "
                   "dp_auth/dp_pb KeyPair objects as the legitimate one, rather than a "
                   "distinct-but-still-CI-issued keypair a truly independent rogue operator "
                   "would hold in reality.",
        mutation="static inspection, not a mutation",
        observed=f"rogue_smdp.pki.dp_auth is real_smdp.pki.dp_auth == {same_dp_auth_key}",
        classification=record.ARTIFACT,
        rationale="A real rogue/compromised operator would hold its OWN CERT.DPauth.SIG "
                  "with its own keypair, merely chaining to the same CI -- not the identical "
                  "bytes. Reusing the same KeyPair (per this task's setup instructions) is a "
                  "simplification of key material, not of the security property under test: "
                  "a distinct-but-CI-issued keypair would chain and role-check identically, "
                  "so it would not change the S2 outcome. Flagged for honesty, not because it "
                  "affects the REAL-GAP classification above.",
        severity="info",
        artifact_path="testbed/ecosim/campaign/test_c1_rogue_smdp.py",
    ))

    record.append_many(findings)
    return findings


if __name__ == "__main__":
    results = run()
    by_class: dict[str, int] = {}
    for f in results:
        by_class[f.classification] = by_class.get(f.classification, 0) + 1
    print(f"D4 rogue-smdp-substitution: {len(results)} findings {by_class}")
    for f in results:
        print(f"  [{f.classification}/{f.severity}] {f.hypothesis}")
        print(f"      observed: {f.observed}")
