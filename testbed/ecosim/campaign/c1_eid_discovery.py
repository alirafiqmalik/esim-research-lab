"""Goal 1 -- how a C1 network attacker discovers the device EID.

The EID lives in CERT.EUICC.SIG.subject.serialNumber (SGP.22 SS4.3.1), and that
certificate crosses C1 in AuthenticateClient.req (device -> SM-DP+) and again in
HandleNotification.req. So the EID is exposed to any party that can read C1 --
which, under the "TLS stripped / attacker-on-path" model, is the network
attacker. This module maps the discovery vectors and, importantly, the LIMITS:
what the attacker can and cannot induce.

Defensive research on a local simulation with our own PKI.
Runnable: ./venv/bin/python -m testbed.ecosim.campaign.c1_eid_discovery
"""

from __future__ import annotations

import random

from cryptography import x509

from .. import codec, crypto, protocol, tlv
from ..bus import Bus
from ..euicc import SoftwareEuicc
from ..lpa import Lpa
from ..mno import Mno
from ..pki import build_pki, eid_from_certificate
from ..smdp import SmDpPlus
from ..orchestrator import build_ecosystem, run_flow
from .c1_adversary import C1Adversary
from . import record


def run() -> list[record.Finding]:
    findings: list[record.Finding] = []

    # --- Vector 1: passive observation of a real download flow ---------------
    eco = build_ecosystem(seed=101)
    real_eid = eco.euicc.get_eid()
    adv = C1Adversary(bus=eco.bus)
    adv.attach()
    try:
        run_flow(eco, profile_name="victim-plan")
    finally:
        adv.detach()
    recovered = adv.observed_eid()
    leak_msgs = [o.kind for o in adv.observed if o.obj.get("euiccCertificate")]
    findings.append(record.Finding(
        round=6, direction="C1-eid-discovery", channel="C1",
        spec_section="SGP.22 §4.3.1 (EID in CERT.EUICC.SIG.subject.serialNumber) / §5.6.2",
        hypothesis="A passive C1 observer recovers the device EID from the eUICC certificate, "
                   "with no GetEID/local-bus access.",
        mutation="observe a normal download flow; extract EID from euiccCertificate",
        observed=f"real_eid={real_eid} recovered={recovered} match={recovered == real_eid} "
                 f"leaked_in_messages={leak_msgs}",
        classification=record.REAL_GAP if recovered == real_eid else record.ARTIFACT,
        severity="medium",
        rationale="The eUICC certificate is transmitted in cleartext-relative-to-the-attacker on C1 "
                  "(AuthenticateClient.req and HandleNotification.req), and SS4.3.1 puts the EID in its "
                  "subject.serialNumber. Under the TLS-stripped model this is a direct EID read. Even "
                  "WITH TLS intact, the EID reaches whichever SM-DP+ terminates the session -- so a "
                  "rogue-but-CI-valid SM-DP+ (D4) learns it too; TLS only stops a pure passive WAN sniffer.",
        artifact_path="testbed/ecosim/campaign/c1_eid_discovery.py",
    ))

    # --- Vector 2: what leaks in the FIRST (pre-authentication) message -------
    # InitiateAuthentication.req is sent before any server auth. Confirm it
    # fingerprints the device (euiccInfo1) but does NOT carry the EID.
    fp = adv.observed_fingerprint()
    first_req = next((o for o in adv.observed if o.kind == "InitiateAuthentication.req"), None)
    eid_in_first = first_req is not None and real_eid.encode().hex() in fp.get("euiccInfo1_hex", "")
    findings.append(record.Finding(
        round=6, direction="C1-eid-discovery", channel="C1",
        spec_section="SGP.22 §5.6.1 (InitiateAuthentication) / EUICCInfo1 ASN.1",
        hypothesis="The pre-authentication InitiateAuthentication.req fingerprints the device "
                   "(SVN, supported CI public-key IDs, RSP capabilities) but does NOT leak the EID.",
        mutation="inspect the first C1 message the attacker sees, before any server auth",
        observed=f"eid_present_in_first_message={eid_in_first} fingerprint_fields={list(fp)} "
                 f"euiccInfo1={fp.get('euiccInfo1_hex')}",
        classification=record.CONFORMANT,
        rationale="Matches spec (round-3 Q10): EID is never a field of EUICCInfo1/2. So the earliest "
                  "attacker-visible message discloses a device fingerprint (useful for targeting/version "
                  "downgrade reconnaissance) but the EID specifically only appears later, inside the "
                  "certificate -- an important precision: EID disclosure requires the flow to reach "
                  "AuthenticateClient, not merely to start.",
        severity="info",
        artifact_path="testbed/ecosim/campaign/c1_eid_discovery.py",
    ))

    # --- Vector 3: ACTIVE induction with a rogue-but-CI-valid SM-DP+ ----------
    # An attacker holding any CI-valid DPauth cert (compromised/rogue operator,
    # D4) can drive the eUICC through AuthenticateServer and thereby FORCE it to
    # hand over its EID-bearing certificate, without the user intending a
    # download to that server.
    pki = build_pki(eid="88888888888888888888888888888888")
    victim = SoftwareEuicc(pki, random.Random(3))
    ci = pki.ci.certificate
    challenge = tlv.find(tlv.walk(victim.get_euicc_challenge()), codec.TAG_GET_EUICC_CHALLENGE).children[0].value
    info1 = victim.get_euicc_info1(pki.ci_public_key_id())
    # Attacker plays SM-DP+ using the CI-valid DPauth key.
    tx = bytes(16)
    server_otsk = crypto.ephemeral_keypair()
    server_signed1 = protocol.server_signed1(tx, challenge, b"rogue-smdp", protocol.point_bytes(server_otsk))
    server_sig1 = crypto.sign(pki.dp_auth.private_key, server_signed1)
    auth = victim.authenticate_server(tx, server_signed1, server_sig1, pki.dp_auth.cert_der(), ci,
                                      codec.ctx_params1("anything"))
    induced_cert = x509.load_der_x509_certificate(auth["euiccCertificate"])
    induced_eid = eid_from_certificate(induced_cert)
    findings.append(record.Finding(
        round=6, direction="C1-eid-discovery", channel="C1",
        spec_section="SGP.22 §5.7.13 / §3.0.1",
        hypothesis="An attacker holding ANY CI-valid DPauth certificate can actively induce the eUICC "
                   "to disclose its EID-bearing certificate by completing AuthenticateServer, without "
                   "the user intending a download.",
        mutation="attacker acts as SM-DP+ with a CI-valid DPauth key; eUICC completes AuthenticateServer",
        observed=f"induced_eid={induced_eid} matches_device={induced_eid == victim.get_eid()}",
        classification=record.REAL_GAP if induced_eid == victim.get_eid() else record.ARTIFACT,
        severity="medium",
        rationale="The eUICC returns euiccSigned1 + euiccCertificate the moment AuthenticateServer "
                  "succeeds (valid CI chain + signature + challenge match) -- it does not require the "
                  "USER to have chosen this server. So EID disclosure is available to any rogue-but-CI-"
                  "valid SM-DP+, tying this to D4: the CI trust anchor authenticates the server to the "
                  "eUICC but does nothing to authorize it against the user's intent.",
        artifact_path="testbed/ecosim/campaign/c1_eid_discovery.py",
    ))

    # --- Vector 4 (the LIMIT): a pure forger CANNOT induce EID disclosure -----
    # Without a CI-valid cert, the eUICC aborts at AuthenticateServer BEFORE it
    # ever produces its certificate. This is the boundary the CI anchor enforces.
    forged_key = crypto.ephemeral_keypair()
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
    import datetime as _dt
    self_signed = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fake-smdp")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fake-smdp")]))
        .public_key(forged_key.public_key())
        .serial_number(9999)
        .not_valid_before(_dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc))
        .not_valid_after(_dt.datetime(2036, 1, 1, tzinfo=_dt.timezone.utc))
        .sign(forged_key, hashes.SHA256())
    )
    victim2 = SoftwareEuicc(pki, random.Random(4))
    challenge2 = tlv.find(tlv.walk(victim2.get_euicc_challenge()), codec.TAG_GET_EUICC_CHALLENGE).children[0].value
    fss1 = protocol.server_signed1(tx, challenge2, b"fake", protocol.point_bytes(crypto.ephemeral_keypair()))
    fsig = crypto.sign(forged_key, fss1)
    forger_blocked = False
    reason = ""
    try:
        victim2.authenticate_server(tx, fss1, fsig, self_signed.public_bytes(
            __import__("cryptography").hazmat.primitives.serialization.Encoding.DER), ci)
    except ValueError as exc:
        forger_blocked = True
        reason = str(exc)[:80]
    findings.append(record.Finding(
        round=6, direction="C1-eid-discovery", channel="C1",
        spec_section="SGP.22 §5.7.13 (server cert SHALL chain to CI)",
        hypothesis="A network attacker WITHOUT any CI-valid certificate cannot actively induce EID "
                   "disclosure -- the eUICC aborts at AuthenticateServer before revealing its certificate.",
        mutation="attacker forges InitiateAuthentication.resp with a self-signed (non-CI) cert",
        observed=f"forger_blocked_before_eid_disclosure={forger_blocked} reason={reason!r}",
        classification=record.CONFORMANT if forger_blocked else record.ARTIFACT,
        severity="info",
        rationale="This is the real limit on active EID discovery: the CI trust anchor stops a credential-"
                  "less forger. So active induction requires a CI-valid cert (Vector 3), while a pure "
                  "on-path forger is limited to PASSIVE EID capture from a flow the user themselves starts "
                  "(Vector 1). Defenders: EID confidentiality on C1 rests entirely on TLS, since the "
                  "application layer transmits it (in the cert) with no additional protection.",
        artifact_path="testbed/ecosim/campaign/c1_eid_discovery.py",
    ))

    record.append_many(findings)
    return findings


if __name__ == "__main__":
    results = run()
    by_class: dict[str, int] = {}
    for f in results:
        by_class[f.classification] = by_class.get(f.classification, 0) + 1
    print(f"C1 EID discovery: {len(results)} findings {by_class}")
    for f in results:
        print(f"  [{f.classification}/{f.severity}] {f.hypothesis[:95]}")
        print(f"      {f.observed[:160]}")
