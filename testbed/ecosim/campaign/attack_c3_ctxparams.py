"""D2-ctxparams-confused-deputy (channel C3): SGP.22 v3.1 SS5.7.13 AuthenticateServer.

Ground truth (see spec_notes/round1.md, section D2): ctxParams1 is built by the
LPA and travels UNSIGNED across the LPA<->eUICC hop. The eUICC "SHALL neither
check the values provided in ctxParams1 ... nor correlate them with subsequent
session activities" -- it just signs whatever matchingId/deviceInfo it was
handed into EuiccSigned1. The only backstop against a tampered matchingId is
the SM-DP+, which at AuthenticateClient (SS3.1.3 step 3) looks up the pending
order named by the eUICC-attested matchingId and rejects anything it does not
recognize.

This module drives the handshake by hand (mirroring lpa.Lpa.download_profile,
but calling euicc/smdp directly so ctxParams1 can be substituted the way an
on-device MITM between the LPAd and the eUICC APDU transport would) across
five scenarios, and records one classified finding per observed outcome:

  S1  baseline: ctxParams1 names the order the user's activation code intends.
  S2  confused deputy: ctxParams1 is rewritten to a DIFFERENT, still-valid,
      matchingId after the user scanned an activation code for another order.
  S3  unknown matchingId: ctxParams1 names an order that was never registered.
  S4  malformed ctxParams1: garbage / truncated bytes instead of a TLV.
  S5  structural matchingId edge cases inside an otherwise well-formed
      ctxParams1: oversized, embedded control characters, empty.

Run: ./venv/bin/python -m testbed.ecosim.campaign.attack_c3_ctxparams
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization

from .. import codec, tlv
from ..orchestrator import Ecosystem, build_ecosystem
from . import record

VICTIM_MID = "VICTIM-MID"
ATTACKER_MID = "ATTACKER-MID"
NONEXISTENT_MID = "NONEXISTENT-MID"

VICTIM_ICCID = "89010000000000000001"
ATTACKER_ICCID = "89020000000000000002"

ARTIFACT_PATH = "testbed/ecosim/campaign/attack_c3_ctxparams.py"
SPEC_SECTION = "SGP.22 v3.1 SS5.7.13 / SS3.1.3"


@dataclass
class HandshakeResult:
    installed: bool
    iccid: str
    profile_name: str


def _ci_public_key_id(eco: Ecosystem) -> bytes:
    spki = eco.pki.ci.certificate.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA1())
    digest.update(spki)
    return digest.finalize()


def _decode_challenge(wire: bytes) -> bytes:
    top = tlv.find(tlv.walk(wire), codec.TAG_GET_EUICC_CHALLENGE)
    if top is None:
        raise ValueError("GetEUICCChallenge.resp: missing top-level tag")
    inner = tlv.find(top.children, 0x80)
    if inner is None:
        raise ValueError("GetEUICCChallenge.resp: missing challenge value")
    return inner.value


def _decode_metadata_preview(metadata_preview_b64: str) -> tuple[str, str]:
    wire = codec.unb64(metadata_preview_b64)
    top = tlv.find(tlv.walk(wire), codec.TAG_STORE_METADATA)
    if top is None:
        raise ValueError("metadataPreview: missing top-level tag")
    iccid_node = tlv.find(top.children, codec.TAG_ICCID)
    name_node = tlv.find(top.children, codec.TAG_PROFILE_NAME)
    if iccid_node is None or name_node is None:
        raise ValueError("metadataPreview: missing ICCID or profile name")
    return iccid_node.value.hex(), name_node.value.decode("utf-8")


def _install_status_ok(wire: bytes) -> bool:
    # ProfileInstallationResult is now signed (euiccSignPIR over BF27), added
    # mid-campaign after this script originally ran -- use the current codec API
    # rather than the flat 0x80/0x81 tags this script predates.
    _transaction_id, _seq, ok, _sig = codec.parse_profile_installation_result(wire)
    return ok


def setup_orders(eco: Ecosystem) -> None:
    """Register a VICTIM order and an ATTACKER-visible order on the same SM-DP+.

    Both live on one SmDpPlus instance, exactly the shared-infrastructure case
    SS5.7.13's confused-deputy surface targets: any matchingId the eUICC signs
    is resolved against the FULL order book of that SM-DP+, not just the order
    the user's activation code named.
    """
    eco.smdp.register_order(
        matching_id=VICTIM_MID, iccid=VICTIM_ICCID, profile_name="victim-plan",
        sp_name="victim-mno", profile_class=0,
    )
    eco.smdp.register_order(
        matching_id=ATTACKER_MID, iccid=ATTACKER_ICCID, profile_name="attacker-plan",
        sp_name="attacker-mno", profile_class=0,
    )


def run_handshake(eco: Ecosystem, ctx_params1: bytes) -> HandshakeResult:
    """Drive one ES9+/ES10 handshake with caller-supplied ctxParams1 bytes.

    ``ctx_params1`` stands in for whatever the LPAd handed the eUICC over the
    on-device APDU transport at AuthenticateServer -- a MITM sitting on that
    hop can substitute it freely (SS5.7.13: unsigned at this leg). Any
    ValueError raised by euicc.authenticate_server or smdp.authenticate_client
    propagates to the caller so each scenario can classify its own failure
    mode instead of this helper papering over it.
    """
    euicc = eco.euicc
    smdp = eco.smdp
    ci_cert = eco.pki.ci.certificate

    challenge_wire = euicc.get_euicc_challenge()
    euicc_challenge = _decode_challenge(challenge_wire)
    euicc_info1_wire = euicc.get_euicc_info1(_ci_public_key_id(eco))

    init_resp = smdp.initiate_authentication(euicc_challenge, euicc_info1_wire, smdp.address)
    transaction_id = bytes.fromhex(init_resp["transactionId"])
    server_signed1 = codec.unb64(init_resp["serverSigned1"])
    server_signature1 = codec.unb64(init_resp["serverSignature1"])
    server_cert_der = codec.unb64(init_resp["serverCertificate"])

    # Per SS5.7.13 the eUICC signs ctx_params1 verbatim: this call only ever
    # raises on session/cert/signature mismatches, never on ctxParams1 content.
    auth_fields = euicc.authenticate_server(
        transaction_id, server_signed1, server_signature1, server_cert_der, ci_cert, ctx_params1,
    )

    auth_req = {
        "transactionId": init_resp["transactionId"],
        "euiccSigned1": codec.b64(auth_fields["euiccSigned1"]),
        "euiccSignature1": codec.b64(auth_fields["euiccSignature1"]),
        "euiccCertificate": codec.b64(auth_fields["euiccCertificate"]),
        "eumCertificate": codec.b64(auth_fields["eumCertificate"]),
        "euiccOtpk": codec.b64(auth_fields["euiccOtpk"]),
    }
    # The sole backstop: SM-DP+ resolves the eUICC-attested matchingId against
    # its own order book and raises if there is no pending order for it.
    auth_client_resp = smdp.authenticate_client(auth_req, ci_cert)

    bpp = smdp.get_bound_profile_package(auth_client_resp["transactionId"])
    install_wire = euicc.install_bound_profile_package(bpp)
    installed = _install_status_ok(install_wire)
    iccid, profile_name = _decode_metadata_preview(bpp["metadataPreview"])
    return HandshakeResult(installed=installed, iccid=iccid, profile_name=profile_name)


def scenario_s1_baseline(eco: Ecosystem) -> dict:
    ac = codec.ActivationCode(smdp_address=eco.smdp.address, matching_id=VICTIM_MID)
    ctx = codec.ctx_params1(ac.matching_id)
    result = run_handshake(eco, ctx)
    return {
        "name": "S1-baseline",
        "activation_code": ac.encode(),
        "result": result,
        "matches_intent": result.iccid == VICTIM_ICCID.lower() and result.profile_name == "victim-plan",
    }


def scenario_s2_confused_deputy(eco: Ecosystem) -> dict:
    """User scans an AC naming VICTIM-MID; an on-device MITM rewrites ctxParams1
    to ATTACKER-MID before the eUICC signs it. No signature/verification step
    anywhere in the handshake is sensitive to this -- the eUICC attests
    whatever matchingId it was handed, and the SM-DP+ dutifully serves the
    order that matchingId names."""
    ac = codec.ActivationCode(smdp_address=eco.smdp.address, matching_id=VICTIM_MID)
    mitm_ctx = codec.ctx_params1(ATTACKER_MID)
    result = run_handshake(eco, mitm_ctx)
    return {
        "name": "S2-confused-deputy",
        "user_activation_code": ac.encode(),
        "user_intended_matching_id": ac.matching_id,
        "mitm_rewritten_matching_id": ATTACKER_MID,
        "result": result,
        "wrong_profile_installed": result.iccid == ATTACKER_ICCID.lower()
        and result.profile_name == "attacker-plan",
    }


def scenario_s3_unknown_id(eco: Ecosystem) -> dict:
    ctx = codec.ctx_params1(NONEXISTENT_MID)
    try:
        run_handshake(eco, ctx)
        return {"name": "S3-unknown-id", "rejected": False, "error": ""}
    except ValueError as exc:
        return {"name": "S3-unknown-id", "rejected": True, "error": str(exc)}


def scenario_s4_malformed(eco: Ecosystem, label: str, ctx: bytes) -> dict:
    """Feed non-TLV / truncated bytes as ctxParams1. The eUICC must still sign
    it (it never parses ctxParams1), and the SM-DP+ must be the one that fails,
    inside codec.parse_matching_id -- confirming eUICC non-validation is
    faithful to SS5.7.13 rather than an accidental crash-early shortcut."""
    euicc_signed_without_raising = False
    smdp_rejected = False
    error = ""
    euicc = eco.euicc
    smdp = eco.smdp
    ci_cert = eco.pki.ci.certificate

    challenge_wire = euicc.get_euicc_challenge()
    euicc_challenge = _decode_challenge(challenge_wire)
    euicc_info1_wire = euicc.get_euicc_info1(_ci_public_key_id(eco))
    init_resp = smdp.initiate_authentication(euicc_challenge, euicc_info1_wire, smdp.address)
    transaction_id = bytes.fromhex(init_resp["transactionId"])
    server_signed1 = codec.unb64(init_resp["serverSigned1"])
    server_signature1 = codec.unb64(init_resp["serverSignature1"])
    server_cert_der = codec.unb64(init_resp["serverCertificate"])

    auth_fields = euicc.authenticate_server(
        transaction_id, server_signed1, server_signature1, server_cert_der, ci_cert, ctx,
    )
    euicc_signed_without_raising = True

    auth_req = {
        "transactionId": init_resp["transactionId"],
        "euiccSigned1": codec.b64(auth_fields["euiccSigned1"]),
        "euiccSignature1": codec.b64(auth_fields["euiccSignature1"]),
        "euiccCertificate": codec.b64(auth_fields["euiccCertificate"]),
        "eumCertificate": codec.b64(auth_fields["eumCertificate"]),
        "euiccOtpk": codec.b64(auth_fields["euiccOtpk"]),
    }
    try:
        smdp.authenticate_client(auth_req, ci_cert)
    except ValueError as exc:
        smdp_rejected = True
        error = str(exc)

    return {
        "name": f"S4-malformed-{label}",
        "euicc_signed_without_raising": euicc_signed_without_raising,
        "smdp_rejected": smdp_rejected,
        "error": error,
    }


def scenario_s5_structural(eco: Ecosystem, label: str, matching_id: str) -> dict:
    ctx = codec.ctx_params1(matching_id)
    base = {
        "name": f"S5-structural-{label}",
        "matching_id": matching_id,
        "matching_id_repr": repr(matching_id),
        "matching_id_len": len(matching_id),
    }
    try:
        result = run_handshake(eco, ctx)
        return {**base, "rejected": False, "result": result, "error": ""}
    except ValueError as exc:
        return {**base, "rejected": True, "error": str(exc)}


def _finding(**kwargs: object) -> record.Finding:
    kwargs.setdefault("round", 1)
    kwargs.setdefault("direction", "D2-ctxparams-confused-deputy")
    kwargs.setdefault("channel", "C3")
    kwargs.setdefault("spec_section", SPEC_SECTION)
    kwargs.setdefault("artifact_path", ARTIFACT_PATH)
    return record.Finding(**kwargs)


def build_findings(s1: dict, s2: dict, s3: dict, s4a: dict, s4b: dict, s5a: dict, s5b: dict, s5c: dict) -> list[record.Finding]:
    findings: list[record.Finding] = []

    r1: HandshakeResult = s1["result"]
    findings.append(_finding(
        hypothesis="A single, uncontested activation code naming VICTIM-MID resolves to the victim's own order.",
        mutation="ctxParams1 = codec.ctx_params1('VICTIM-MID'), matching the user's activation code.",
        observed=(
            f"eUICC signed ctxParams1, SM-DP+ served the VICTIM order, profile installed: "
            f"iccid={r1.iccid} profileName={r1.profile_name!r} (matches_intent={s1['matches_intent']})."
        ),
        classification=record.CONFORMANT,
        rationale="Baseline sanity check: with no tampering the handshake behaves exactly as SGP.22 intends.",
        severity="info",
    ))

    r2: HandshakeResult = s2["result"]
    findings.append(_finding(
        hypothesis=(
            "SGP.22 SS5.7.13: the eUICC 'SHALL neither check the values provided in ctxParams1 ... "
            "nor correlate them with subsequent session activities.' An on-device MITM between the "
            "LPAd and the eUICC (the APDU/C3 hop) can therefore swap the matchingId the eUICC signs "
            "for a DIFFERENT one, and the eUICC will attest it with no error."
        ),
        mutation=(
            f"User's activation code names matchingId={s2['user_intended_matching_id']!r} "
            f"({s2['user_activation_code']!r}); MITM rewrites ctxParams1 to matchingId="
            f"{s2['mitm_rewritten_matching_id']!r} before the eUICC signs."
        ),
        observed=(
            f"authenticate_server raised no error (no signature/verification failure -- the eUICC "
            f"attested attacker-supplied data as if it were legitimate). SM-DP+ AuthenticateClient "
            f"resolved the eUICC-attested matchingId to the ATTACKER order and served it. Installed "
            f"iccid={r2.iccid} profileName={r2.profile_name!r} -- the ATTACKER profile -- while the "
            f"user's activation code named the VICTIM order (iccid={VICTIM_ICCID.lower()}, "
            f"profileName='victim-plan'). wrong_profile_installed={s2['wrong_profile_installed']}."
        ),
        classification=record.REAL_GAP,
        rationale=(
            "This is not a testbed simplification: SS5.7.13 mandates the eUICC skip ctxParams1 "
            "validation in real RSP too, so the SAME confused-deputy surface exists on real hardware "
            "wherever the LPAd<->eUICC hop is attacker-controlled (rooted device, malicious/compromised "
            "LPA app, or a modem-level MITM). The SM-DP+'s per-matchingId order lookup (proven here as "
            "the S3 backstop) is the ONLY thing standing between a tampered ctxParams1 and a wrong-profile "
            "install; if a real SM-DP+ implementation trusted matchingId less strictly than the spec's "
            "'verify pending order' step (SS3.1.3 step 3) -- e.g. served the most-recent order for the "
            "eUICC's EID, or fell back to a default order -- the wrong profile would be silently bound "
            "and installed under a user-approved activation code that never named it."
        ),
        severity="high",
    ))

    findings.append(_finding(
        hypothesis="A matchingId naming an order that was never registered on this SM-DP+ must be rejected.",
        mutation=f"ctxParams1 = codec.ctx_params1('{NONEXISTENT_MID}') (no such order registered).",
        observed=f"smdp.authenticate_client raised ValueError: {s3['error']!r}. rejected={s3['rejected']}.",
        classification=record.CONFORMANT,
        rationale=(
            "This is the exact backstop SS3.1.3 step 3 requires and that S2 depends on: the SM-DP+ "
            "must refuse any matchingId with no pending order. Confirms our SmDpPlus._select_order "
            "implements the real-world safety net correctly -- S2's success is a genuine gap in the "
            "eUICC's non-validation, not a broken backstop."
        ),
        severity="info",
    ))

    findings.append(_finding(
        hypothesis="The eUICC does not parse/validate ctxParams1 content at all, so non-TLV garbage bytes are signed exactly like a well-formed structure.",
        mutation=f"ctxParams1 = {s4a['name'].split('-')[-1]} garbage bytes (not a valid BER-TLV).",
        observed=(
            f"euicc_signed_without_raising={s4a['euicc_signed_without_raising']}, "
            f"smdp_rejected={s4a['smdp_rejected']}, SM-DP+ error: {s4a['error']!r}."
        ),
        classification=record.REAL_GAP,
        rationale=(
            "Faithful to SS5.7.13: the eUICC's non-validation is spec-mandated behavior, not a testbed "
            "shortcut, so a real eUICC would sign this same garbage. The downstream risk is entirely at "
            "whichever party trusts the eUICC's attestation of ctxParams1 without independently parsing "
            "and validating it -- here the SM-DP+ catches it via parse_matching_id, but a party that "
            "skipped that step would propagate garbage further."
        ),
        severity="medium",
    ))

    findings.append(_finding(
        hypothesis="A truncated ctxParams1 TLV (cut mid-structure) is likewise signed unchecked by the eUICC and only caught downstream.",
        mutation="ctxParams1 = codec.ctx_params1('VICTIM-MID') truncated to its first 4 bytes.",
        observed=(
            f"euicc_signed_without_raising={s4b['euicc_signed_without_raising']}, "
            f"smdp_rejected={s4b['smdp_rejected']}, SM-DP+ error: {s4b['error']!r}."
        ),
        classification=record.REAL_GAP,
        rationale=(
            "Same as the garbage-bytes case: SS5.7.13 does not carve out an exception for malformed "
            "ctxParams1, so a real eUICC would sign a truncated structure too. SM-DP+-side TLV parsing "
            "is the only thing that turns this into a clean rejection instead of undefined behavior "
            "further downstream."
        ),
        severity="medium",
    ))

    findings.append(_finding(
        hypothesis="An oversized matchingId inside an otherwise well-formed ctxParams1 does not let an attacker bypass the SM-DP+ order lookup.",
        mutation=f"ctxParams1 with matchingId of length {s5a['matching_id_len']} (no matching order registered).",
        observed=f"rejected={s5a['rejected']}, error: {s5a['error']!r}.",
        classification=record.CONFORMANT,
        rationale="The order lookup is a plain dict/table match; an oversized key simply fails to match any registered order, same backstop as S3.",
        severity="info",
    ))

    findings.append(_finding(
        hypothesis="A matchingId containing embedded control characters does not smuggle a match against a differently-encoded registered order.",
        mutation=f"ctxParams1 with matchingId={s5b['matching_id_repr']} (control chars embedded, decoded via utf-8 'replace').",
        observed=f"rejected={s5b['rejected']}, error: {s5b['error']!r}.",
        classification=record.CONFORMANT,
        rationale="No normalization/truncation happens between decode and lookup, so control characters just produce a distinct string that matches no order.",
        severity="info",
    ))

    findings.append(_finding(
        hypothesis="An empty matchingId (zero-length TLV value, legal per SGP.22 Table 8 AC_Token grammar) does not default to any pending order.",
        mutation="ctxParams1 with matchingId='' (zero-length tag-0x80 value).",
        observed=f"rejected={s5c['rejected']}, error: {s5c['error']!r}.",
        classification=record.CONFORMANT,
        rationale="Empty string is looked up like any other key; since no order was registered under '', the SM-DP+ correctly rejects rather than silently choosing a default order.",
        severity="info",
    ))

    return findings


def main() -> None:
    eco = build_ecosystem()
    setup_orders(eco)

    s1 = scenario_s1_baseline(eco)
    s2 = scenario_s2_confused_deputy(eco)
    s3 = scenario_s3_unknown_id(eco)
    s4a = scenario_s4_malformed(eco, "garbage-bytes", b"\x01\x02\xff\x00\x13\x37")
    s4b = scenario_s4_malformed(eco, "truncated-tlv", codec.ctx_params1(VICTIM_MID)[:4])
    s5a = scenario_s5_structural(eco, "oversized-matchingid", "X" * 4096)
    s5b = scenario_s5_structural(eco, "control-chars-matchingid", "VIC\x00TIM\x07-MID")
    s5c = scenario_s5_structural(eco, "empty-matchingid", "")

    for scenario in (s1, s2, s3, s4a, s4b, s5a, s5b, s5c):
        print(json.dumps(scenario, default=lambda o: vars(o) if hasattr(o, "__dict__") else str(o)))

    findings = build_findings(s1, s2, s3, s4a, s4b, s5a, s5b, s5c)
    record.append_many(findings)

    print(json.dumps({
        "direction": "D2-ctxparams-confused-deputy",
        "channel": "C3",
        "findings_recorded": len(findings),
        "by_classification": {
            cls: sum(1 for f in findings if f.classification == cls)
            for cls in sorted({f.classification for f in findings})
        },
        "s2_wrong_profile_installed": s2["wrong_profile_installed"],
    }))


if __name__ == "__main__":
    main()
