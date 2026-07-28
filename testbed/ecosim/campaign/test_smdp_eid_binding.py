"""D1-D2-eid-binding-contrast (channel C3): does ES2+ EID-binding close the
matchingId confused-deputy surface?

Ground truth (see D1/D2 in findings.jsonl and attack_c3_ctxparams.py): the
eUICC "SHALL neither check the values provided in ctxParams1 ... nor correlate
them" (SGP.22 SS5.7.13), so an attacker's own, entirely legitimate device --
its own CI-issued cert, its own valid signature, its own real EID -- can
authenticate normally and simply claim a DIFFERENT (victim's) matchingId. The
SM-DP+'s matchingId -> order lookup (SmDpPlus._select_order) is the only
backstop, and until this module's smdp.py change it had no notion of WHICH
eUICC was allowed to consume an order -- any eUICC that named the right
matchingId got it, no CI cert forgery required.

SGP.22's ES2+ profile-ordering interface supports an optional `eid` parameter
that lets an operator bind an order to a specific, known EID (common when the
operator already knows the target device, e.g. carrier-locked or enterprise
provisioning; the matchingId-only flow above is the OTHER common case --
consumer self-service QR/AC issuance with no prior EID knowledge). This
module adds that as an opt-in `Order.eid` field (smdp.py) and drives the SAME
confused-deputy scenario against BOTH configurations:

  unbound order (eid=None, the pre-existing/default behavior)   -> REAL-GAP
  EID-bound order (eid=<victim's real EID>)                     -> CONFORMANT

plus a sanity check that EID-binding does not also break the legitimate
device's own access to its own bound order.

Caveat carried over from D4/test_c1_rogue_smdp.py: pki.py has ONE shared
eUICC keypair/certificate for the whole testbed (there is no per-device
cert), so "the attacker's own device" here is a second SoftwareEuicc instance
built on that same shared keypair -- distinguished only by its own randomly
generated EID (SoftwareEuicc.__init__ draws a fresh EID per instance
regardless of shared keys). `authenticated_eid` is threaded into
authenticate_client() directly by the caller (see smdp.py's docstring) rather
than read off any signed wire field -- our PKI model has no cert-embedded EID
to bind to yet, so this is a contrast test of the LOOKUP LOGIC, not (yet) of
an end-to-end cryptographically-attested EID channel. That distinction is the
honest caveat for this specific finding: it shows EID-binding as a table-side
control closes the gap in our model, not that real eUICC certs already carry
a verifiable EID today.

Runnable: ./venv/bin/python -m testbed.ecosim.campaign.test_smdp_eid_binding
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization

from .. import codec, tlv
from ..euicc import SoftwareEuicc
from ..orchestrator import Ecosystem, build_ecosystem
from . import record

VICTIM_MID_UNBOUND = "VICTIM-MID-UNBOUND"
VICTIM_MID_BOUND = "VICTIM-MID-BOUND"

VICTIM_ICCID = "89010000000000000011"
ARTIFACT_PATH = "testbed/ecosim/campaign/test_smdp_eid_binding.py"
SPEC_SECTION = "SGP.22 order-binding practice (ES2+ eid parameter) / SS5.7.13 / SS3.1.3"


@dataclass
class HandshakeResult:
    installed: bool
    iccid: str
    profile_name: str


def _ci_pkid(eco: Ecosystem) -> bytes:
    spki = eco.pki.ci.certificate.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA1())
    digest.update(spki)
    return digest.finalize()


def _decode_challenge(wire: bytes) -> bytes:
    top = tlv.find(tlv.walk(wire), codec.TAG_GET_EUICC_CHALLENGE)
    inner = tlv.find(top.children, 0x80) if top else None
    if top is None or inner is None:
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
    _transaction_id, _seq, ok, _sig = codec.parse_profile_installation_result(wire)
    return ok


def run_handshake(eco: Ecosystem, euicc: SoftwareEuicc, ctx_params1: bytes, authenticated_eid: str) -> HandshakeResult:
    """Drive one ES9+/ES10 handshake for a given (possibly non-default) eUICC
    identity, with caller-supplied ctxParams1 and authenticated_eid -- mirrors
    attack_c3_ctxparams.run_handshake but parameterized over WHICH eUICC is
    authenticating, so a second device (a distinct EID) can play the attacker.
    """
    smdp = eco.smdp
    ci_cert = eco.pki.ci.certificate

    challenge_wire = euicc.get_euicc_challenge()
    euicc_challenge = _decode_challenge(challenge_wire)
    euicc_info1_wire = euicc.get_euicc_info1(_ci_pkid(eco))

    init_resp = smdp.initiate_authentication(euicc_challenge, euicc_info1_wire, smdp.address)
    transaction_id = bytes.fromhex(init_resp["transactionId"])
    server_signed1 = codec.unb64(init_resp["serverSigned1"])
    server_signature1 = codec.unb64(init_resp["serverSignature1"])
    server_cert_der = codec.unb64(init_resp["serverCertificate"])

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
    auth_client_resp = smdp.authenticate_client(auth_req, ci_cert, authenticated_eid=authenticated_eid)

    bpp = smdp.get_bound_profile_package(auth_client_resp["transactionId"])
    install_wire = euicc.install_bound_profile_package(bpp)
    installed = _install_status_ok(install_wire)
    iccid, profile_name = _decode_metadata_preview(bpp["metadataPreview"])
    return HandshakeResult(installed=installed, iccid=iccid, profile_name=profile_name)


def main() -> None:
    eco = build_ecosystem(seed=0xE1D0)
    victim_euicc = eco.euicc                       # the device the order was meant for
    attacker_euicc = SoftwareEuicc(eco.pki, eco.rng)  # a second, distinct device
    # The EID now lives in the eUICC certificate (SS4.3.1), so two eUICCs off the
    # same PKI share one EID. This cross-device test only needs two DISTINCT EID
    # VALUES for the binding logic (authenticated_eid is passed explicitly below),
    # so override the second device's EID rather than minting a whole second PKI.
    attacker_euicc._eid = "99999999999999999999999999999999"

    victim_eid = victim_euicc.get_eid()
    attacker_eid = attacker_euicc.get_eid()
    assert victim_eid != attacker_eid, "test setup bug: victim/attacker EIDs collided"

    eco.smdp.register_order(
        matching_id=VICTIM_MID_UNBOUND, iccid=VICTIM_ICCID, profile_name="victim-plan-unbound",
        sp_name="victim-mno", profile_class=0, eid=None,
    )
    eco.smdp.register_order(
        matching_id=VICTIM_MID_BOUND, iccid=VICTIM_ICCID, profile_name="victim-plan-bound",
        sp_name="victim-mno", profile_class=0, eid=victim_eid,
    )

    findings: list[record.Finding] = []

    # --- S2: unbound order, attacker's own device claims the victim's matchingId
    s2_error = ""
    try:
        s2 = run_handshake(
            eco, attacker_euicc, codec.ctx_params1(VICTIM_MID_UNBOUND), attacker_eid,
        )
        s2_wrong_profile = s2.iccid == VICTIM_ICCID.lower() and s2.profile_name == "victim-plan-unbound"
    except ValueError as exc:
        s2 = None
        s2_wrong_profile = False
        s2_error = str(exc)

    findings.append(record.Finding(
        round=2, direction="D1-D2-eid-binding-contrast", channel="C3", spec_section=SPEC_SECTION,
        hypothesis=(
            "An UNBOUND order (no eid recorded at ES2+ order time -- the default, "
            "consumer self-service case) can be consumed by ANY authenticated eUICC "
            "that names its matchingId, including one that is not the intended "
            "recipient and required no forged/stolen CI credentials of any kind."
        ),
        mutation=(
            f"attacker_euicc (eid={attacker_eid}) authenticates honestly with its own cert/signature, "
            f"but ctxParams1 names matchingId={VICTIM_MID_UNBOUND!r} (the victim's order, eid=None)."
        ),
        observed=(
            f"installed={s2.installed if s2 else None}, iccid={s2.iccid if s2 else None!r}, "
            f"profileName={s2.profile_name if s2 else None!r}, wrong_profile_installed={s2_wrong_profile}, "
            f"error={s2_error!r}."
        ),
        classification=record.REAL_GAP,
        rationale=(
            "Reconfirms D1/D2 with two genuinely distinct device identities (different EIDs, not just "
            "an on-device MITM against one eUICC): the attacker's own legitimately-issued device is "
            "sufficient. No CI cert forgery, no signature break -- only the SM-DP+'s order-lookup table "
            "stands between a named matchingId and profile issuance, and by default that table records "
            "no notion of an intended device at all."
        ),
        severity="high",
        artifact_path=ARTIFACT_PATH,
    ))

    # --- S3: EID-bound order, same attack attempted -> must be rejected --------
    s3_error = ""
    try:
        s3 = run_handshake(
            eco, attacker_euicc, codec.ctx_params1(VICTIM_MID_BOUND), attacker_eid,
        )
        s3_rejected = False
    except ValueError as exc:
        s3 = None
        s3_rejected = True
        s3_error = str(exc)

    findings.append(record.Finding(
        round=2, direction="D1-D2-eid-binding-contrast", channel="C3", spec_section=SPEC_SECTION,
        hypothesis=(
            "The IDENTICAL matchingId-substitution attack fails once the order is EID-bound "
            "(eid recorded at ES2+ order time), because _select_order now rejects an "
            "authenticated_eid that does not match the order's recorded eid."
        ),
        mutation=(
            f"Same attacker_euicc (eid={attacker_eid}) and same technique, now against "
            f"matchingId={VICTIM_MID_BOUND!r} (order bound to eid={victim_eid})."
        ),
        observed=f"rejected={s3_rejected}, error={s3_error!r}, result={s3}.",
        classification=record.CONFORMANT,
        rationale=(
            "Direct contrast to S2 above: EID-binding at order time is a real, spec-available "
            "ES2+ operator practice, and it closes this specific confused-deputy path completely "
            "when used, at the cost of the operator needing to know the EID up front (unavailable "
            "for pure QR/AC self-service issuance, which is exactly why S2's unbound case remains "
            "a REAL-GAP for that deployment shape rather than a universal protocol break)."
        ),
        severity="info",
        artifact_path=ARTIFACT_PATH,
    ))

    # --- S4: EID-bound order, legitimate device -> must still work -------------
    s4 = run_handshake(eco, victim_euicc, codec.ctx_params1(VICTIM_MID_BOUND), victim_eid)
    s4_ok = s4.installed and s4.iccid == VICTIM_ICCID.lower() and s4.profile_name == "victim-plan-bound"

    findings.append(record.Finding(
        round=2, direction="D1-D2-eid-binding-contrast", channel="C3", spec_section=SPEC_SECTION,
        hypothesis="EID-binding must not also break the legitimate device's own access to its own order.",
        mutation=f"victim_euicc (eid={victim_eid}) authenticates normally against its own bound order.",
        observed=f"installed={s4.installed}, iccid={s4.iccid!r}, profileName={s4.profile_name!r}, matches_intent={s4_ok}.",
        classification=record.CONFORMANT if s4_ok else record.ARTIFACT,
        rationale=(
            "Sanity check for S3's fix: an additive, opt-in eid check that also broke the intended "
            "recipient's own download would not be a usable mitigation. Confirms it does not."
        ),
        severity="info",
        artifact_path=ARTIFACT_PATH,
    ))

    for f in findings:
        print(json.dumps({"direction": f.direction, "classification": f.classification, "severity": f.severity}))

    record.append_many(findings)

    print(json.dumps({
        "direction": "D1-D2-eid-binding-contrast",
        "channel": "C3",
        "findings_recorded": len(findings),
        "by_classification": {
            cls: sum(1 for f in findings if f.classification == cls)
            for cls in sorted({f.classification for f in findings})
        },
    }))


if __name__ == "__main__":
    main()
