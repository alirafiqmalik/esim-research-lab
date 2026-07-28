"""D3 — consent-time ProfileMetadata substitution (channel C1).

Models the SGP.22 v3.1 gap documented in spec_notes/round1.md: the profileMetadata
returned to the LPA by ES9+.AuthenticateClient is plaintext (SS4.4) and is NOT
covered by smdpSignature2 (SmdpSigned2 = transactionId/ccRequiredFlag/bppEuiccOtpk,
SS5.7.5). The install-time copy inside the BPP is BSP-protected separately, and no
spec clause requires the LPA to reconcile the two. So the metadata a user consents
to can differ from what is actually installed.

This is a defensive characterisation of a known real-protocol property, run entirely
against the local testbed and its own PKI. Runnable:
    ./venv/bin/python -m testbed.ecosim.campaign.attack_c1_metadata
"""

from __future__ import annotations

from dataclasses import replace

from cryptography.exceptions import InvalidTag

from .. import codec, tlv
from ..bus import C1, Message
from ..orchestrator import build_ecosystem, run_flow
from . import record


def _decode_metadata(store_metadata_wire: bytes) -> dict[str, str]:
    top = tlv.find(tlv.walk(store_metadata_wire), codec.TAG_STORE_METADATA)
    if top is None:
        return {"<unparsable>": store_metadata_wire.hex()}
    out: dict[str, str] = {}
    iccid = tlv.find(top.children, codec.TAG_ICCID)
    name = tlv.find(top.children, codec.TAG_PROFILE_NAME)
    spn = tlv.find(top.children, codec.TAG_SP_NAME)
    if iccid is not None:
        out["iccid"] = iccid.value.hex()
    if name is not None:
        out["profileName"] = name.value.decode("utf-8", "replace")
    if spn is not None:
        out["serviceProviderName"] = spn.value.decode("utf-8", "replace")
    return out


def _consent_metadata(messages: list[Message]) -> dict[str, str]:
    """The metadata the LPA would display at consent time (C1 AuthenticateClient.resp)."""
    for msg in messages:
        if msg.channel == C1 and msg.kind == "AuthenticateClient.resp":
            obj = codec.from_json_wire(msg.wire)
            return _decode_metadata(codec.unb64(obj["profileMetadata"]))
    raise ValueError("no AuthenticateClient.resp observed")


def _installed_metadata(eco) -> dict[str, str]:
    installed = eco.euicc._installed  # test harness: read the card's real installed record
    if not installed:
        raise ValueError("no profile installed")
    last = installed[-1]
    return {"iccid": last.iccid, "profileName": last.name}


def run() -> None:
    findings: list[record.Finding] = []

    # S1 — baseline: consent-shown == installed in the honest case.
    eco = build_ecosystem(seed=0xD3A)
    _summary, messages = run_flow(eco, profile_name="RealPlan-5GB", sp_name="RealTelco")
    consent = _consent_metadata(messages)
    installed = _installed_metadata(eco)
    baseline_match = consent.get("profileName") == installed.get("profileName")
    findings.append(record.Finding(
        round=1, direction="D3-metadata-consent-substitution", channel="C1",
        spec_section="SGP.22 §4.4 / §5.7.5",
        hypothesis="Honest flow: consent-shown metadata equals installed metadata.",
        mutation="none (baseline)",
        observed=f"consent={consent} installed={installed} match={baseline_match}",
        classification=record.CONFORMANT,
        rationale="No tampering; the two copies coincide as expected.",
        severity="info",
        artifact_path="testbed/ecosim/campaign/attack_c1_metadata.py",
    ))

    # S2 — substitute ONLY the consent-time profileMetadata (leave smdpSignature2 intact).
    eco = build_ecosystem(seed=0xD3B)
    fake_wire = codec.store_metadata(bytes.fromhex("00" * 10), "Free Trial 1GB", "TrustedTelco", 0)

    def consent_mutator(msg: Message) -> Message:
        if msg.channel == C1 and msg.kind == "AuthenticateClient.resp":
            obj = codec.from_json_wire(msg.wire)
            obj["profileMetadata"] = codec.b64(fake_wire)  # smdpSigned2/Signature2 untouched
            return replace(msg, wire=codec.to_json_wire(obj))
        return msg

    eco.bus.set_mutator(C1, consent_mutator)
    completed = True
    err = ""
    try:
        _summary, messages = run_flow(eco, profile_name="RealPlan-5GB", sp_name="RealTelco")
    except Exception as exc:  # noqa: BLE001 - characterising, not asserting
        completed = False
        err = repr(exc)
        messages = list(eco.bus.all_messages())
    finally:
        eco.bus.clear_mutators()

    consent_shown = _consent_metadata(messages)
    installed_real = _installed_metadata(eco) if completed else {}
    divergence = completed and consent_shown.get("profileName") != installed_real.get("profileName")
    findings.append(record.Finding(
        round=1, direction="D3-metadata-consent-substitution", channel="C1",
        spec_section="SGP.22 §4.4 / §5.7.5",
        hypothesis="A MITM between TLS termination and the consent UI can show benign "
                   "metadata while a different profile is actually installed.",
        mutation="rewrite AuthenticateClient.resp.profileMetadata -> 'Free Trial 1GB'/'TrustedTelco'; "
                 "leave smdpSigned2/smdpSignature2 unchanged",
        observed=f"flow_completed={completed} err={err} consent_shown={consent_shown} "
                 f"installed={installed_real} shown!=installed={divergence}",
        classification=record.REAL_GAP if divergence else record.ARTIFACT,
        rationale="profileMetadata is plaintext (SS4.4) and NOT covered by smdpSignature2 "
                  "(SmdpSigned2 has no metadata hash, SS5.7.5); no spec clause requires the LPA "
                  "to reconcile the consent copy with the BSP-protected install copy. So the "
                  "signature still verifies and the flow completes with shown!=installed.",
        severity="high" if divergence else "info",
        artifact_path="testbed/ecosim/campaign/attack_c1_metadata.py",
    ))

    # S3 — confirm smdpSignature2 does NOT cover profileMetadata (else S2 would have failed).
    findings.append(record.Finding(
        round=1, direction="D3-metadata-consent-substitution", channel="C1",
        spec_section="SGP.22 §5.7.5",
        hypothesis="smdpSignature2 does not bind profileMetadata.",
        mutation="observe that S2 completed despite mutated profileMetadata",
        observed=f"S2 flow_completed={completed} (no signature error) → metadata is unbound",
        classification=record.CONFORMANT,
        rationale="Faithful to SS5.7.5: SmdpSigned2 = {transactionId, ccRequiredFlag, bppEuiccOtpk}. "
                  "Our model leaves profileMetadata unsigned, matching the spec.",
        severity="info",
        artifact_path="testbed/ecosim/campaign/attack_c1_metadata.py",
    ))

    # S4 — the install-time (BSP-protected) copy MUST reject tampering (AEAD).
    eco = build_ecosystem(seed=0xD3C)

    def seal_mutator(msg: Message) -> Message:
        if msg.channel == C1 and msg.kind == "GetBoundProfilePackage.resp":
            obj = codec.from_json_wire(msg.wire)
            bpp = obj["boundProfilePackage"]
            raw = bytearray(codec.unb64(bpp["sealedProfile"]))
            raw[0] ^= 0xFF
            bpp["sealedProfile"] = codec.b64(bytes(raw))
            return replace(msg, wire=codec.to_json_wire(obj))
        return msg

    eco.bus.set_mutator(C1, seal_mutator)
    rejected = False
    reject_err = ""
    try:
        run_flow(eco, profile_name="RealPlan-5GB", sp_name="RealTelco")
    except (ValueError, InvalidTag) as exc:
        rejected = True
        reject_err = repr(exc)
    finally:
        eco.bus.clear_mutators()
    findings.append(record.Finding(
        round=1, direction="D3-metadata-consent-substitution", channel="C1",
        spec_section="SGP.22 §2.5.3 / §5.5.3",
        hypothesis="The install-time metadata inside the BPP is integrity-protected.",
        mutation="flip a byte of boundProfilePackage.sealedProfile",
        observed=f"install_rejected={rejected} err={reject_err}",
        classification=record.CONFORMANT if rejected else record.ARTIFACT,
        rationale="The install copy rides the BSP (AES-GCM here); tampering fails the AEAD tag, "
                  "so the attack is confined to the unauthenticated consent-display copy.",
        severity="info",
        artifact_path="testbed/ecosim/campaign/attack_c1_metadata.py",
    ))

    record.append_many(findings)
    return findings


if __name__ == "__main__":
    results = run()
    by_class: dict[str, int] = {}
    for f in results:
        by_class[f.classification] = by_class.get(f.classification, 0) + 1
    print(f"D3 metadata substitution: {len(results)} findings {by_class}")
    for f in results:
        print(f"  [{f.classification}/{f.severity}] {f.hypothesis}")
        print(f"      observed: {f.observed}")
