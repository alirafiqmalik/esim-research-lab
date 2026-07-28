"""Message builders/parsers for every layer of the simulated flow.

ES2+ / ES9+ are modelled as JSON (matching reality: JSON envelopes carrying
base64 blobs). ES10 (C3) is modelled as BER-TLV APDUs. The tag numbers follow
SGP.22 so the structure verifier and the invariant analysis reflect real framing.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from . import crypto, tlv

# --- ES10 (C3) APDU tags, per SGP.22 ---------------------------------------
TAG_GET_EUICC_CHALLENGE = 0xBF2E
TAG_GET_EUICC_INFO1 = 0xBF20
TAG_AUTHENTICATE_SERVER = 0xBF38
TAG_PREPARE_DOWNLOAD = 0xBF21
TAG_BOUND_PROFILE_PACKAGE = 0xBF36
TAG_STORE_METADATA = 0xBF25
TAG_PROFILE_INSTALL_RESULT = 0xBF37
TAG_LIST_NOTIFICATION = 0xBF28
TAG_GET_EID = 0xBF3E   # ES10c.GetEID (GetEuiccDataResponse, tag [62]) -- plaintext, unsigned
TAG_EID_VALUE = 0x80   # eidValue [APPLICATION 26] Octet16 in the real spec; scoped tag here

# Post-install profile lifecycle (ES10c): local LPA<->eUICC commands, ICCID-keyed.
# Tag numbers here are ours (mirroring this codebase's existing practice for
# inner/local tags, e.g. TAG_CTX_PARAMS1) -- what's under test is the
# authorization boundary, not exact SGP.22 wire-format tag values.
TAG_ENABLE_PROFILE = 0xBF31
TAG_DISABLE_PROFILE = 0xBF32
TAG_DELETE_PROFILE = 0xBF33
TAG_MEMORY_RESET = 0xBF34
TAG_LIFECYCLE_RESULT = 0x80

# StoreMetadata / ProfileInfo inner tags
TAG_ICCID = 0x5A
TAG_PROFILE_NAME = 0x92
TAG_SP_NAME = 0x91
TAG_PROFILE_CLASS = 0x95
TAG_ICON_TYPE = 0x93
TAG_ICON = 0x94


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(s: str) -> bytes:
    return base64.b64decode(s)


def to_json_wire(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def from_json_wire(wire: bytes) -> dict:
    return json.loads(wire.decode("utf-8"))


# --- C2a: activation code ---------------------------------------------------
@dataclass
class ActivationCode:
    smdp_address: str
    matching_id: str
    oid: str = ""
    cc_required: bool = False
    version: str = "1"

    def encode(self) -> str:
        parts = [f"LPA:{self.version}", self.smdp_address, self.matching_id, self.oid]
        s = "$".join(parts)
        if self.cc_required:
            s += "$1"
        return s

    @classmethod
    def parse(cls, text: str) -> "ActivationCode":
        if not text.startswith("LPA:"):
            raise ValueError("activation code missing 'LPA:' scheme")
        body = text[len("LPA:"):]
        fields = body.split("$")
        if len(fields) < 3:
            raise ValueError(f"activation code needs >=3 fields, got {len(fields)}")
        version = fields[0]
        if version != "1":
            # SGP.22 SS4.1 Table 8 / SS3.1.3.1 step 1: AC_Format SHALL be "1"; any
            # other value SHALL be treated as invalid by a conformant LPA.
            raise ValueError(f"AC_Format must be '1', got {version!r}")
        smdp = fields[1]
        matching = fields[2]
        oid = fields[3] if len(fields) > 3 else ""
        cc = len(fields) > 4 and fields[4] == "1"
        if not smdp:
            raise ValueError("empty SM-DP+ address")
        return cls(smdp_address=smdp, matching_id=matching, oid=oid, cc_required=cc, version=version)


# --- ES10 APDU builders -----------------------------------------------------
def apdu_get_euicc_challenge() -> bytes:
    return tlv.encode(TAG_GET_EUICC_CHALLENGE, b"")


def apdu_get_euicc_info1() -> bytes:
    return tlv.encode(TAG_GET_EUICC_INFO1, b"")


def apdu_get_eid() -> bytes:
    return tlv.encode(TAG_GET_EID, b"")


def eid_response(eid_digits: str) -> bytes:
    """SGP.22 SS5.7.20: GetEuiccDataResponse -- plaintext, unsigned, unencrypted."""
    return tlv.encode_constructed(TAG_GET_EID, [tlv.encode(TAG_EID_VALUE, eid_digits.encode("ascii"))])


def apdu_enable_profile(iccid: bytes) -> bytes:
    return tlv.encode_constructed(TAG_ENABLE_PROFILE, [tlv.encode(TAG_ICCID, iccid)])


def apdu_disable_profile(iccid: bytes) -> bytes:
    return tlv.encode_constructed(TAG_DISABLE_PROFILE, [tlv.encode(TAG_ICCID, iccid)])


def apdu_delete_profile(iccid: bytes) -> bytes:
    return tlv.encode_constructed(TAG_DELETE_PROFILE, [tlv.encode(TAG_ICCID, iccid)])


def lifecycle_result(tag: int, ok: bool) -> bytes:
    return tlv.encode_constructed(tag, [tlv.encode(TAG_LIFECYCLE_RESULT, b"\x00" if ok else b"\x01")])


def apdu_memory_reset() -> bytes:
    """SGP.22 SS5.7.19: deletes entire profile categories 'regardless of ... any
    Profile Policy Rules' -- no ICCID/category parameter needed for this model,
    which resets everything (the maximal, most-permissive case)."""
    return tlv.encode(TAG_MEMORY_RESET, b"")


def parse_eid_response(wire: bytes) -> str:
    top = tlv.find(tlv.walk(wire), TAG_GET_EID)
    if top is None:
        raise ValueError("GetEID.resp: missing top-level tag (BF3E)")
    node = tlv.find(top.children, TAG_EID_VALUE)
    if node is None:
        raise ValueError("GetEID.resp: missing eidValue")
    return node.value.decode("ascii", "replace")


def euicc_info1(svn: bytes, ci_pkid: bytes) -> bytes:
    """EUICCInfo1: SVN (82) + list of CI public-key identifiers (A9/AA)."""
    svn_tlv = tlv.encode(0x82, svn)
    verify_ids = tlv.encode(0xA9, tlv.encode(0x04, ci_pkid))
    sign_ids = tlv.encode(0xAA, tlv.encode(0x04, ci_pkid))
    return tlv.encode_constructed(TAG_GET_EUICC_INFO1, [svn_tlv, verify_ids, sign_ids])


def euicc_challenge_response(challenge: bytes) -> bytes:
    return tlv.encode_constructed(TAG_GET_EUICC_CHALLENGE, [tlv.encode(0x80, challenge)])


def store_metadata(iccid: bytes, profile_name: str, sp_name: str, profile_class: int) -> bytes:
    return tlv.encode_constructed(TAG_STORE_METADATA, [
        tlv.encode(TAG_ICCID, iccid),
        tlv.encode(TAG_PROFILE_NAME, profile_name.encode("utf-8")),
        tlv.encode(TAG_SP_NAME, sp_name.encode("utf-8")),
        tlv.encode(TAG_PROFILE_CLASS, bytes([profile_class])),
    ])


# ctxParams1 (CtxParamsForCommonAuthentication, SGP.22 SS5.7.13): matchingId + deviceInfo.
# Built by the LPA; the eUICC signs it unchecked. Tag A0 (context-constructed).
TAG_CTX_PARAMS1 = 0xA0
TAG_MATCHING_ID = 0x80
TAG_DEVICE_INFO = 0x81


def ctx_params1(matching_id: str, device_info: bytes = b"ecosim-device") -> bytes:
    return tlv.encode_constructed(TAG_CTX_PARAMS1, [
        tlv.encode(TAG_MATCHING_ID, matching_id.encode("utf-8")),
        tlv.encode(TAG_DEVICE_INFO, device_info),
    ])


def parse_matching_id(ctx_params1_wire: bytes) -> str:
    """Extract matchingId from a ctxParams1 TLV. Raises ValueError if absent/malformed."""
    nodes = tlv.walk(ctx_params1_wire)
    top = tlv.find(nodes, TAG_CTX_PARAMS1)
    if top is None:
        raise ValueError("ctxParams1: missing A0 container")
    mid = tlv.find(top.children, TAG_MATCHING_ID)
    if mid is None:
        raise ValueError("ctxParams1: missing matchingId (tag 0x80)")
    return mid.value.decode("utf-8", "replace")


# ProfileInstallationResult (SGP.22 SS2.5.6): euiccSignPIR is a mandatory eUICC
# signature over profileInstallationResultData, which includes seqNumber and
# finalResult -- unlike euiccCiPKIdToBeUsed or consent-time profileMetadata,
# nothing here is meant to be unsigned.
TAG_PIR_DATA = 0xBF27
TAG_NOTIF_METADATA = 0xBF2F
TAG_PIR_SIGNATURE = 0x5F37
TAG_PIR_TRANSACTION_ID = 0x80   # scoped under BF27
TAG_PIR_SEQ_NUMBER = 0x80       # scoped under BF2F
TAG_PIR_FINAL_RESULT = 0x82     # scoped under BF27


def profile_installation_result_data(transaction_id: bytes, seq: int, ok: bool) -> bytes:
    notif_metadata = tlv.encode_constructed(TAG_NOTIF_METADATA, [
        tlv.encode(TAG_PIR_SEQ_NUMBER, seq.to_bytes(2, "big")),
    ])
    return tlv.encode_constructed(TAG_PIR_DATA, [
        tlv.encode(TAG_PIR_TRANSACTION_ID, transaction_id),
        notif_metadata,
        tlv.encode(TAG_PIR_FINAL_RESULT, b"\x00" if ok else b"\x01"),
    ])


def profile_installation_result(pir_data_wire: bytes, signature: bytes) -> bytes:
    return tlv.encode_constructed(TAG_PROFILE_INSTALL_RESULT, [
        pir_data_wire,
        tlv.encode(TAG_PIR_SIGNATURE, signature),
    ])


def parse_profile_installation_result(wire: bytes) -> tuple[bytes, int, bool, bytes]:
    """Returns (transaction_id, seq, ok, signature). Raises ValueError on malformed input."""
    top = tlv.find(tlv.walk(wire), TAG_PROFILE_INSTALL_RESULT)
    if top is None:
        raise ValueError("ProfileInstallationResult: missing top-level tag (BF37)")
    pir_data = tlv.find(top.children, TAG_PIR_DATA)
    sig_node = tlv.find(top.children, TAG_PIR_SIGNATURE)
    if pir_data is None:
        raise ValueError("ProfileInstallationResult: missing profileInstallationResultData (BF27)")
    if sig_node is None:
        raise ValueError("ProfileInstallationResult: missing euiccSignPIR (5F37)")
    txid_node = tlv.find(pir_data.children, TAG_PIR_TRANSACTION_ID)
    notif_node = tlv.find(pir_data.children, TAG_NOTIF_METADATA)
    final_node = tlv.find(pir_data.children, TAG_PIR_FINAL_RESULT)
    if txid_node is None or notif_node is None or final_node is None:
        raise ValueError("ProfileInstallationResultData: missing transactionId/notificationMetadata/finalResult")
    seq_node = tlv.find(notif_node.children, TAG_PIR_SEQ_NUMBER)
    if seq_node is None:
        raise ValueError("NotificationMetadata: missing seqNumber")
    ok = final_node.value == b"\x00"
    return txid_node.value, int.from_bytes(seq_node.value, "big"), ok, sig_node.value


def verify_profile_installation_result(wire: bytes, euicc_public_key) -> tuple[bytes, int, bool]:
    """Reconstruct the canonical PIRData bytes and verify euiccSignPIR over them.

    Raises ValueError on any parse or signature failure -- callers (the SM-DP+
    receiving HandleNotification) MUST NOT trust seq/ok without this passing."""
    transaction_id, seq, ok, signature = parse_profile_installation_result(wire)
    pir_data_wire = profile_installation_result_data(transaction_id, seq, ok)
    if not crypto.verify(euicc_public_key, signature, pir_data_wire):
        raise ValueError("euiccSignPIR verification failed")
    return transaction_id, seq, ok
