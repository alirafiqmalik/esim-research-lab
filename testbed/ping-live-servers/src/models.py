"""Typed request/response dataclasses for the device-callable ES9+/ES11 functions.

Field names mostly match the real GSMA RSP JSON wire format (see
notes/03-api-request-list.md). Two functions -- AuthenticateClient and
GetBoundProfilePackage -- carry fields in ecosim's *decomposed* shape
(individual b64 fields) rather than the real single-ASN.1-blob field
(`authenticateServerResponse` / `boundProfilePackage`), because that decomposed
shape is what testbed/ecosim/ actually implements and what Step 4 validates
against. Each such dataclass says so in its docstring; notes/03 documents the
real vs. ecosim shape side by side.

Byte fields are base64 on the wire; dataclasses hold raw bytes so callers
never juggle encoding by hand.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

from .errors import MalformedResponseError


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text)


def _require(obj: dict, key: str) -> object:
    if key not in obj:
        raise MalformedResponseError(f"response missing required field {key!r}")
    return obj[key]


def _require_str(obj: dict, key: str) -> str:
    value = _require(obj, key)
    if not isinstance(value, str):
        raise MalformedResponseError(f"field {key!r} expected a string, got {type(value).__name__}")
    return value


def _require_b64(obj: dict, key: str) -> bytes:
    try:
        return _unb64(_require_str(obj, key))
    except (ValueError, TypeError) as exc:
        raise MalformedResponseError(f"field {key!r} is not valid base64") from exc


# --- ES9+ #1 / ES11 #6: InitiateAuthentication ------------------------------


@dataclass
class InitiateAuthenticationRequest:
    """Real wire shape, unchanged by ecosim. `smdp_address` is required for
    ES9+ and omitted for ES11 (talking to the SM-DS itself)."""

    euicc_challenge: bytes
    euicc_info1: bytes
    smdp_address: str = ""

    def to_wire(self) -> dict[str, object]:
        body: dict[str, object] = {
            "euiccChallenge": _b64(self.euicc_challenge),
            "euiccInfo1": _b64(self.euicc_info1),
        }
        if self.smdp_address:
            body["smdpAddress"] = self.smdp_address
        return body


@dataclass
class InitiateAuthenticationResponse:
    transaction_id: str
    server_signed1: bytes
    server_signature1: bytes
    euicc_ci_pkid_to_be_used: bytes
    server_certificate: bytes
    server_otpk: bytes | None = None  # ecosim-only convenience field; not on the real wire

    @classmethod
    def from_wire(cls, obj: dict) -> InitiateAuthenticationResponse:
        return cls(
            transaction_id=_require_str(obj, "transactionId"),
            server_signed1=_require_b64(obj, "serverSigned1"),
            server_signature1=_require_b64(obj, "serverSignature1"),
            euicc_ci_pkid_to_be_used=_require_b64(obj, "euiccCiPKIdToBeUsed"),
            server_certificate=_require_b64(obj, "serverCertificate"),
            server_otpk=_unb64(obj["serverOtpk"]) if "serverOtpk" in obj else None,
        )


# --- ES9+ #2: AuthenticateClient --------------------------------------------


@dataclass
class AuthenticateClientRequest:
    """ecosim-decomposed shape: individual euiccSigned1/euiccSignature1/
    euiccCertificate/eumCertificate/euiccOtpk fields. The real wire carries
    these inside one `authenticateServerResponse` ASN.1 blob -- ecosim (and
    this library, to stay validate-able against it) does not build real
    ASN.1; see notes/03-api-request-list.md."""

    transaction_id: str
    euicc_signed1: bytes
    euicc_signature1: bytes
    euicc_certificate: bytes
    eum_certificate: bytes
    euicc_otpk: bytes

    def to_wire(self) -> dict[str, object]:
        return {
            "transactionId": self.transaction_id,
            "euiccSigned1": _b64(self.euicc_signed1),
            "euiccSignature1": _b64(self.euicc_signature1),
            "euiccCertificate": _b64(self.euicc_certificate),
            "eumCertificate": _b64(self.eum_certificate),
            "euiccOtpk": _b64(self.euicc_otpk),
        }


@dataclass
class AuthenticateClientResponse:
    transaction_id: str
    profile_metadata: bytes
    smdp_signed2: bytes
    smdp_signature2: bytes
    smdp_pb_certificate: bytes

    @classmethod
    def from_wire(cls, obj: dict) -> AuthenticateClientResponse:
        return cls(
            transaction_id=_require_str(obj, "transactionId"),
            profile_metadata=_require_b64(obj, "profileMetadata"),
            smdp_signed2=_require_b64(obj, "smdpSigned2"),
            smdp_signature2=_require_b64(obj, "smdpSignature2"),
            smdp_pb_certificate=_require_b64(obj, "smdpPbCertificate"),
        )


# --- ES9+ #3: GetBoundProfilePackage ----------------------------------------


@dataclass
class GetBoundProfilePackageRequest:
    transaction_id: str

    def to_wire(self) -> dict[str, object]:
        return {"transactionId": self.transaction_id}


@dataclass
class GetBoundProfilePackageResponse:
    """ecosim-decomposed shape (serverOtpk/sealedProfile/metadataPreview).
    The real wire carries one `boundProfilePackage` ASN.1 blob instead."""

    transaction_id: str
    server_otpk: bytes
    sealed_profile: bytes
    metadata_preview: bytes

    @classmethod
    def from_wire(cls, obj: dict) -> GetBoundProfilePackageResponse:
        return cls(
            transaction_id=_require_str(obj, "transactionId"),
            server_otpk=_require_b64(obj, "serverOtpk"),
            sealed_profile=_require_b64(obj, "sealedProfile"),
            metadata_preview=_require_b64(obj, "metadataPreview"),
        )


# --- ES9+ #4: HandleNotification --------------------------------------------


@dataclass
class HandleNotificationRequest:
    """ecosim-decomposed shape (notification/seq/euiccCertificate). The real
    wire carries one `pendingNotification` ASN.1 blob instead."""

    notification: bytes
    seq: int
    euicc_certificate: bytes

    def to_wire(self) -> dict[str, object]:
        return {
            "notification": _b64(self.notification),
            "seq": self.seq,
            "euiccCertificate": _b64(self.euicc_certificate),
        }


# --- ES9+ #5: CancelSession --------------------------------------------------


@dataclass
class CancelSessionRequest:
    """Real wire shape. Not modeled in ecosim -- builder only, no local
    validation target for this function (see notes/03-api-request-list.md)."""

    transaction_id: str
    cancel_session_response: bytes

    def to_wire(self) -> dict[str, object]:
        return {
            "transactionId": self.transaction_id,
            "cancelSessionResponse": _b64(self.cancel_session_response),
        }


# --- ES11 #7: discovery ------------------------------------------------------


@dataclass
class Es11DiscoveryRequest:
    """Stands in for the real ES11.InitiateAuthentication + ES11.AuthenticateClient
    handshake, collapsed to a single EID-keyed lookup -- matching ecosim's
    `smds.SmDs.discover(eid)`, which does the same collapse deliberately (its
    docstring explains why: discovery is unauthenticated pre-auth in the real
    protocol too, so nothing is lost in the collapse for this purpose)."""

    eid: str

    def to_wire(self) -> dict[str, object]:
        return {"eid": self.eid}


@dataclass
class Es11EventEntry:
    event_id: str
    rsp_server_address: str


@dataclass
class Es11DiscoveryResponse:
    event_entries: list[Es11EventEntry] = field(default_factory=list)

    @classmethod
    def from_wire(cls, obj: dict) -> Es11DiscoveryResponse:
        entries_raw = obj.get("eventEntries", [])
        if not isinstance(entries_raw, list):
            raise MalformedResponseError("eventEntries must be a list")
        entries = [
            Es11EventEntry(
                event_id=_require_str(e, "eventId"),
                rsp_server_address=_require_str(e, "rspServerAddress"),
            )
            for e in entries_raw
        ]
        return cls(event_entries=entries)
