"""Structure verification for messages captured off the bus.

Data-driven: ``SPEC`` maps (channel, kind) to the shape a well-formed message
of that kind must have. ``verify_message``/``verify_run`` never raise — a
parse failure or a missing field is reported as a violation string, which is
the whole point (the fuzz campaign classifies outcomes by these lists).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import codec, tlv
from .bus import C1, C2A, C2B, C3, Message
from .codec import ActivationCode


@dataclass(frozen=True)
class MessageSpec:
    encoding: str
    required_keys: frozenset[str] = field(default_factory=frozenset)
    tag: int | None = None  # apdu only; None means "any top tag, just parse"


SPEC: dict[tuple[str, str], MessageSpec] = {
    (C3, "GetEUICCChallenge.resp"): MessageSpec(encoding="apdu", tag=codec.TAG_GET_EUICC_CHALLENGE),
    (C3, "GetEUICCInfo1.resp"): MessageSpec(encoding="apdu", tag=codec.TAG_GET_EUICC_INFO1),
    (C3, "AuthenticateServer.resp"): MessageSpec(encoding="apdu", tag=codec.TAG_AUTHENTICATE_SERVER),
    (C3, "ProfileInstallResult"): MessageSpec(encoding="apdu", tag=codec.TAG_PROFILE_INSTALL_RESULT),
    (C3, "GetEID.resp"): MessageSpec(encoding="apdu", tag=codec.TAG_GET_EID),
    (C2B, "ApduTransport"): MessageSpec(encoding="apdu"),
    (C1, "InitiateAuthentication.req"): MessageSpec(
        encoding="json",
        required_keys=frozenset({"func", "euiccChallenge", "euiccInfo1", "smdpAddress"}),
    ),
    (C1, "InitiateAuthentication.resp"): MessageSpec(
        encoding="json",
        required_keys=frozenset({
            "transactionId", "serverSigned1", "serverSignature1",
            "serverCertificate", "euiccCiPKIdToBeUsed", "serverOtpk",
        }),
    ),
    (C1, "AuthenticateClient.req"): MessageSpec(
        encoding="json",
        required_keys=frozenset({
            "func", "transactionId", "euiccSigned1", "euiccSignature1",
            "euiccCertificate", "eumCertificate", "euiccOtpk",
        }),
    ),
    (C1, "AuthenticateClient.resp"): MessageSpec(
        encoding="json",
        required_keys=frozenset({
            "transactionId", "profileMetadata", "smdpSigned2", "smdpSignature2", "smdpPbCertificate",
        }),
    ),
    (C1, "GetBoundProfilePackage.req"): MessageSpec(
        encoding="json", required_keys=frozenset({"func", "transactionId"}),
    ),
    (C1, "GetBoundProfilePackage.resp"): MessageSpec(
        encoding="json", required_keys=frozenset({"transactionId", "boundProfilePackage"}),
    ),
    (C1, "HandleNotification.req"): MessageSpec(
        encoding="json",
        required_keys=frozenset({"func", "notification", "seq", "euiccCertificate"}),
    ),
}


def _verify_activation_code(msg: Message) -> list[str]:
    prefix = f"{msg.channel}/{msg.kind}"
    try:
        ActivationCode.parse(msg.wire.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        return [f"{prefix}: {exc}"]
    return []


def _verify_json(msg: Message, spec: MessageSpec) -> list[str]:
    prefix = f"{msg.channel}/{msg.kind}"
    try:
        obj = codec.from_json_wire(msg.wire)
    except (UnicodeDecodeError, ValueError) as exc:
        return [f"{prefix}: JSON parse failure: {exc}"]
    if not isinstance(obj, dict):
        return [f"{prefix}: expected a JSON object, got {type(obj).__name__}"]
    missing = spec.required_keys - obj.keys()
    return [f"{prefix}: missing required key '{key}'" for key in sorted(missing)]


def _verify_apdu(msg: Message, spec: MessageSpec) -> list[str]:
    prefix = f"{msg.channel}/{msg.kind}"
    try:
        nodes = tlv.walk(msg.wire)
    except tlv.TLVError as exc:
        return [f"{prefix}: TLV parse failure: {exc}"]
    if not nodes:
        return [f"{prefix}: empty APDU wire"]
    if spec.tag is not None and nodes[0].tag != spec.tag:
        return [f"{prefix}: top tag {nodes[0].tag:#x} != expected {spec.tag:#x}"]
    return []


def verify_message(msg: Message) -> list[str]:
    """Return structure violations for a single message (empty = ok)."""
    if (msg.channel, msg.kind) == (C2A, "ActivationCode"):
        return _verify_activation_code(msg)

    spec = SPEC.get((msg.channel, msg.kind))
    if spec is None:
        return []  # no spec registered for this (channel, kind): nothing to check

    if spec.encoding == "json":
        return _verify_json(msg, spec)
    if spec.encoding == "apdu":
        return _verify_apdu(msg, spec)
    return [f"{msg.channel}/{msg.kind}: unknown spec encoding '{spec.encoding}'"]


def verify_run(messages: list[Message]) -> list[str]:
    """Verify every message, then check cross-message ordering invariants."""
    violations: list[str] = []
    for index, msg in enumerate(messages):
        violations.extend(f"[{index}] {v}" for v in verify_message(msg))

    seen_challenge = False
    seen_authenticate_client_resp = False
    for index, msg in enumerate(messages):
        if msg.channel == C3 and msg.kind == "GetEUICCChallenge.resp":
            seen_challenge = True
        elif msg.channel == C3 and msg.kind == "AuthenticateServer.resp" and not seen_challenge:
            violations.append(f"[{index}] AuthenticateServer.resp appears before GetEUICCChallenge.resp")

        if msg.channel == C1 and msg.kind == "AuthenticateClient.resp":
            seen_authenticate_client_resp = True
        elif msg.channel == C1 and msg.kind == "GetBoundProfilePackage.resp" and not seen_authenticate_client_resp:
            violations.append(f"[{index}] GetBoundProfilePackage.resp appears before AuthenticateClient.resp")

    return violations
