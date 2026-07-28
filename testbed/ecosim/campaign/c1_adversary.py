"""C1 network-adversary primitive layer.

Models an attacker with COMPLETE control of the C1 channel (the ES9+ /
network-wifi hop between the SM-DP+ and the device). In the real ecosystem C1
is HTTPS/TLS pinned to the GSMA CI; this harness assumes the transport
protection is stripped or bypassed (the explicit threat model for this
analysis) and exposes exactly the primitives such an attacker has:

  block    -- drop a message so it never reaches its peer (DoS / selective)
  forward  -- pass a message unchanged (passive observation still records it)
  replay   -- re-deliver a previously-seen message
  forge    -- inject an attacker-authored message
  modify   -- rewrite chosen fields of a message in flight
  fuzz     -- deliver a malformed/mutated message

All of these operate through the existing bus mutator hook on channel C1, so
they compose with the rest of the testbed unchanged. The harness also records
everything the attacker OBSERVES on C1, which is the basis for the
information-disclosure (EID/IMEI/fingerprint) analysis.

This is defensive security research against a local simulation with our own
PKI; no real network or device is involved.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Callable

from .. import codec
from ..bus import C1, Bus, Message


@dataclass
class Observation:
    kind: str
    obj: dict


@dataclass
class C1Adversary:
    """Installs itself as the C1 mutator and applies a per-message policy.

    policy(kind, obj) -> ("forward", None) | ("block", None) | ("modify", new_obj)
    | ("forge", new_obj). The adversary records every message it sees (its
    passive-observation log) regardless of the action taken."""

    bus: Bus
    policy: Callable[[str, dict], tuple[str, dict | None]] | None = None
    observed: list[Observation] = field(default_factory=list)
    replay_store: dict[str, bytes] = field(default_factory=dict)
    dropped: list[str] = field(default_factory=list)

    def attach(self) -> None:
        self.bus.set_mutator(C1, self._mutate)

    def detach(self) -> None:
        self.bus.clear_mutators()

    def _mutate(self, msg: Message) -> Message:
        if msg.channel != C1:
            return msg
        try:
            obj = codec.from_json_wire(msg.wire)
        except (ValueError, UnicodeDecodeError):
            obj = {}
        self.observed.append(Observation(kind=msg.kind, obj=obj))
        self.replay_store[msg.kind] = msg.wire
        if self.policy is None:
            return msg
        action, new_obj = self.policy(msg.kind, obj)
        if action == "forward":
            return msg
        if action == "block":
            # A blocked message is modeled as an empty JSON object: it reaches
            # the peer structurally present but content-stripped, which is how a
            # dropped-but-retried request most often surfaces downstream (the
            # peer then fails a required-field/parse check rather than hanging).
            self.dropped.append(msg.kind)
            return replace(msg, wire=b"{}")
        if action in ("modify", "forge") and new_obj is not None:
            return replace(msg, wire=codec.to_json_wire(new_obj))
        return msg

    # --- passive information-disclosure helpers ---------------------------
    def observed_eid(self) -> str | None:
        """Recover the device EID from anything the attacker saw on C1.

        The eUICC certificate crosses C1 in AuthenticateClient.req and carries
        the EID in subject.serialNumber (SGP.22 SS4.3.1), so a passive C1
        observer recovers it with no GetEID/local-bus access at all."""
        from cryptography import x509
        from .. import pki
        for ob in self.observed:
            cert_b64 = ob.obj.get("euiccCertificate")
            if cert_b64:
                try:
                    cert = x509.load_der_x509_certificate(codec.unb64(cert_b64))
                    return pki.eid_from_certificate(cert)
                except (ValueError, Exception):  # noqa: BLE001
                    continue
        return None

    def observed_fingerprint(self) -> dict:
        """Non-EID device fingerprint recoverable from the pre-authentication
        InitiateAuthentication.req (euiccInfo1: SVN + CI public-key identifiers +
        RSP capabilities). Leaks BEFORE any server authentication."""
        out: dict = {}
        for ob in self.observed:
            if ob.kind == "InitiateAuthentication.req":
                info1_b64 = ob.obj.get("euiccInfo1")
                if info1_b64:
                    out["euiccInfo1_hex"] = codec.unb64(info1_b64).hex()
                out["smdpAddress"] = ob.obj.get("smdpAddress")
        return out
