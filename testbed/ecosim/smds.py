"""Simulated SM-DS (Subscription Manager Discovery Server), SGP.22 SS3.6.

Models event registration (an SM-DP+ or another SM-DS tells the SM-DS "an
event is waiting for EID X at address A") and discovery (the LPA asks "is
anything waiting for my EID?").

Live probing corrected an earlier premise here. The real ES11 discovery flow
is `InitiateAuthentication` (body carries euiccChallenge + euiccInfo1 and
NO EID field) followed by `AuthenticateClient` whose input is the eUICC-signed
authenticateServerResponse -- the EID rides inside CERT.EUICC, which the eUICC
signs. `eventEntries[]` come back only from AuthenticateClient, so the queried
EID is cryptographically bound to a valid eUICC signature. There is no
pre-authentication EID-enumeration oracle: a caller can only learn events for
an EID whose eUICC it holds. See testbed/ping-sm-ds/notes/03-eid-enumeration.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EventRecord:
    event_id: str
    # An event's address may point at an SM-DP+ OR at another SM-DS (cascade);
    # it is not necessarily a download endpoint.
    rsp_server_address: str


@dataclass
class SmDs:
    _events: dict[str, list[EventRecord]] = field(default_factory=dict)

    def register_event(self, eid: str, event_id: str, rsp_server_address: str) -> None:
        """ES12.RegisterEvent-shaped: an SM-DP+ or another SM-DS tells this
        SM-DS an event is waiting for this EID. Called by an RSP-server side,
        not the device."""
        self._events.setdefault(eid, []).append(
            EventRecord(event_id=event_id, rsp_server_address=rsp_server_address)
        )

    def discover(self, authenticated_eid: str) -> list[dict[str, str]]:
        """ES11-shaped discovery, authenticated.

        `authenticated_eid` is the eUICC-attested identity -- the EID the
        SM-DS recovered from the eUICC signature during AuthenticateClient, NOT
        a caller-chosen argument. It is threaded in here exactly as
        smdp.SmDpPlus.authenticate_client threads `authenticated_eid`, because
        ecosim's shared eUICC cert carries no per-device EID to parse off the
        wire.

        Returns `eventEntries` as wire-shaped dicts, one per pending event, or
        an empty list when nothing is registered (the live events=0 case). The
        EID is auth-bound, so there is no pre-authentication enumeration oracle:
        a caller only ever sees events for the EID its own eUICC attested to.
        See testbed/ping-sm-ds/notes/03-eid-enumeration.md.
        """
        return [
            {"eventId": e.event_id, "rspServerAddress": e.rsp_server_address}
            for e in self._events.get(authenticated_eid, [])
        ]

    def discover_unauthenticated(self, eid: str) -> list[EventRecord]:
        """Historical hypothesis, kept for the adversarial test -- NOT the
        faithful model.

        This is the old bare lookup: it takes a caller-chosen EID with nothing
        binding the query to the eUICC that owns it. The premise was that
        discovery is a pre-authentication EID-enumeration primitive. Live
        probing of three production SM-DS REFUTED that: `InitiateAuthentication`
        carries no EID and `eventEntries[]` come only from the eUICC-signed
        `AuthenticateClient`, so no synthetic caller can query an EID it does
        not hold the eUICC for. See testbed/ping-sm-ds/notes/03-eid-enumeration.md.
        """
        return list(self._events.get(eid, []))
