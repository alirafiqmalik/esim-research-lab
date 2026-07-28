"""Simulated SM-DS (Subscription Manager Discovery Server), SGP.22 SS3.6.

Models the piece of the ecosystem no prior direction in this campaign touched:
event registration (SM-DP+ tells the SM-DS "a profile is waiting for EID X at
my address") and discovery (the LPA asks the SM-DS "is anything waiting for
my EID?"). Discovery happens BEFORE any mutual authentication -- the eUICC's
identity isn't cryptographically established until the LPA is redirected to
the actual SM-DP+ and runs the normal AuthenticateServer/AuthenticateClient
flow. That means the EID a caller presents to the SM-DS at discovery time is,
by construction, exactly as unauthenticated as the plaintext GetEID response
this campaign already found unsigned in D10 -- this module exists to test
whether that unauthenticated combination is exploitable as an EID-enumeration
primitive, not to model ES12/ES15 to full ASN.1 fidelity.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EventRecord:
    event_id: str
    smdp_address: str


@dataclass
class SmDs:
    """No cryptographic state at all -- faithful to discovery happening pre-auth."""

    _events: dict[str, list[EventRecord]] = field(default_factory=dict)

    def register_event(self, eid: str, event_id: str, smdp_address: str) -> None:
        """ES12.RegisterEvent-shaped: the SM-DP+ tells the SM-DS a profile is
        waiting for this EID. Called by the SM-DP+ side, not the device."""
        self._events.setdefault(eid, []).append(EventRecord(event_id=event_id, smdp_address=smdp_address))

    def discover(self, eid: str) -> list[EventRecord]:
        """ES9+/ES11-shaped discovery: return pending events for the given EID.

        Takes the EID as a bare argument, exactly as a real SM-DS does at this
        pre-authentication stage -- there is nothing here that verifies the
        caller actually owns the EID it presents."""
        return list(self._events.get(eid, []))
