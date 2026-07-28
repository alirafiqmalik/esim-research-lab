"""Channel abstraction with tap / record / mutate hooks.

Every message between two components crosses a Channel. The Channel records the
message (for later invariant/variable analysis) and, if a mutator is installed,
lets a fuzzer rewrite the wire bytes in flight before delivery. Channels:

    C1  : SM-DP+ <-> device/LPA   (ES9+, JSON over "HTTPS")
    C2a : device <-> LPA          (activation-code / LPA API)
    C2b : device <-> eUICC        (APDU transport / modem)
    C3  : LPA <-> eUICC           (ES10, BER-TLV APDUs)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

C1 = "C1"
C2A = "C2a"
C2B = "C2b"
C3 = "C3"
ALL_CHANNELS = (C1, C2A, C2B, C3)


@dataclass
class Message:
    channel: str
    direction: str          # e.g. "smdp->lpa"
    kind: str               # protocol message name, e.g. "InitiateAuthentication.req"
    wire: bytes             # canonical on-the-wire bytes (JSON utf-8, or APDU)
    encoding: str           # "json" | "apdu" | "text"
    meta: dict = field(default_factory=dict)

    def hexwire(self) -> str:
        return self.wire.hex()


Mutator = Callable[[Message], Message]


@dataclass
class Channel:
    name: str
    log: list[Message] = field(default_factory=list)
    mutator: Mutator | None = None
    protected: bool = False   # True once TLS/SCP is modelled as active on this hop

    def send(self, msg: Message) -> Message:
        """Record, optionally mutate, and return the (possibly rewritten) message."""
        if self.mutator is not None:
            msg = self.mutator(msg)
        self.log.append(msg)
        return msg


@dataclass
class Bus:
    channels: dict[str, Channel] = field(default_factory=dict)

    @classmethod
    def default(cls) -> "Bus":
        return cls(channels={c: Channel(name=c) for c in ALL_CHANNELS})

    def send(self, msg: Message) -> Message:
        return self.channels[msg.channel].send(msg)

    def set_mutator(self, channel: str, mutator: Mutator | None) -> None:
        self.channels[channel].mutator = mutator

    def clear_mutators(self) -> None:
        for ch in self.channels.values():
            ch.mutator = None

    def all_messages(self) -> list[Message]:
        out: list[Message] = []
        for ch in self.channels.values():
            out.extend(ch.log)
        return out

    def reset_logs(self) -> None:
        for ch in self.channels.values():
            ch.log = []
