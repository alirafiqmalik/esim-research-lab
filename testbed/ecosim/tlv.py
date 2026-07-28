"""BER-TLV codec for the ES10 (C3) APDU layer.

A fuller encoder/decoder than esim/euicc/tlv.py, which only walks one level.
Supports 1- and 2-byte tags, definite long-form lengths, and nested construction.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class TLVError(ValueError):
    """Raised when a byte string cannot be parsed as BER-TLV."""


@dataclass
class TLV:
    tag: int
    value: bytes = b""
    children: list["TLV"] = field(default_factory=list)

    def is_constructed(self) -> bool:
        first = self.tag >> 8 if self.tag > 0xFF else self.tag
        return bool(first & 0x20)


def _encode_tag(tag: int) -> bytes:
    if tag <= 0xFF:
        return bytes([tag])
    return tag.to_bytes((tag.bit_length() + 7) // 8, "big")


def _encode_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def encode(tag: int, value: bytes) -> bytes:
    """Encode one primitive TLV."""
    return _encode_tag(tag) + _encode_len(len(value)) + value


def encode_constructed(tag: int, children: list[bytes]) -> bytes:
    """Encode a constructed TLV from already-encoded child TLVs."""
    body = b"".join(children)
    return _encode_tag(tag) + _encode_len(len(body)) + body


# A real card applet must reject over-nested input with a status word, never
# crash/reset. walk() recurses one Python frame per constructed-nesting level,
# so an unbounded depth is itself a denial-of-service primitive (confirmed by
# campaign fuzzing: unhandled RecursionError past ~995 levels). Cap it well
# under Python's default recursion limit and treat the overflow as malformed
# input, the same as any other structural violation.
_MAX_NESTING_DEPTH = 64


def walk(b: bytes, _depth: int = 0) -> list[TLV]:
    """Parse a byte string into a flat list of top-level TLVs.

    Constructed tags (bit 0x20 set on the leading tag byte) get their children
    parsed recursively into ``children``; ``value`` still holds the raw body.
    """
    if _depth > _MAX_NESTING_DEPTH:
        raise TLVError(f"nesting exceeds max depth {_MAX_NESTING_DEPTH}")
    out: list[TLV] = []
    i = 0
    n = len(b)
    while i < n:
        first = b[i]
        tag = first
        i += 1
        if first & 0x1F == 0x1F:  # multi-byte tag
            if i >= n:
                raise TLVError("truncated multi-byte tag")
            tag = (tag << 8) | b[i]
            i += 1
        if i >= n:
            raise TLVError("truncated length")
        length = b[i]
        i += 1
        if length & 0x80:
            k = length & 0x7F
            if k == 0 or i + k > n:
                raise TLVError("bad long-form length")
            length = int.from_bytes(b[i:i + k], "big")
            i += k
        if i + length > n:
            raise TLVError(f"value overruns buffer: tag={tag:x} len={length}")
        val = b[i:i + length]
        i += length
        node = TLV(tag=tag, value=val)
        if first & 0x20:
            try:
                node.children = walk(val, _depth + 1)
            except TLVError:
                node.children = []
        out.append(node)
    return out


def find(nodes: list[TLV], tag: int) -> TLV | None:
    for node in nodes:
        if node.tag == tag:
            return node
    return None
