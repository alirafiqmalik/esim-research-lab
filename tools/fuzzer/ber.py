"""Minimal BER-TLV encode/decode for the AuthenticateServer fuzzer.

The AuthenticateServer command (BF38) and its inner constructs are DER-encoded
BER-TLV. This module is the small, dependency-free codec the seed parser and the
mutation generator share. It handles multi-byte tags (``5F37``, ``BF38``) and
long-form lengths (the server certificate needs ``82`` two-byte lengths).

Nothing here talks to a device. It is pure byte manipulation.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Field:
    """One decoded TLV: its integer tag, its value, and the full tag+len+value."""

    tag: int
    value: bytes
    raw: bytes


class BerError(ValueError):
    """Raised when a byte string is not well-formed BER-TLV."""


def _read_tag(data: bytes, i: int) -> tuple[int, int]:
    if i >= len(data):
        raise BerError("truncated tag")
    first = data[i]
    i += 1
    tag = first
    if (first & 0x1F) == 0x1F:
        while True:
            if i >= len(data):
                raise BerError("truncated multi-byte tag")
            b = data[i]
            i += 1
            tag = (tag << 8) | b
            if not (b & 0x80):
                break
    return tag, i


def _read_len(data: bytes, i: int) -> tuple[int, int]:
    if i >= len(data):
        raise BerError("truncated length")
    b = data[i]
    i += 1
    if b & 0x80:
        n = b & 0x7F
        if n == 0:
            raise BerError("indefinite length not supported")
        if i + n > len(data):
            raise BerError("truncated long-form length")
        length = int.from_bytes(data[i : i + n], "big")
        i += n
    else:
        length = b
    return length, i


def walk(data: bytes) -> list[Field]:
    """Decode one level of TLVs. Raises BerError on a length that overruns."""
    out: list[Field] = []
    i = 0
    while i < len(data):
        start = i
        tag, i = _read_tag(data, i)
        length, i = _read_len(data, i)
        if i + length > len(data):
            raise BerError(
                f"value of tag 0x{tag:X} overruns buffer "
                f"({length} bytes at offset {i}, {len(data) - i} available)"
            )
        value = data[i : i + length]
        i += length
        out.append(Field(tag=tag, value=value, raw=data[start:i]))
    return out


def encode_tag(tag: int) -> bytes:
    if tag < 0:
        raise BerError(f"negative tag {tag}")
    if tag < 0x100:
        return bytes([tag])
    return tag.to_bytes((tag.bit_length() + 7) // 8, "big")


def encode_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, value: bytes) -> bytes:
    """Encode one TLV from an integer tag and a value."""
    return encode_tag(tag) + encode_len(len(value)) + bytes(value)


def first(data: bytes, tag: int) -> Field:
    """Return the first top-level field with ``tag``. Raises if absent."""
    for field in walk(data):
        if field.tag == tag:
            return field
    raise BerError(f"tag 0x{tag:X} not found")
