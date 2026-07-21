from __future__ import annotations


def _tlv_walk(b: bytes) -> list[tuple[int, bytes]]:
    """Minimal BER-TLV walker (single level). Handles 2-byte tags and long-form length."""
    out, i = [], 0
    while i < len(b):
        tag = b[i]; i += 1
        if tag & 0x1F == 0x1F:  # multi-byte tag
            tag = (tag << 8) | b[i]; i += 1
        length = b[i]; i += 1
        if length & 0x80:
            n = length & 0x7F
            length = int.from_bytes(b[i:i + n], "big"); i += n
        out.append((tag, b[i:i + length])); i += length
    return out


def _parse_addresses(resp_hex: str) -> dict:
    """Decode a GetEuiccConfiguredAddresses (BF3C) response into the two addresses."""
    try:
        b = bytes.fromhex(resp_hex)
    except ValueError:
        return {}
    if len(b) >= 2 and b[-2:] == b"\x90\x00":
        b = b[:-2]
    res: dict = {}
    for tag, val in _tlv_walk(b):
        if tag == 0xBF3C:
            for t2, v2 in _tlv_walk(val):
                if t2 == 0x80:
                    res["defaultDpAddress"] = v2.decode("utf-8", "replace")
                elif t2 == 0x81:
                    res["rootDsAddress"] = v2.decode("utf-8", "replace")
    return res
