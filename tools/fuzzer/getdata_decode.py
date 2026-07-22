"""Decode readable GET DATA data objects into concrete eUICC facts.

Consumes a capture of GET DATA responses (the JSONL a live enum run writes, or a
plain ``tag -> hex`` mapping) and parses the standard GlobalPlatform / ISO-7816
data objects into structured fields:

- CPLC (``9F7F``): the 42-byte Card Production Life Cycle block. IC fabricator,
  IC type, OS identifier, OS release date/level, fabrication date, serial, batch,
  module fabricator/packaging, ICC manufacturer, embedding date, pre-personalizer.
- CardData (``66``) / GlobalPlatform card recognition data: OID, GP version, SCP.
- ExtendedCardResources (``FF21``): installed applications, free non-volatile
  memory, free volatile memory (``81`` / ``82`` / ``83`` sub-TLVs).
- KeyInfoTemplate (``E0``), tag ``67``, and GP counters: best-effort structured
  dump.

The vendor code tables map IC fabricator and OS identifier bytes to known chip
vendors. Mapping source: the CPLC field layout in the GlobalPlatform Card
Specification, cross-referenced with the community-maintained IC-fabricator code
lists used by GlobalPlatformPro and pyResMan. The mapping is best-effort; unknown
codes are reported as ``unknown`` with the raw bytes preserved.

Standalone:

    python getdata_decode.py <captured.jsonl> --out euicc_profile.md
                             [--json euicc_profile.json]

Nothing here sends anything. It only parses bytes already captured.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

# ---- vendor code tables -----------------------------------------------------
# Source: GlobalPlatform Card Specification CPLC layout + community IC-fabricator
# code lists (GlobalPlatformPro / pyResMan). Best-effort; extend as confirmed.
IC_FABRICATORS: dict[int, str] = {
    0x4090: "Infineon",
    0x4180: "Atmel",
    0x4250: "Samsung",
    0x4790: "NXP (Philips Semiconductors)",
    0x4700: "NXP",
    0x3060: "Renesas",
    0x2050: "Philips",
    0x0007: "STMicroelectronics",
    0x4030: "STMicroelectronics",
    0x0005: "Infineon",
    0x0002: "Gemalto/Thales",
}

# OS / platform identifier high-level hints. The OS identifier is vendor-defined,
# so only a few well-known values are mapped; the rest are reported raw.
OS_IDENTIFIERS: dict[int, str] = {
    0x4791: "NXP JCOP",
    0x0304: "JCOP",
    0x8211: "Java Card platform (vendor-specific)",
}


class DecodeError(Exception):
    """Raised when a data object cannot be parsed into its expected structure."""


def _strip_tlv(value_hex: str, expected_tag_hex: str) -> bytes:
    """Return the value bytes of a top-level DO, stripping a leading tag+length.

    Accepts either the bare value or the full DO TLV. When the bytes start with
    ``expected_tag_hex`` the tag and (short- or long-form) length are removed.
    """
    raw = bytes.fromhex(value_hex.replace(" ", ""))
    tag = bytes.fromhex(expected_tag_hex)
    if not raw.startswith(tag):
        return raw
    index = len(tag)
    if index >= len(raw):
        raise DecodeError(f"DO {expected_tag_hex} has a tag but no length")
    first = raw[index]
    index += 1
    if first & 0x80:
        num = first & 0x7F
        index += num
    return raw[index:]


def _read_tlvs(body: bytes) -> list[tuple[int, bytes]]:
    """Parse a flat sequence of BER-TLVs into ``(tag, value)`` pairs, best-effort."""
    out: list[tuple[int, bytes]] = []
    i = 0
    while i < len(body):
        first = body[i]
        i += 1
        tag = first
        if (first & 0x1F) == 0x1F:
            if i >= len(body):
                break
            tag = (first << 8) | body[i]
            i += 1
        if i >= len(body):
            break
        length = body[i]
        i += 1
        if length & 0x80:
            num = length & 0x7F
            if i + num > len(body):
                break
            length = int.from_bytes(body[i : i + num], "big")
            i += num
        value = body[i : i + length]
        out.append((tag, value))
        i += length
    return out


# ---- CPLC -------------------------------------------------------------------

# (field name, byte length). Sums to 42, the classic CPLC block.
_CPLC_LAYOUT: tuple[tuple[str, int], ...] = (
    ("ic_fabricator", 2),
    ("ic_type", 2),
    ("os_identifier", 2),
    ("os_release_date", 2),
    ("os_release_level", 2),
    ("ic_fabrication_date", 2),
    ("ic_serial_number", 4),
    ("ic_batch_identifier", 2),
    ("ic_module_fabricator", 2),
    ("ic_module_packaging_date", 2),
    ("icc_manufacturer", 2),
    ("ic_embedding_date", 2),
    ("ic_pre_personalizer", 2),
    ("ic_pre_personalization_equipment_date", 2),
    ("ic_pre_personalization_equipment_id", 4),
    ("ic_personalizer", 2),
    ("ic_personalization_date", 2),
    ("ic_personalization_equipment_id", 4),
)

CPLC_LENGTH = sum(n for _, n in _CPLC_LAYOUT)  # 42


@dataclass(frozen=True)
class CplcInfo:
    """Decoded Card Production Life Cycle block."""

    fields: dict[str, str]
    ic_fabricator: str
    ic_fabricator_vendor: str
    ic_type: str
    os_identifier: str
    os_vendor: str
    ic_fabrication_date: str
    ic_serial_number: str


def _cplc_date(raw_hex: str) -> str:
    """Interpret a 2-byte CPLC date (``YDDD`` BCD) as ``year-digit day-of-year``.

    The decade is not encoded, so only the last year digit is known. Returns the
    raw hex plus the interpreted day when the digits are plausible.
    """
    if len(raw_hex) != 4 or not raw_hex.isdigit():
        return f"{raw_hex} (non-date)"
    year_digit = raw_hex[0]
    day = int(raw_hex[1:])
    if 1 <= day <= 366:
        return f"{raw_hex} (year ...{year_digit}, day {day})"
    return f"{raw_hex} (unparsed)"


def decode_cplc(value_hex: str) -> CplcInfo:
    """Decode a CPLC value (bare 42 bytes or a full ``9F7F`` TLV)."""
    body = _strip_tlv(value_hex, "9F7F")
    if len(body) < CPLC_LENGTH:
        raise DecodeError(
            f"CPLC is {len(body)} bytes, expected at least {CPLC_LENGTH}"
        )
    fields: dict[str, str] = {}
    offset = 0
    for name, size in _CPLC_LAYOUT:
        chunk = body[offset : offset + size].hex().upper()
        offset += size
        if name.endswith("_date"):
            fields[name] = _cplc_date(chunk)
        else:
            fields[name] = chunk

    fab = int(body[0:2].hex(), 16)
    os_id = int(body[4:6].hex(), 16)
    return CplcInfo(
        fields=fields,
        ic_fabricator=f"{fab:04X}",
        ic_fabricator_vendor=IC_FABRICATORS.get(fab, "unknown"),
        ic_type=body[2:4].hex().upper(),
        os_identifier=f"{os_id:04X}",
        os_vendor=OS_IDENTIFIERS.get(os_id, "unknown"),
        ic_fabrication_date=fields["ic_fabrication_date"],
        ic_serial_number=body[12:16].hex().upper(),
    )


# ---- CardData 66 / card recognition data ------------------------------------


@dataclass(frozen=True)
class CardDataInfo:
    """Decoded GlobalPlatform card recognition data (tag ``66`` -> ``73``)."""

    oids: list[str]
    gp_version: str | None
    scp: str | None
    raw: str


def _decode_oid(value: bytes) -> str:
    if not value:
        return ""
    first = value[0]
    parts = [str(first // 40), str(first % 40)]
    acc = 0
    for byte in value[1:]:
        acc = (acc << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(acc))
            acc = 0
    return ".".join(parts)


def decode_card_data(value_hex: str) -> CardDataInfo:
    """Decode CardData (``66``). The GP OID ``2A8648869F0D01`` tail carries version/SCP."""
    body = _strip_tlv(value_hex, "66")
    inner = _strip_tlv(body.hex(), "73") if body[:1] == b"\x73" else body
    oids: list[str] = []
    gp_version: str | None = None
    scp: str | None = None
    for tag, value in _read_tlvs(inner):
        if tag == 0x06:
            oid = _decode_oid(value)
            oids.append(oid)
            # GP card recognition OIDs: 1.2.840.114283.2.<version> (card mgmt),
            # ...3 (identifies GP), ...4.<scp> (security domain SCP).
            head = "1.2.840.114283"
            if oid.startswith(head + ".2."):
                gp_version = oid[len(head) + 3 :]
            if oid.startswith(head + ".4."):
                scp = oid[len(head) + 3 :]
    return CardDataInfo(oids=oids, gp_version=gp_version, scp=scp, raw=value_hex.upper())


# ---- ExtendedCardResources FF21 ---------------------------------------------


@dataclass(frozen=True)
class CardResourcesInfo:
    """Decoded ExtendedCardResources (``FF21``): app count and free memory."""

    installed_applications: int | None
    free_non_volatile_memory: int | None
    free_volatile_memory: int | None
    raw: str


def decode_extended_card_resources(value_hex: str) -> CardResourcesInfo:
    """Decode ExtendedCardResources (``FF21`` -> ``81`` / ``82`` / ``83``)."""
    body = _strip_tlv(value_hex, "FF21")
    apps: int | None = None
    free_nvm: int | None = None
    free_vol: int | None = None
    for tag, value in _read_tlvs(body):
        number = int.from_bytes(value, "big") if value else 0
        if tag == 0x81:
            apps = number
        elif tag == 0x82:
            free_nvm = number
        elif tag == 0x83:
            free_vol = number
    return CardResourcesInfo(
        installed_applications=apps,
        free_non_volatile_memory=free_nvm,
        free_volatile_memory=free_vol,
        raw=value_hex.upper(),
    )


# ---- best-effort dumps: KeyInfoTemplate E0, tag 67, counters ----------------


@dataclass(frozen=True)
class KeyInfoEntry:
    """One key entry inside a KeyInfoTemplate (``C0`` sub-TLV)."""

    key_identifier: str
    key_version: str
    components_hex: str


@dataclass(frozen=True)
class KeyInfoTemplate:
    """Decoded KeyInfoTemplate (``E0``): the card's key catalogue."""

    entries: list[KeyInfoEntry]
    raw: str


def decode_key_info_template(value_hex: str) -> KeyInfoTemplate:
    """Best-effort decode of KeyInfoTemplate (``E0`` -> repeated ``C0`` entries)."""
    body = _strip_tlv(value_hex, "E0")
    entries: list[KeyInfoEntry] = []
    for tag, value in _read_tlvs(body):
        if tag == 0xC0 and len(value) >= 2:
            entries.append(
                KeyInfoEntry(
                    key_identifier=f"{value[0]:02X}",
                    key_version=f"{value[1]:02X}",
                    components_hex=value[2:].hex().upper(),
                )
            )
    return KeyInfoTemplate(entries=entries, raw=value_hex.upper())


def decode_counter(value_hex: str, tag_hex: str) -> int:
    """Decode a GP counter DO (``C1`` / ``C2`` / ``CF``) as a big-endian integer."""
    body = _strip_tlv(value_hex, tag_hex)
    return int.from_bytes(body, "big") if body else 0


# ---- capture loading + aggregate profile ------------------------------------


@dataclass
class EuiccProfile:
    """The aggregated set of eUICC facts extracted from a GET DATA capture."""

    cplc: CplcInfo | None = None
    card_data: CardDataInfo | None = None
    card_resources: CardResourcesInfo | None = None
    key_info: KeyInfoTemplate | None = None
    counters: dict[str, int] = field(default_factory=dict)
    tag67_hex: str | None = None
    raw_objects: dict[str, str] = field(default_factory=dict)


def _normalize_tag(tag: str | None, resp: str) -> str:
    """Pick the DO tag: prefer the leading tag of the response bytes."""
    resp = (resp or "").replace(" ", "").upper()
    if len(resp) >= 2:
        first = int(resp[:2], 16)
        if (first & 0x1F) == 0x1F and len(resp) >= 4:
            return resp[:4]
        return resp[:2]
    return (tag or "").upper()


def load_capture(path: Path) -> dict[str, str]:
    """Load a GET DATA capture into a ``tag -> response-hex`` mapping.

    Accepts the JSONL a live enum run writes (rows with ``resp`` / ``tag`` / ``sw``)
    or a single JSON object mapping tag strings to hex. Only rows that returned
    data (``sw`` starting ``9000`` / ``61`` / ``62`` / ``63``, or no ``sw`` key)
    with a non-empty response are kept.
    """
    text = path.read_text().strip()
    if not text:
        raise DecodeError(f"empty capture: {path}")

    objects: dict[str, str] = {}
    if text[0] == "{" and "\n" not in text.strip().rstrip("}"):
        # Single JSON object: tag -> hex.
        data = json.loads(text)
        if isinstance(data, dict):
            for tag, hexval in data.items():
                if hexval:
                    objects[_normalize_tag(str(tag), str(hexval))] = str(hexval).upper()
            return objects

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        resp = row.get("resp")
        if not resp:
            continue
        sw = row.get("sw")
        if sw is not None:
            s = str(sw).upper()
            if not (s == "9000" or s[:2] in ("61", "62", "63")):
                continue
        tag = _normalize_tag(row.get("tag"), str(resp))
        objects[tag] = str(resp).upper()
    return objects


def build_profile(objects: dict[str, str]) -> EuiccProfile:
    """Decode every recognised DO in a capture into an :class:`EuiccProfile`."""
    upper = {k.upper(): v for k, v in objects.items()}
    profile = EuiccProfile(raw_objects=dict(sorted(upper.items())))

    def find(*tags: str) -> str | None:
        for t in tags:
            if t in upper:
                return upper[t]
        return None

    cplc_hex = find("9F7F")
    if cplc_hex:
        try:
            profile.cplc = decode_cplc(cplc_hex)
        except DecodeError:
            pass

    card_hex = find("66")
    if card_hex:
        try:
            profile.card_data = decode_card_data(card_hex)
        except (DecodeError, IndexError):
            pass

    res_hex = find("FF21")
    if res_hex:
        try:
            profile.card_resources = decode_extended_card_resources(res_hex)
        except (DecodeError, IndexError):
            pass

    e0_hex = find("E0")
    if e0_hex:
        try:
            profile.key_info = decode_key_info_template(e0_hex)
        except (DecodeError, IndexError):
            pass

    for tag in ("C1", "C2", "CF"):
        hexval = find(tag)
        if hexval:
            try:
                profile.counters[tag] = decode_counter(hexval, tag)
            except (DecodeError, ValueError):
                pass

    profile.tag67_hex = find("67")
    return profile


# ---- rendering --------------------------------------------------------------


def _profile_json(profile: EuiccProfile) -> dict[str, object]:
    return {
        "cplc": asdict(profile.cplc) if profile.cplc else None,
        "card_data": asdict(profile.card_data) if profile.card_data else None,
        "card_resources": asdict(profile.card_resources) if profile.card_resources else None,
        "key_info": asdict(profile.key_info) if profile.key_info else None,
        "counters": dict(profile.counters),
        "tag67_hex": profile.tag67_hex,
        "readable_objects": sorted(profile.raw_objects),
    }


def render_markdown(profile: EuiccProfile) -> str:
    """Render the profile as a human-readable Markdown report."""
    lines: list[str] = ["# eUICC Profile", ""]

    lines.append("## Chip and OS")
    lines.append("")
    if profile.cplc:
        c = profile.cplc
        lines.append(f"- IC fabricator: `{c.ic_fabricator}` ({c.ic_fabricator_vendor})")
        lines.append(f"- IC type: `{c.ic_type}`")
        lines.append(f"- OS identifier: `{c.os_identifier}` ({c.os_vendor})")
        lines.append(f"- OS release date: {c.fields['os_release_date']}")
        lines.append(f"- OS release level: `{c.fields['os_release_level']}`")
        lines.append(f"- IC fabrication date: {c.ic_fabrication_date}")
        lines.append(f"- IC serial number: `{c.ic_serial_number}`")
        lines.append(f"- IC batch: `{c.fields['ic_batch_identifier']}`")
        lines.append(f"- ICC manufacturer: `{c.fields['icc_manufacturer']}`")
    else:
        lines.append("- CPLC not present in capture.")
    lines.append("")

    lines.append("## GlobalPlatform")
    lines.append("")
    if profile.card_data:
        d = profile.card_data
        lines.append(f"- GP version: `{d.gp_version or 'unknown'}`")
        lines.append(f"- SCP: `{d.scp or 'unknown'}`")
        for oid in d.oids:
            lines.append(f"- OID: `{oid}`")
    else:
        lines.append("- CardData (`66`) not present in capture.")
    lines.append("")

    lines.append("## Memory and applications")
    lines.append("")
    if profile.card_resources:
        r = profile.card_resources
        lines.append(f"- Installed applications: `{r.installed_applications}`")
        lines.append(f"- Free non-volatile memory: `{r.free_non_volatile_memory}` bytes")
        lines.append(f"- Free volatile memory: `{r.free_volatile_memory}` bytes")
    else:
        lines.append("- ExtendedCardResources (`FF21`) not present in capture.")
    lines.append("")

    lines.append("## Keys and counters")
    lines.append("")
    if profile.key_info and profile.key_info.entries:
        for entry in profile.key_info.entries:
            lines.append(
                f"- Key id `{entry.key_identifier}` version `{entry.key_version}` "
                f"components `{entry.components_hex or '-'}`"
            )
    else:
        lines.append("- KeyInfoTemplate (`E0`) not present or empty.")
    for tag, val in sorted(profile.counters.items()):
        lines.append(f"- Counter `{tag}`: `{val}`")
    if profile.tag67_hex:
        lines.append(f"- Tag `67` ({len(bytes.fromhex(profile.tag67_hex))} bytes): `{profile.tag67_hex}`")
    lines.append("")

    lines.append("## Readable data objects")
    lines.append("")
    for tag in sorted(profile.raw_objects):
        lines.append(f"- `{tag}`: `{profile.raw_objects[tag]}`")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Decode GET DATA capture into eUICC facts.")
    parser.add_argument("capture", type=Path, help="captured GET DATA JSONL or tag->hex JSON")
    parser.add_argument("--out", type=Path, default=Path("euicc_profile.md"))
    parser.add_argument("--json", dest="json_out", type=Path, default=None)
    args = parser.parse_args(argv)

    objects = load_capture(args.capture)
    profile = build_profile(objects)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render_markdown(profile))

    json_out = args.json_out or args.out.with_suffix(".json")
    json_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(_profile_json(profile), indent=2) + "\n")

    sys.stderr.write(
        f"[decode] {len(objects)} readable DOs -> {args.out} / {json_out}\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
