"""Application / security-domain enumeration by GlobalPlatform GET STATUS (INS F2).

Sweeps the GET STATUS parameter space to enumerate every entry the eUICC's GP
registry will disclose: the Issuer Security Domain, applications and Supplementary
Security Domains, Executable Load Files, and their Executable Modules. GET STATUS
reads registry data only. Its write counterpart is SET STATUS (INS F0), which the
safety layer blocks.

Skills applied:

- ``fuzzing-dictionary``: the P1 reference-control scope bytes, the P2
  occurrence/format bytes, and the request-body tag lists (``4F 00`` all-AIDs,
  ``5C`` tag-list search) are the GP GET STATUS grammar. They steer the sweep onto
  the values a GP card actually answers instead of random bytes that always
  return 6A86 / 6D00.
- ``coverage-analysis``: a black-box secure element exposes no in-process
  coverage, so effectiveness is measured by two proxies: response/SW diversity
  (the novelty engine) and an explicit discovery count (distinct registry entries
  decoded from the ``E3`` templates in the responses).

Nothing here sends anything on its own. Every candidate routes through
``engine.FuzzEngine.consider`` -> ``safety.guard_send``. The enumerated-apps list
is built after the fact by decoding the responses the engine recorded.

Ref: GlobalPlatform Card Specification v2.3.1, section 11.4 (GET STATUS).
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

from engine import FuzzEngine
from explore_common import Candidate, drive
from novelty import NoveltyEngine
from reporting import UniqueBehaviourReporter
from safety import ALLOWLIST_INS

_INS_GET_STATUS = 0xF2
_COMMAND = "GETSTATUS"

# P1 reference control: which registry subset to enumerate. The four defined
# scopes plus reserved/invalid bytes to observe rejection behaviour (expected
# 6A86 "incorrect P1 P2"). GP Card Spec v2.3.1 Table 11-42.
_P1_SCOPES: tuple[tuple[str, int], ...] = (
    ("ISD", 0x80),  # Issuer Security Domain
    ("apps+SSD", 0x40),  # Applications and Supplementary Security Domains
    ("ELF", 0x20),  # Executable Load Files
    ("ELF+modules", 0x10),  # Executable Load Files and their Executable Modules
    ("reserved-00", 0x00),  # no scope bit set
    ("reserved-08", 0x08),  # undefined bit
    ("reserved-C0", 0xC0),  # two scope bits at once
    ("reserved-FF", 0xFF),  # all bits set
)

# P2 occurrence + response format. Bit b1 (0x01): first vs next occurrence.
# Bit b2 (0x02): response structure, tag-value list vs expanded 'E3' TLV template.
# GP Card Spec v2.3.1 Table 11-43.
_P2_MODES: tuple[tuple[str, int], ...] = (
    ("first/legacy", 0x00),  # first or all occurrence, tag-value format
    ("next/legacy", 0x01),  # next occurrence, tag-value format
    ("first/tlv", 0x02),  # first or all, expanded E3 TLV format
    ("next/tlv", 0x03),  # next occurrence, expanded E3 TLV format
)

# Request bodies: the GET STATUS search qualifier. Empty, the all-AIDs search
# (4F with zero-length value), and 5C tag-list searches selecting which data
# objects the card should return per entry.
_BODIES: tuple[tuple[str, bytes], ...] = (
    ("empty", b""),
    ("all-aids", bytes.fromhex("4F00")),  # 4F 00: match every AID
    ("taglist-aid-lc-priv", bytes.fromhex("5C034F9F70")),  # 5C: return 4F, 9F70
    ("taglist-empty", bytes.fromhex("5C00")),  # 5C 00: default object set
)

# Both the plain (80) and secured (84) GlobalPlatform class bytes. 84 requires an
# active SCP secure channel and is expected to fail off-channel; swept anyway to
# record the distinct rejection SW.
_CLASSES: tuple[int, ...] = (0x80, 0x84)


def get_status_apdu(*, cla: int = 0x80, p1: int = 0x40, p2: int = 0x00, body: bytes = b"", le: int | None = 0x00) -> str:
    """Build a GlobalPlatform GET STATUS (INS F2) APDU as an upper-hex string."""
    apdu = bytes((cla & 0xFF, _INS_GET_STATUS, p1 & 0xFF, p2 & 0xFF))
    apdu += bytes((len(body) & 0xFF,)) + body
    if le is not None:
        apdu += bytes((le & 0xFF,))
    return apdu.hex().upper()


def candidates() -> Iterator[Candidate]:
    """Yield the full read-only GET STATUS sweep across CLA / P1 / P2 / body."""
    for cla in _CLASSES:
        for scope_name, p1 in _P1_SCOPES:
            reserved = scope_name.startswith("reserved")
            for mode_name, p2 in _P2_MODES:
                for body_name, body in _BODIES:
                    yield Candidate(
                        apdu_hex=get_status_apdu(cla=cla, p1=p1, p2=p2, body=body),
                        command=_COMMAND,
                        tag=None,
                        target=f"GS:CLA{cla:02X}:{scope_name}:{mode_name}:{body_name}",
                        malformed=reserved,
                    )


# ---- GET STATUS response decoder (E3 application template) ------------------

# Life-cycle byte meanings differ by scope. For applications/SDs (GP Card Spec
# Table 11-3): the low bits encode the state. This maps the common values so the
# markdown report is readable; unknown bytes fall through as the raw hex.
_LIFECYCLE_NAMES: dict[int, str] = {
    0x01: "LOADED",
    0x03: "INSTALLED",
    0x07: "SELECTABLE",
    0x0F: "PERSONALIZED",
    0x83: "LOCKED",
    0x87: "LOCKED",
}

# GP privilege byte 1 bits, most significant first (GP Card Spec Table 6-2).
_PRIV_BYTE1_BITS: tuple[tuple[int, str], ...] = (
    (0x80, "Security Domain"),
    (0x40, "DAP Verification"),
    (0x20, "Delegated Management"),
    (0x10, "Card Lock"),
    (0x08, "Card Terminate"),
    (0x04, "Card Reset"),
    (0x02, "CVM Management"),
    (0x01, "Mandated DAP Verification"),
)


@dataclass(frozen=True)
class AppEntry:
    """One registry entry decoded from a GET STATUS E3 application template."""

    aid: str
    lifecycle_raw: int | None
    lifecycle: str
    privileges_raw: str
    privileges: list[str] = field(default_factory=list)


def _read_tlv(data: bytes, pos: int) -> tuple[int, bytes, int]:
    """Read one BER-TLV at ``pos``. Return (tag, value, next_pos).

    Raises ValueError on a truncated element so the caller can stop cleanly at
    the end of a best-effort parse.
    """
    if pos >= len(data):
        raise ValueError("no TLV at position")
    first = data[pos]
    pos += 1
    tag = first
    if (first & 0x1F) == 0x1F:  # multi-byte tag
        if pos >= len(data):
            raise ValueError("truncated multi-byte tag")
        tag = (tag << 8) | data[pos]
        pos += 1
    if pos >= len(data):
        raise ValueError("truncated length")
    length = data[pos]
    pos += 1
    if length & 0x80:  # long form
        num = length & 0x7F
        if num == 0 or pos + num > len(data):
            raise ValueError("unsupported or truncated long-form length")
        length = int.from_bytes(data[pos : pos + num], "big")
        pos += num
    if pos + length > len(data):
        raise ValueError("truncated value")
    return tag, data[pos : pos + length], pos + length


def _decode_privileges(priv: bytes) -> list[str]:
    if not priv:
        return []
    return [name for mask, name in _PRIV_BYTE1_BITS if priv[0] & mask]


def _decode_app_template(value: bytes) -> AppEntry:
    aid = ""
    lifecycle_raw: int | None = None
    priv = b""
    pos = 0
    while pos < len(value):
        try:
            tag, val, pos = _read_tlv(value, pos)
        except ValueError:
            break
        if tag == 0x4F:
            aid = val.hex().upper()
        elif tag == 0x9F70:
            lifecycle_raw = val[0] if val else None
        elif tag == 0xC5:
            priv = val
    lifecycle = (
        _LIFECYCLE_NAMES.get(lifecycle_raw, f"0x{lifecycle_raw:02X}")
        if lifecycle_raw is not None
        else "unknown"
    )
    return AppEntry(
        aid=aid,
        lifecycle_raw=lifecycle_raw,
        lifecycle=lifecycle,
        privileges_raw=priv.hex().upper(),
        privileges=_decode_privileges(priv),
    )


def decode_getstatus(resp: bytes) -> list[AppEntry]:
    """Decode a GET STATUS response into its registry entries.

    Best-effort: walks the top-level TLV stream and decodes every ``E3``
    application template found. A response with no ``E3`` template (legacy
    tag-value format, or an error response) yields an empty list. Trailing
    unparseable bytes stop the walk without raising.
    """
    entries: list[AppEntry] = []
    pos = 0
    while pos < len(resp):
        try:
            tag, val, pos = _read_tlv(resp, pos)
        except ValueError:
            break
        if tag == 0xE3:
            entries.append(_decode_app_template(val))
    return entries


def run(
    *,
    engine: FuzzEngine,
    out_path,
    summary_path,
    phase: str,
    wall: int,
    send_cap: int | None,
) -> dict[str, object]:
    """Run the GET STATUS enumeration campaign."""
    novelty = NoveltyEngine()
    allowlist = [f"INS_{i:02X}" for i in sorted(ALLOWLIST_INS)]
    with UniqueBehaviourReporter(
        out_path=out_path,
        summary_path=summary_path,
        mode="explore_getstatus",
        phase=phase,
        allowlist=allowlist,
    ) as reporter:
        return drive(
            angle="getstatus",
            engine=engine,
            novelty=novelty,
            reporter=reporter,
            candidates=candidates(),
            phase=phase,
            wall=wall,
            send_cap=send_cap,
        )


def enumerate_apps(engine: FuzzEngine) -> dict[str, AppEntry]:
    """Decode every response the engine recorded into apps keyed by AID.

    Later occurrences of an AID overwrite earlier ones, so the richest decode
    (whichever scope/format returned the most tags) wins. Entries with no AID are
    skipped.
    """
    apps: dict[str, AppEntry] = {}
    for outcome in engine.outcomes:
        if not outcome.sent or not outcome.resp_hex:
            continue
        resp = outcome.resp_hex
        if outcome.sw and resp.upper().endswith(outcome.sw.upper()):
            resp = resp[: -len(outcome.sw)]
        if not resp:
            continue
        try:
            body = bytes.fromhex(resp)
        except ValueError:
            continue
        for entry in decode_getstatus(body):
            if entry.aid:
                apps[entry.aid] = entry
    return apps
