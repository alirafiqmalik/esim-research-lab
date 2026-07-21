"""Domain fuzzing dictionary for the read-only eUICC command surface.

Informed by ``testing-handbook-skills:fuzzing-dictionary`` (domain tokens),
``fuzzing-obstacles`` (length/BER framing barriers), and ``harness-writing``
(structured input extraction). The tokens here steer body/parameter mutation of
the allowlisted commands toward the eUICC's BER-TLV and ISO-7816 grammar instead
of blind byte flips, which would almost never build a parseable APDU.

Nothing here sends anything. It only produces candidate byte fragments. Every
built APDU is still classified by ``safety.py`` before it can leave the host.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ES10x store-data prefix: CLA=0x81 INS=0xE2 (STORE DATA) P1=0x91 P2=0x00.
STORE_DATA_PREFIX = bytes((0x81, 0xE2, 0x91, 0x00))


@dataclass(frozen=True)
class DictionaryEntry:
    """One domain token the mutator can splice into a candidate body."""

    name: str
    value: bytes
    category: str


def _b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


# SGP.22 BER-TLV tags. Two-byte BFxx command tags plus the one-byte sub-TLV tags
# that appear inside read-command bodies and responses.
_SGP22_TAGS: tuple[DictionaryEntry, ...] = (
    DictionaryEntry("tag_GetEID", _b("BF3E"), "sgp22_tag"),
    DictionaryEntry("tag_GetEUICCInfo1", _b("BF20"), "sgp22_tag"),
    DictionaryEntry("tag_GetEUICCInfo2", _b("BF22"), "sgp22_tag"),
    DictionaryEntry("tag_GetEUICCChallenge", _b("BF2E"), "sgp22_tag"),
    DictionaryEntry("tag_GetProfilesInfo", _b("BF2D"), "sgp22_tag"),
    DictionaryEntry("tag_ListNotification", _b("BF28"), "sgp22_tag"),
    DictionaryEntry("tag_RetrieveNotifications", _b("BF2B"), "sgp22_tag"),
    DictionaryEntry("tag_GetConfiguredAddresses", _b("BF3C"), "sgp22_tag"),
    DictionaryEntry("tag_GetRAT", _b("BF43"), "sgp22_tag"),
    # One-byte structural tags used inside bodies / responses.
    DictionaryEntry("tag_list_5C", _b("5C"), "ber_tag"),
    DictionaryEntry("tag_iccid_5A", _b("5A"), "ber_tag"),
    DictionaryEntry("tag_eid_5A", _b("5A"), "ber_tag"),
    DictionaryEntry("tag_aid_4F", _b("4F"), "ber_tag"),
    DictionaryEntry("tag_ctx0_80", _b("80"), "ber_tag"),
    DictionaryEntry("tag_ctx1_81", _b("81"), "ber_tag"),
    DictionaryEntry("tag_seq_A0", _b("A0"), "ber_tag"),
    DictionaryEntry("tag_seq_30", _b("30"), "ber_tag"),
    DictionaryEntry("tag_oid_06", _b("06"), "ber_tag"),
    DictionaryEntry("tag_pkid_9F70", _b("9F70"), "ber_tag"),
)

# Valid sub-TLV templates per read command: the body the eUICC expects. These are
# the "known good" fragments a mutator perturbs.
_SUBTLV_TEMPLATES: tuple[DictionaryEntry, ...] = (
    # GetEID asks for tag 5A via a tag-list: 5C 01 5A.
    DictionaryEntry("body_geteid_taglist", _b("5C015A"), "template"),
    # Empty body: the common ES10x "get" with no criteria (info1/info2/rat/addr).
    DictionaryEntry("body_empty", b"", "template"),
    # RetrieveNotificationsList by sequence number: A0 03 80 01 <seq>.
    DictionaryEntry("body_retrieve_seq_1", _b("A003800101"), "template"),
    DictionaryEntry("body_retrieve_seq_0", _b("A003800100"), "template"),
    # ProfileInfoListRequest search criteria: tag-list of fields to return.
    DictionaryEntry("body_profiles_taglist", _b("5C035A4F9F"), "template"),
    DictionaryEntry("body_profiles_search_iccid", _b("A00A5A08" + "98" * 8), "template"),
    # ListNotification filter by notification event bitmask.
    DictionaryEntry("body_listnotif_filter", _b("80020F00"), "template"),
)

# Common value tokens: realistic identifier byte patterns the card recognises.
_VALUE_TOKENS: tuple[DictionaryEntry, ...] = (
    # EID: 16 BCD bytes (32 nibbles). Pattern from the testbed device.
    DictionaryEntry("val_eid", _b("89033023427100000000027143866816"), "value"),
    # ICCID: up to 10 BCD bytes, F-padded.
    DictionaryEntry("val_iccid", _b("98001122334455667FFF"), "value"),
    # ISD-R AID.
    DictionaryEntry("val_aid_isdr", _b("A0000005591010FFFFFFFF8900000100"), "value"),
    # ECASD AID.
    DictionaryEntry("val_aid_ecasd", _b("A0000005591010FFFFFFFF8900000200"), "value"),
    # CI public-key identifier (SHA-1, 20 bytes) from the production CI.
    DictionaryEntry("val_pkid", _b("81370F5125D0B1D408D4C3B232E6D25E795BEBFB"), "value"),
    # Sequence-number values for notification retrieval.
    DictionaryEntry("val_seq_zero", _b("00"), "value"),
    DictionaryEntry("val_seq_max", _b("FFFFFFFF"), "value"),
)

# ISO-7816 header sweep tokens: P1/P2 values worth exercising per command.
P1_SWEEP: tuple[int, ...] = (0x00, 0x01, 0x02, 0x04, 0x08, 0x0C, 0x10, 0x7F, 0x80, 0xFF)
P2_SWEEP: tuple[int, ...] = (0x00, 0x01, 0x02, 0x03, 0x04, 0x0C, 0x7F, 0x80, 0xFF)


def lc_boundary_values(actual: int) -> list[int]:
    """Lc bytes worth probing for a body of length ``actual``.

    Includes the true length, its neighbours, and the classic single-byte
    boundaries. Long-form Lc is produced separately by :func:`encode_lc`.
    """
    candidates = {0, 1, actual, actual - 1, actual + 1, 0x7F, 0x80, 0xFF}
    return sorted(v for v in candidates if 0 <= v <= 0xFF)


def encode_lc(length: int, *, form: str = "auto") -> bytes:
    """Encode an APDU Lc field.

    ``form`` selects the encoding to exercise BER/APDU length framing barriers
    (``fuzzing-obstacles``): ``short`` (one byte), ``long2`` (``82 xx xx`` even
    when short would do), or ``auto`` (short when it fits).
    """
    if form == "long2" or (form == "auto" and length > 0xFF):
        return bytes((0x82, (length >> 8) & 0xFF, length & 0xFF))
    if form == "long1" or (form == "auto" and length > 0x7F):
        return bytes((0x81, length & 0xFF))
    return bytes((length & 0xFF,))


def ber_length_edge_cases(true_len: int) -> list[DictionaryEntry]:
    """BER length fields that stress the eUICC's TLV length parser.

    Covers long-form, truncated, over-long, deeply nested, and indefinite forms
    per ``fuzzing-obstacles``. Values are the raw length-field bytes; the caller
    splices them where a TLV length would sit.
    """
    tl = true_len & 0xFF
    return [
        DictionaryEntry("len_short_true", bytes((tl,)), "ber_len"),
        DictionaryEntry("len_zero", b"\x00", "ber_len"),
        DictionaryEntry("len_long1_true", bytes((0x81, tl)), "ber_len"),
        DictionaryEntry("len_long2_true", bytes((0x82, 0x00, tl)), "ber_len"),
        DictionaryEntry("len_long1_overstated", bytes((0x81, 0xFF)), "ber_len"),
        DictionaryEntry("len_long2_overstated", bytes((0x82, 0xFF, 0xFF)), "ber_len"),
        DictionaryEntry("len_truncated_long", b"\x82\x01", "ber_len"),
        DictionaryEntry("len_indefinite", b"\x80", "ber_len"),
        DictionaryEntry("len_reserved_ff", b"\xFF", "ber_len"),
    ]


def malformed_framing(prefix: bytes, tag: bytes, value: bytes) -> list[DictionaryEntry]:
    """Store-data candidates whose framing is deliberately inconsistent.

    Per ``fuzzing-obstacles``: wrong Lc versus body length, a dangling TLV whose
    inner length overruns the body, and an over-long inner length. Returned as
    whole-APDU byte candidates ready to hex-encode.
    """
    good_tlv = tag + bytes((len(value),)) + value
    entries: list[DictionaryEntry] = []
    # Lc claims one more byte than the body actually carries.
    entries.append(
        DictionaryEntry(
            "frame_lc_over",
            prefix + bytes((len(good_tlv) + 1,)) + good_tlv,
            "malformed",
        )
    )
    # Lc claims one byte fewer than the body.
    if len(good_tlv) >= 1:
        entries.append(
            DictionaryEntry(
                "frame_lc_under",
                prefix + bytes((len(good_tlv) - 1,)) + good_tlv,
                "malformed",
            )
        )
    # Dangling TLV: inner length says more value bytes than are present.
    dangling = tag + bytes((len(value) + 4,)) + value
    entries.append(
        DictionaryEntry(
            "frame_dangling_tlv",
            prefix + bytes((len(dangling),)) + dangling,
            "malformed",
        )
    )
    # Inner length maxed out against a tiny value.
    overlong = tag + b"\xFF" + value
    entries.append(
        DictionaryEntry(
            "frame_inner_overlong",
            prefix + bytes((len(overlong),)) + overlong,
            "malformed",
        )
    )
    return entries


@dataclass(frozen=True)
class FuzzingDictionary:
    """The assembled domain dictionary for the read-only command surface."""

    tags: tuple[DictionaryEntry, ...] = _SGP22_TAGS
    templates: tuple[DictionaryEntry, ...] = _SUBTLV_TEMPLATES
    values: tuple[DictionaryEntry, ...] = _VALUE_TOKENS
    p1_sweep: tuple[int, ...] = P1_SWEEP
    p2_sweep: tuple[int, ...] = P2_SWEEP
    value_bytes: tuple[int, ...] = field(default=(0x00, 0x01, 0x5A, 0x7F, 0x80, 0xFF))

    def all_entries(self) -> list[DictionaryEntry]:
        """Every static token, for corpus seeding or export."""
        return [*self.tags, *self.templates, *self.values]

    def bodies_for_tag(self, tag: bytes) -> list[bytes]:
        """Candidate inner bodies (value part) to pair with a command tag."""
        bodies: list[bytes] = [t.value for t in self.templates]
        bodies.extend(v.value for v in self.values)
        for b in self.value_bytes:
            bodies.append(bytes((b,)))
            bodies.append(bytes((b, b)))
        # Deduplicate while keeping order stable for reproducible runs.
        seen: set[bytes] = set()
        out: list[bytes] = []
        for body in bodies:
            if body not in seen:
                seen.add(body)
                out.append(body)
        return out

    def to_afl_dict(self) -> str:
        """Render as an AFL/libFuzzer ``.dict`` file (one quoted token per line)."""
        lines = ["# eUICC read-only command dictionary (generated by dictionary.py)"]
        for entry in self.all_entries():
            escaped = "".join(f"\\x{byte:02X}" for byte in entry.value)
            lines.append(f'{entry.name}="{escaped}"')
        return "\n".join(lines) + "\n"
