"""Decoder tests against REAL GET DATA bytes captured from the live eUICC.

These vectors are the exact card responses. The decoder must key each on the
REQUESTED GET DATA tag, not the response's leading TLV: CardData is asked for as
``66`` but answers with a ``73`` template, which is the bug these tests pin.
"""

from __future__ import annotations

import json

import getdata_decode

# Real 42-byte CPLC value (bare, no 9F7F wrapper), requested as tag 9F7F.
CPLC_9F7F = (
    "475001CC007720450100FF4A4162C2E64A79"
    "000000000000000000000000000000000000000000000000"
)

# Real 75-byte CardData value, requested as tag 66. Leads with a 73 template, so
# keying on the response byte would file it under 73 and never find it under 66.
CARDDATA_66 = (
    "734906072A864886FC6B01600B06092A864886FC6B020203630906072A864886FC6B03"
    "650D060B2A864886FC6B05040200006617060B2B060104012A026E010301060853544D3036380100"
)

# Real 15-byte ExtendedCardResources value, requested as tag FF21.
FF21 = "8101038204000C1750830400003C2D"


# ---- CPLC (9F7F) ------------------------------------------------------------


def test_cplc_real_vector_ic_serial_and_fields() -> None:
    info = getdata_decode.decode_cplc(CPLC_9F7F)
    assert info.ic_serial_number == "4162C2E6"
    # Fields parse into the full CPLC layout.
    assert info.ic_fabricator == "4750"
    assert info.ic_type == "01CC"
    assert info.os_identifier == "0077"
    assert len(info.fields) == 18


# ---- CardData (66) ----------------------------------------------------------


def test_carddata_real_vector_detects_oids_and_text() -> None:
    info = getdata_decode.decode_card_data(CARDDATA_66)
    # GlobalPlatform RID 2A864886FC6B appears across the recognition OIDs.
    assert any(h.startswith("2A864886FC6B") for h in info.oids_hex)
    # Java Card platform OID 2B060104012A026E.
    assert any(h.startswith("2B060104012A026E") for h in info.oids_hex)
    # ASCII product marker STM068 (STMicroelectronics ST33 family).
    assert any("STM068" in s for s in info.ascii_strings)


# ---- ExtendedCardResources (FF21) -------------------------------------------


def test_extended_card_resources_real_vector() -> None:
    info = getdata_decode.decode_extended_card_resources(FF21)
    assert info.installed_applications == 3
    # Bytes are 82 04 00 0C 17 50 -> 0x000C1750 == 792400.
    assert info.free_non_volatile_memory == 792400
    assert info.free_volatile_memory == 15405  # 0x00003C2D


# ---- keying regression: requested tag, not response leading byte ------------


def test_capture_keys_on_requested_tag_not_response(tmp_path) -> None:
    capture = tmp_path / "cap.jsonl"
    rows = [
        {"requested_tag": "9F7F", "sw": "9000", "resp": CPLC_9F7F},
        # CardData: requested 66, but resp bytes lead with 73.
        {"requested_tag": "66", "sw": "9000", "resp": CARDDATA_66},
        {"requested_tag": "FF21", "sw": "9000", "resp": FF21},
        {"requested_tag": "6A", "sw": "6A88", "resp": "6A88"},  # not-found, skipped
    ]
    capture.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    objects = getdata_decode.load_capture(capture)
    assert set(objects) == {"9F7F", "66", "FF21"}  # keyed on requested tag
    assert "73" not in objects  # NOT the response's leading byte

    profile = getdata_decode.build_profile(objects)
    assert profile.cplc is not None
    assert profile.cplc.ic_serial_number == "4162C2E6"
    assert profile.card_data is not None
    assert any(h.startswith("2A864886FC6B") for h in profile.card_data.oids_hex)
    assert profile.card_resources is not None
    assert profile.card_resources.installed_applications == 3

    md = getdata_decode.render_markdown(profile)
    assert "4162C2E6" in md
    assert "STM068" in md
    assert "Installed applications: `3`" in md
    # The bug symptom must be gone.
    assert "CPLC not present" not in md
    assert "not present in capture" not in md


def test_capture_falls_back_to_legacy_tag_field(tmp_path) -> None:
    capture = tmp_path / "legacy.jsonl"
    rows = [
        {"tag": "FF21", "sw": "9000", "resp": FF21},
        {"tag": "9F7F", "sw": "9000", "resp": CPLC_9F7F},
    ]
    capture.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    objects = getdata_decode.load_capture(capture)
    assert objects == {"FF21": FF21.upper(), "9F7F": CPLC_9F7F.upper()}
