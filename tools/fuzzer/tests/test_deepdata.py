"""Unit tests for the deep read-only data extraction campaign. No device touched.

The enum and disclosure generators are checked to emit only allowlisted GET DATA
(CA/CB) and BF2D STORE DATA candidates. The CPLC decoder is checked against a
real 42-byte CPLC test vector, and the ExtendedCardResources decoder against a
synthetic FF21 TLV. The disclosure length comparison is exercised with a fake
transport that returns responses of differing lengths.
"""

from __future__ import annotations

import json

import bf2d_disclosure
import getdata_decode
import getdata_enum
from engine import FuzzEngine
from euicc_transport import ApduResult
from safety import Classification, classify

# A real 42-byte CPLC block wrapped in its 9F7F/2A DO. IC fabricator 4790 (NXP),
# OS identifier 4791 (NXP JCOP).
CPLC_VALUE = (
    "4790516847916265040010631234567890124791108047911090"
    "82111100AABBCCDD8211111011223344"
)
CPLC_TLV = "9F7F2A" + CPLC_VALUE

# Synthetic ExtendedCardResources: 20 apps, 256000 B free NVM, 65536 B free vol.
FF21_TLV = "FF21108102001482040003E800830400010000"


def _ins(apdu_hex: str) -> int:
    return bytes.fromhex(apdu_hex)[1]


# ---- generators emit only allowlisted candidates ----------------------------


def test_enum_generator_only_ca_cb_and_allowed() -> None:
    cands = list(getdata_enum.candidates())
    assert cands
    for cand in cands:
        assert _ins(cand.apdu_hex) in (0xCA, 0xCB), cand.apdu_hex
        assert classify(cand.apdu_hex).classification is Classification.ALLOWED


def test_enum_sweep_covers_both_ins_full_1byte_and_2byte() -> None:
    cands = list(getdata_enum.candidates())
    one_byte = {c.target for c in cands if c.target.startswith("DO:1byte:")}
    ca_one = {t for t in one_byte if ":CA:" in t}
    cb_one = {t for t in one_byte if ":CB:" in t}
    assert len(ca_one) == 256  # full 0x00..0xFF on the even INS
    assert len(cb_one) == 256  # full 0x00..0xFF on the odd INS
    joined = " ".join(c.target for c in cands)
    assert "9F7F" in joined  # CPLC two-byte tag present
    assert "FF21" in joined  # ExtendedCardResources two-byte tag present
    assert any(_ins(c.apdu_hex) == 0xCB for c in cands)


def test_disclosure_generator_only_bf2d_store_data_and_allowed() -> None:
    cands = bf2d_disclosure.candidates()
    assert cands
    for cand in cands:
        assert _ins(cand.apdu_hex) == 0xE2, cand.apdu_hex  # STORE DATA
        verdict = classify(cand.apdu_hex)
        assert verdict.classification is Classification.ALLOWED
        assert verdict.tag == 0xBF2D
    assert any(c.target.endswith("canonical") for c in cands)


# ---- CPLC decoder against a real 42-byte vector -----------------------------


def test_cplc_decodes_known_vector() -> None:
    info = getdata_decode.decode_cplc(CPLC_TLV)
    assert info.ic_fabricator == "4790"
    assert info.ic_fabricator_vendor == "NXP (Philips Semiconductors)"
    assert info.ic_type == "5168"
    assert info.os_identifier == "4791"
    assert info.os_vendor == "NXP JCOP"
    assert info.ic_serial_number == "12345678"
    assert info.fields["ic_batch_identifier"] == "9012"
    assert "year ...1, day 63" in info.fields["ic_fabrication_date"]


def test_cplc_accepts_bare_value_without_wrapper() -> None:
    info = getdata_decode.decode_cplc(CPLC_VALUE)
    assert info.ic_fabricator == "4790"


def test_cplc_rejects_short_input() -> None:
    try:
        getdata_decode.decode_cplc("9F7F029000")
    except getdata_decode.DecodeError:
        return
    raise AssertionError("short CPLC should raise DecodeError")


# ---- ExtendedCardResources decoder against a synthetic TLV ------------------


def test_extended_card_resources_decodes_synthetic() -> None:
    info = getdata_decode.decode_extended_card_resources(FF21_TLV)
    assert info.installed_applications == 20
    assert info.free_non_volatile_memory == 256000
    assert info.free_volatile_memory == 65536


def test_counter_decodes_integer() -> None:
    assert getdata_decode.decode_counter("C1020100", "C1") == 0x0100


# ---- capture loading + full profile build -----------------------------------


def test_load_capture_and_build_profile(tmp_path) -> None:
    capture = tmp_path / "cap.jsonl"
    rows = [
        {"tag": "9F7F", "sw": "9000", "resp": CPLC_TLV + "9000"},
        {"tag": "FF21", "sw": "9000", "resp": FF21_TLV + "9000"},
        {"tag": "6A88", "sw": "6A88", "resp": "6A88"},  # not-found, skipped
    ]
    capture.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    objects = getdata_decode.load_capture(capture)
    assert "9F7F" in objects
    assert "FF21" in objects
    assert "6A88" not in objects  # only readable DOs kept

    profile = getdata_decode.build_profile(objects)
    assert profile.cplc is not None
    assert profile.cplc.ic_fabricator_vendor == "NXP (Philips Semiconductors)"
    assert profile.card_resources is not None
    assert profile.card_resources.installed_applications == 20

    md = getdata_decode.render_markdown(profile)
    assert "NXP" in md
    assert "Installed applications" in md


# ---- disclosure length comparison with a fake transport ---------------------


class _LenTransport:
    """Fake transport whose response byte-length is chosen per APDU."""

    def __init__(self, len_by_apdu: dict[str, int]) -> None:
        self._len = len_by_apdu

    def send(self, apdu_hex: str) -> ApduResult:
        n = self._len.get(apdu_hex.upper(), 4)
        value = "AB" * n
        resp = (value + "9000").upper()
        return ApduResult(resp_hex=resp, sw="9000", ok=True, raw={})


def test_disclosure_flags_longer_response(tmp_path) -> None:
    cands = bf2d_disclosure.candidates()
    canonical = next(c.apdu_hex for c in cands if c.target.endswith("canonical")).upper()
    leak = next(c.apdu_hex for c in cands if c.target.endswith("inner_len_over_ff")).upper()

    engine = FuzzEngine(live=True, transport=_LenTransport({canonical: 4, leak: 12}))
    summary = bf2d_disclosure.run(
        engine=engine,
        out_path=tmp_path / "d.jsonl",
        summary_path=tmp_path / "d.summary.json",
        phase="live",
        wall=30,
        send_cap=None,
    )
    assert summary["canonical_resp_len_bytes"] == 4
    assert "inner_len_over_ff" in summary["disclosure_flagged"]
    on_disk = json.loads((tmp_path / "d.summary.json").read_text())
    assert on_disk["angle"] == "bf2d_disclosure"


def test_disclosure_dry_run_sends_nothing(tmp_path) -> None:
    engine = FuzzEngine(live=False, transport=None)
    summary = bf2d_disclosure.run(
        engine=engine,
        out_path=tmp_path / "d.jsonl",
        summary_path=tmp_path / "d.summary.json",
        phase="dry",
        wall=30,
        send_cap=None,
    )
    assert summary["sent"] == 0
    assert summary["canonical_resp_len_bytes"] is None
    assert "note" in summary


# ---- enum dry-run smoke: nothing sent, discovery empty ----------------------


def test_enum_dry_run_no_send(tmp_path) -> None:
    engine = FuzzEngine(live=False, transport=None)
    summary = getdata_enum.run(
        engine=engine,
        out_path=tmp_path / "e.jsonl",
        summary_path=tmp_path / "e.summary.json",
        phase="dry",
        wall=30,
        send_cap=None,
    )
    assert summary["angle"] == "getdata_enum"
    assert summary["sent"] == 0
    assert summary["discovery"] == []
