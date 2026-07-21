from esim.euicc.tlv import _tlv_walk, _parse_addresses


def test_tlv_walk_multibyte_tag_and_len():
    # BF3C (2-byte tag), length 0x03, value 80 01 41
    tags = _tlv_walk(bytes.fromhex("BF3C03800141"))
    assert tags == [(0xBF3C, bytes.fromhex("800141"))]


def test_parse_addresses_extracts_dp_and_ds():
    # BF3C { 80 "smdp.example"  81 "ds.example" } + 9000 trailer
    dp = b"smdp.example"; ds = b"ds.example"
    inner = bytes([0x80, len(dp)]) + dp + bytes([0x81, len(ds)]) + ds
    outer = bytes([0xBF, 0x3C, len(inner)]) + inner + b"\x90\x00"
    res = _parse_addresses(outer.hex())
    assert res == {"defaultDpAddress": "smdp.example", "rootDsAddress": "ds.example"}
