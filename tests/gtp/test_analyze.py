from esim.gtp.analyze import analyze_variant, VARIANTS


def test_variants_parse_and_report_iccid():
    s = analyze_variant(VARIANTS[0])
    assert s.iccid == "89000123456789012341"
    assert s.saip_version and s.der_bytes > 0
