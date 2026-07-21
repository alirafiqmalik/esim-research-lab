from esim.euicc.cli import build_parser, ACT_OPS


def test_parser_accepts_apdu_op():
    args = build_parser().parse_args(["apdu", "BF3E00"])
    assert args.op == "apdu" and args.hex == "BF3E00"


def test_act_ops_has_expected_keys():
    for k in ("list", "eid", "apdu", "get-addresses", "discovery", "card-info2"):
        assert k in ACT_OPS
