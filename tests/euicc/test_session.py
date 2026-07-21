from unittest.mock import patch
from esim.euicc.session import detect_serial, _extract_rsp


def test_detect_serial_picks_first_device():
    out = "List of devices attached\nABC123\tdevice\nXYZ\toffline\n"
    with patch("esim.euicc.session.subprocess.run") as m:
        m.return_value.stdout = out
        assert detect_serial() == "ABC123"


def test_extract_rsp_parses_url_and_bodies():
    log = ("transmit(url = https://smdp.example/gsma/rsp2/es9plus)\n"
           "HTTP tx = {\"a\":1}\nHTTP response body = {\"b\":2}\n")
    msgs = _extract_rsp(log)
    kinds = [m["kind"] for m in msgs]
    assert kinds == ["request-url", "request-body", "response-body"]
