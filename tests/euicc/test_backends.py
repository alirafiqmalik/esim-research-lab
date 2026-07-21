from unittest.mock import MagicMock, patch
from esim.euicc.backends import _activity


def test_activity_parses_result_line():
    sess = MagicMock()
    sess.read_log.return_value = 'foo\nESIMCTL: ab12cd34 RESULT {"ok": true, "eid": "X"}\n'
    with patch("esim.euicc.backends.adb"), \
         patch("esim.euicc.backends.uuid.uuid4") as u:
        u.return_value.hex = "ab12cd34ffff"
        r = _activity("SER", sess, "eid", "lpac", timeout=2)
    assert r == {"ok": True, "eid": "X"}
