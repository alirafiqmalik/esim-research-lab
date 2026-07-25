from unittest.mock import MagicMock, patch
from esim.euicc.backends import _activity, _activity_seq_file


def test_activity_parses_result_line():
    sess = MagicMock()
    sess.read_log.return_value = 'foo\nESIMCTL: ab12cd34 RESULT {"ok": true, "eid": "X"}\n'
    with patch("esim.euicc.backends.adb"), \
         patch("esim.euicc.backends.uuid.uuid4") as u:
        u.return_value.hex = "ab12cd34ffff"
        r = _activity("SER", sess, "eid", "lpac", timeout=2)
    assert r == {"ok": True, "eid": "X"}


def test_activity_seq_file_stages_and_reads_results_back():
    sess = MagicMock()
    sess.read_log.return_value = (
        'ESIMCTL: ab12cd34 RESULT '
        '{"ok": true, "op": "seq", "count": 2, '
        '"results_file": "/data/data/im.angry.openeuicc/files/esimctl_result_ab12cd34.json"}\n'
    )

    def fake_adb(serial, *args, **kw):
        if args and args[0] == "shell" and "stat -c %u" in " ".join(map(str, args)):
            return "10317\n"
        if args and args[0] == "shell" and args[1:2] == ("su",) and "cat " in args[-1]:
            return '{"results": [{"apdu": "A", "resp": "9000", "ok": true}, ' \
                   '{"apdu": "B", "resp": "6A80", "ok": false}]}'
        return ""

    with patch("esim.euicc.backends.adb", side_effect=fake_adb), \
         patch("esim.euicc.backends.uuid.uuid4") as u:
        u.return_value.hex = "ab12cd34ffff"
        r = _activity_seq_file("SER", sess, ["A", "B"], timeout=2)

    # results are read back from the device file, not the truncated logcat line
    assert r["ok"] is True and r["count"] == 2
    assert "results_file" not in r
    assert [e["resp"] for e in r["results"]] == ["9000", "6A80"]
