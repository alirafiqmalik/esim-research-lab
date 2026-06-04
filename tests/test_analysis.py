import json
from pathlib import Path
import pytest
from esim.analysis import Session, RSPCall, LogEvent, _detect_interface, _parse_logcat_line


def write_session(tmp_path: Path, logcat: str = "", mitm: bool = False) -> Path:
    meta = {
        "serial": "3ddf2893",
        "eid": "89049032004008882600000000000000",
        "subscriptions": [],
        "started_at": "2026-06-03T14:23:01+00:00",
        "duration_s": 45.2,
    }
    (tmp_path / "metadata.json").write_text(json.dumps(meta))
    (tmp_path / "logcat.txt").write_text(logcat)
    (tmp_path / "euicc_state.json").write_text(json.dumps({"start": {}, "end": {}}))
    if not mitm:
        (tmp_path / "traffic.mitm").write_bytes(b"")
    return tmp_path


def test_session_load(tmp_path):
    write_session(tmp_path)
    s = Session.load(tmp_path)
    assert s._metadata["eid"] == "89049032004008882600000000000000"


def test_detect_interface_es11():
    assert _detect_interface("https://smdsc.t-mobile.com/gsma/rsp2/es11/initiateAuthentication") == "ES11"


def test_detect_interface_es9plus():
    assert _detect_interface("https://smdp.example.com/gsma/rsp2/es9plus/getBoundProfilePackage") == "ES9+"


def test_detect_interface_unknown():
    assert _detect_interface("https://example.com/other") is None


def test_parse_logcat_line_valid():
    line = "06-03 14:23:01.123  1234  5678 D EuiccManager: prepareDownload called"
    event = _parse_logcat_line(line)
    assert event is not None
    assert event.tag == "EuiccManager"
    assert "prepareDownload" in event.message


def test_parse_logcat_line_invalid():
    assert _parse_logcat_line("not a log line") is None


def test_logcat_events_empty(tmp_path):
    write_session(tmp_path, logcat="")
    s = Session.load(tmp_path)
    assert s.logcat_events() == []


def test_logcat_events_parsed(tmp_path):
    logcat = "06-03 14:23:01.123  1234  5678 D EuiccManager: prepareDownload called"
    write_session(tmp_path, logcat=logcat)
    s = Session.load(tmp_path)
    events = s.logcat_events()
    assert len(events) == 1
    assert isinstance(events[0], LogEvent)


def test_es11_and_es9_empty_without_mitm(tmp_path):
    write_session(tmp_path)
    s = Session.load(tmp_path)
    assert s.es11_calls() == []
    assert s.es9_calls() == []
    assert s.bpp_blobs() == []


def test_timeline_merges_and_sorts(tmp_path):
    logcat = "06-03 14:23:01.123  1234  5678 D EuiccManager: step one"
    write_session(tmp_path, logcat=logcat)
    s = Session.load(tmp_path)
    tl = s.timeline()
    assert all("t_ms" in item for item in tl)
    assert tl == sorted(tl, key=lambda x: x["t_ms"])
