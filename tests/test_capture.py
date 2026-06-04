import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from esim.capture import Capture, CaptureSession
from esim.device import Device, Subscription


def make_device():
    d = MagicMock(spec=Device)
    d.serial = "3ddf2893"
    d._adb_prefix = ["adb", "-s", "3ddf2893"]
    d.get_eid.return_value = "89049032004008882600000000000000"
    d.get_euicc_state.return_value = MagicMock(raw="state_data")
    d.list_subscriptions.return_value = [
        Subscription(1, "89012703278015354865", "T-Mobile", 0, False),
        Subscription(2, "89049032004008882600", "eSIM", -1, True),
    ]
    return d


@patch("subprocess.Popen")
def test_capture_starts_mitmdump(mock_popen, tmp_path):
    mock_proc = MagicMock()
    mock_proc.stdout = iter([])
    mock_popen.return_value = mock_proc

    d = make_device()
    with Capture(device=d, port=8081, sessions_root=tmp_path) as cap:
        pass

    calls = [c.args[0] for c in mock_popen.call_args_list]
    mitm_call = next(c for c in calls if "mitmdump" in c)
    assert "--listen-port" in mitm_call
    assert "8081" in mitm_call


@patch("subprocess.Popen")
def test_capture_save_writes_required_files(mock_popen, tmp_path):
    mock_proc = MagicMock()
    mock_proc.stdout = iter(["log line 1\n", "log line 2\n"])
    mock_popen.return_value = mock_proc

    d = make_device()
    with Capture(device=d, port=8080, sessions_root=tmp_path) as cap:
        cap._logcat_lines = ["log line 1", "log line 2"]
        session_dir = cap._session_dir
        (session_dir / "traffic.mitm").write_bytes(b"data")

    session = cap.save(session_dir)

    assert (session_dir / "logcat.txt").read_text() == "log line 1\nlog line 2"
    assert (session_dir / "traffic.mitm").exists()
    assert (session_dir / "euicc_state.json").exists()
    meta = json.loads((session_dir / "metadata.json").read_text())
    assert meta["serial"] == "3ddf2893"
    assert meta["eid"] == "89049032004008882600000000000000"
    assert len(meta["subscriptions"]) == 2
    assert isinstance(session, CaptureSession)


@patch("subprocess.Popen")
def test_capture_exit_terminates_processes(mock_popen, tmp_path):
    mock_proc = MagicMock()
    mock_proc.stdout = iter([])
    mock_popen.return_value = mock_proc

    d = make_device()
    with Capture(device=d, sessions_root=tmp_path) as cap:
        pass

    assert mock_proc.terminate.called
