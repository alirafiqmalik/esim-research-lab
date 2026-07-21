"""Unit tests for the CLI transport adapter.

These never touch a device. ``subprocess.run`` is mocked, mirroring the repo
rule that tests mock subprocess.run and never hit real ADB.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from euicc_transport import ApduResult, EuiccTransport, TransportError


def _proc(returncode: int = 0, stdout: str = "", stderr: str = "") -> SimpleNamespace:
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def _transport() -> EuiccTransport:
    return EuiccTransport(repo_root=Path("/repo"), python_executable="python3")


def test_parses_ok_json_into_apdu_result() -> None:
    payload = {"resp": "BF3E035C015A9000", "sw": "9000", "ok": True, "extra": 1}
    with patch("euicc_transport.subprocess.run", return_value=_proc(stdout=json.dumps(payload))) as run:
        result = _transport().send("81E2910006BF3E035C015A")

    assert isinstance(result, ApduResult)
    assert result.resp_hex == "BF3E035C015A9000"
    assert result.sw == "9000"
    assert result.ok is True
    assert result.raw["extra"] == 1

    cmd = run.call_args.args[0]
    assert cmd == ["python3", "-m", "esim.cli", "euicc", "apdu", "81E2910006BF3E035C015A"]
    assert run.call_args.kwargs["cwd"] == Path("/repo")
    assert run.call_args.kwargs["capture_output"] is True
    assert run.call_args.kwargs["text"] is True
    assert run.call_args.kwargs["timeout"] == 30


def test_ok_false_is_still_parsed() -> None:
    payload = {"resp": "6A80", "sw": "6A80", "ok": False}
    with patch("euicc_transport.subprocess.run", return_value=_proc(stdout=json.dumps(payload))):
        result = _transport().send("81E2910003BF2000")
    assert result.ok is False
    assert result.sw == "6A80"


def test_nonzero_exit_raises() -> None:
    with patch("euicc_transport.subprocess.run", return_value=_proc(returncode=1, stderr="no device")):
        with pytest.raises(TransportError, match="exited 1"):
            _transport().send("81E2910003BF2000")


def test_malformed_json_raises() -> None:
    with patch("euicc_transport.subprocess.run", return_value=_proc(stdout="not json")):
        with pytest.raises(TransportError, match="not JSON"):
            _transport().send("81E2910003BF2000")


def test_empty_output_raises() -> None:
    with patch("euicc_transport.subprocess.run", return_value=_proc(stdout="   ")):
        with pytest.raises(TransportError, match="empty CLI output"):
            _transport().send("81E2910003BF2000")


def test_missing_key_raises() -> None:
    with patch("euicc_transport.subprocess.run", return_value=_proc(stdout=json.dumps({"resp": "9000"}))):
        with pytest.raises(TransportError, match="missing"):
            _transport().send("81E2910003BF2000")


def test_timeout_raises() -> None:
    with patch("euicc_transport.subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 30)):
        with pytest.raises(TransportError, match="timed out"):
            _transport().send("81E2910003BF2000")
