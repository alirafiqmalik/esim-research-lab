from unittest.mock import MagicMock, patch
from click.testing import CliRunner
from esim.cli import main
from esim.device import Subscription, ADBError, EuiccState


def make_device_mock(eid="89049032004008882600000000000000"):
    d = MagicMock()
    d.get_eid.return_value = eid
    d.list_subscriptions.return_value = [
        Subscription(1, "89012703278015354865", "T-Mobile", 0, False),
        Subscription(2, "89049032004008882600", "eSIM", -1, True),
    ]
    d.enable_profile.return_value = True
    d.disable_profile.return_value = True
    d.set_data_sim.return_value = True
    return d


@patch("esim.cli.Device")
def test_eid_command(mock_device_cls):
    mock_device_cls.return_value = make_device_mock()
    result = CliRunner().invoke(main, ["eid"])
    assert result.exit_code == 0
    assert "89049032004008882600000000000000" in result.output


@patch("esim.cli.Device")
def test_eid_adb_error(mock_device_cls):
    d = MagicMock()
    d.get_eid.side_effect = ADBError("no device")
    mock_device_cls.return_value = d
    result = CliRunner().invoke(main, ["eid"])
    assert result.exit_code != 0
    assert "no device" in result.output


@patch("esim.cli.Device")
def test_profiles_list(mock_device_cls):
    mock_device_cls.return_value = make_device_mock()
    result = CliRunner().invoke(main, ["profiles", "list"])
    assert result.exit_code == 0
    assert "T-Mobile" in result.output
    assert "eSIM" in result.output


@patch("esim.cli.Device")
def test_profiles_enable(mock_device_cls):
    d = make_device_mock()
    mock_device_cls.return_value = d
    result = CliRunner().invoke(main, ["profiles", "enable", "2"])
    assert result.exit_code == 0
    d.enable_profile.assert_called_once_with(2)


@patch("esim.cli.Device")
def test_profiles_disable(mock_device_cls):
    d = make_device_mock()
    mock_device_cls.return_value = d
    result = CliRunner().invoke(main, ["profiles", "disable", "2"])
    assert result.exit_code == 0
    d.disable_profile.assert_called_once_with(2)


@patch("esim.cli.Device")
def test_data_sim_set(mock_device_cls):
    d = make_device_mock()
    mock_device_cls.return_value = d
    result = CliRunner().invoke(main, ["data-sim", "1"])
    assert result.exit_code == 0
    d.set_data_sim.assert_called_once_with(1)


def test_analyze_command(tmp_path):
    import json
    meta = {"serial": "x", "eid": "1" * 32, "subscriptions": [],
            "started_at": "2026-06-03T00:00:00+00:00", "duration_s": 10}
    (tmp_path / "metadata.json").write_text(json.dumps(meta))
    (tmp_path / "logcat.txt").write_text("")
    (tmp_path / "euicc_state.json").write_text(json.dumps({"start": {}, "end": {}}))
    (tmp_path / "traffic.mitm").write_bytes(b"")
    result = CliRunner().invoke(main, ["analyze", str(tmp_path)])
    assert result.exit_code == 0
    assert "ES11" in result.output
    assert "ES9+" in result.output
