from unittest.mock import patch, MagicMock
import pytest
from esim.device import Device, Subscription, ADBError

DUMPSYS_EUICC = """
EuiccController:
  EID: 89049032004008882600000000000000
  Installed profiles: 1
"""

DUMPSYS_PHONE = """
Phone {id=0}:
  mSubscriptions:
    SubscriptionInfo {id=1, iccId=89012703278015354865, simSlotIndex=0, displayName=T-Mobile, isEmbedded=false}
    SubscriptionInfo {id=2, iccId=89049032004008882600, simSlotIndex=-1, displayName=eSIM, isEmbedded=true}
"""


def make_result(stdout="", returncode=0):
    r = MagicMock()
    r.stdout = stdout
    r.stderr = ""
    r.returncode = returncode
    return r


@patch("subprocess.run")
def test_get_eid(mock_run):
    mock_run.return_value = make_result(DUMPSYS_EUICC)
    assert Device().get_eid() == "89049032004008882600000000000000"
    mock_run.assert_called_once_with(
        ["adb", "shell", "dumpsys", "euicc_card_controller"],
        capture_output=True, text=True, timeout=30,
    )


@patch("subprocess.run")
def test_get_eid_not_found(mock_run):
    mock_run.return_value = make_result("no eid here")
    with pytest.raises(ADBError, match="EID not found"):
        Device().get_eid()


@patch("subprocess.run")
def test_list_subscriptions(mock_run):
    mock_run.return_value = make_result(DUMPSYS_PHONE)
    subs = Device().list_subscriptions()
    assert len(subs) == 2
    phys = next(s for s in subs if not s.is_esim)
    esim = next(s for s in subs if s.is_esim)
    assert phys.sub_id == 1
    assert phys.slot == 0
    assert phys.iccid == "89012703278015354865"
    assert esim.sub_id == 2
    assert esim.slot == -1
    assert esim.is_esim is True


@patch("subprocess.run")
def test_enable_profile(mock_run):
    mock_run.return_value = make_result("")
    assert Device().enable_profile(2) is True
    mock_run.assert_called_once_with(
        ["adb", "shell", "service", "call", "phone", "193", "i32", "2", "i32", "1"],
        capture_output=True, text=True, timeout=30,
    )


@patch("subprocess.run")
def test_disable_profile(mock_run):
    mock_run.return_value = make_result("")
    assert Device().disable_profile(2) is True
    mock_run.assert_called_once_with(
        ["adb", "shell", "service", "call", "phone", "193", "i32", "2", "i32", "0"],
        capture_output=True, text=True, timeout=30,
    )


@patch("subprocess.run")
def test_set_data_sim(mock_run):
    mock_run.return_value = make_result("")
    assert Device().set_data_sim(1) is True
    mock_run.assert_called_once_with(
        ["adb", "shell", "settings", "put", "global", "multi_sim_data_call", "1"],
        capture_output=True, text=True, timeout=30,
    )


@patch("subprocess.run")
def test_adb_error_on_nonzero(mock_run):
    mock_run.return_value = make_result("error: no devices", returncode=1)
    with pytest.raises(ADBError):
        Device().get_eid()


@patch("subprocess.run")
def test_serial_prepended(mock_run):
    mock_run.return_value = make_result(DUMPSYS_EUICC)
    Device(serial="abc123").get_eid()
    args = mock_run.call_args[0][0]
    assert args[:3] == ["adb", "-s", "abc123"]
