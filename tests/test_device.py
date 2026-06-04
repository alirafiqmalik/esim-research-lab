import subprocess
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


# --- New tests ---

DUMPSYS_PHONE_NESTED = """
Phone {id=0}:
  mSubscriptions:
    SubscriptionInfo {id=1, iccId=89012703278015354865, simSlotIndex=0, displayName=AT&T Prepaid, groupUuid={00000000-0000-0000-0000-000000000000}, isEmbedded=false}
    SubscriptionInfo {id=2, iccId=89049032004008882600, simSlotIndex=-1, displayName=eSIM Profile, isEmbedded=true}
"""


@patch("subprocess.run")
def test_list_subscriptions_display_name_with_spaces(mock_run):
    mock_run.return_value = make_result(DUMPSYS_PHONE_NESTED)
    subs = Device().list_subscriptions()
    phys = next(s for s in subs if not s.is_esim)
    assert phys.display_name == "AT&T Prepaid"


@patch("subprocess.run")
def test_list_subscriptions_nested_braces(mock_run):
    mock_run.return_value = make_result(DUMPSYS_PHONE_NESTED)
    subs = Device().list_subscriptions()
    assert len(subs) == 2
    phys = next(s for s in subs if not s.is_esim)
    assert phys.sub_id == 1
    assert phys.slot == 0


@patch("subprocess.run")
def test_list_subscriptions_empty(mock_run):
    mock_run.return_value = make_result("")
    assert Device().list_subscriptions() == []


@patch("subprocess.run")
def test_list_subscriptions_garbage(mock_run):
    mock_run.return_value = make_result("this is garbage\nno subscriptions here")
    assert Device().list_subscriptions() == []


def test_timeout_raises_adb_error():
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="adb", timeout=30)):
        with pytest.raises(ADBError, match="timed out"):
            Device().get_eid()


@patch("subprocess.run")
def test_adb_error_prefers_stderr(mock_run):
    r = MagicMock()
    r.stdout = ""
    r.stderr = "error from stderr"
    r.returncode = 1
    mock_run.return_value = r
    with pytest.raises(ADBError, match="error from stderr"):
        Device().get_eid()


@patch("subprocess.run")
def test_get_eid_case_insensitive(mock_run):
    mock_run.return_value = make_result("eid: 89049032004008882600000000000000\n")
    assert Device().get_eid() == "89049032004008882600000000000000"


@patch("subprocess.run")
def test_get_euicc_state_returns_euicc_state(mock_run):
    mock_run.return_value = make_result("some state output")
    from esim.device import EuiccState
    state = Device().get_euicc_state()
    assert isinstance(state, EuiccState)
    assert state.raw == "some state output"


@patch("subprocess.run")
def test_get_euicc_state_uses_isub(mock_run):
    mock_run.return_value = make_result("isub output")
    Device().get_euicc_state()
    args = mock_run.call_args[0][0]
    assert args[-1] == "isub"


# --- isub (SubscriptionInfoInternal) format tests ---

DUMPSYS_ISUB_ONE_PHYSICAL = """
SubscriptionManagerService:
Active subscriptions:
  [SubscriptionInfoInternal: id=1 iccId=890126022TEST simSlotIndex=0 portIndex=0 isEmbedded=0 isRemovableEmbedded=0 carrierId=1 displayName=T-Mobile carrierName=T-Mobile]

Embedded subscriptions: []
Euicc enabled=false
"""

DUMPSYS_ISUB_WITH_ESIM = """
SubscriptionManagerService:
Active subscriptions:
  [SubscriptionInfoInternal: id=1 iccId=890126022PHYS simSlotIndex=0 portIndex=0 isEmbedded=0 displayName=T-Mobile]
  [SubscriptionInfoInternal: id=2 iccId=89049032ESIM simSlotIndex=0 portIndex=1 isEmbedded=1 isRemovableEmbedded=1 displayName=eSIM Profile]

Euicc enabled=true
"""


@patch("subprocess.run")
def test_list_subscriptions_isub_physical(mock_run):
    mock_run.return_value = make_result(DUMPSYS_ISUB_ONE_PHYSICAL)
    subs = Device().list_subscriptions()
    assert len(subs) == 1
    assert subs[0].sub_id == 1
    assert subs[0].iccid == "890126022TEST"
    assert subs[0].display_name == "T-Mobile"
    assert subs[0].slot == 0
    assert subs[0].is_esim is False


@patch("subprocess.run")
def test_list_subscriptions_isub_with_esim(mock_run):
    mock_run.return_value = make_result(DUMPSYS_ISUB_WITH_ESIM)
    subs = Device().list_subscriptions()
    # Active subscriptions block has 2 entries, All subscriptions block may duplicate them
    phys = next(s for s in subs if not s.is_esim)
    esim = next(s for s in subs if s.is_esim)
    assert phys.iccid == "890126022PHYS"
    assert esim.iccid == "89049032ESIM"
    assert esim.is_esim is True


@patch("subprocess.run")
def test_list_subscriptions_prefers_isub(mock_run):
    """When isub returns subscriptions, dumpsys phone is never called."""
    mock_run.return_value = make_result(DUMPSYS_ISUB_ONE_PHYSICAL)
    Device().list_subscriptions()
    assert mock_run.call_count == 1
    args = mock_run.call_args[0][0]
    assert "isub" in args


@patch("subprocess.run")
def test_get_eid_euicc_disabled(mock_run):
    """Raises a clear ADBError when dumpsys isub shows Euicc enabled=false."""
    def side_effect(cmd, **_):
        r = MagicMock()
        r.returncode = 0
        r.stderr = ""
        if "euicc_card_controller" in cmd:
            r.stdout = "Can't find service: euicc_card_controller"
        else:
            r.stdout = "Euicc enabled=false\nEmbedded subscriptions: []"
        return r

    mock_run.side_effect = side_effect
    with pytest.raises(ADBError, match="eUICC hardware not present"):
        Device().get_eid()


@patch("subprocess.run")
def test_get_eid_found_via_isub(mock_run):
    """Returns EID from isub when euicc_card_controller has no EID."""
    def side_effect(cmd, **_):
        r = MagicMock()
        r.returncode = 0
        r.stderr = ""
        if "euicc_card_controller" in cmd:
            r.stdout = "Can't find service: euicc_card_controller"
        else:
            r.stdout = "EID: 89049032004008882600000000000001\nEuicc enabled=true"
        return r

    mock_run.side_effect = side_effect
    assert Device().get_eid() == "89049032004008882600000000000001"
