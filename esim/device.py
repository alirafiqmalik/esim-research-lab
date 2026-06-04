import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Subscription:
    sub_id: int
    iccid: str
    display_name: str
    slot: int
    is_esim: bool


@dataclass
class EuiccState:
    raw: str


class ADBError(Exception):
    pass


class Device:
    def __init__(self, serial: str | None = None):
        self.serial = serial
        self._adb_prefix = ["adb"] + (["-s", serial] if serial else [])

    def _run(self, *args: str) -> str:
        try:
            result = subprocess.run(
                self._adb_prefix + list(args),
                capture_output=True, text=True, timeout=30,
            )
        except subprocess.TimeoutExpired as e:
            raise ADBError(f"ADB command timed out: {' '.join(args)}") from e
        if result.returncode != 0:
            raise ADBError(result.stderr.strip() or result.stdout.strip())
        return result.stdout

    def get_eid(self) -> str:
        output = self._run("shell", "dumpsys", "euicc_card_controller")
        match = re.search(r"EID[:\s]+([0-9A-Fa-f]{32})", output, re.IGNORECASE)
        if not match:
            raise ADBError("EID not found in euicc_card_controller output")
        return match.group(1).upper()

    def list_subscriptions(self) -> list[Subscription]:
        output = self._run("shell", "dumpsys", "phone")
        return _parse_subscriptions(output)

    def get_euicc_state(self) -> EuiccState:
        output = self._run("shell", "dumpsys", "euicc_card_controller")
        return EuiccState(raw=output)

    def enable_profile(self, sub_id: int) -> bool:
        # 193 is the Binder transaction code for IPhoneSubInfo.setSubscriptionEnabled on this OEM
        self._run("shell", "service", "call", "phone", "193",
                  "i32", str(sub_id), "i32", "1")
        return True

    def disable_profile(self, sub_id: int) -> bool:
        # 193 is the Binder transaction code for IPhoneSubInfo.setSubscriptionEnabled on this OEM
        self._run("shell", "service", "call", "phone", "193",
                  "i32", str(sub_id), "i32", "0")
        return True

    def set_data_sim(self, sub_id: int) -> bool:
        self._run("shell", "settings", "put", "global",
                  "multi_sim_data_call", str(sub_id))
        return True

    def bugreport(self, out_dir: Path) -> Path:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / "bugreport.zip"
        self._run("bugreport", str(path))
        return path


def _parse_subscriptions(output: str) -> list[Subscription]:
    subs = []
    for line in output.splitlines():
        if "SubscriptionInfo" not in line:
            continue
        m = re.search(r"SubscriptionInfo\s*\{(.+)\}", line)
        if not m:
            continue
        sub = _parse_sub_block(m.group(1))
        if sub is not None:
            subs.append(sub)
    return subs


def _parse_sub_block(block: str) -> "Subscription | None":
    def field(key: str) -> str:
        # Match value until next ", key=" pattern or end-of-block
        m = re.search(rf"\b{key}=(.+?)(?:,\s*\w+=|\Z)", block)
        return m.group(1).strip().rstrip(",").strip() if m else ""

    try:
        sub_id_raw = field("id") or field("subId")
        slot_raw = field("simSlotIndex")
        return Subscription(
            sub_id=int(sub_id_raw) if sub_id_raw else -1,
            iccid=field("iccId") or field("iccid"),
            display_name=field("displayName"),
            slot=int(slot_raw) if slot_raw.lstrip("-").isdigit() else -1,
            is_esim=field("isEmbedded").lower() == "true",
        )
    except ValueError:
        return None
