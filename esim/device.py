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


class ADBError(Exception):
    pass


class Device:
    def __init__(self, serial: str | None = None):
        self.serial = serial
        self._adb_prefix = ["adb"] + (["-s", serial] if serial else [])

    def _run(self, *args: str) -> str:
        result = subprocess.run(
            self._adb_prefix + list(args),
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            raise ADBError(result.stderr.strip() or result.stdout.strip())
        return result.stdout

    def get_eid(self) -> str:
        output = self._run("shell", "dumpsys", "euicc_card_controller")
        match = re.search(r"EID[:\s]+([0-9A-Fa-f]{32})", output)
        if not match:
            raise ADBError("EID not found in euicc_card_controller output")
        return match.group(1).upper()

    def list_subscriptions(self) -> list[Subscription]:
        output = self._run("shell", "dumpsys", "phone")
        return _parse_subscriptions(output)

    def get_euicc_state(self) -> dict[str, str]:
        output = self._run("shell", "dumpsys", "euicc_card_controller")
        return {"raw": output}

    def enable_profile(self, sub_id: int) -> bool:
        self._run("shell", "service", "call", "phone", "193",
                  "i32", str(sub_id), "i32", "1")
        return True

    def disable_profile(self, sub_id: int) -> bool:
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


_SUB_PATTERN = re.compile(r"SubscriptionInfo\s*\{([^}]+)\}", re.DOTALL)
_FIELD = re.compile(r"(\w+)=([^,\s}]+)")


def _parse_subscriptions(output: str) -> list[Subscription]:
    subs = []
    for m in _SUB_PATTERN.finditer(output):
        fields = dict(_FIELD.findall(m.group(1)))
        try:
            subs.append(Subscription(
                sub_id=int(fields.get("id", fields.get("subId", -1))),
                iccid=fields.get("iccId", fields.get("iccid", "")),
                display_name=fields.get("displayName", ""),
                slot=int(fields.get("simSlotIndex", -1)),
                is_esim=fields.get("isEmbedded", "false").lower() == "true",
            ))
        except ValueError:
            continue
    return subs
