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
        # euicc_card_controller exists only when eUICC hardware is active
        output = self._run("shell", "dumpsys", "euicc_card_controller")
        match = re.search(r"EID[:\s]+([0-9A-Fa-f]{32})", output, re.IGNORECASE)
        if match:
            return match.group(1).upper()
        # Service missing or no EID — check isub for a better error message
        isub_output = self._run("shell", "dumpsys", "isub")
        if re.search(r"Euicc enabled=false", isub_output):
            raise ADBError("eUICC hardware not present or disabled (Euicc enabled=false)")
        eid_match = re.search(r"EID[:\s]+([0-9A-Fa-f]{32})", isub_output, re.IGNORECASE)
        if eid_match:
            return eid_match.group(1).upper()
        raise ADBError("EID not found — no euicc_card_controller service and no EID in isub output")

    def list_subscriptions(self) -> list[Subscription]:
        # dumpsys isub (Android 13+) is more reliable; fall back to dumpsys phone
        output = self._run("shell", "dumpsys", "isub")
        subs = _parse_subscriptions_isub(output)
        if subs:
            return subs
        output = self._run("shell", "dumpsys", "phone")
        return _parse_subscriptions(output)

    def get_euicc_state(self) -> EuiccState:
        # dumpsys isub is always present; euicc_card_controller may not exist
        output = self._run("shell", "dumpsys", "isub")
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


def _parse_subscriptions_isub(output: str) -> list[Subscription]:
    """Parse SubscriptionInfoInternal records from dumpsys isub (Android 13+)."""
    seen: set[int] = set()
    subs = []
    for line in output.splitlines():
        if "SubscriptionInfoInternal:" not in line:
            continue
        m = re.search(r'\[SubscriptionInfoInternal:\s+(.+)', line)
        if not m:
            continue
        block = m.group(1).rstrip(']').strip()
        sub = _parse_isub_block(block)
        if sub is not None and sub.sub_id not in seen:
            seen.add(sub.sub_id)
            subs.append(sub)
    return subs


def _parse_isub_block(block: str) -> "Subscription | None":
    """Parse a single SubscriptionInfoInternal block (space-separated key=value).

    Values can contain spaces (e.g. displayName=eSIM Go), so we build a field
    map by treating each space+word+equals as the start of the next field.
    """
    fields: dict[str, str] = {}
    for m in re.finditer(r'\b(\w+)=', block):
        key = m.group(1)
        val_start = m.end()
        nxt = re.search(r'\s+\w+=', block[val_start:])
        val_end = val_start + nxt.start() if nxt else len(block)
        fields[key] = block[val_start:val_end].strip()

    try:
        sub_id_raw = fields.get("id", "")
        slot_raw = fields.get("simSlotIndex", "")
        return Subscription(
            sub_id=int(sub_id_raw) if sub_id_raw else -1,
            iccid=fields.get("iccId", ""),
            display_name=fields.get("displayName", "") or fields.get("carrierName", ""),
            slot=int(slot_raw) if slot_raw.lstrip("-").isdigit() else -1,
            is_esim=fields.get("isEmbedded", "") == "1",
        )
    except ValueError:
        return None


def _parse_subscriptions(output: str) -> list[Subscription]:
    """Parse SubscriptionInfo records from dumpsys phone (older format)."""
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
    """Parse a single SubscriptionInfo block (comma-separated key=value)."""
    def field(key: str) -> str:
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
