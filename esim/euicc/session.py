from __future__ import annotations
import json
import re
import subprocess
import time
from datetime import datetime

from esim.euicc.const import SESS_BASE


def adb(serial: str, *args: str, check: bool = True) -> str:
    r = subprocess.run(["adb", "-s", serial, *args],
                       capture_output=True, text=True, timeout=60)
    if check and r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip())
    return r.stdout


def detect_serial() -> str:
    out = subprocess.run(["adb", "devices"], capture_output=True, text=True).stdout
    devs = [ln.split()[0] for ln in out.splitlines()[1:] if ln.strip().endswith("device")]
    if not devs:
        raise SystemExit("no adb device in 'device' state")
    return devs[0]


class Session:
    """Per-op log directory + a background logcat capture started BEFORE the op."""
    def __init__(self, serial: str, op: str):
        self.serial = serial
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.dir = SESS_BASE / f"{ts}-{op}"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.logcat_path = self.dir / "logcat.txt"
        self._proc = None

    def start_logging(self):
        adb(self.serial, "logcat", "-c")
        self._f = open(self.logcat_path, "w")
        self._proc = subprocess.Popen(
            ["adb", "-s", self.serial, "logcat", "-v", "time"], stdout=self._f, stderr=subprocess.STDOUT)
        time.sleep(0.6)

    def stop_logging(self):
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._f.close()

    def read_log(self) -> str:
        try:
            return self.logcat_path.read_text(errors="replace")
        except FileNotFoundError:
            return ""

    def save(self, name: str, data):
        p = self.dir / name
        p.write_text(data if isinstance(data, str) else json.dumps(data, indent=2))
        return p


def _isub(serial: str) -> str:
    return adb(serial, "shell", "dumpsys isub")


def _extract_rsp(log: str) -> list[dict]:
    msgs = []
    for m in re.finditer(r"transmit\(url = (\S+)\)|HTTP tx = (.+)|HTTP response body = (.+)", log):
        if m.group(1):
            msgs.append({"kind": "request-url", "value": m.group(1)})
        elif m.group(2):
            msgs.append({"kind": "request-body", "value": m.group(2)[:600]})
        elif m.group(3):
            msgs.append({"kind": "response-body", "value": m.group(3)[:600]})
    return msgs
