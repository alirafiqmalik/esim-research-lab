"""Robust Android UI helper: dump the view hierarchy, find nodes by
resource-id / text / class, and tap element centers. Coordinate-free so it
survives layout shifts (the failure mode of hardcoded taps)."""
from __future__ import annotations
import re
import subprocess
import time
import xml.etree.ElementTree as ET


class UiError(RuntimeError):
    pass


class Ui:
    def __init__(self, serial: str, timeout: int = 30):
        self.serial = serial
        self.timeout = timeout

    def _adb(self, *args: str, text: bool = True) -> str:
        r = subprocess.run(
            ["adb", "-s", self.serial, *args],
            capture_output=True, text=text, timeout=self.timeout,
        )
        if r.returncode != 0:
            raise UiError((r.stderr or r.stdout).strip())
        return r.stdout

    def shell(self, cmd: str) -> str:
        return self._adb("shell", cmd)

    def dump(self) -> str:
        # uiautomator dump to device, then read it back
        self.shell("uiautomator dump /sdcard/esimctl_ui.xml >/dev/null 2>&1")
        return self._adb("exec-out", "cat", "/sdcard/esimctl_ui.xml")

    @staticmethod
    def _bounds_center(b: str) -> tuple[int, int]:
        m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", b)
        if not m:
            raise UiError(f"bad bounds {b}")
        x1, y1, x2, y2 = map(int, m.groups())
        return (x1 + x2) // 2, (y1 + y2) // 2

    def find(self, *, rid: str | None = None, text: str | None = None,
             text_contains: str | None = None, cls: str | None = None,
             clickable: bool | None = None) -> tuple[int, int] | None:
        """Return the center (x,y) of the first matching node, or None."""
        xml = self.dump()
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            # uiautomator sometimes emits stray bytes; fall back to regex scan
            return self._find_regex(xml, rid, text, text_contains, cls)
        for n in root.iter("node"):
            a = n.attrib
            if rid and not a.get("resource-id", "").endswith(rid):
                continue
            if text and a.get("text", "") != text:
                continue
            if text_contains and text_contains not in a.get("text", ""):
                continue
            if cls and cls not in a.get("class", ""):
                continue
            if clickable is not None and (a.get("clickable") == "true") != clickable:
                continue
            return self._bounds_center(a.get("bounds", ""))
        return None

    def _find_regex(self, xml, rid, text, text_contains, cls):
        for m in re.finditer(r"<node\b[^>]*?/?>", xml):
            s = m.group(0)
            def attr(k):
                mm = re.search(rf'{k}="([^"]*)"', s)
                return mm.group(1) if mm else ""
            if rid and not attr("resource-id").endswith(rid):
                continue
            if text and attr("text") != text:
                continue
            if text_contains and text_contains not in attr("text"):
                continue
            if cls and cls not in attr("class"):
                continue
            b = attr("bounds")
            if b:
                return self._bounds_center(b)
        return None

    def wait(self, *, rid=None, text=None, text_contains=None, cls=None,
             clickable=None, timeout: float = 15, poll: float = 0.6):
        """Wait until a matching node appears; return its center or raise."""
        end = time.time() + timeout
        while time.time() < end:
            c = self.find(rid=rid, text=text, text_contains=text_contains,
                          cls=cls, clickable=clickable)
            if c:
                return c
            time.sleep(poll)
        raise UiError(f"element not found: rid={rid} text={text} "
                      f"contains={text_contains} cls={cls}")

    def tap(self, x: int, y: int):
        self.shell(f"input tap {x} {y}")

    def tap_el(self, **kw):
        x, y = self.wait(**kw)
        self.tap(x, y)
        return x, y

    def type(self, s: str):
        # single-quote so the device shell does not expand $ in activation codes
        self.shell("input text '" + s.replace("'", "'\\''") + "'")

    def back(self):
        self.shell("input keyevent KEYCODE_BACK")

    def present(self, **kw) -> bool:
        return self.find(**kw) is not None
