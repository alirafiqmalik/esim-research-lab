from __future__ import annotations
import json
import re
import shlex
import time
import uuid
from typing import TYPE_CHECKING

from esim.euicc.const import ACT
from esim.euicc.session import adb

if TYPE_CHECKING:
    from esim.euicc.session import Session


def _activity(serial: str, sess: "Session", op: str, backend: str = "lpac",
              timeout: int = 120, raise_on_fail: bool = True, **extras) -> dict:
    reqid = uuid.uuid4().hex[:8]
    parts = [f"am start -n {ACT}", f"--es id {reqid}", f"--es op {op}",
             f"--es backend {backend}"]
    for k, v in extras.items():
        if v is not None:
            parts.append(f"--es {k} {shlex.quote(str(v))}")  # keep $ literal on device
    adb(serial, "shell", " ".join(parts), check=False)
    pat = re.compile(rf"{reqid} RESULT (\{{.*\}})")
    end = time.time() + timeout
    while time.time() < end:
        for line in sess.read_log().splitlines():
            m = pat.search(line)
            if m:
                r = json.loads(m.group(1))
                if raise_on_fail and not r.get("ok", False):
                    raise RuntimeError(r.get("error", "activity op failed"))
                return r
        time.sleep(1)
    raise RuntimeError(f"activity op '{op}' timed out (no ESIMCTL result)")


def _resolve_iccid(serial: str, sess: "Session", target: str, backend: str) -> str:
    if len(target) >= 15 and target.isdigit():
        return target  # already an iccid
    idx = int(target) - 1
    profs = _activity(serial, sess, "list", backend)["profiles"]
    if idx < 0 or idx >= len(profs):
        raise SystemExit(f"profile #{target} not found ({len(profs)} profiles)")
    return profs[idx]["iccid"]
