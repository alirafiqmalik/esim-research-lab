from __future__ import annotations
import json
import re
import shlex
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

from esim.euicc.const import ACT, PKG, REPO
from esim.euicc.session import adb

if TYPE_CHECKING:
    from esim.euicc.session import Session

# Inline `--es apdus` hits three walls for big sequences: the ~4KB logcat RESULT line
# truncates the readback, the binder intent-extra transaction fails (~90KB in), and the
# host adb argv exceeds ARG_MAX (~180KB in). Above either bound, av_seq stages the tokens
# in an on-device file instead (see _activity_seq_file). The tokens delivered are exactly
# the caller's — this is a transport change only, no new command capability.
_SEQ_INLINE_MAX_TOKENS = 30
_SEQ_INLINE_MAX_BYTES = 2000
_APP_FILES_DIR = f"/data/data/{PKG}/files"


def _await_result(sess: "Session", reqid: str, timeout: int,
                  op: str, raise_on_fail: bool) -> dict:
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


def _activity(serial: str, sess: "Session", op: str, backend: str = "lpac",
              timeout: int = 120, raise_on_fail: bool = True, **extras) -> dict:
    reqid = uuid.uuid4().hex[:8]
    parts = [f"am start -n {ACT}", f"--es id {reqid}", f"--es op {op}",
             f"--es backend {backend}"]
    for k, v in extras.items():
        if v is not None:
            parts.append(f"--es {k} {shlex.quote(str(v))}")  # keep $ literal on device
    adb(serial, "shell", " ".join(parts), check=False)
    return _await_result(sess, reqid, timeout, op, raise_on_fail)


def _activity_seq_file(serial: str, sess: "Session", tokens: list[str],
                       timeout: int = 180, raise_on_fail: bool = True) -> dict:
    """Deliver a large same-channel seq via an on-device file, read results back.

    Tokens (one per line) are pushed to /data/local/tmp, copied with root into the
    app's own files dir (correct SELinux label so the app can read them), and named
    to the activity via --es apdus_file. The activity writes the full results array to
    --es results_file (also in its files dir); we read it back with root. This bypasses
    the intent-extra binder limit (in) and the logcat line cap (out). Same tokens as the
    inline path — HOW they are delivered is the only difference.
    """
    reqid = uuid.uuid4().hex[:8]
    in_dev = f"/data/local/tmp/esimctl_seq_{reqid}.txt"
    in_app = f"{_APP_FILES_DIR}/esimctl_seq_{reqid}.txt"
    out_app = f"{_APP_FILES_DIR}/esimctl_result_{reqid}.json"
    local = REPO / ".temp" / f"esimctl_seq_{reqid}.txt"
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_text("\n".join(tokens))
    try:
        adb(serial, "push", str(local), in_dev)
        uid = adb(serial, "shell", "su", "-c", f"stat -c %u /data/data/{PKG}").strip()
        if not uid.isdigit():
            raise RuntimeError(f"could not resolve app uid (got {uid!r})")
        adb(serial, "shell", "su", "-c", f"cp {in_dev} {in_app}")
        adb(serial, "shell", "su", "-c", f"chown {uid}:{uid} {in_app}")
        adb(serial, "shell", "su", "-c", f"restorecon {in_app}", check=False)
        parts = [f"am start -n {ACT}", f"--es id {reqid}", "--es op seq",
                 "--es backend lpac",
                 f"--es apdus_file {shlex.quote(in_app)}",
                 f"--es results_file {shlex.quote(out_app)}"]
        adb(serial, "shell", " ".join(parts), check=False)
        r = _await_result(sess, reqid, timeout, "seq", raise_on_fail)
        results_file = r.pop("results_file", None)
        if results_file:
            raw = adb(serial, "shell", "su", "-c", f"cat {shlex.quote(results_file)}")
            r["results"] = json.loads(raw)["results"]
        return r
    finally:
        adb(serial, "shell", "rm", "-f", in_dev, check=False)
        adb(serial, "shell", "su", "-c", f"rm -f {in_app} {out_app}", check=False)
        Path(local).unlink(missing_ok=True)


def _resolve_iccid(serial: str, sess: "Session", target: str, backend: str) -> str:
    if len(target) >= 15 and target.isdigit():
        return target  # already an iccid
    idx = int(target) - 1
    profs = _activity(serial, sess, "list", backend)["profiles"]
    if idx < 0 or idx >= len(profs):
        raise SystemExit(f"profile #{target} not found ({len(profs)} profiles)")
    return profs[idx]["iccid"]
