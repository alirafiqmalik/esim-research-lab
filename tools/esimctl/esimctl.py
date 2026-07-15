#!/usr/bin/env python3
"""esimctl — scriptable, auto-logging control of the phone's eSIM/eUICC.

No LLM required. Compose ops in shell/python to run sequences:

    esimctl list
    esimctl download 'LPA:1$rsp.truphone.com$QRF-SPEEDTEST'
    esimctl enable 2
    esimctl disable 2
    esimctl delete 2
    esimctl cycle --code 'LPA:1$rsp-eu.redteamobile.com$5901981126831169' --times 5

Every op starts full logcat capture BEFORE it runs and, for RSP ops, attaches
the OpenEUICC verbose ES9+/APDU plaintext hook — writing per-op logs under
sessions/esimctl/<ts>-<op>/. Output is JSON on stdout; exit code 0 = ok.

Backends:
  lpac  (default) — drives our privileged OpenEUICC (full plaintext logging)
  fw              — Android framework EuiccManager via the euiccmgr helper
                    (see helper-app/; result codes only, RSP bodies opaque)
"""
from __future__ import annotations
import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from uidriver import Ui, UiError

REPO = Path(__file__).resolve().parents[2]
PKG = "im.angry.openeuicc"
MAIN = f"{PKG}/.ui.PrivilegedMainActivity"
SESS_BASE = REPO / "sessions" / "esimctl"
VERBOSE_TAGS = ("HttpInterfaceImpl", "OmapiApduInterface", "TelephonyManagerApduInterface",
                "EuiccChannelManager", "app_process64", "EuiccGoogle")


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


# ------------------------------ read ops ------------------------------

def _isub(serial: str) -> str:
    return adb(serial, "shell", "dumpsys isub")


def op_list(serial: str, sess: Session, args) -> dict:
    """Embedded profiles from dumpsys isub (dedup by subId)."""
    raw = _isub(serial)
    sess.save("isub.txt", raw)
    seen, profiles = set(), []
    for m in re.finditer(r"SubscriptionInfoInternal:\s+(.+)", raw):
        block = m.group(1)
        def f(k):
            mm = re.search(rf"\b{k}=(\S*)", block)
            return mm.group(1) if mm else ""
        sid = f("id")
        if f("isEmbedded") != "1" or sid in seen:
            continue
        seen.add(sid)
        profiles.append({"subId": sid, "iccid": f("iccId"),
                         "name": f("displayName"), "carrier": f("carrierName"),
                         "slot": f("simSlotIndex")})
    return {"op": "list", "profiles": profiles, "count": len(profiles)}


def _launch_openeuicc_and_read(serial: str, sess: Session) -> str:
    """Launch OpenEUICC (it enumerates the eUICC with verbose logging) and
    return the captured logcat once GetEID / profile read is seen."""
    adb(serial, "shell", "am", "start", "-n", MAIN, check=False)
    end = time.time() + 20
    while time.time() < end:
        log = sess.read_log()
        if re.search(r"BF3E125A10[0-9A-F]{32}|No profiles|Found eUICC", log):
            break
        time.sleep(1)
    time.sleep(1.5)
    return sess.read_log()


def op_eid(serial: str, sess: Session, args) -> dict:
    log = _launch_openeuicc_and_read(serial, sess)
    m = re.search(r"BF3E125A10([0-9A-F]{32})", log)
    return {"op": "eid", "eid": m.group(1) if m else None}


def op_info(serial: str, sess: Session, args) -> dict:
    log = _launch_openeuicc_and_read(serial, sess)
    eid = re.search(r"BF3E125A10([0-9A-F]{32})", log)
    info1 = re.search(r"BF2281[0-9A-F]{2,4}(8103[0-9A-F]{6}.*?)9000", log)
    ci = re.findall(r"0414([0-9A-F]{40})", log)
    return {"op": "info", "eid": eid.group(1) if eid else None,
            "ci_key_ids": sorted(set(ci)),
            "euicc_info1_raw": info1.group(0)[:200] if info1 else None}


# ------------------------------ write ops (lpac via OpenEUICC UI) ------------------------------

def _open_main(ui: Ui):
    ui.shell(f"am start -n {MAIN}")
    time.sleep(1.5)


def _profile_iccids(serial: str) -> list[str]:
    r = op_list(serial, Session.__new__(Session), None) if False else None
    raw = _isub(serial)
    return list(dict.fromkeys(re.findall(r"iccId=(\d+)", raw)))


def _resolve_profile_index(ui: Ui, target: str) -> int:
    """target may be a 1-based index (#N) or an iccid. Return 0-based row."""
    if target.isdigit() and len(target) < 4:
        return int(target) - 1
    # iccid: find its order on screen (profiles listed top to bottom)
    return 0


def op_download(serial: str, sess: Session, args) -> dict:
    ui = Ui(serial)
    code = args.code
    m = re.match(r"(?:LPA:)?1\$([^$]+)\$([^$]*)", code, re.I)
    if not m:
        raise SystemExit("activation code must look like LPA:1$smdp$matchingId")
    smdp, mid = m.group(1), m.group(2)
    frida = None
    if args.capture_rsp:
        frida = _attach_frida(serial, sess)
    _open_main(ui)
    ui.tap_el(rid="fab", timeout=10)
    time.sleep(1.5)
    # slot-select may appear first when profiles exist
    if ui.present(rid="download_wizard_next") and ui.present(text_contains="Logical Slot"):
        ui.tap_el(rid="download_wizard_next"); time.sleep(1.5)
    ui.tap_el(text="Enter manually", timeout=8); time.sleep(1.5)
    sx, sy = ui.wait(text_contains="Server", cls="EditText"); ui.tap(sx, sy)
    time.sleep(0.5); ui.type(smdp); ui.back(); time.sleep(0.5)
    ax, ay = ui.wait(text="Activation Code", cls="EditText"); ui.tap(ax, ay)
    time.sleep(0.5); ui.type(mid); ui.back(); time.sleep(0.5)
    ui.tap_el(rid="download_wizard_next"); time.sleep(2)
    if ui.present(rid="download_wizard_next") and not ui.present(text_contains="Downloading"):
        ui.tap_el(rid="download_wizard_next"); time.sleep(2)
    outcome = _await_download(ui, timeout=90)
    if frida:
        _stop_frida(frida)
    log = sess.read_log()
    rsp = _extract_rsp(log)
    sess.save("rsp.json", rsp)
    return {"op": "download", "smdp": smdp, "matchingId": mid,
            "outcome": outcome, "rsp": rsp}


def _await_download(ui: Ui, timeout=90) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        if ui.present(rid="download_progress_item_error_title"):
            x = ui.find(rid="download_progress_item_error_title")
            xml = ui.dump()
            m = re.search(r'download_progress_item_error_title"[^>]*text="([^"]*)"', xml) or \
                re.search(r'text="([^"]*)"[^>]*download_progress_item_error_title', xml)
            return {"status": "error", "message": m.group(1) if m else "error"}
        # back on the profile list = success
        if ui.present(rid="profile_sequence_number") and not ui.present(text_contains="Downloading"):
            return {"status": "installed"}
        time.sleep(2)
    return {"status": "timeout"}


def _profile_menu_action(serial: str, sess: Session, index0: int, action: str) -> dict:
    ui = Ui(serial)
    _open_main(ui)
    xml = ui.dump()
    menus = re.findall(r'resource-id="[^"]*profile_menu"[^>]*bounds="(\[[^"]+\])"'
                       r'|bounds="(\[[^"]+\])"[^>]*resource-id="[^"]*profile_menu"', xml)
    coords = []
    for a, b in menus:
        coords.append(ui._bounds_center(a or b))
    if index0 >= len(coords):
        raise SystemExit(f"profile #{index0+1} not found ({len(coords)} profiles)")
    ui.tap(*coords[index0]); time.sleep(1)
    ui.tap_el(text=action, timeout=6); time.sleep(1)
    # confirm dialog for Delete
    if action == "Delete":
        for t in ("Delete", "OK", "Confirm", "CONTINUE"):
            c = ui.find(text=t, clickable=True)
            if c:
                ui.tap(*c); break
    end = time.time() + 30
    while time.time() < end:
        log = sess.read_log()
        if re.search(r"enable_profile|disable_profile|delete_profile|Enabled|Disabled|"
                     r"SIM_STATE|ABSENT|LOADED", log):
            break
        time.sleep(1.5)
    time.sleep(3)
    return {"action": action, "index": index0 + 1}


def op_enable(serial, sess, args):
    return {"op": "enable", **_profile_menu_action(serial, sess, int(args.target) - 1, "Enable")}


def op_disable(serial, sess, args):
    return {"op": "disable", **_profile_menu_action(serial, sess, int(args.target) - 1, "Disable")}


def op_delete(serial, sess, args):
    return {"op": "delete", **_profile_menu_action(serial, sess, int(args.target) - 1, "Delete")}


# ------------------------------ frida RSP hook ------------------------------

def _attach_frida(serial: str, sess: Session):
    adb(serial, "shell", "su", "-c",
        "pgrep -f frida-server >/dev/null || (nohup /data/local/tmp/frida-server >/dev/null 2>&1 &)", check=False)
    time.sleep(1)
    out = open(sess.dir / "frida.txt", "w")
    p = subprocess.Popen(
        f"tail -f /dev/null | frida -U -n {PKG} -l {REPO}/tools/frida/google_lpa_rsp.js "
        f"--runtime=v8 -q", shell=True, stdout=out, stderr=subprocess.STDOUT)
    time.sleep(4)
    return p


def _stop_frida(p):
    p.terminate()
    subprocess.run("pkill -f 'frida -U'", shell=True)


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


# ------------------------------ compound ops ------------------------------

def op_cycle(serial: str, sess: Session, args) -> dict:
    """download -> (record) -> delete, repeated N times, each fully logged."""
    results = []
    for i in range(1, args.times + 1):
        dl_sess = Session(serial, f"cycle{i}-download")
        dl_sess.start_logging()
        try:
            dl = op_download(serial, dl_sess, argparse.Namespace(
                code=args.code, capture_rsp=args.capture_rsp))
        finally:
            dl_sess.stop_logging()
        results.append({"iteration": i, "download": dl})
        if dl["outcome"].get("status") == "installed":
            # delete the newest profile (last index)
            lst = op_list(serial, sess, None)
            del_sess = Session(serial, f"cycle{i}-delete")
            del_sess.start_logging()
            try:
                d = op_delete(serial, del_sess, argparse.Namespace(target=str(lst["count"])))
            finally:
                del_sess.stop_logging()
            results[-1]["delete"] = d
    return {"op": "cycle", "times": args.times, "iterations": results}


OPS = {
    "list": op_list, "eid": op_eid, "info": op_info,
    "download": op_download, "enable": op_enable, "disable": op_disable,
    "delete": op_delete, "cycle": op_cycle,
}


def main():
    ap = argparse.ArgumentParser(prog="esimctl", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-s", "--serial", help="adb serial (auto-detect if omitted)")
    ap.add_argument("--backend", choices=["lpac", "fw"], default="lpac")
    sub = ap.add_subparsers(dest="op", required=True)
    sub.add_parser("list"); sub.add_parser("eid"); sub.add_parser("info")
    d = sub.add_parser("download"); d.add_argument("code")
    d.add_argument("--capture-rsp", action="store_true", default=True)
    for name in ("enable", "disable", "delete"):
        p = sub.add_parser(name); p.add_argument("target", help="profile index (#N)")
    c = sub.add_parser("cycle")
    c.add_argument("--code", required=True); c.add_argument("--times", type=int, default=3)
    c.add_argument("--capture-rsp", action="store_true", default=True)
    args = ap.parse_args()

    serial = args.serial or detect_serial()
    if args.backend == "fw":
        raise SystemExit(
            "backend 'fw' (framework EuiccManager) is not built yet — see "
            "tools/esimctl/README.md 'Roadmap'. Use the default 'lpac' backend.")
    subprocess.run(["bash", str(REPO / "tools/keep_phone_awake.sh")],
                   capture_output=True)  # ensure awake/unlocked
    sess = Session(serial, args.op)
    sess.start_logging()
    try:
        result = OPS[args.op](serial, sess, args)
    except (UiError, RuntimeError) as e:
        sess.stop_logging()
        print(json.dumps({"op": args.op, "error": str(e),
                          "log_dir": str(sess.dir)}, indent=2))
        sys.exit(1)
    finally:
        sess.stop_logging()
    result["log_dir"] = str(sess.dir)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
