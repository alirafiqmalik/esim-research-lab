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
import shlex
import subprocess
import sys
import time
import uuid
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
    r = subprocess.run(["bash", str(REPO / "tools/frida/ensure_frida.sh")],
                       capture_output=True, text=True, env={**os.environ, "ESIMCTL_SERIAL": serial})
    if r.returncode != 0:
        raise RuntimeError(f"frida-server not ready: {r.stderr.strip()}")
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


# ------------------------------ activity backend (robust, non-UI) ------------------------------
# Drives OpenEUICC's headless EsimCtlActivity, which runs the op via its own
# lpac stack (backend=lpac, full plaintext in this op's logcat) or the framework
# EuiccManager (backend=fw), and logs `ESIMCTL: <id> RESULT <json>`.
ACT = f"{PKG}/.ui.EsimCtlActivity"


def _activity(serial: str, sess: Session, op: str, backend: str = "lpac",
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


def _resolve_iccid(serial: str, sess: Session, target: str, backend: str) -> str:
    if len(target) >= 15 and target.isdigit():
        return target  # already an iccid
    idx = int(target) - 1
    profs = _activity(serial, sess, "list", backend)["profiles"]
    if idx < 0 or idx >= len(profs):
        raise SystemExit(f"profile #{target} not found ({len(profs)} profiles)")
    return profs[idx]["iccid"]


def av_read(op):
    def fn(serial, sess, args):
        return _activity(serial, sess, op, args.backend)
    return fn


def av_download(serial, sess, args):
    # a server-side failure (e.g. matchingId refused / pool empty) is still a
    # valid captured outcome — don't raise; the RSP plaintext is the deliverable.
    r = _activity(serial, sess, "download", args.backend, timeout=180,
                  raise_on_fail=False, code=args.code)
    r["rsp"] = _extract_rsp(sess.read_log())
    sess.save("rsp.json", r["rsp"])
    return r


def av_switch(enable):
    def fn(serial, sess, args):
        iccid = _resolve_iccid(serial, sess, args.target, args.backend)
        return _activity(serial, sess, "enable" if enable else "disable",
                         args.backend, iccid=iccid)
    return fn


def protected_iccids() -> set[str]:
    vals = set(filter(None, os.environ.get("ESIMCTL_PROTECTED_ICCIDS", "").split(",")))
    f = REPO / "tools/esimctl/protected_iccids.txt"
    if f.exists():
        vals |= {ln.strip() for ln in f.read_text().splitlines()
                 if ln.strip() and not ln.startswith("#")}
    return vals


def av_delete(serial, sess, args):
    return _do_delete(serial, sess, args.backend, args.target,
                      yes=args.yes, dry_run=getattr(args, "dry_run", False),
                      force=args.force)


def _do_delete(serial, sess, backend, target, *, yes, dry_run, force):
    profs = _activity(serial, sess, "list", backend)["profiles"]
    idx = int(target) - 1
    if idx < 0 or idx >= len(profs):
        raise SystemExit(f"profile #{target} not found ({len(profs)} profiles)")
    iccid = profs[idx]["iccid"]
    base = {"op": "delete", "iccid": iccid, "index": idx + 1}
    if dry_run:
        return {**base, "ok": True, "dry_run": True}
    if not force and iccid in protected_iccids():
        return {**base, "ok": False, "error": f"protected iccid {iccid}; use --force"}
    if not force and len(profs) <= 1:
        return {**base, "ok": False, "error": "refusing to delete the last profile; use --force"}
    if not yes:
        return {**base, "ok": False, "error": "refusing to delete without --yes (or --dry-run)"}
    r = _activity(serial, sess, "delete", backend, iccid=iccid)
    return {**base, **r}


def av_cycle(serial, sess, args):
    iterations = []
    for i in range(1, args.times + 1):
        it_sess = Session(serial, f"cycle{i}-download")
        it_sess.start_logging()
        try:
            before = {p["iccid"] for p in _activity(serial, it_sess, "list", args.backend)["profiles"]}
            dl = _activity(serial, it_sess, "download", args.backend, timeout=180,
                           raise_on_fail=False, code=args.code)
            dl["rsp"] = _extract_rsp(it_sess.read_log())
            after = _activity(serial, it_sess, "list", args.backend)["profiles"]
        finally:
            it_sess.stop_logging()
        rec = {"iteration": i, "download": dl, "log_dir": str(it_sess.dir)}
        new = [p["iccid"] for p in after if p["iccid"] not in before]
        if new:
            d_sess = Session(serial, f"cycle{i}-delete")
            d_sess.start_logging()
            try:
                rec["delete"] = _activity(serial, d_sess, "delete", args.backend, iccid=new[0])
            finally:
                d_sess.stop_logging()
            rec["deleted_iccid"] = new[0]
        iterations.append(rec)
    return {"op": "cycle", "times": args.times, "ok": True, "iterations": iterations}


# ------------------------------ raw ES10x / unbridged-command ops ------------------------------

def _tlv_walk(b: bytes) -> list[tuple[int, bytes]]:
    """Minimal BER-TLV walker (single level). Handles 2-byte tags and long-form length."""
    out, i = [], 0
    while i < len(b):
        tag = b[i]; i += 1
        if tag & 0x1F == 0x1F:  # multi-byte tag
            tag = (tag << 8) | b[i]; i += 1
        length = b[i]; i += 1
        if length & 0x80:
            n = length & 0x7F
            length = int.from_bytes(b[i:i + n], "big"); i += n
        out.append((tag, b[i:i + length])); i += length
    return out


def _parse_addresses(resp_hex: str) -> dict:
    """Decode a GetEuiccConfiguredAddresses (BF3C) response into the two addresses."""
    try:
        b = bytes.fromhex(resp_hex)
    except ValueError:
        return {}
    if len(b) >= 2 and b[-2:] == b"\x90\x00":
        b = b[:-2]
    res: dict = {}
    for tag, val in _tlv_walk(b):
        if tag == 0xBF3C:
            for t2, v2 in _tlv_walk(val):
                if t2 == 0x80:
                    res["defaultDpAddress"] = v2.decode("utf-8", "replace")
                elif t2 == 0x81:
                    res["rootDsAddress"] = v2.decode("utf-8", "replace")
    return res


def av_apdu(serial, sess, args):
    return _activity(serial, sess, "apdu", args.backend, hex=args.hex.replace(" ", ""))


def av_get_addresses(serial, sess, args):
    r = _activity(serial, sess, "get-addresses", args.backend)
    r.update(_parse_addresses(r.get("resp", "")))
    return r


def av_get_rat(serial, sess, args):
    return _activity(serial, sess, "get-rat", args.backend)


def av_set_dp_address(serial, sess, args):
    return _activity(serial, sess, "set-dp-address", args.backend, address=args.address)


def av_nickname(serial, sess, args):
    iccid = _resolve_iccid(serial, sess, args.target, args.backend)
    return _activity(serial, sess, "nickname", args.backend, iccid=iccid, name=args.name)


def av_remove_notification(serial, sess, args):
    return _activity(serial, sess, "remove-notification", args.backend, seq=args.seq)


def av_handle_notification(serial, sess, args):
    return _activity(serial, sess, "handle-notification", args.backend, seq=args.seq)


def av_reset(serial, sess, args):
    # euiccMemoryReset erases every profile; require the explicit opt-in flag.
    if not args.confirm:
        return {"op": "reset", "ok": False,
                "error": "euiccMemoryReset wipes ALL profiles; pass --confirm-wipe to run"}
    return _activity(serial, sess, "reset", args.backend, confirm="RESET")


def av_info1(serial, sess, args):
    return _activity(serial, sess, "info1", args.backend)


def av_challenge(serial, sess, args):
    return _activity(serial, sess, "challenge", args.backend)


def av_retrieve_notification(serial, sess, args):
    return _activity(serial, sess, "retrieve-notification", args.backend, seq=args.seq)


def av_apdu_aid(serial, sess, args):
    return _activity(serial, sess, "apdu-aid", args.backend,
                     aid=args.aid.replace(" ", ""), hex=args.hex.replace(" ", ""))


def av_select_aid(serial, sess, args):
    return _activity(serial, sess, "select-aid", args.backend, aid=args.aid.replace(" ", ""))


def av_card(method_op):
    # second command path: framework IEuiccCardController via EuiccCardManager reflection.
    # raise_on_fail=False: a non-OK resultCode (e.g. -3 RESULT_CALLER_NOT_ALLOWED) is an
    # informative outcome about the authz gate, not a harness error.
    def fn(serial, sess, args):
        return _activity(serial, sess, method_op, backend="card", raise_on_fail=False)
    return fn


ACT_OPS = {
    "list": av_read("list"), "eid": av_read("eid"), "info": av_read("info"),
    "notifications": av_read("notifications"), "download": av_download,
    "enable": av_switch(True), "disable": av_switch(False), "delete": av_delete,
    "cycle": av_cycle,
    "apdu": av_apdu, "get-addresses": av_get_addresses, "get-rat": av_get_rat,
    "set-dp-address": av_set_dp_address, "nickname": av_nickname,
    "remove-notification": av_remove_notification,
    "handle-notification": av_handle_notification, "reset": av_reset,
    "info1": av_info1, "challenge": av_challenge,
    "retrieve-notification": av_retrieve_notification,
    "apdu-aid": av_apdu_aid, "select-aid": av_select_aid,
    # card backend: framework IEuiccCardController (2nd command path via the OEM card)
    "card-challenge": av_card("challenge"), "card-info1": av_card("info1"),
    "card-info2": av_card("info2"), "card-smds": av_card("smds"),
    "card-default-smdp": av_card("default-smdp"), "card-rat": av_card("rat"),
    "card-profiles": av_card("profiles"),
}


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
    ap.add_argument("--backend", choices=["lpac", "fw", "ui"], default="lpac",
                    help="lpac=OpenEUICC activity (full plaintext); fw=framework "
                         "EuiccManager; ui=OpenEUICC UI automation (fallback)")
    sub = ap.add_subparsers(dest="op", required=True)
    sub.add_parser("list"); sub.add_parser("eid"); sub.add_parser("info")
    sub.add_parser("notifications")
    d = sub.add_parser("download"); d.add_argument("code")
    d.add_argument("--capture-rsp", action="store_true", default=True)
    for name in ("enable", "disable"):
        p = sub.add_parser(name); p.add_argument("target", help="profile index (#N)")
    dele = sub.add_parser("delete"); dele.add_argument("target")
    dele.add_argument("--yes", action="store_true", help="required to actually delete")
    dele.add_argument("--dry-run", action="store_true")
    dele.add_argument("--force", action="store_true",
                      help="override last-profile and protected-ICCID guards")
    c = sub.add_parser("cycle")
    c.add_argument("--code", required=True); c.add_argument("--times", type=int, default=3)
    c.add_argument("--capture-rsp", action="store_true", default=True)
    # unbridged commands: raw ES10x over ISD-R + LPA methods not on the basic path
    ap_apdu = sub.add_parser("apdu"); ap_apdu.add_argument("hex", help="raw APDU hex → ISD-R")
    sub.add_parser("get-addresses")   # ES10a GetEuiccConfiguredAddresses
    sub.add_parser("get-rat")         # ES10b GetRAT
    sdp = sub.add_parser("set-dp-address"); sdp.add_argument("address", help="default SM-DP+ FQDN")
    nk = sub.add_parser("nickname")
    nk.add_argument("target", help="profile index (#N) or iccid"); nk.add_argument("name")
    rn = sub.add_parser("remove-notification"); rn.add_argument("seq", help="notification seq number")
    hn = sub.add_parser("handle-notification"); hn.add_argument("seq", help="notification seq number")
    rs = sub.add_parser("reset")
    rs.add_argument("--confirm-wipe", dest="confirm", action="store_true",
                    help="required: euiccMemoryReset erases ALL profiles")
    sub.add_parser("info1")       # ES10b GetEUICCInfo1 (BF20)
    sub.add_parser("challenge")   # ES10b GetEUICCChallenge (BF2E)
    rnf = sub.add_parser("retrieve-notification"); rnf.add_argument("seq", help="notification seq")
    aa = sub.add_parser("apdu-aid")
    aa.add_argument("aid", help="applet AID (e.g. A00000015141434C00 for ARA-M)")
    aa.add_argument("hex", help="APDU hex to send on that channel")
    sa = sub.add_parser("select-aid"); sa.add_argument("aid", help="applet AID to SELECT (returns FCI)")
    for cop in ("card-challenge", "card-info1", "card-info2", "card-smds",
                "card-default-smdp", "card-rat", "card-profiles"):
        sub.add_parser(cop)  # framework IEuiccCardController path (independent of --backend)
    args = ap.parse_args()

    serial = args.serial or os.environ.get("ESIMCTL_SERIAL") or detect_serial()
    subprocess.run(["bash", str(REPO / "tools/keep_phone_awake.sh")],
                   capture_output=True)  # ensure awake/unlocked
    # ui backend = OpenEUICC UI automation; lpac/fw = headless EsimCtlActivity
    table = OPS if args.backend == "ui" else ACT_OPS
    if args.op not in table:
        raise SystemExit(f"op '{args.op}' not available on backend '{args.backend}'")
    sess = Session(serial, args.op)
    sess.start_logging()
    try:
        result = table[args.op](serial, sess, args)
    except (UiError, RuntimeError) as e:
        sess.stop_logging()
        print(json.dumps({"op": args.op, "error": str(e),
                          "log_dir": str(sess.dir)}, indent=2))
        sys.exit(1)
    finally:
        sess.stop_logging()
    result["log_dir"] = str(sess.dir)
    print(json.dumps(result, indent=2))
    if result.get("ok") is False:
        sys.exit(2)


if __name__ == "__main__":
    main()
