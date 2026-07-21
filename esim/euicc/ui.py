from __future__ import annotations
import argparse
import os
import re
import subprocess
import time

from esim.euicc.const import MAIN, PKG, REPO
from esim.euicc.session import Session, adb, _extract_rsp, _isub
from esim.euicc.uidriver import Ui


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


def _attach_frida(serial: str, sess: Session):
    r = subprocess.run(["bash", str(REPO / "scripts/frida/ensure_frida.sh")],
                       capture_output=True, text=True, env={**os.environ, "ESIMCTL_SERIAL": serial})
    if r.returncode != 0:
        raise RuntimeError(f"frida-server not ready: {r.stderr.strip()}")
    out = open(sess.dir / "frida.txt", "w")
    p = subprocess.Popen(
        f"tail -f /dev/null | frida -U -n {PKG} -l {REPO}/scripts/frida/google_lpa_rsp.js "
        f"--runtime=v8 -q", shell=True, stdout=out, stderr=subprocess.STDOUT)
    time.sleep(4)
    return p


def _stop_frida(p):
    p.terminate()
    subprocess.run("pkill -f 'frida -U'", shell=True)


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
