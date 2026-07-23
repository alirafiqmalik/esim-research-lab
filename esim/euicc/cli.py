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
.sessions/esimctl/<ts>-<op>/. Output is JSON on stdout; exit code 0 = ok.

Backends:
  lpac  (default) — drives our privileged OpenEUICC (full plaintext logging)
  fw              — Android framework EuiccManager via the euiccmgr helper
                    (see helper-app/; result codes only, RSP bodies opaque)
"""
from __future__ import annotations
import argparse
import json
import os
import subprocess
import sys

from esim.euicc.const import REPO
from esim.euicc.session import Session, detect_serial
from esim.euicc.backends import _activity, _resolve_iccid
from esim.euicc.tlv import _parse_addresses
from esim.euicc.session import _extract_rsp
from esim.euicc.ui import OPS
from esim.euicc.uidriver import UiError


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
    f = REPO / "testbed/protected_iccids.txt"
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


def av_apdu(serial, sess, args):
    return _activity(serial, sess, "apdu", args.backend, hex=args.hex.replace(" ", ""))


def av_seq(serial, sess, args):
    # Many APDUs on ONE ISD-R channel (state persists); a literal RESET token between
    # APDUs close+reopens the channel (re-SELECT ISD-R, transient state only). The list
    # is joined with commas for the activity extra — each APDU hex has no commas itself.
    tokens = [t.replace(" ", "") if t.upper() != "RESET" else "RESET" for t in args.apdus]
    return _activity(serial, sess, "seq", args.backend, apdus=",".join(tokens))


def av_get_addresses(serial, sess, args):
    r = _activity(serial, sess, "get-addresses", args.backend)
    r.update(_parse_addresses(r.get("resp", "")))
    return r


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


def av_discovery(serial, sess, args):
    # ES11 SM-DS discovery: real network round trip to the root SM-DS (production CI)
    return _activity(serial, sess, "discovery", args.backend, timeout=120,
                     raise_on_fail=False, smds=args.smds)


def av_authenticate(serial, sess, args):
    # standalone AuthenticateServer CI-trust probe; a rejection is a valid outcome
    return _activity(serial, sess, "authenticate", args.backend, timeout=120,
                     raise_on_fail=False, server=args.server)


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
    "apdu": av_apdu, "seq": av_seq,
    "get-addresses": av_get_addresses, "get-rat": av_read("get-rat"),
    "set-dp-address": av_set_dp_address, "nickname": av_nickname,
    "remove-notification": av_remove_notification,
    "handle-notification": av_handle_notification, "reset": av_reset,
    "info1": av_read("info1"), "challenge": av_read("challenge"), "discovery": av_discovery,
    "authenticate": av_authenticate,
    "retrieve-notification": av_retrieve_notification,
    "apdu-aid": av_apdu_aid, "select-aid": av_select_aid,
    # card backend: framework IEuiccCardController (2nd command path via the OEM card)
    "card-challenge": av_card("challenge"), "card-info1": av_card("info1"),
    "card-info2": av_card("info2"), "card-smds": av_card("smds"),
    "card-default-smdp": av_card("default-smdp"), "card-rat": av_card("rat"),
    "card-profiles": av_card("profiles"),
}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="esim euicc", description=__doc__,
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
    ap_seq = sub.add_parser("seq")    # many APDUs on ONE channel; RESET token close+reopens ISD-R
    ap_seq.add_argument("apdus", nargs="+",
                        help="APDU hex list on ONE ISD-R channel; a literal RESET close+reopens it")
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
    disc = sub.add_parser("discovery")  # ES11 SM-DS discovery
    disc.add_argument("--smds", default="lpa.ds.gsma.com", help="SM-DS domain (default root)")
    au = sub.add_parser("authenticate")  # standalone AuthenticateServer CI-trust probe
    au.add_argument("server", help="SM-DP+/SM-DS FQDN to run AuthenticateServer against")
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
    return ap


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    serial = args.serial or os.environ.get("ESIMCTL_SERIAL") or detect_serial()
    subprocess.run(["bash", str(REPO / "scripts/device/keep_phone_awake.sh")],
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
