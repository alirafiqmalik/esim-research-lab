# Testbed fixes — implementation spec

Implement exactly this. No design decisions left open. Targets the issues in
`docs/testbed/testbed-evaluation.md`. Keep changes minimal; match the project code style
(Python 3.12+, type hints on public sigs, raise on error, `subprocess.run(...,
capture_output=True, text=True, timeout=30)` for adb, no `print()` in library code —
`esimctl.py`'s CLI `main`/ops may print JSON, that is the CLI boundary).

Repo root = `/home/ahm/Desktop/project/Research/exp/eSIM_phone_mitm` (`$REPO`).
OpenEUICC sibling clone = `$REPO/../OpenEUICC` (`$OPENEUICC_DIR`).

---

## Fix 5 (do first) — exit codes in `esimctl.py`

`main()` currently: catches `(UiError, RuntimeError)` → `sys.exit(1)`; on success prints
JSON and exits 0 even when `result["ok"] is False`. Change the success path:

```python
    result["log_dir"] = str(sess.dir)
    print(json.dumps(result, indent=2))
    if result.get("ok") is False:
        sys.exit(2)
```

Convention: **0** = ok, **2** = op ran but failed at the eSIM/RSP layer (`ok:false`),
**1** = harness/tool error (exception). `cycle` returns `ok:true` for the run itself, so
it stays exit 0 even when individual iterations fail — do NOT change that.

Acceptance: `esim euicc download 'LPA:1$rsp-eu.redteamobile.com$5901981126831169'; echo $?`
prints the RSP JSON then `2`. `esim euicc list; echo $?` → `0`.

---

## Fix 7 (minor) — serial resolution

`main()`: `serial = args.serial or os.environ.get("ESIMCTL_SERIAL") or detect_serial()`.
`import os` already present. In `scripts/setup/setup_capture_pixel7a.sh` and any other `.sh` that
hardcodes `SERIAL="${1:-35181JEHN08662}"`, replace the default with
`SERIAL="${1:-${ESIMCTL_SERIAL:-$(adb devices | awk '$2=="device"{print $1;exit}')}}"`.
`keep_phone_awake.sh` already auto-detects — leave it.

---

## Fix 3 — `delete` safety rails (`esimctl.py`)

New argparse for `delete` (and `enable`/`disable` keep just `target`):

```python
    dele = sub.add_parser("delete"); dele.add_argument("target")
    dele.add_argument("--yes", action="store_true", help="required to actually delete")
    dele.add_argument("--dry-run", action="store_true")
    dele.add_argument("--force", action="store_true",
                      help="override last-profile and protected-ICCID guards")
```

Protected ICCIDs come from: env `ESIMCTL_PROTECTED_ICCIDS` (comma-separated) UNION the
lines of `$REPO/testbed/protected_iccids.txt` if it exists (ignore blank/`#` lines).
Add a helper:

```python
def protected_iccids() -> set[str]:
    vals = set(filter(None, os.environ.get("ESIMCTL_PROTECTED_ICCIDS", "").split(",")))
    f = REPO / "testbed/protected_iccids.txt"
    if f.exists():
        vals |= {ln.strip() for ln in f.read_text().splitlines()
                 if ln.strip() and not ln.startswith("#")}
    return vals
```

Rewrite `av_delete` (activity backend). It must accept an internal `force`/`yes` bypass so
`cycle` can call it:

```python
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
```

Note `_activity(..., "delete")` already returns `ok`. A refusal returns `ok:false` → exit 2
(via Fix 5). Keep `op_delete` (ui backend) unchanged for now but route its `delete` through
the same guards is out of scope — the `ui` backend is fallback; only guard the activity path.

Acceptance:
- `esim euicc delete 2` (no flags) → `ok:false`, "refusing … without --yes", exit 2, profile intact.
- `esim euicc delete 2 --dry-run` → `ok:true, dry_run:true`, exit 0, profile intact.
- With `ESIMCTL_PROTECTED_ICCIDS=<iccid1>`, `esim euicc delete 1 --yes` → refused unless `--force`.
- `esim euicc delete <last> --yes` when only 1 profile → refused unless `--force`.

---

## Fix 4 — `cycle` on the activity backend (`esimctl.py`)

Add `av_cycle` and register it in `ACT_OPS`. It downloads, identifies the newly-installed
profile by ICCID diff, deletes exactly that one (bypassing the `--yes` prompt since the
profile is freshly created by this cycle), N times. If the code does not install (e.g. pool
empty / matchingId refused), it records the RSP and does NOT delete.

```python
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
```

Register: add `"cycle": av_cycle` to `ACT_OPS`. Delete the old `op_cycle`/`OPS["cycle"]`
only if `op_cycle` is not otherwise referenced; simplest: leave `op_cycle` for `--backend ui`
but ensure `ACT_OPS["cycle"]` exists so the default backend works.

Acceptance:
- `esim euicc cycle --code 'LPA:1$rsp.truphone.com$QRF-SPEEDTEST' --times 1` installs then deletes
  that profile, `list` count returns to the starting value, exit 0.
- `esim euicc cycle --code 'LPA:1$rsp-eu.redteamobile.com$5901981126831169' --times 1` records rsp,
  no delete, count unchanged, exit 0.
- `esim euicc --backend lpac cycle ...` no longer errors "not available".

---

## Fix 2 — Frida robustness

Root cause of `unable to connect to remote frida-server: closed`: more than one
frida-server instance (started repeatedly via `pgrep || nohup` without ever killing stale
ones) and/or the client connecting before the daemon is ready. The proven-good recipe from
this session: kill ALL, start exactly ONE with an explicit listen addr, then health-check
`frida-ps -U` with retries.

Create `scripts/frida/ensure_frida.sh` (executable):

```bash
#!/usr/bin/env bash
# Guarantee exactly one healthy frida-server on the device. Idempotent.
set -u
serial="${ESIMCTL_SERIAL:-$(adb devices | awk '$2=="device"{print $1;exit}')}"
[ -z "$serial" ] && { echo "ensure_frida: no device" >&2; exit 1; }
ADB="adb -s $serial"
$ADB shell "su -c 'ls /data/local/tmp/frida-server' " >/dev/null 2>&1 || {
  echo "ensure_frida: /data/local/tmp/frida-server missing (run setup_testbed.sh)" >&2; exit 1; }
$ADB shell "su -c 'pkill -9 -f frida-server'" 2>/dev/null; sleep 1
$ADB shell "su -c 'nohup /data/local/tmp/frida-server -l 127.0.0.1:27042 >/data/local/tmp/frida.log 2>&1 &'"
for _ in $(seq 1 12); do
  if frida-ps -U >/dev/null 2>&1; then echo "ensure_frida: ready"; exit 0; fi
  sleep 1
done
echo "ensure_frida: frida-server not healthy after 12s" >&2
$ADB shell "su -c 'cat /data/local/tmp/frida.log'" >&2 2>/dev/null
exit 1
```

Change `esimctl.py` `_attach_frida` to call it instead of the inline pgrep-or-nohup:

```python
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
```

Acceptance: `bash scripts/frida/ensure_frida.sh` twice in a row both print "ready" and
`frida-ps -U | grep -c frida-server` shows exactly 1 server process implied (one healthy
connection). Note: the activity `lpac` backend does NOT need frida (it logs via OpenEUICC
verbose); frida is only for the stock-LPA capture path.

---

## Fix 6 — regression smoke test `testbed/selftest.sh` (executable)

Non-destructive. Fails loudly. Catches the `cycle`-broke-silently class.

```bash
#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
E="python3 -m esim.cli euicc"
fail=0
check() { # name  expected_exit  jq_filter  (reads stdin json)
  local name="$1" exp="$2" filt="$3"; shift 3
  if [ "$rc" = "$exp" ] && echo "$out" | python3 -c "import json,sys;d=json.load(sys.stdin);sys.exit(0 if ($filt) else 1)" 2>/dev/null; then
    echo "PASS $name"; else echo "FAIL $name (rc=$rc exp=$exp)"; fail=1; fi
}
out=$($E list); rc=$?;  check "list"  0 "d['count']>=0 and 'profiles' in d"
out=$($E eid);  rc=$?;  check "eid"   0 "len(d.get('eid') or '')==32"
out=$($E info); rc=$?;  check "info"  0 "d.get('ok') is True"
out=$($E download 'LPA:1$rsp-eu.redteamobile.com$5901981126831169'); rc=$?
check "download-capture" 2 "d.get('ok') is False and len(d.get('rsp',[]))>=2"
# cycle must be wired on the default backend (was the silent regression)
$E --help >/dev/null 2>&1
out=$($E cycle --code 'LPA:1$rsp-eu.redteamobile.com$5901981126831169' --times 1); rc=$?
check "cycle-default-backend" 0 "d.get('op')=='cycle' and len(d['iterations'])==1"
[ $fail -eq 0 ] && echo "ALL PASS" || echo "SOME FAILED"
exit $fail
```

Acceptance: `bash testbed/selftest.sh` prints per-test PASS and `ALL PASS`, exit 0,
without changing the profile count (RedteaGO never installs).

---

## Fix 1 — reproducibility: `scripts/setup/setup_testbed.sh` (executable)

Strategy: **build from source** (do NOT vendor a 16 MB debug APK into git). One command,
idempotent, clear preconditions. It clones/patches/builds/installs OpenEUICC, provisions
frida-server, sets datastore prefs, then runs the smoke test.

Env (all optional, with defaults):
`ESIMCTL_SERIAL` (else first adb device), `OPENEUICC_DIR` (`$REPO/../OpenEUICC`),
`ANDROID_SDK` (`${ANDROID_HOME:-/opt/android-sdk}`), `JAVA_HOME` (`/usr/lib/jvm/java-21-openjdk`),
`FRIDA_VERSION` (else `frida --version`).

Ordered steps, each fails with a one-line reason:

0. **Preconditions.** `command -v adb git python3 dot keytool` all present; host `frida
   --version` works; device present + in `device` state; device UNLOCKED
   (`dumpsys window | grep -q 'isKeyguardShowing=false'`, else print "unlock the phone" and
   exit); `java -version 2>&1 | grep -q 'version "21'`; `$ANDROID_SDK/ndk/26.1.10909125` exists;
   `$ANDROID_SDK/platforms/android-35` exists. For the two SDK components, if missing, attempt
   `"$ANDROID_SDK"/cmdline-tools/latest/bin/sdkmanager 'ndk;26.1.10909125' 'platforms;android-35'`
   and re-check; else fail with the sdkmanager command to run.
1. **Clone/refresh OpenEUICC.** If `$OPENEUICC_DIR` absent:
   `git clone https://gitea.angry.im/PeterCxy/OpenEUICC.git "$OPENEUICC_DIR"` then
   `git -C "$OPENEUICC_DIR" submodule update --init --recursive`. If present, skip (idempotent).
2. **Apply the EsimCtlActivity patch.**
   `cp "$REPO/testbed/openeuicc/EsimCtlActivity.kt" "$OPENEUICC_DIR/app/src/main/java/im/angry/openeuicc/ui/EsimCtlActivity.kt"`.
   Manifest: if `grep -q EsimCtlActivity "$OPENEUICC_DIR/app/src/main/AndroidManifest.xml"` is
   false, insert before the line containing `AppLocalesMetadataHolderService`:
   ```xml
           <activity
               android:name=".ui.EsimCtlActivity"
               android:exported="true"
               android:excludeFromRecents="true"
               android:noHistory="true" />
   ```
   Use a bash here-doc + `sed`/`awk` insert; idempotent via the grep guard.
3. **Keystore + local.properties.** If `$OPENEUICC_DIR/keystore.properties` absent: run
   `keytool -genkeypair -v -keystore "$OPENEUICC_DIR/openeuicc-research.jks" -storepass research123
   -keypass research123 -alias oeuicc -keyalg RSA -keysize 2048 -validity 10000
   -dname "CN=OpenEUICC Research, O=research, C=US"` and write `keystore.properties` with
   storePassword/keyPassword/keyAlias=oeuicc, unprivKeyPassword=research123, unprivKeyAlias=oeuicc,
   storeFile=<abs path to jks>. If `local.properties` absent, write `sdk.dir=$ANDROID_SDK`.
   (These files are already `.gitignore`d in the clone; the passwords are throwaway research
   values — acceptable, matching existing `esimresearch` precedent.)
4. **Build.** `cd "$OPENEUICC_DIR" && JAVA_HOME="$JAVA_HOME" ./gradlew --no-daemon
   :app:assembleDebugMagiskModuleDir`. Verify
   `$OPENEUICC_DIR/app/build/magisk/debug/system/system_ext/priv-app/OpenEUICC/OpenEUICC.apk` exists.
5. **Install privileged.** If `adb -s $SERIAL shell pm list packages im.angry.openeuicc` is empty
   OR `pm dump im.angry.openeuicc | grep -q PRIVILEGED` is false → first-time privileged install:
   `cd "$OPENEUICC_DIR/app/build/magisk/debug" && zip -r -q /tmp/oeuicc-mod.zip .`,
   `adb push /tmp/oeuicc-mod.zip /data/local/tmp/`, `adb shell su -c 'magisk --install-module
   /data/local/tmp/oeuicc-mod.zip'`, then print "REBOOT REQUIRED — rerun setup after reboot"
   and `adb reboot`; exit 0 (the rerun continues idempotently). Else (already privileged) update
   in place: `adb -s $SERIAL install -r <APK>`. Verify PRIVILEGED after.
6. **frida-server.** Determine `$FRIDA_VERSION`. If device `/data/local/tmp/frida-server`
   absent: download `https://github.com/frida/frida/releases/download/$FRIDA_VERSION/frida-server-$FRIDA_VERSION-android-arm64.xz`
   to `$REPO/tmp/`, `unxz`, `adb push` to `/data/local/tmp/frida-server`, `adb shell su -c 'chmod
   755 /data/local/tmp/frida-server'`. Then `bash "$REPO/scripts/frida/ensure_frida.sh"`.
7. **Datastore prefs.** Generate the Preferences-DataStore protobuf enabling
   `developer_options_enabled` and `verbose_logging` (both bool true). Embed the generator inline
   (the same encoding used earlier — repeated field 1 map entries: key string field 1, value
   message field 2 with bool field 1). Push to
   `/data/data/im.angry.openeuicc/files/datastore/prefs.preferences_pb`, `chown` to the app uid
   (`adb shell su -c 'stat -c %u /data/data/im.angry.openeuicc'`), `restorecon`, then
   `adb shell su -c 'am force-stop im.angry.openeuicc'`. Idempotent (overwrite).
8. **Keep awake + verify.** `bash "$REPO/tools/keep_phone_awake.sh"`; then
   `bash "$REPO/testbed/selftest.sh"`. Print "TESTBED READY" on success.

Idempotency: safe to re-run; each step guards on "already done". Precondition failures print
the exact command to fix and exit non-zero.

Acceptance: on a machine with the toolchain + an unlocked rooted Pixel, `bash
scripts/setup/setup_testbed.sh` ends in `ALL PASS` / `TESTBED READY` (allowing one reboot cycle on a
first-time privileged install). Re-running is a no-op that still ends green.

Also: add a short "Reproduce from scratch: `bash scripts/setup/setup_testbed.sh`" section to
`esim/euicc/README.md` and create `testbed/protected_iccids.txt` with a header
comment and one example commented line (so the file exists and is documented, protecting
nothing by default).

---

## Order of edits for the mechanical agent

1. `esimctl.py`: Fix 5 (exit codes), Fix 7 (serial env), Fix 3 (`_do_delete`/`av_delete` +
   `protected_iccids` + argparse), Fix 4 (`av_cycle` + `ACT_OPS["cycle"]`).
2. `scripts/frida/ensure_frida.sh` + wire `_attach_frida` (Fix 2).
3. `testbed/protected_iccids.txt`, `testbed/selftest.sh` (Fix 6).
4. `scripts/setup/setup_testbed.sh` (Fix 1) + README note + serial default in `setup_capture_pixel7a.sh` (Fix 7).
5. Verify: `bash testbed/selftest.sh` green; `esim euicc delete 2` refused; `esim euicc delete 2
   --dry-run` ok; `esim euicc cycle --code 'LPA:1$rsp-eu.redteamobile.com$5901981126831169' --times 1`
   ok with count unchanged; `bash scripts/frida/ensure_frida.sh` green twice. Leave the eUICC at its
   original 2 disabled profiles.
