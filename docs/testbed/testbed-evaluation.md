# eSIM RSP Testbed — Evaluation

Hands-on walkthrough of every capability by a researcher who wants to *use* this
testbed, judged against a professional RSP-testbed bar (reproducibility,
determinism, logging, error handling, safety, docs). Device `35181JEHN08662`,
unlocked. Artifacts under `sessions/`.

## Verdict

Usable and genuinely capable for RSP research **on this one already-provisioned
device**. The lpac/esimctl path is deterministic, well-logged, and captures full
ES9+ plaintext. It is **not yet reproducible or safe** enough for an
industry-grade testbed: the central dependency (the patched OpenEUICC) cannot be
rebuilt from this repo, destructive ops have no guard rails, and one advertised
op is broken on the default backend.

## Capability results

| # | Capability | Result | Evidence |
|---|-----------|--------|----------|
| 1 | keep-awake + SessionStart hook | **PASS** | `keep_phone_awake` → `Awake`, keyguard clear; hook present in `.claude/settings.json` |
| 2 | esimctl lpac: list/eid/info/notifications | **PASS** | exit 0, `ok:true`, each wrote `sessions/esimctl/<ts>-<op>/logcat.txt` |
| 2 | esimctl lpac: download (RedteaGO) | **PASS** | exit 0, `ok:false`, 6 RSP msgs, final `Failed 9.4/10.1` captured |
| 2 | esimctl lpac: enable 1 / disable 1 | **PASS** | operator→`BetterRoaming` then `ABSENT,NOT_READY`; reversible |
| 3 | destructive delete + restore cycle (#2) | **PASS** | delete #2 → count 1 → download `QRF-SPEEDTEST` (11-msg full flow incl. `getBoundProfilePackage`) → count 2; #1 untouched; delete notification `seq 14 … Delete` captured |
| 4 | esimctl fw backend (eid/info) | **PASS** | framework `EuiccManager` returns EID, `available:true` |
| 5 | esimctl ui backend (eid) | **PASS** | uiautomator fallback returns EID |
| 6 | Frida RSP hooks attach/capture | **FAIL (flaky)** | `frida-ps` sees procs, but attach+inject drops `frida-server: closed` — 2/2 tries, incl. after a clean `-l 127.0.0.1:27042` restart |
| 7 | MSD pipeline on fresh capture | **PASS** | `rsp_to_msd.py --check` parsed 4-step success flow; `render_msd.sh` → valid `sessions/esimctl-eval/restore-msd.{dot,svg,png}` |
| 8 | docs accuracy / reproducibility | **PARTIAL** | commands run as written, but the setup cannot be reproduced from this repo alone (see MAJOR-1) |

Final eUICC state verified: **2 profiles, both Disabled** (BetterRoaming #1,
Speedtest Travel #2). Restored.

## Issues (severity-ranked)

### MAJOR-1 — the testbed is not reproducible from the repo
The whole lpac path depends on a **patched, privileged OpenEUICC** build that is
not in this repo (`git ls-files | grep OpenEUICC/app` → 0). Rebuilding it needs a
separate clone, a generated keystore, the `EsimCtlActivity` patch, a Magisk
privileged install, `frida-server` provisioning, and the `verbose_logging`
DataStore pref — all scattered across `device-pixel7a.md`,
`testbed/openeuicc/README.md`, and `openeuicc-experiments.md`, and several
are documented as "already set." A new researcher with a fresh device + this repo
**cannot** stand it up.
*Fix:* a single `scripts/setup/setup_testbed.sh` that pins the OpenEUICC commit, applies
the patch, generates the keystore, builds, installs the module, pushes a
version-matched `frida-server`, and writes the `verbose_logging` pref.

### MAJOR-2 — `cycle` is broken on the default backend
`esimctl cycle` advertises ✓ for lpac in the README, but `cycle` is only in
`OPS` (ui), not `ACT_OPS`. `esimctl cycle --code … --times 1` →
`op 'cycle' not available on backend 'lpac'`. The one compound op most useful for
repeat testing only runs on the fragile uiautomator backend.
*Fix:* add `av_cycle` (compose `av_download` + `av_delete`) to `ACT_OPS`.

### MAJOR-3 — no safety rails on destructive ops
`delete` (lpac/activity) deletes immediately: no confirm, no `--dry-run`, no
refusal to delete the last profile, no protected-ICCID list. This evaluation had
to hand-carry a "never touch #1" rule because the tool enforces nothing. A
fat-fingered index can wipe the eUICC.
*Fix:* require `--yes`, refuse when it would drop below 1 profile (or below a
configured floor), support a protected-ICCID list, add `--dry-run`.

### MAJOR-4 — Frida instrumentation unreliable
Attach+inject drops the frida-server connection (2/2, even after a clean
restart). The stock-LPA instrumentation capability is currently unusable. It is
*not* on the critical path (lpac gives plaintext without Frida), but it is
advertised as a capability.
*Fix:* wrap frida-server with restart-on-drop and pin a known-good server build;
or mark Frida as best-effort and lean on the lpac verbose path.

### MINOR-1 — `download` exit code hides failure
A server-side failure returns exit 0 with `ok:false`. `esimctl download … && next`
proceeds after a failed download. Scripts must parse JSON.
*Fix:* non-zero exit on `ok:false`, or a `--strict` flag.

### MINOR-2 — hardcoded device serial in examples/scripts
`esimctl` auto-detects the serial (good), but `keep_phone_awake` examples, the
Frida README, and the capture scripts hardcode `35181JEHN08662`. Breaks on a
second device.

### MINOR-3 — `frida-server` not provisioned by the repo
It lives in gitignored `tmp/`. The Frida README says "push frida-server" without
a fetch step or pinned URL/version beyond a comment.

### MINOR-4 — ui backend is non-deterministic by construction
uiautomator taps are inherently fragile (the parent session hit repeated tap
drift). Fine as a fallback; not CI-grade.

## Industry-readiness assessment

**Meets the bar:**
- Structured per-op logging + retained artifacts (`sessions/esimctl/<ts>-<op>/`) — good auditability.
- Deterministic core: the lpac backend drives eSIM ops via a headless activity, not screen-scraping.
- Composable: JSON out, so sequences are scriptable without an LLM.
- Full ES9+ plaintext capture, and an MSD pipeline that regenerates a diagram straight from a capture — real traceability.
- Free, reusable, production-CI activation codes enable repeat download/delete cycles at zero cost.

**Falls short:**
- **Reproducibility:** no one-command bootstrap; the key artifact (patched OpenEUICC) is out-of-tree (MAJOR-1).
- **Safety:** no guard rails on destructive ops (MAJOR-3).
- **Test/CI:** no automated regression suite; capabilities are verified by hand. `cycle` regressed on the default backend and nothing caught it (MAJOR-2).
- **Config:** device/codes hardcoded in examples rather than a config file.
- **Determinism gaps:** Frida flaky (MAJOR-4); ui backend non-deterministic (MINOR-4).

## Recommendations (priority order)

1. **`scripts/setup/setup_testbed.sh`** — reproducible bootstrap of the patched OpenEUICC + frida-server + verbose_logging from a fresh device. (Unblocks everyone else.)
2. **Wire `cycle` (and audit all ops) into `ACT_OPS`; add a smoke-test** script that runs list/eid/info/download/enable/disable/delete across backends and asserts JSON + exit codes.
3. **Add delete/erase safety rails** (`--yes`, last-profile floor, protected ICCIDs, `--dry-run`).
4. **Fix exit-code semantics** (non-zero on `ok:false` or `--strict`).
5. **Stabilize or de-scope Frida**; provision `frida-server` via the setup script with a pinned version.
6. **Add a config file** (serial, activation-code catalog, paths) and drop hardcoded serials.

---

## Re-evaluation (2026-07-15, after fix commit 9732a8b)

Re-ran the walkthrough. All three first-pass MAJOR issues are resolved and
verified on-device; `selftest.sh` is green; the eUICC stays at its original 2
disabled profiles.

**Verified fixed:**
- Reproducibility — `scripts/setup/setup_testbed.sh` runs end-to-end → `TESTBED READY`.
  (Verification also caught + fixed a malformed-XML bug in the fresh-clone
  manifest awk-patch: it anchored on the `AppLocalesMetadataHolderService`
  attribute line, injecting `<activity>` inside `<service>`. Now anchors on
  `</application>` + validates the XML.)
- `cycle` on the default backend — works, captures RSP, skips delete when nothing installs.
- `delete` safety rails — `--dry-run`, refuse-without-`--yes` (exit 2), protected-ICCID refuse, last-profile floor.
- Exit codes — op failure → 2, harness error → 1, ok → 0.
- Frida — single health-checked instance via `ensure_frida.sh`.

**New issue found + fixed this pass:**
- **MAJOR — `fw` (framework EuiccManager) action ops broken on Android 14+.**
  `EuiccManager` requires a `FLAG_MUTABLE` PendingIntent, but an *implicit*
  mutable PendingIntent is disallowed on U+ (`IllegalArgumentException:
  Targeting U+ ... disallows ... FLAG_MUTABLE`). `fw download`/`delete`/`switch`
  threw; only the synchronous `fw eid`/`info` worked, which is why the first
  eval (testing only `eid`/`info`) missed it. Fix: make the intent explicit via
  `setPackage`. Also mapped `fw` `ok`/exit-codes to the framework `resultCode`
  (0 = OK) for parity with lpac. Added `fw-eid` + `fw-download` to `selftest.sh`.

**Grade movement:** the reproducibility, safety, and cross-backend-consistency
blockers are closed; the testbed sets up from one command and a 7-check smoke
test guards regressions. Remaining minors (non-blocking, documented): the `ui`
fallback backend's results carry no `ok` field; the from-scratch setup path
still needs one privileged-install reboot.
