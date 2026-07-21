# Codebase Reorganization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reorganize the repo into one Python package (`esim/`), one `scripts/` tree, a `testbed/` for device-side artifacts, and a 3-bucket `docs/` — in three verified, revertible phases.

**Architecture:** Phase 1 moves files and fixes paths only (no behavior change). Phase 2 sorts docs (no code). Phase 3 folds `esimctl.py` into `esim/euicc/` as split modules exposed via `esim euicc <op>`, and the GTP scripts into `esim/gtp/`. Each phase ends in one commit behind a green gate.

**Tech Stack:** Python 3.12 (click + argparse), pytest + pytest-mock, bash, adb. Device: rooted Pixel 7a, OpenEUICC, on-device selftest.

**Standing constraints:** No eUICC writes. Preserve profile #1 (BetterRoaming). No factory reset. git-commit skill on every commit — no AI attribution. Repo-relative path edits only; never touch on-device `/data/local/tmp` or OS `/tmp` strings. Design source: `docs/superpowers/specs/2026-07-20-codebase-reorg-design.md`.

**Command form in scripts:** after Phase 3, scripts and selftest invoke the tool as `python3 -m esim.cli euicc <op>` (module form — no dependence on an installed console script or PATH).

---

## Phase 1 — Structure (mechanical moves, no behavior change)

### Task 1.1: Move shell scripts into `scripts/`

**Files:**
- Move: `tools/setup_testbed.sh`, `tools/setup_capture_pixel7a.sh`, `tools/setup_hotspot.sh` → `scripts/setup/`
- Move: `tools/install_mitm_cert.sh`, `tools/install_system_cert.sh`, `tools/keep_phone_awake.sh` → `scripts/device/`
- Move: `tools/frida/` → `scripts/frida/`, `tools/msd/` → `scripts/msd/`
- Move: `tools/README-keepawake.md` → `scripts/device/README.md`

- [ ] **Step 1: Create dirs and git mv**

```bash
cd /home/ahm/Desktop/project/Research/exp/eSIM_phone_mitm
mkdir -p scripts/setup scripts/device
git mv tools/setup_testbed.sh tools/setup_capture_pixel7a.sh tools/setup_hotspot.sh scripts/setup/
git mv tools/install_mitm_cert.sh tools/install_system_cert.sh tools/keep_phone_awake.sh scripts/device/
git mv tools/frida scripts/frida
git mv tools/msd scripts/msd
git mv tools/README-keepawake.md scripts/device/README.md
```

- [ ] **Step 2: Fix internal script path references**

In `scripts/setup/setup_capture_pixel7a.sh` line ~23: `tools/install_system_cert.sh` → `scripts/device/install_system_cert.sh`.

In `scripts/setup/setup_testbed.sh`: any reference to `tools/frida`, `tools/msd`, `tools/keep_phone_awake.sh` → `scripts/frida`, `scripts/msd`, `scripts/device/keep_phone_awake.sh`. (Grep it: `grep -n "tools/" scripts/setup/setup_testbed.sh`.)

- [ ] **Step 3: Grep for any remaining `tools/` refs to moved scripts**

Run: `grep -rn "tools/setup_\|tools/frida\|tools/msd\|tools/install_\|tools/keep_phone_awake\|tools/README-keepawake" --include=*.sh --include=*.py --include=*.md .`
Expected: only hits inside `docs/` (fixed in Phase 2) and this plan. Fix any in code/scripts now.

- [ ] **Step 4: Commit** — deferred to Task 1.6 (whole phase is one commit).

---

### Task 1.2: Move device-side artifacts into `testbed/`

**Files:**
- Move: `tools/esimctl/openeuicc/` → `testbed/openeuicc/`
- Move: `tools/esimctl/protected_iccids.txt` → `testbed/protected_iccids.txt`
- Move: `tools/esimctl/selftest.sh` → `testbed/selftest.sh`
- Modify: `tools/esimctl/esimctl.py` (path constants — file itself stays put until Phase 3)

- [ ] **Step 1: git mv**

```bash
mkdir -p testbed
git mv tools/esimctl/openeuicc testbed/openeuicc
git mv tools/esimctl/protected_iccids.txt testbed/protected_iccids.txt
git mv tools/esimctl/selftest.sh testbed/selftest.sh
```

- [ ] **Step 2: Update `esimctl.py` path constants**

`tools/esimctl/esimctl.py` line 366, change:
```python
    f = REPO / "tools/esimctl/protected_iccids.txt"
```
to:
```python
    f = REPO / "testbed/protected_iccids.txt"
```

- [ ] **Step 3: Update `setup_testbed.sh` openeuicc/patch path**

In `scripts/setup/setup_testbed.sh`, change references from `tools/esimctl/openeuicc/` (e.g. `es11-discovery.patch`, `EsimCtlActivity.kt`) to `testbed/openeuicc/`. Grep: `grep -n "tools/esimctl/openeuicc\|openeuicc/es11-discovery" scripts/setup/setup_testbed.sh`.

- [ ] **Step 4: Update `selftest.sh` self-reference to esimctl**

`testbed/selftest.sh` invokes esimctl by path. Leave it pointing at `tools/esimctl/esimctl.py` for now (the file moves in Phase 3; selftest is re-pointed to `python3 -m esim.cli euicc` in Task 3.7). Only fix the path if it referenced `selftest.sh`'s own old location.

---

### Task 1.3: Move the TS.48 asset bundle into `assets/`

**Files:**
- Move: `gsma-esim-test-profile/TS.48-v7.1-Generic-eUICC-Test-Profile-for-DevicTesting/` → `assets/ts48-test-profile/`
- Move: `gsma-esim-test-profile/TS.48-v7.1-Generic-eUICC-Test-Profile-for-DevicTesting.zip` → `assets/ts48-test-profile.zip`
- Modify: `gsma-esim-test-profile/src/analyze_gtp.py` (PKG constant), `gsma-esim-test-profile/src/try_direct_load.py` (DER constant)

- [ ] **Step 1: git mv**

```bash
mkdir -p assets
git mv "gsma-esim-test-profile/TS.48-v7.1-Generic-eUICC-Test-Profile-for-DevicTesting" assets/ts48-test-profile
git mv "gsma-esim-test-profile/TS.48-v7.1-Generic-eUICC-Test-Profile-for-DevicTesting.zip" assets/ts48-test-profile.zip
```

- [ ] **Step 2: Repoint `analyze_gtp.py` PKG**

`gsma-esim-test-profile/src/analyze_gtp.py` lines 17-18, change:
```python
PKG = Path(__file__).resolve().parents[1] / \
    "TS.48-v7.1-Generic-eUICC-Test-Profile-for-DevicTesting" / "TS48 V7.0 eSIM_GTP_SAIP2.3"
```
to (note: `parents[2]` — src is now two levels under repo, asset is under repo/assets):
```python
PKG = Path(__file__).resolve().parents[2] / \
    "assets" / "ts48-test-profile" / "TS48 V7.0 eSIM_GTP_SAIP2.3"
```

- [ ] **Step 3: Repoint `try_direct_load.py` DER**

`gsma-esim-test-profile/src/try_direct_load.py` lines 23-24, change the base from `SRC.parents[1] / "TS.48-...DevicTesting"` to `SRC.parents[2] / "assets" / "ts48-test-profile"`:
```python
DER = SRC.parents[2] / "assets" / "ts48-test-profile" / \
    "TS48 V7.0 eSIM_GTP_SAIP2.3" / "TS48 V7.0 eSIM_GTP_SAIP2.3_NoBERTLV.rename2der"
```

- [ ] **Step 4: Verify GTP analyzer still runs**

Run: `python3 gsma-esim-test-profile/src/analyze_gtp.py`
Expected: same 4-variant summary as before (PE counts, ICCID `89000123456789012341`, RFM present/absent lines).

---

### Task 1.4: Rename runtime dirs `sessions/`→`.sessions/`, `tmp/`→`.temp/`

**Files:**
- Rename: `sessions/` → `.sessions/`, `tmp/` → `.temp/`
- Modify: `.gitignore`, `tools/esimctl/esimctl.py`, `esim/capture.py`, `esim/cli.py`, `scripts/setup/setup_testbed.sh`, `scripts/setup/setup_capture_pixel7a.sh`

- [ ] **Step 1: Rename the dirs** (they are gitignored, so plain `mv`)

```bash
[ -d sessions ] && mv sessions .sessions || mkdir -p .sessions
[ -d tmp ] && mv tmp .temp || mkdir -p .temp
```

- [ ] **Step 2: Update `.gitignore`**

Change lines `sessions/` → `.sessions/` and `tmp/` → `.temp/`.

- [ ] **Step 3: Update repo-relative code paths**

`tools/esimctl/esimctl.py` line 40:
```python
SESS_BASE = REPO / ".sessions" / "esimctl"
```
Line 15 docstring: `sessions/esimctl/<ts>-<op>/` → `.sessions/esimctl/<ts>-<op>/`.

`esim/capture.py` line 30:
```python
                 sessions_root: Path | str = ".sessions"):
```
`esim/cli.py` line 128:
```python
@click.option("--out", "out_dir", default=".sessions", show_default=True, type=click.Path())
```

- [ ] **Step 4: Update repo-relative shell paths (NOT `/data/local/tmp` or `/tmp`)**

`scripts/setup/setup_testbed.sh`: `$REPO/tmp` → `$REPO/.temp` (all 4 occurrences: mkdir, frida-server.xz download, unxz, push) and `repo / "tmp"` → `repo / ".temp"` (the embedded python at line ~172). Leave `/tmp/oeuicc-mod.zip` and `$MANIFEST.tmp` unchanged.

`scripts/setup/setup_capture_pixel7a.sh`: `SESS="sessions/..."` → `SESS=".sessions/..."`; `./tmp/${HASH}.0` → `./.temp/${HASH}.0` (both occurrences). Leave the absolute `/tmp/${HASH}.0` fallback unchanged.

- [ ] **Step 5: Verify no stray repo-relative refs remain**

Run: `grep -rn '"sessions"\|"tmp"\|/sessions/\|\./tmp/\|\$REPO/tmp\b\|REPO / "tmp"' --include=*.py --include=*.sh esim scripts tools`
Expected: no matches. (Hits inside docs are handled in Phase 2.)

---

### Task 1.5: Relocate root clutter

**Files:**
- Move: `status-update.md`, `temp_report.md` → `docs/archive/`

- [ ] **Step 1: git mv**

```bash
mkdir -p docs/archive
git mv status-update.md docs/archive/status-update.md
git mv temp_report.md docs/archive/temp_report.md
```

---

### Task 1.6: Phase 1 gate + commit

- [ ] **Step 1: Run unit tests**

Run: `python3 -m pytest -q`
Expected: PASS (existing `tests/test_capture.py`, `test_analysis.py`, `test_cli.py`, `test_device.py`). The `.sessions` default change must not break `test_capture.py` — if a test asserts the literal `"sessions"` default, update the assertion to `".sessions"`.

- [ ] **Step 2: Run on-device selftest**

Run: `bash testbed/selftest.sh`
Expected: all checks PASS (esimctl still at `tools/esimctl/esimctl.py`; only its data paths moved).

- [ ] **Step 3: Commit via git-commit skill**

```
refactor(layout): move scripts, testbed artifacts, assets; dot-prefix runtime dirs
```

---

## Phase 2 — Docs consolidation (zero code risk)

### Task 2.1: Create buckets and move docs

**Files:**
- Move the 20 loose `docs/*.md` into `docs/reference/`, `docs/research/`, `docs/testbed/`

- [ ] **Step 1: Make dirs + git mv**

```bash
cd /home/ahm/Desktop/project/Research/exp/eSIM_phone_mitm
mkdir -p docs/reference docs/research docs/testbed
git mv docs/euicc-api-capability-map.md docs/eUICC-IO-mapping.md docs/default-lpa-exploration.md docs/reference/
git mv docs/research-aosp-esim-testing.md docs/research-gsma-ts48-test-profile.md \
       docs/research-other-free-esim-codes.md docs/research-repeatable-esim-issuer.md \
       docs/research-researcher-esim-access.md docs/research-rsp-testing-certificate-workarounds.md \
       docs/rsp-dataset-analysis.md docs/google-lpa-vs-openeuicc-rsp.md docs/research/
git mv docs/testbed-evaluation.md docs/testbed-fixes-spec.md \
       docs/testbed-test-report-2026-07-16.md docs/betterroaming-activation.md docs/testbed/
```
(`docs/euicc-api-reference.md` and `docs/euicc-api-frontier.md` stay in place — merged in Task 2.2.)

---

### Task 2.2: Merge reference + frontier into `docs/reference/euicc-api.md`

**Files:**
- Create: `docs/reference/euicc-api.md`
- Delete: `docs/euicc-api-reference.md`, `docs/euicc-api-frontier.md`

- [ ] **Step 1: Read both source docs fully.**

- [ ] **Step 2: Compose `docs/reference/euicc-api.md`**

Structure: keep `euicc-api-reference.md`'s command → APDU tag → exposure matrix as the spine. Fold `euicc-api-frontier.md`'s "frontier ops" in as rows/section marked **implemented** (they now ship in esimctl). Where the two overlap, keep one authoritative statement. Preserve every unique fact (AIDs, tags, the CI-trust boundary, the card-path authz gate). Apply `markdown-style.md` (no banned phrases, active voice, short sentences).

- [ ] **Step 3: Remove the two source files**

```bash
git rm docs/euicc-api-reference.md docs/euicc-api-frontier.md
```

---

### Task 2.3: Write the docs index

**Files:**
- Create: `docs/README.md`

- [ ] **Step 1: Write `docs/README.md`**

One page: the three buckets (`reference/`, `research/`, `testbed/`) with a one-line description of each file, the canonical entry point (`reference/euicc-api.md`), pointers to `docs/diagrams/`, `docs/msd/`, `docs/superpowers/`, `docs/archive/`, and a pointer to the fast-index note `.claude/notes/euicc-api-surface.md`. Follow `markdown-style.md`.

---

### Task 2.4: Fix internal doc links (paths only, not command syntax)

**Files:**
- Modify: any `docs/**/*.md` and `.claude/notes/*.md` that link to a moved doc or moved code path

- [ ] **Step 1: Find broken doc-to-doc and doc-to-path links**

Run: `grep -rn "euicc-api-reference\|euicc-api-frontier\|docs/testbed-\|docs/research-\|tools/esimctl/openeuicc\|tools/frida\|tools/msd\|gsma-esim-test-profile/TS" docs .claude/notes`

- [ ] **Step 2: Rewrite each hit** to the new location (e.g. `docs/reference/euicc-api.md`, `testbed/openeuicc/`, `scripts/frida/`, `assets/ts48-test-profile/`). **Do not** change `esimctl …`/`tools/esimctl/esimctl.py` command syntax yet — that flips to `esim euicc …` in Phase 3 so docs never reference a command that does not exist.

---

### Task 2.5: Phase 2 gate + commit

- [ ] **Step 1: Verify no dangling internal links**

Run: `grep -rn "euicc-api-reference\|euicc-api-frontier" docs .claude` → expect no matches (all point at `euicc-api.md`). Spot-check `docs/README.md` renders (each linked file exists): `for f in $(grep -oE '\(([a-zA-Z0-9_./-]+\.md)\)' docs/README.md | tr -d '()'); do test -e "docs/$f" || echo "MISSING: $f"; done`

- [ ] **Step 2: Commit via git-commit skill**

```
docs: sort into reference/research/testbed, merge api reference+frontier, add index
```

---

## Phase 3 — Code unification (riskiest, last)

Split `tools/esimctl/esimctl.py` into `esim/euicc/`. Functions move **verbatim** unless a step says otherwise; only imports and a few constants change. Function → module assignment:

| Module | Functions / symbols from esimctl.py |
|---|---|
| `esim/euicc/const.py` | `PKG`, `MAIN`, `ACT`, `VERBOSE_TAGS`, `REPO`, `SESS_BASE` |
| `esim/euicc/session.py` | `adb`, `detect_serial`, `Session`, `_isub`, `_extract_rsp` |
| `esim/euicc/tlv.py` | `_tlv_walk`, `_parse_addresses` |
| `esim/euicc/backends.py` | `_activity`, `_resolve_iccid` |
| `esim/euicc/uidriver.py` | (moved verbatim from `tools/esimctl/uidriver.py`) |
| `esim/euicc/ui.py` | `op_list`, `op_eid`, `op_info`, `op_download`, `op_enable/disable/delete`, `op_cycle`, `_launch_openeuicc_and_read`, `_open_main`, `_profile_iccids`, `_resolve_profile_index`, `_await_download`, `_profile_menu_action`, `_attach_frida`, `_stop_frida`, `OPS` |
| `esim/euicc/cli.py` | `av_*` handlers, `protected_iccids`, `_do_delete`, `ACT_OPS`, `main(argv)` |

`REPO` becomes `Path(__file__).resolve().parents[2]` in `const.py` (esim/euicc/const.py → repo root). Frida/keep-awake script paths inside functions update to `scripts/`.

### Task 3.1: Scaffold package + const + session

**Files:**
- Create: `esim/euicc/__init__.py`, `esim/euicc/const.py`, `esim/euicc/session.py`
- Test: `tests/euicc/__init__.py`, `tests/euicc/test_session.py`

- [ ] **Step 1: Write the failing test**

`tests/euicc/test_session.py`:
```python
from unittest.mock import patch
from esim.euicc.session import detect_serial, _extract_rsp


def test_detect_serial_picks_first_device():
    out = "List of devices attached\nABC123\tdevice\nXYZ\toffline\n"
    with patch("esim.euicc.session.subprocess.run") as m:
        m.return_value.stdout = out
        assert detect_serial() == "ABC123"


def test_extract_rsp_parses_url_and_bodies():
    log = ("transmit(url = https://smdp.example/gsma/rsp2/es9plus)\n"
           "HTTP tx = {\"a\":1}\nHTTP response body = {\"b\":2}\n")
    msgs = _extract_rsp(log)
    kinds = [m["kind"] for m in msgs]
    assert kinds == ["request-url", "request-body", "response-body"]
```

- [ ] **Step 2: Run it, expect ImportError/fail**

Run: `python3 -m pytest tests/euicc/test_session.py -q`
Expected: FAIL (module not found).

- [ ] **Step 3: Create `esim/euicc/__init__.py`** (empty) and **`esim/euicc/const.py`**:

```python
from __future__ import annotations
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PKG = "im.angry.openeuicc"
MAIN = f"{PKG}/.ui.PrivilegedMainActivity"
ACT = f"{PKG}/.ui.EsimCtlActivity"
SESS_BASE = REPO / ".sessions" / "esimctl"
VERBOSE_TAGS = ("HttpInterfaceImpl", "OmapiApduInterface", "TelephonyManagerApduInterface",
                "EuiccChannelManager", "app_process64", "EuiccGoogle")
```

- [ ] **Step 4: Create `esim/euicc/session.py`** — move `adb`, `detect_serial`, `Session`, `_isub`, `_extract_rsp` verbatim from esimctl.py; header imports:

```python
from __future__ import annotations
import json
import re
import subprocess
import time
from datetime import datetime

from esim.euicc.const import SESS_BASE
```
(`Session.__init__` uses `SESS_BASE` — now imported. `_extract_rsp` and `_isub` move here unchanged.)

- [ ] **Step 5: Run test, expect PASS**

Run: `python3 -m pytest tests/euicc/test_session.py -q` → PASS.

- [ ] **Step 6: Commit** — deferred to Task 3.9 (phase is one commit). Do NOT delete esimctl.py yet.

---

### Task 3.2: `tlv.py` (pure) + test

**Files:**
- Create: `esim/euicc/tlv.py`
- Test: `tests/euicc/test_tlv.py`

- [ ] **Step 1: Write the failing test**

`tests/euicc/test_tlv.py`:
```python
from esim.euicc.tlv import _tlv_walk, _parse_addresses


def test_tlv_walk_multibyte_tag_and_len():
    # BF3C (2-byte tag), length 0x03, value 80 01 41
    tags = _tlv_walk(bytes.fromhex("BF3C03800141"))
    assert tags == [(0xBF3C, bytes.fromhex("800141"))]


def test_parse_addresses_extracts_dp_and_ds():
    # BF3C { 80 "smdp.example"  81 "ds.example" } + 9000 trailer
    dp = b"smdp.example"; ds = b"ds.example"
    inner = bytes([0x80, len(dp)]) + dp + bytes([0x81, len(ds)]) + ds
    outer = bytes([0xBF, 0x3C, len(inner)]) + inner + b"\x90\x00"
    res = _parse_addresses(outer.hex())
    assert res == {"defaultDpAddress": "smdp.example", "rootDsAddress": "ds.example"}
```

- [ ] **Step 2: Run, expect fail.** Run: `python3 -m pytest tests/euicc/test_tlv.py -q` → FAIL (no module).

- [ ] **Step 3: Create `esim/euicc/tlv.py`** — move `_tlv_walk`, `_parse_addresses` verbatim. No imports needed beyond `from __future__ import annotations`.

- [ ] **Step 4: Run, expect PASS.** Run: `python3 -m pytest tests/euicc/test_tlv.py -q` → PASS.

---

### Task 3.3: `backends.py` + test

**Files:**
- Create: `esim/euicc/backends.py`
- Test: `tests/euicc/test_backends.py`

- [ ] **Step 1: Write the failing test**

`tests/euicc/test_backends.py`:
```python
from unittest.mock import MagicMock, patch
from esim.euicc.backends import _activity


def test_activity_parses_result_line():
    sess = MagicMock()
    sess.read_log.return_value = 'foo\nESIMCTL: ab12cd34 RESULT {"ok": true, "eid": "X"}\n'
    with patch("esim.euicc.backends.adb"), \
         patch("esim.euicc.backends.uuid.uuid4") as u:
        u.return_value.hex = "ab12cd34ffff"
        r = _activity("SER", sess, "eid", "lpac", timeout=2)
    assert r == {"ok": True, "eid": "X"}
```

- [ ] **Step 2: Run, expect fail.**

- [ ] **Step 3: Create `esim/euicc/backends.py`** — move `_activity`, `_resolve_iccid` verbatim; header:
```python
from __future__ import annotations
import json
import re
import shlex
import time
import uuid

from esim.euicc.const import ACT
from esim.euicc.session import adb
```
(`_resolve_iccid` calls `_activity` — same module, fine.)

- [ ] **Step 4: Run, expect PASS.**

---

### Task 3.4: `uidriver.py` + `ui.py` (UI backend, first-class)

**Files:**
- Move: `tools/esimctl/uidriver.py` → `esim/euicc/uidriver.py`
- Create: `esim/euicc/ui.py`

- [ ] **Step 1: git mv the driver**

```bash
git mv tools/esimctl/uidriver.py esim/euicc/uidriver.py
```

- [ ] **Step 2: Create `esim/euicc/ui.py`** — move all `op_*` funcs + helpers + `OPS` verbatim; header:
```python
from __future__ import annotations
import argparse
import os
import re
import subprocess
import time

from esim.euicc.const import MAIN, PKG, REPO
from esim.euicc.session import Session, adb, _extract_rsp, _isub
from esim.euicc.uidriver import Ui, UiError
```
Then fix two script paths inside the moved code:
- `_attach_frida`: `REPO / "tools/frida/ensure_frida.sh"` → `REPO / "scripts/frida/ensure_frida.sh"`; `{REPO}/tools/frida/google_lpa_rsp.js` → `{REPO}/scripts/frida/google_lpa_rsp.js`.

- [ ] **Step 3: Smoke-import**

Run: `python3 -c "import esim.euicc.ui"`
Expected: no error.

---

### Task 3.5: `cli.py` (argparse dispatch) + test

**Files:**
- Create: `esim/euicc/cli.py`
- Test: `tests/euicc/test_cli.py`

- [ ] **Step 1: Write the failing test**

`tests/euicc/test_cli.py`:
```python
from unittest.mock import patch
from esim.euicc.cli import build_parser, ACT_OPS


def test_parser_accepts_apdu_op():
    args = build_parser().parse_args(["apdu", "BF3E00"])
    assert args.op == "apdu" and args.hex == "BF3E00"


def test_act_ops_has_expected_keys():
    for k in ("list", "eid", "apdu", "get-addresses", "discovery", "card-info2"):
        assert k in ACT_OPS
```

- [ ] **Step 2: Run, expect fail.**

- [ ] **Step 3: Create `esim/euicc/cli.py`**

Move verbatim: `av_read`, `av_download`, `av_switch`, `protected_iccids`, `av_delete`, `_do_delete`, `av_cycle`, `av_apdu`, `av_get_addresses`, `av_set_dp_address`, `av_nickname`, `av_remove_notification`, `av_handle_notification`, `av_reset`, `av_discovery`, `av_authenticate`, `av_retrieve_notification`, `av_apdu_aid`, `av_select_aid`, `av_card`, `ACT_OPS`.

Header:
```python
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
```
Fix in `protected_iccids`: `REPO / "tools/esimctl/protected_iccids.txt"` → `REPO / "testbed/protected_iccids.txt"`.

**Refactor `main()` into `build_parser()` + `main(argv=None)`** so it is testable and callable from click. Replace the top of the old `main()` (the `argparse.ArgumentParser(...)` through `args = ap.parse_args()`) with a `build_parser()` that returns the parser; `main` becomes:
```python
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="esim euicc", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    # ... (all the add_argument / add_subparsers lines, verbatim from old main) ...
    return ap


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    serial = args.serial or os.environ.get("ESIMCTL_SERIAL") or detect_serial()
    subprocess.run(["bash", str(REPO / "scripts/device/keep_phone_awake.sh")],
                   capture_output=True)
    table = OPS if args.backend == "ui" else ACT_OPS
    if args.op not in table:
        raise SystemExit(f"op '{args.op}' not available on backend '{args.backend}'")
    sess = Session(serial, args.op)
    sess.start_logging()
    try:
        result = table[args.op](serial, sess, args)
    except (UiError, RuntimeError) as e:
        sess.stop_logging()
        print(json.dumps({"op": args.op, "error": str(e), "log_dir": str(sess.dir)}, indent=2))
        sys.exit(1)
    finally:
        sess.stop_logging()
    result["log_dir"] = str(sess.dir)
    print(json.dumps(result, indent=2))
    if result.get("ok") is False:
        sys.exit(2)


if __name__ == "__main__":
    main()
```
Note the keep-awake path changed to `scripts/device/keep_phone_awake.sh`. Set the module docstring to esimctl.py's original docstring (lines 2-21) so `--help` is unchanged.

- [ ] **Step 4: Run test, expect PASS.** Run: `python3 -m pytest tests/euicc/test_cli.py -q` → PASS.

---

### Task 3.6: Move GTP scripts into `esim/gtp/` + tests

**Files:**
- Create: `esim/gtp/__init__.py`, `esim/gtp/analyze.py`, `esim/gtp/load_test.py`
- Test: `tests/gtp/__init__.py`, `tests/gtp/test_analyze.py`
- Remove: `gsma-esim-test-profile/src/` (after move)

- [ ] **Step 1: git mv + repoint asset path**

```bash
mkdir -p esim/gtp
git mv gsma-esim-test-profile/src/analyze_gtp.py esim/gtp/analyze.py
git mv gsma-esim-test-profile/src/try_direct_load.py esim/gtp/load_test.py
```
In `esim/gtp/analyze.py`, `PKG = Path(__file__).resolve().parents[2] / "assets" / ...` still holds (esim/gtp/analyze.py → parents[2] = repo). In `esim/gtp/load_test.py`, update `ESIMCTL` and `DER`:
```python
DER = SRC.parents[2] / "assets" / "ts48-test-profile" / \
    "TS48 V7.0 eSIM_GTP_SAIP2.3" / "TS48 V7.0 eSIM_GTP_SAIP2.3_NoBERTLV.rename2der"
```
and change the esimctl subprocess call to module form:
```python
def esimctl(*args: str) -> dict:
    r = subprocess.run(["python3", "-m", "esim.cli", "euicc", *args],
                       capture_output=True, text=True, timeout=90,
                       cwd=SRC.parents[2])
    ...
```

- [ ] **Step 2: Write the failing test**

`tests/gtp/test_analyze.py`:
```python
from esim.gtp.analyze import analyze_variant, VARIANTS


def test_variants_parse_and_report_iccid():
    s = analyze_variant(VARIANTS[0])
    assert s.iccid == "89000123456789012341"
    assert s.saip_version and s.der_bytes > 0
```

- [ ] **Step 3: Run, expect PASS** (asset present at new path). Run: `python3 -m pytest tests/gtp/test_analyze.py -q` → PASS. If FAIL on path, fix the `parents[]` depth.

- [ ] **Step 4: Move `PLAN.md` and drop the empty src dir**

```bash
git mv gsma-esim-test-profile/src/PLAN.md docs/testbed/ts48-gtp-plan.md
rmdir gsma-esim-test-profile/src 2>/dev/null || true
```
(If `gsma-esim-test-profile/` is now empty of tracked files, remove it too.)

---

### Task 3.7: Wire `euicc` + `gtp` into `esim/cli.py`; repoint callers

**Files:**
- Modify: `esim/cli.py`, `testbed/selftest.sh`, `scripts/setup/setup_testbed.sh`, docs command syntax

- [ ] **Step 1: Add the groups to `esim/cli.py`**

Append (imports at top: `from esim.euicc.cli import main as _euicc_main`; `from esim.gtp import analyze as _gtp_analyze, load_test as _gtp_load`):
```python
@main.command("euicc", context_settings=dict(ignore_unknown_options=True,
                                              allow_extra_args=True,
                                              help_option_names=[]))
@click.argument("op_args", nargs=-1, type=click.UNPROCESSED)
def euicc(op_args) -> None:
    """eUICC control (esimctl). Runs `<op> [args]` — e.g. `esim euicc list`."""
    _euicc_main(list(op_args))


@main.group("gtp")
def gtp() -> None:
    """GSMA TS.48 test-profile tools."""


@gtp.command("analyze")
def gtp_analyze() -> None:
    """Summarize the TS.48 GTP packages."""
    _gtp_analyze.main()


@gtp.command("load-test")
def gtp_load_test() -> None:
    """Attempt (and expect to fail) an out-of-session GTP load."""
    _gtp_load.main()
```
The `euicc` passthrough forwards all args/flags to the argparse parser, so `esim euicc download 'LPA:1$...'`, `esim euicc apdu BF3E00`, `esim euicc --backend fw eid`, and `esim euicc -h` all work (argparse renders help).

- [ ] **Step 2: Repoint `testbed/selftest.sh`**

Replace every `python3 tools/esimctl/esimctl.py` (or `$ESIMCTL`) invocation with `python3 -m esim.cli euicc`. If the script sets a variable, change it to `ESIMCTL="python3 -m esim.cli euicc"` and keep call sites.

- [ ] **Step 3: Repoint `setup_testbed.sh`** — any `tools/esimctl/esimctl.py` reference → `python3 -m esim.cli euicc` (or drop if only a comment).

- [ ] **Step 4: Flip doc command syntax**

Grep: `grep -rln "tools/esimctl/esimctl.py\|esimctl " docs .claude/notes`
In each, change `python3 tools/esimctl/esimctl.py <op>` and bare `esimctl <op>` → `esim euicc <op>`. Update `docs/reference/euicc-api.md`, `euicc-api-capability-map.md`, `eUICC-IO-mapping.md`, `default-lpa-exploration.md`, `docs/testbed/*`, `.claude/notes/euicc-api-surface.md`.

---

### Task 3.8: Remove old esimctl location

**Files:**
- Remove: `tools/esimctl/esimctl.py`, `tools/esimctl/README.md`, empty `tools/`

- [ ] **Step 1: Move the README, delete the old script**

```bash
git mv tools/esimctl/README.md esim/euicc/README.md   # if it documents the tool; else git rm
git rm tools/esimctl/esimctl.py
rmdir tools/esimctl tools 2>/dev/null || true
```
Update `esim/euicc/README.md` invocation examples to `esim euicc …` / `python3 -m esim.cli euicc …`.

- [ ] **Step 2: Final grep for dead references**

Run: `grep -rn "tools/esimctl" . --include=*.py --include=*.sh --include=*.md | grep -v docs/superpowers`
Expected: no matches.

---

### Task 3.9: Phase 3 gate + commit

- [ ] **Step 1: Full unit suite**

Run: `python3 -m pytest -q`
Expected: PASS — existing 4 files + `tests/euicc/*` + `tests/gtp/*`.

- [ ] **Step 2: CLI smoke (no device writes)**

Run: `python3 -m esim.cli euicc -h` (argparse help renders) and `python3 -m esim.cli gtp analyze` (4-variant summary).
Expected: both succeed.

- [ ] **Step 3: On-device selftest**

Run: `bash testbed/selftest.sh`
Expected: all checks PASS via the `esim euicc` path. Profile #1 (BetterRoaming) untouched; no writes.

- [ ] **Step 4: Commit via git-commit skill**

```
refactor(euicc): fold esimctl into esim.euicc package, expose as `esim euicc`
```

---

## Self-review notes

- **Spec coverage:** target layout (§ target), Phase 1/2/3 all present with gates; `testbed/` split (1.2), single doc merge (2.2), asset rename (1.3), UI backend first-class (3.4), `.sessions/.temp` renames (1.4) — all covered.
- **Type/name consistency:** module names match between the § table and Task 3.x headers; `build_parser`/`main(argv)` referenced consistently in Task 3.5 test and 3.7 wiring; `_extract_rsp` lives in `session.py` and is imported by both `ui.py` and `cli.py`.
- **Path depth:** `parents[2]` verified for `esim/euicc/const.py`, `esim/gtp/analyze.py`, `esim/gtp/load_test.py` (all two levels under repo root).
