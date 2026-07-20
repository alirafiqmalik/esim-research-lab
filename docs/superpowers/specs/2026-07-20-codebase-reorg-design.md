# Codebase Reorganization — Design

**Goal:** Reorganize the eSIM/eUICC research repo for navigability and long-term
management: one Python package, one scripts tree, device-side artifacts split
out, and the 20 loose docs sorted into a small canonical set.

**Strategy:** Three sequential phases (Structure → Docs → Code). Each phase is a
single verified, revertible commit. The live testbed stays green between phases.

**Constraints (standing):** No eUICC writes. Preserve profile #1 (BetterRoaming).
No factory reset. git-commit skill on every commit, no AI attribution. Do not
break `setup_testbed.sh` or the selftest without updating callers in the same commit.

---

## Target layout

```
esim/                      # THE Python package — all Python code
  cli.py                   # `esim` root (click); registers capture/analysis/euicc/gtp
  capture.py analysis.py device.py     # capture toolchain (logic unchanged)
  euicc/                   # was tools/esimctl/esimctl.py, split by responsibility
    session.py             #   adb / Session / serial detection
    tlv.py                 #   BER-TLV walk + build, address parsing
    backends.py            #   lpac / fw / card backend dispatch
    ui.py                  #   op_* UI-automation + uidriver (--backend ui, first-class)
    cli.py                 #   ACT_OPS registry, av_* handlers → `esim euicc <op>`
  gtp/                     # was gsma-esim-test-profile/src
    analyze.py             #   `esim gtp analyze`   (was analyze_gtp.py)
    load_test.py           #   `esim gtp load-test` (was try_direct_load.py)

tests/                     # mirrors esim/ — existing 4 files + new euicc/ and gtp/
scripts/
  setup/                   # setup_testbed, setup_capture_pixel7a, setup_hotspot
  device/                  # install_mitm_cert, install_system_cert, keep_phone_awake
  frida/                   # *.js + ensure_frida.sh
  msd/                     # rsp_to_msd.py + render/analyze + templates
testbed/
  openeuicc/               # EsimCtlActivity.kt snapshot, es11-discovery.patch, README
  protected_iccids.txt
  selftest.sh
assets/
  ts48-test-profile/       # TS.48 zip/docx/xlsx bundle (renamed from the long dir)
docs/
  README.md                # index (new)
  reference/  research/  testbed/  archive/
  diagrams/  msd/  superpowers/     # unchanged
.claude/  .sessions/  .temp/  pyproject.toml
```

`.sessions/` and `.temp/` replace `sessions/` and `tmp/` (gitignored runtime).

---

## Phase 1 — Structure (mechanical, no behavior change)

Moves via `git mv` to preserve history:

| From | To |
|---|---|
| `tools/esimctl/openeuicc/`, `protected_iccids.txt`, `selftest.sh` | `testbed/…` |
| `tools/setup_*.sh` | `scripts/setup/` |
| `tools/install_*_cert.sh`, `keep_phone_awake.sh` | `scripts/device/` |
| `tools/frida/`, `tools/msd/` | `scripts/frida/`, `scripts/msd/` |
| `gsma-esim-test-profile/TS.48…/` bundle | `assets/ts48-test-profile/` |
| `sessions/` → `.sessions/`, `tmp/` → `.temp/` | rename |
| `status-update.md`, `temp_report.md` | `docs/archive/` |

`tools/esimctl/{esimctl.py,uidriver.py,README.md}` stay in place this phase (moved
in Phase 3). `tools/README-keepawake.md` folds into `scripts/` README; `.gitkeep` dropped.

Caller / path edits in the same commit:
- `.gitignore`: `sessions/`→`.sessions/`, `tmp/`→`.temp/`
- `tools/esimctl/esimctl.py`: `SESS_BASE = REPO/".sessions"/"esimctl"`; `testbed/`
  paths for `protected_iccids.txt` and the openeuicc snapshot; docstring
- `esim/capture.py` + `esim/cli.py`: default output `"sessions"` → `".sessions"`
- `scripts/setup/setup_testbed.sh`: `$REPO/tmp`→`$REPO/.temp` (4 refs); patch/frida/msd paths
- `scripts/setup/setup_capture_pixel7a.sh`: `sessions/`→`.sessions/`; `./tmp/`→`./.temp/`;
  `tools/install_system_cert.sh` → `scripts/device/install_system_cert.sh`
- `testbed/selftest.sh`, `gsma…/try_direct_load.py`: reach `esimctl.py` at its Phase-1 location

On-device `/data/local/tmp` and OS `/tmp` paths are NOT touched — repo-relative only.

**Gate:** `pytest` green + `testbed/selftest.sh` green on device.

---

## Phase 2 — Docs consolidation (zero code risk)

- `docs/reference/`: `euicc-api.md` (**merge** of `euicc-api-reference.md` +
  `euicc-api-frontier.md` — frontier ops are shipped, fold in as implemented rows);
  `euicc-api-capability-map.md`, `eUICC-IO-mapping.md`, `default-lpa-exploration.md` kept as-is.
- `docs/research/`: six `research-*.md`, `rsp-dataset-analysis.md`, `google-lpa-vs-openeuicc-rsp.md`.
- `docs/testbed/`: `testbed-evaluation.md`, `testbed-fixes-spec.md`,
  `testbed-test-report-2026-07-16.md`, `betterroaming-activation.md`.
- `docs/README.md`: new index — bucket contents, canonical entry points, pointer to
  `.claude/notes/euicc-api-surface.md`.

Only one *merge* (reference + frontier); capability-map and IO-mapping stay separate
to avoid reintroducing recently-fixed staleness. Doc internal links/paths updated here;
command syntax (`esim euicc …`) updated in Phase 3 so nothing documents a
not-yet-existing command.

**Gate:** no broken internal links; index resolves.

---

## Phase 3 — Code unification (riskiest, last)

Split `tools/esimctl/esimctl.py` (660 lines) into `esim/euicc/`:

| Module | From esimctl.py |
|---|---|
| `session.py` | `adb`, `detect_serial`, `Session`, `_isub` |
| `tlv.py` | `_tlv_walk`, `_parse_addresses`, `der`/`derInt`, `storeData` |
| `backends.py` | `_activity`, backend dispatch (lpac/fw/card), `_resolve_iccid` |
| `ui.py` | `op_*` handlers + `uidriver.py` (first-class `--backend ui`) |
| `cli.py` | `ACT_OPS`, `av_*` handlers, click wiring → `esim euicc <op>` |

Wiring: `esim/cli.py` gains `euicc` and `gtp` groups; `pyproject.toml` keeps single
`esim = esim.cli:main`. `gsma-esim-test-profile/src/*` → `esim/gtp/`, TS.48 path →
`assets/ts48-test-profile/`.

Tests (mock `subprocess.run`, never real ADB):
- `tests/euicc/test_tlv.py` (pure), `test_session.py`, `test_backends.py`, `test_cli.py`
- `tests/gtp/test_analyze.py` (parses asset, asserts 4-variant summary)

Caller updates: `testbed/selftest.sh`, `esim/gtp/load_test.py`,
`scripts/setup/setup_testbed.sh`, all doc command syntax → `esim euicc …`.

**Gate:** `pytest` (existing + new) green + `testbed/selftest.sh` green on device +
manual `esim euicc list` / `esim gtp analyze` smoke run.

---

## Verification & rollback

Each phase is one commit behind its gate; any phase reverts with `git revert` without
touching the others. Safety invariants (no eUICC writes, profile #1 preserved, no
factory reset, git-commit skill) hold throughout.
