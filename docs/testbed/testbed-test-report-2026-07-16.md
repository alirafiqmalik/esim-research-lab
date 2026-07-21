# Testbed test report — 2026-07-16

Full end-to-end regression of the esimctl eUICC control pipeline on the rooted
Pixel 7a (lynx, serial 35181JEHN08662, Android 17, Magisk root, privileged
OpenEUICC build). Every op driven live against the embedded eUICC on slot 0/port 0.

**Overall: PASS.** selftest 11/11. Every op verified. eUICC left clean.

## Setup + regression

| Check | Command | Result | Evidence |
|---|---|:--:|---|
| Idempotent setup | `bash scripts/setup/setup_testbed.sh` | PASS | reached `TESTBED READY`, update-in-place, no reboot |
| Regression suite | `bash testbed/selftest.sh` | PASS | 11/11 `ALL PASS` |

selftest checks: list, eid, info, download-capture, cycle-default-backend,
fw-eid, fw-download, apdu-geteid, get-addresses, get-rat, reset-guarded.

## Per-op (lpac backend)

| Capability | Command | Result | Evidence |
|---|---|:--:|---|
| List profiles | `list` | PASS | ok:true, count 2 |
| EID | `eid` | PASS | ok:true, 32-char eid |
| Info (euiccInfo2) | `info` | PASS | ok:true, 32-char eid |
| Notifications | `notifications` | PASS | ok:true |
| ES10a get addresses | `get-addresses` | PASS | rootDs `lpa.ds.gsma.com`, defaultDp empty |
| ES10b GetRAT | `get-rat` | PASS | resp `BF4319…` |
| Raw ES10x APDU | `apdu 81E2910006BF3E035C015A` | PASS | resp carries `BF3E125A10…` (GetEID) |
| ES10a set default SM-DP+ | `set-dp-address testdp.example.com` | PASS | resp `BF3F038001009000` (result 0) |
| — verify set | `get-addresses` | PASS | resp `BF3C25 8012<testdp.example.com> 810F<lpa.ds.gsma.com>`, defaultDp=`testdp.example.com` |
| — clear + verify | `set-dp-address ""` → `get-addresses` | PASS | resp `BF3F038001009000`; defaultDp back to empty |
| ES10c set nickname | `nickname 1 REGTEST` | PASS | ok:true, iccid …257715, nickname REGTEST |
| — verify + restore | `list` → `nickname 1 ""` | PASS | nick1=REGTEST, then restored to `""` |
| ES10b remove notification (wiring) | `remove-notification 999999` | PASS | ok:true, removed:false (no real change) |
| ES9+ handle notification (wiring) | `handle-notification 999999` | PASS | ok:true, handled:false (no real change) |
| eUICCMemoryReset guard | `reset` (no `--confirm-wipe`) | PASS | ok:false, error demands `--confirm-wipe`; profiles stay 2 |
| Download + RSP capture | `download 'LPA:1$rsp-eu.redteamobile.com$5901981126831169'` | PASS | ok:false (server rejects) with 6 RSP messages captured (3 req/resp pairs) |

## Per-op (framework backend)

| Capability | Command | Result | Evidence |
|---|---|:--:|---|
| Framework EID | `--backend fw eid` | PASS | ok:true, 32-char eid |
| Framework info | `--backend fw info` | PASS | ok:true, 32-char eid, available:true |

## One observation (not a defect)

First `set-dp-address` pass read back `null` on the immediate verify. A clean
retry read back the value correctly (`BF3C25 8012<testdp.example.com>…`). Cause:
concurrent ISD-R access from a second process reflecting/reusing the same open
logical channel handle mid-operation. The ops are correct; concurrent eUICC
access from two drivers at once can interleave a read. Run one driver at a time.

## Final state (left clean)

- Profiles: 2 (`8944476500015257715` BetterRoaming = safety anchor, `8944476500015198679` BetterRoaming), both nickname empty.
- defaultDpAddress: empty. rootDsAddress: `lpa.ds.gsma.com`.
- No reset run. No profile deleted. No real notification removed.
