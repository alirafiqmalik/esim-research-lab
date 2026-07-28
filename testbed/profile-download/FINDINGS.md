# Profile Download Lifecycle — Findings

Date: 2026-07-28
Device: Pixel 7a, OpenEUICC lpac backend
Profile: `LPA:1$rsp.truphone.com$QRF-SPEEDTEST` (1GLOBAL/Truphone, GSMA Live CI)

## Result: delete + re-download succeeded, same ICCID

Log set: `logs/20260728_041930-lifecycle-QRF-SPEEDTEST/`

| Step | Outcome |
|---|---|
| snapshot before | 2 profiles |
| delete A (index-resolved) | ok, removed `8944476500015198679` |
| verify deleted | 1 profile |
| re-download (same code) | ok |
| verify B | 2 profiles |

Profile A ICCID == profile B ICCID == `8944476500015198679`. The `QRF-SPEEDTEST`
matchingID maps to a **fixed profile**, re-issued with the identical ICCID — not
a fresh pool instance. The code is reusable and not EID-locked, so the delete was
fully recoverable.

## One download exercises the whole ES9+ chain

The re-download's `rsp.json` holds the full server-facing procedure set:

- `es9plus/initiateAuthentication` — serverSigned1 + CERT.DPauth (CI1)
- `es9plus/authenticateClient` — eUICC's `authenticateServerResponse` (the leg
  where the **server** authenticates the eUICC)
- `es9plus/getBoundProfilePackage` — the BoundProfilePackage (encrypted profile)
- `es9plus/handleNotification` — install notification delivered to the SM-DP+

So the download flow covers AuthenticateClient, GetBoundProfilePackage, and
HandleNotification in one run — the procedures beyond the standalone
`authenticate` CI-trust probe.

## Batch: full lifecycle across all 5 catalog codes (2026-07-28)

`scripts/batch_lifecycle.py`, logs `logs/20260728_044004-batch/`. Sequence per
code: download -> enable -> disable -> delete -> re-download.

| Code | ICCID | Result | enable/disable | Reason |
|---|---|---|---|---|
| `QR-G-5C-KR-1PCDWP9` (BetterRoaming) | 8944476500015257715 | OK | Enabled/Disabled | full cycle |
| `QRF-BETTERROAMING-PMRDGIR2EARDEIT5` | 8944476500015257715 | OK | Enabled/Disabled | full cycle |
| `QRF-SPEEDTEST` (Speedtest) | 8944476500015198679 | OK | Enabled/Disabled | full cycle |
| `QR-G-5C-1LS-1W1Z9P7` (BetterRoaming) | — | FAILED | — | `8.1.1/3.8 EID Refused` |
| `5901981126831169` (RedteaGO) | — | FAILED | — | `9.4/10.1 campaign resource pool is empty` |

Findings:

- 3 of 5 codes complete the whole download/enable/disable/delete/re-download
  cycle. Re-download returns the same ICCID every time (fixed profiles).
- `QR-G-5C-KR` and `QRF-BETTERROAMING` map to the **same profile** (ICCID
  ...5257715). The three BetterRoaming codes are not distinct profiles.
- `QR-G-5C-1LS` is refused for this EID (`8.1.1/3.8`) — consumed/retired.
- RedteaGO's free pool is exhausted server-side (`9.4/10.1`) — a supply state,
  not a crypto or eUICC failure. Contrast the earlier ping probe where Redtea
  rejected at InitiateAuthentication; here it passes InitiateAuthentication and
  fails at AuthenticateClient.
- Re-downloading a code whose ICCID is already installed returns
  `8.2.6/3.8 Matching ID Refused`; it succeeds again once the profile is deleted.
- enable then disable works on every successful profile (Enabled -> Disabled).

Design fix after this run: the first version purged all catalog profiles on any
"no new profile" download, which deleted good profiles when a *server* rejection
(not a collision) occurred, leaving the phone empty. Fixed to purge per-cycle for
a clean slate and to restore originally-installed profiles at the end. The phone
was restored to its starting 2 profiles (...5198679 + ...5257715, both Disabled).

## Harness quirk found and worked around

`esim euicc delete <target>` takes a **1-based list index**, not an ICCID
(`_do_delete` does `int(target)-1`; it does not call `_resolve_iccid`). Passing an
ICCID fails with `profile #<iccid> not found`. `download_lifecycle.py` resolves
the ICCID to its current list index immediately before deleting.
