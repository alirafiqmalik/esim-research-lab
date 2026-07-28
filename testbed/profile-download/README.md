# Profile Download Lifecycle Testbed

Download, delete, and re-download a single reusable commercial test profile on
the Pixel eUICC, logging every RSP step. Scoped to 1GLOBAL/Truphone and Redtea.

## Layout

- `catalog/profiles.jsonl`, `catalog/profiles.md` — the test-profile catalog
- `scripts/build_catalog.py` — regenerate the catalog (deterministic)
- `scripts/check_installed.py` — read-only: match installed profiles to the catalog
- `scripts/download_lifecycle.py` — gated download/delete/re-download orchestrator
- `logs/<ts>-lifecycle-<label>/` — per-run step logs + captured ES9+ plaintext

## Catalog

Five reusable, no-signup, GSMA Live CI codes. Build with:

```
./venv/bin/python testbed/profile-download/scripts/build_catalog.py
```

## Check what is installed (read-only)

```
./venv/bin/python testbed/profile-download/scripts/check_installed.py
```

Ranks catalog candidates by provider match. The exact matchingID that produced
an installed profile cannot be recovered from `list` output, so all candidates
are shown.

## Lifecycle (gated)

Dry run (default, safe — prints the plan, fires nothing):

```
./venv/bin/python testbed/profile-download/scripts/download_lifecycle.py \
    --lpa 'LPA:1$rsp.truphone.com$QRF-SPEEDTEST'
```

Live run requires all three gates:

```
ESIM_MITM_ALLOW_LIVE_FIRE=1 \
./venv/bin/python testbed/profile-download/scripts/download_lifecycle.py \
    --lpa 'LPA:1$rsp.truphone.com$QRF-SPEEDTEST' \
    --allow-live-fire --i-understand-real-profile
```

Start from an already-installed profile with `--target-iccid <iccid>` instead of
downloading a fresh instance first.

## Safety

- Only reusable, not-EID-locked codes are in scope, so delete + re-download is
  recoverable.
- The lifecycle script fires nothing unless the env var and both flags are set.
- `delete` needs `--yes`; guarded ICCIDs need `--force`.
