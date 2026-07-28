# ping-sm-ds

Live-ping and testing setup for SM-DS (discovery) servers, driven from the
phone's real eUICC. Companion to `testbed/ping-live-servers` (SM-DP+).

## Layout

- `notes/01-smds-addresses.md` — SM-DS addresses, how discovery works, provenance
- `notes/02-findings.md` — probe results
- `scripts/ping_sm_ds.py` — per-SM-DS `authenticate` + ES11 `discovery` probe
- `logs/smds-<ts>/` — per-host logcat + results.jsonl + summary.txt

## Run

```
ESIM_MITM_ALLOW_LIVE_FIRE=1 \
./venv/bin/python testbed/ping-sm-ds/scripts/ping_sm_ds.py --allow-live-fire
```

Read-only: discovery and authenticate query the SM-DS, they do not download or
change any profile. `--host <fqdn>` probes a single server.

## Targets

`lpa.ds.gsma.com` (GSMA root), `lpa.live.esimdiscovery.com`,
`lpa.live.esimdiscovery.dev` — all production-CI. See `notes/01`.
