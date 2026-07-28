# ES9+ Device ↔ SM-DP+ Message-Flow Probe

Exercise and log every device-facing ES9+ procedure against the live SM-DP+
servers we hold consumer test profiles for (Truphone, Redtea).

## Run

```
ESIM_MITM_ALLOW_LIVE_FIRE=1 \
./venv/bin/python testbed/es9-message-flow/scripts/probe_es9_flow.py \
    --allow-live-fire --i-understand-real-profile
```

Per server: `authenticate` (CI-trust + InitiateAuthentication), then a clean
`download` (deletes any installed instance first, so the chain runs fresh and the
fixed profile is restored). Originals are restored at the end.

## Coverage (2026-07-28, logs `logs/es9-flow-20260728_133029/`)

| Procedure | rsp.truphone.com | rsp-eu.redteamobile.com |
|---|---|---|
| InitiateAuthentication | Executed-Success | Executed-Success |
| AuthenticateClient | Executed-Success | Failed `9.4/10.1 pool empty` |
| GetBoundProfilePackage | Executed-Success | not reached |
| HandleNotification | sent (HTTP 204 ack) | not reached |
| CancelSession | n/a | n/a |

## Notes

- **Truphone gives full coverage** of the four device-drivable ES9+ procedures.
  A successful download emits them in order; the parsed exchange is in each
  server's `04-download/rsp.json`.
- **HandleNotification returns HTTP 204 with no body** — it is fire-and-forget,
  so there is no `functionExecutionStatus` to report. "sent" is the success
  state.
- **Redtea stops at AuthenticateClient** — its free pool is exhausted
  (`9.4/10.1 campaign resource pool is empty`), a real server-side supply state,
  so GetBoundProfilePackage and HandleNotification are never reached.
- **CancelSession is not device-triggerable** from the headless lpac path. The
  LPA emits it only on a user-declined confirmation or an SM-DP+ abort, neither
  of which an automated download produces. It is modeled in `testbed/ecosim`
  and `testbed/ping-live-servers/src/models.py` (CancelSessionRequest).

## Parser note

The harness truncates large response bodies in `rsp.json` (~600 chars), so the
cert/BPP blobs make the JSON incomplete. The probe reads `status` and
`statusCodeData` by regex (both sit at the front of the body), not `json.loads`.
