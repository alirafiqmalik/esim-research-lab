# Profile Delivery Methods

Three trigger methods start a profile install. All three converge on the same
ES9+ download flow (`01-interfaces.md`). They differ only in how the activation
string reaches the LPA:

```
LPA:1$<smdp-address>$<matchingId>
```

Once the LPA has that string, the download is identical regardless of how it
arrived. The string carries the SM-DP+ FQDN and the matchingId; the LPA fills in
the rest from the eUICC.

## QR code scanning

The default consumer path. A QR image encodes the `LPA:1$...` string. The camera
decodes it, the LPA parses the three `$`-separated fields, and the download
starts.

- SM-DP+ address → the `smdpAddress` in ES9+ InitiateAuthentication.
- matchingId → carried to ES9+ AuthenticateClient inside `ctxParams1`.
- Generate a QR for any catalog code with `scripts/make_qr.py`.

## Manual input

Typing the two fields into the phone's eSIM settings. No optical step. Same
result. Our repo already documents the exact OpenEUICC steps
(`docs/research/research-gsma-ts48-test-profile.md`):

1. Open the LPA. Choose add/download profile, then manual entry (not scan).
2. SM-DP+ address field: the host only, e.g. `rsp.truphone.com`. No `LPA:`, no
   `1$`, no `://`.
3. Activation/matching code field: the matchingId only, e.g. `QRF-SPEEDTEST`.
4. Leave confirmation code empty (none of our catalog codes use one).
5. Start the download.

The single-string QR form is `LPA:1$<host>$<matchingId>`; manual entry splits it
back into the two fields.

## Carrier apps and universal links

Automated paths that hand the LPA string to the system without a camera or
typing. Android specifics:

- **`LPA:` URI scheme.** An intent carrying an `LPA:1$...` URI routes to the eSIM
  handler. The draft in `scripts/trigger_download.py` shows the exact
  `am start -a android.intent.action.VIEW -d 'LPA:1$...'` form.
- **`EuiccManager.downloadSubscription`.** A carrier app builds a
  `DownloadableSubscription` from the activation code and calls
  `EuiccManager.downloadSubscription(...)`. The framework LPA runs the same ES9+
  flow. This is the `--backend fw` path our harness exposes.
- **Universal / deep links.** A web link (for example an `https://` link the OS
  maps to the eSIM handler, or a vendor scheme) opens the LPA prefilled with the
  SM-DP+ address and code. The user confirms; the download runs.

### Push vs pull

- **Pull** — user-initiated. The user scans, types, or taps a link. The device
  goes to the named SM-DP+ and downloads. Every catalog code in this repo is a
  pull.
- **Push** — server-initiated. No activation code changes hands. Instead an
  SM-DP+ registers a pending event at the SM-DS (ES12.RegisterEvent). The device
  polls the SM-DS at power-on (ES11 discovery), learns an event is waiting, and
  is routed to the SM-DP+. See `testbed/ping-sm-ds/` for the discovery side. Our
  EID currently has zero registered events, so no push path is live for us.

## Common outcome

Whichever method fires, the LPA ends up running the ES9+ chain from
`01-interfaces.md`. The delivery method is a wrapper around one download. For
MITM work, the trigger is not the attack surface; the ES9+ exchange is.
