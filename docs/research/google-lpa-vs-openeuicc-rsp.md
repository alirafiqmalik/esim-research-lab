# Stock Google LPA + Frida vs OpenEUICC — RSP capture

Repeated the RSP procedure on the **stock Google LPA** (`com.google.android.euicc`)
instrumented with Frida, to compare against the open OpenEUICC path. Same device,
same production-CI server (RedteaGO `rsp-eu.redteamobile.com`), full logging started
before the procedure. Session: `sessions/google-lpa-frida-20260629/`.

## Setup differences

| | OpenEUICC (open) | Stock Google LPA |
|---|---|---|
| Make it the active flow | default | `pm disable-user im.angry.openeuicc` (then re-enabled) |
| RSP client | `lpac` + Kotlin `HttpInterfaceImpl` (logs bodies) | `com.android.euicc.smdp.ProfileDownloadTransaction` / `SmdxApiImplV2` (closed) |
| Download UI | in-app wizard | Settings → Set up eSIM → Use a different SIM → troubleshoot → Enter manually |

## What happened (RedteaGO, production CI)

**Identical RSP behaviour, confirmed via logcat:** the Google LPA ran
`onGetDownloadableSubscriptionMetadata → ProfileDownloadTransaction.authenticate`
and halted with `SmdpException subjectCode=9.4 reasonCode=10.1` — the same
"campaign resource pool is empty" the OpenEUICC RedteaGO run hit. So:
`initiateAuthentication` succeeded (production CI matched), the eUICC accepted the
SM-DP+ cert, and the server then refused at `authenticateClient` because the free
pool was empty. Production-CI vs test-CI behaviour is identical across both LPAs.

## The instrumentation finding

**The Google LPA's RSP message bodies are opaque to straightforward Frida hooks**,
even with root + frida-server attached to the correct process (verified: the RSP
fired in pid 9688 = `com.google.android.euicc`, which Frida was attached to, yet
the hooks captured nothing):

- `SmdxApiImplV2.sendRequest(String, JSONObject)` did not fire — ART JIT-inlined.
- The okhttp TLS does **not** traverse `ConscryptEngineSocket$SSL{In,Out}putStream`
  (the classes that worked for other apps) — it uses the conscrypt **engine**
  `wrap`/`unwrap` path. Capturing bodies would need hooking `ConscryptEngine.wrap/unwrap`
  (ByteBuffer) or okhttp `HttpEngine` internals — a deeper RE step.

This is the core contrast: **an open LPA (OpenEUICC) yields ES9+/ES10 plaintext for
free; the stock closed LPA performs the identical protocol but resists casual
instrumentation.** The message *bodies* for this exact server/flow are already
captured via OpenEUICC — see `docs/diagrams/rsp-redteago.{svg,png}`.

## Diagrams

- `docs/diagrams/rsp-redteago.{svg,png}` — RedteaGO RSP with full message bodies (OpenEUICC capture).
- `docs/diagrams/rsp-google-lpa-redteago.{svg,png}` — the same flow as executed by the
  stock Google LPA (steps from logcat; ES9+ bodies marked ⟨opaque⟩).

OpenEUICC was re-enabled after the test. The eUICC's two profiles (BetterRoaming #1,
Speedtest Travel #2) were untouched.
