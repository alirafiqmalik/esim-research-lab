# Non-root S24 Mint eSIM capture

A stock, non-rooted Galaxy S24+ downloading a Mint Mobile eSIM, captured host-side
over USB `adb` with `testbed/nonroot-rsp-capture/capture_esim_rsp.sh`. One run,
successful install, logcat + `dumpsys` snapshots + PCAPdroid pcap.

The point of the run: test whether the IMEI-in-`deviceInfo` leak
(`docs/research/imei-deviceinfo-threat-model.md`) is observable without root. It is not.
This session confirms the ceiling.

## Setup

- Device: SM-S926U1 (Galaxy S24+), Android 16, serial R5CX804NGAT.
- eUICC: MEP_A1. Two pre-existing profiles — AT&T "Bootstrap V1.0" (`profileClass=1`,
  provisioning) and Liberty PR (`profileClass=2`, operational). Physical Mint SIM in slot 0.
- Profile added: Mint Mobile eSIM (account replacement, `deliveryType=ESIM`).
- SM-DP+: `t-mobile.idemia.io` (Mint is a T-Mobile MVNO; IDEMIA is the SM-DP+ vendor).
- Capture: `capture_esim_rsp.sh --bugreport --pcapdroid`.

## Timeline

Logcat (`SLPASVC`) and the pcap SNI/timing agree to the second.

| Time (EDT) | Stage | Evidence |
|---|---|---|
| 00:29–00:31 | Mint app checkout generates the activation | pcap SNI `mint-gateway.mintmobile.com`; URL `.../checkout/replacement?deliveryType=ESIM` |
| 00:32:46–48 | SM-DS discovery fan-out — 4 servers polled | `esimdiscovery.com`, `es11.samsung-sm-ds.com`, `lpa.ds.gsma.com` (GSMA root), `lpads.vzw.otgeuicc.com` (Verizon) |
| 00:32:49 | Discovery returns no pending event | `resultCode=ES9_NO_EVENT_ENTRY` → direct activation-code, not SM-DS push |
| 00:33:20 | LPA resolves the SM-DP+ | `InitiateAuth.verifySmXxAddress: server address : t-mobile.idemia.io` (40.78.63.202) |
| 00:33:28 | User consent → ES9+ auth handshake | `handleUserConsent()`, `HttpManager.sendToRequest count:0` |
| 00:33:46 | Profile installed | `successfully transferred package to eUICC` (LoadBoundProfilePackage) |
| 00:33:47 | Success flagged | `ContextLogger: profile download success:450F` |
| 00:34:06–24 | HandleNotification — install result POSTed back | `notiByServer: [t-mobile.idemia.io]`, count drains 2→1 |

SM-DP+ contact to installed: ~26 seconds. Subscription entries in `dumpsys isub`
went 19 → 24 across the add.

## The ceiling held

The Samsung LPA is far more verbose than stock AOSP. It logged the whole phase-2 state
machine — normalized SM-DP+/SM-DS URLs, cert-chain lengths, ICCIDs, profile metadata,
notification routing. The IMEI still never appeared.

- No `ctxParams1`, no `deviceInfo`, no IMEI, no TAC in 166 MB of logcat. The signed ES9+
  request bodies are never logged.
- The pcap shows only TLS SNI + IP + timing to `t-mobile.idemia.io`. The
  `AuthenticateClient` payload carrying the IMEI stayed inside pinned RSP TLS. Not
  recoverable.
- Android 16 redacts EID, ICCID (first 9 digits only), IMSI, and MSISDN to `[****]` in
  logcat.

Real-world confirmation of `imei-deviceinfo-threat-model.md`: on a stock non-rooted phone
the IMEI leak is not observable. It is sealed in the pinned transport. Reading the IMEI on
the wire needs the rooted `lpac`/OpenEUICC path (`testbed/profile-download/`).

## What the run does surface without root

- eUICC inventory and profile classes (MEP_A1, bootstrap vs operational).
- The device's configured SM-DS set: GSMA root + Samsung + esimdiscovery + Verizon.
- SM-DP+ hostname, IP, and per-stage timing.
- T-Mobile carrier-privilege cert hashes bound to the Mint profile.
- Install result and notification routing.

## Data handling

The capture output holds real PII. `bugreport.zip` and the pcap carry the unredacted
IMEI, ICCID, and account. `testbed/nonroot-rsp-capture/esim-rsp-capture/` is gitignored.
Only the tool (`capture_esim_rsp.sh`) and its README are tracked.
