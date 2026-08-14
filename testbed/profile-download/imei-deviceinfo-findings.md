# IMEI in deviceInfo — Findings

Date: 2026-08-13
Device: Pixel 7a (rooted), OpenEUICC lpac backend
EID: `89033023427100000000027143866816`
SM-DP+ tested: `rsp.truphone.com` (1GLOBAL/Truphone), `rsp-eu.redteamobile.com` (Redtea)

The download flow carries an IMEI to the SM-DP+ inside `ctxParams1.deviceInfo`
(SGP.22 §5.7.13). This note records where that IMEI comes from, how it is
encoded, and how five test profiles across two operators react to it.

## IMEI source: caller-supplied, not device hardware

`EsimCtlActivity.kt:124` reads the IMEI from an intent extra:

```kotlin
val imei = intent.getStringExtra("imei")   // --es imei <value>
```

The activity never calls `TelephonyManager.getImei()`. It holds no telephony
read permission. The value is whatever the caller passes on `am start`. Absent
the extra, `imei` is `null`. The value flows into
`ProfileDownloadInput(smdp, matchingId, imei, confirmationCode)`, and lpac places
it into the ES9+ `AuthenticateClient` request — inside the eUICC-signed
`authenticateServerResponse` → `euiccSigned1` → `ctxParams1` → `deviceInfo`.

The `esim` CLI now exposes this:

```
esim euicc download 'LPA:1$rsp.truphone.com$QRF-SPEEDTEST' --imei 354287197139020
```

Without `--imei`, the field is omitted and lpac sends its placeholder (see below).

## Encoding: full 15-digit IMEI, not just the TAC

`deviceInfo` is an 18-byte container with two separate populated fields:

| Field | Tag | Bytes | Content |
|---|---|---|---|
| `tac` | `[80]` | 4 | First 8 IMEI digits, BCD-swapped |
| `deviceCapabilities` | `[A1]` | 0 | Empty here |
| `imei` | `[82]` | 8 | Full 15 digits + `0xF` filler, BCD-swapped |

The `imei` field carries the complete IMEI, not a truncated identifier. Observed
values:

| IMEI sent | `tac [80]` | `imei [82]` |
|---|---|---|
| `350000000123451` | `53000000` | `53000000103254f1` |
| `354287197139020` | `53247891` | `53247891179320f0` |

The swap is standard 3GPP TS 24.008 BCD (nibble-reversed per byte).

## Results: 5 profiles, 2 operators, IMEI `354287197139020`

Procedure per code: delete the installed profile, then a fresh download with the
IMEI set. `QRF-*` codes re-provision the same ICCID, so each delete was
reversible.

| Profile / code | SM-DP+ | `authenticateClient` | Outcome |
|---|---|---|---|
| Speedtest `QRF-SPEEDTEST` | truphone | `Executed-Success` | installed |
| BetterRoaming `QRF-BETTERROAMING-PMRDGIR2EARDEIT5` | truphone | `Executed-Success` | installed |
| BetterRoaming `QR-G-5C-1LS-1W1Z9P7` | truphone | `Failed 8.1.1/3.8` EID Refused | rejected |
| BetterRoaming `QR-G-5C-KR-1PCDWP9` | truphone | `Failed 8.2.6/3.8` MatchingID Refused | rejected |
| RedteaGO `5901981126831169` | redtea | `Failed 9.4/10.1` pool empty | rejected |

## Finding 1: no SM-DP+ validates or reacts to the IMEI

Neither Truphone nor Redtea checked the IMEI. A junk-TAC IMEI (`350000000123451`,
TAC `35000000`), a valid-looking-TAC IMEI (`354287197139020`, TAC `35428719`), and
the lpac placeholder all produced identical server behavior. The two `QRF-*` codes
install the same way regardless of IMEI. A "blacklisted" IMEI installs like any
other. The three rejections are order-state failures — spent one-time codes and an
empty profile pool — never an IMEI check. `statusCodeData` is `None` on every
accepted `authenticateClient`.

## Finding 2: the full IMEI leaves the device

`deviceInfo` transmits all 15 digits, confirmed by decoding the `imei [82]` field
in every flow. This is not TAC-only. The whole IMEI reaches the operator.

## Finding 3: rejected downloads still leak the full IMEI

The eUICC-signed `authenticateServerResponse` — which contains `deviceInfo` — is
POSTed to the SM-DP+ in the `AuthenticateClient` request. The server refuses
*after* it receives that request. All three failed downloads sent the complete
IMEI before rejection. A download does not need to succeed to leak the IMEI.

## History: real device identity never transmitted before

The 23 prior committed download logs all carry `tac=35290611, imei=None` — lpac's
built-in placeholder TAC with the IMEI field omitted. No earlier download sent the
real device TAC or IMEI. `--imei` is the only lever that puts a chosen device
identity on the wire.

## Verification method

For each session logcat:

1. Extract the base64 `authenticateServerResponse` from the `AuthenticateClient`
   `HTTP tx` line.
2. Base64-decode to the BER-TLV `authenticateServerResponse`.
3. Walk the tree: `ctxParams1 [A0]` → `deviceInfo [A1]` → `tac [80]` / `imei [82]`.
4. Compare `imei [82]` against the BCD-swapped injection to confirm a byte match.

Session artifacts under `.sessions/esimctl/` (`20260813-18*`, `20260813-21*`).
