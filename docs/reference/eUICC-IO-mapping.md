# Index

Every eUICC command reachable from this testbed (rooted Pixel 7a, OpenEUICC +
lpac over OMAPI), with a shorthand of its observed I/O. Captured live 2026-07-19.
`SW` = ISO-7816 status word. `<..>` = value that varies per device/run.

- `GetEID()` <-- `{EID = 89033023427100000000027143866816}`
- `GetEUICCInfo1()` <-- `{SVN 2.3.0, CI-PKID-sign 81370F…BEBFB, CI-PKID-verify 81370F…BEBFB}`
- `GetEUICCInfo2()` <-- `{SVN 2.3.0, profileVersion 2.3.0, extCardResource, CI lists, sasAcreditation "TS-PA-UP-0423"}`
- `GetProfilesInfo()` <-- `{P1: iccid 8944476500015257715 / ISD-P A0000005591010FFFFFFFF89000011 / "BetterRoaming" / Disabled, P2: iccid 8944476500015198679 / …8900001200 / "Speedtest Travel" / Disabled}`
- `ListNotification()` <-- `{empty A0 00}`
- `RetrieveNotificationsList(seq)` <-- `{empty A0 00}` (queue empty)
- `GetConfiguredAddresses()` <-- `{rootDS = lpa.ds.gsma.com, defaultDP = <none>}`
- `GetRAT()` <-- `{one allocation: allowedMnoOids EEEEEE, no PPRs restricted}`
- `GetEUICCChallenge()` <-- `{16-byte nonce e.g. A55A7F4B948E551BB9C087802C1AA55B}`
- `SetDefaultDpAddress(fqdn)` <-- `{result 00 = OK}`
- `SetNickname(iccid,name)` <-- `{result 00 = OK}`
- `EnableProfile(iccid)` <-- `{result 00 = OK}`
- `DisableProfile(iccid)` <-- `{result 00 = OK}`
- `DeleteProfile(iccid)` <-- `{result 00 = OK}` *(structure only — not run, destructive)*
- `RemoveNotification(seq)` <-- `{result 00 / seq not found}`
- `eUICCMemoryReset()` <-- `{result 00}` *(structure only — GUARDED, wipes all profiles)*
- `CancelSession(reason)` <-- `{signed CancelSessionResponse}` (observed on failed download)
- `SelectApplet(ECASD)` <-- `{FCI: AID + GlobalPlatform OIDs}`
- `ECASD.GetData(66)` <-- `{Card Recognition Data}` ; `ECASD.GetData(E0)` <-- `{Key Info Template}`
- `AuthenticateServer(server)` <-- `{prod-CI: euiccSigned1 + euiccSignature1 (accepted); test-CI: 8.8.4/3.7; Google prod SM-DP+: server refuses eUICC 8.8.2/3.1}`
- `Discovery(smds=lpa.ds.gsma.com)` <-- `{ok, 0 pending events; full ES9+/ES10 auth round trip}`
- `Download(smdp,matchingId)` <-- `{ok:false; reached authenticateClient → EID Refused 8.1.1/3.8 → CancelSession}`
- `fw.getEid()` (EuiccManager) <-- `{EID 89033023…6816, available=true}`
- `card.requestEuiccChallenge()` (IEuiccCardController) <-- `{-3 RESULT_CALLER_NOT_ALLOWED}` (gated to active LPA)

---

# Detail Observations

All ES10x commands ride the GlobalPlatform `STORE DATA` envelope
`81 E2 91 00 Lc <BER-TLV>` sent to the **ISD-R** on lpac's already-open logical
channel (the ISD-R is non-multiselectable). OMAPI's `Channel.transmit` handles
61xx GET RESPONSE, so each response returns full data followed by `SW1 SW2`.

## `GetEID()`

Ping the eUICC and read its unique 32-digit identity (EID).

- I/O format: `GetEID()` <-- EID `89033023427100000000027143866816`

### Raw-Input/Input

#### Input
- raw-input (only one)
```hex
APDU: 81 E2 91 00 06 BF3E 03 5C 01 5A

  - 81 E2 91 00 : GlobalPlatform STORE DATA header (block 0, last block).
  - 06          : Lc, length of the command payload.
  - BF3E 03     : ES10c GetEuiccData tag, length 3.
  - 5C 01 5A    : tag-list requesting object 5A (the EID).
```
- Format:
```hex
BF 3E 03 5C 01 5A
│     │  └─ tag-list: 5C 01 5A  = "give me object 5A (EID)"
│     └─ length (3)
└─ GetEuiccData command tag
```
#### Output
- raw-output (only one)
```hex
BF3E 12 5A 10 89033023427100000000027143866816 9000
```
- Format:
```hex
BF 3E 12 5A 10 89 03 30 23 42 71 00 00 00 00 02 71 43 86 68 16 90 00
│     │  │  │  └─ 16-byte (10h) EID, BCD, 32 digits
│     │  │  └─ length of EID (16)
│     │  └─ tag for EID object (5A)
│     └─ total payload length (18 / 12h)
└─ GetEuiccData response tag
```

### Expected Output
A `BF3E` TLV containing one `5A` of exactly 16 bytes + `9000`. Matches observed.

### Notes
- The leading `8903...` identifies the EUM (issuer); `89033023` = this eUICC vendor.

## `GetEUICCInfo1()`

Return the eUICC's SGP.22 version and the CI public-key IDs it trusts, standalone
(no download session needed).

- I/O format: `GetEUICCInfo1()` <-- `{SVN 2.3.0, CI-sign 81370F…, CI-verify 81370F…}`

### Raw-Input/Input
#### Input
```hex
APDU: 81 E2 91 00 03 BF20 00      (BF20 = GetEUICCInfo1, empty length)
```
#### Output
```hex
BF20 35 8203 020300 A9 16 0414 81370F5125D0B1D408D4C3B232E6D25E795BEBFB
                       AA 16 0414 81370F5125D0B1D408D4C3B232E6D25E795BEBFB 9000
```
- Format:
```hex
8203 020300  = lowestSvn 2.3.0
A9 16 0414 <20-byte keyId>  = euiccCiPKIdListForSigning
AA 16 0414 <20-byte keyId>  = euiccCiPKIdListForVerification
```
### Expected Output
Version + two CI-PKID lists. Observed lists contain **only** the GSMA
**production** CI `81370F…BEBFB` — no test CI.

### Notes
- This single field is why test-CI infrastructure can never provision this eUICC:
  the SM-DP+ reads it and sees no test CI.

## `GetEUICCInfo2()`

Fuller capability block: versions, free memory, the CI lists, UICC category,
forbidden PP rules, and the SAS accreditation label.

- I/O format: `GetEUICCInfo2()` <-- `{SVN 2.3.0 … "TS-PA-UP-0423"}`

### Raw-Input/Input
#### Input
```hex
APDU: 81 E2 91 00 03 BF22 00
```
#### Output (truncated)
```hex
BF22 8187 8103 020301 8203 020300 8303 427100 840F 8101008204000C1C54
     8304 00003C43 8505 067F36F7C0 8603 0D0100 8703 020300 8802 03D8
     A9 16 0414 81370F… AA 16 0414 81370F… 8B0102 9902 064004030100000C14
     54532D50412D55502D30343233 20202020202020 9000
```
- Format: `8103` euiccSpecVersion, `8203` firmwareVer, `840F` extCardResource
  (free NVM/RAM), `A9`/`AA` CI lists, tail `54532D50412D55502D30343233` =
  ASCII **"TS-PA-UP-0423"** (SAS platform label).
### Expected Output
A `BF22` template ≥100 bytes. Matches.
### Notes
- `840F …0C1C54` decodes to free non-volatile memory (~805 KB) available for
  profiles.

## `GetProfilesInfo()`

List installed profiles with ICCID, ISD-P AID, name/nickname, class and state.

- I/O format: `GetProfilesInfo()` <-- `{P1 …, P2 …}` (2 disabled profiles)

### Raw-Input/Input
#### Input
```hex
APDU: 81 E2 91 00 03 BF2D 00     (empty search criteria = all profiles)
```
#### Output (2 profile records)
```hex
BF2D 8190 A0 818D
  E3 43 5A0A 984474560010257517F5   4F10 A0000005591010FFFFFFFF89000011 00
        9F70 01 00   910D "BetterRoaming"  920D "BetterRoaming"  9501 02
  E3 46 5A0A 984474560010158976F9   4F10 A0000005591010FFFFFFFF89000012 00
        9F70 01 00   9110 "Speedtest Travel"  920D "BetterRoaming"  9501 02
9000
```
- Format per record: `E3`=ProfileInfo, `5A`=ICCID (nibble-swapped),
  `4F`=ISD-P AID, `9F70`=state (00=disabled), `91`=profile name, `92`=nickname,
  `95`=profileClass (02=operational).
### Expected Output
One `E3` per profile. Two operational, both **Disabled**. Matches.
### Notes
- ICCID `984474560010257517F5` de-swaps to `8944476500015257715`.

## `ListNotification()` / `RetrieveNotificationsList(seq)`

List pending eUICC notifications; retrieve the full **signed** notification for a
sequence number.

- I/O format: `ListNotification()` <-- `{A0 00}` (empty) ; `RetrieveNotificationsList(0)` <-- `{A0 00}`

### Raw-Input/Input
#### Input
- list:
```hex
81 E2 91 00 03 BF28 00
```
- retrieve by seq (searchCriteria seqNumber [0]):
```hex
81 E2 91 00 08 BF2B 05 A0 03 80 01 00
                       │     └─ 80 01 00 = seqNumber 0
                       └─ A0 = searchCriteria wrapper
```
#### Output
```hex
BF28 02 A0 00 9000        (empty notification list)
BF2B 02 A0 00 9000        (no notification for that seq)
```
### Expected Output
`A0` list, empty when no notifications pending. Matches (queue currently empty).
### Notes
- When populated, each entry is a `ProfileInstallationResult` / signed
  `PendingNotification` the eUICC would POST to the SM-DP+ (extractable/replayable).

## `GetConfiguredAddresses()` / `SetDefaultDpAddress(fqdn)`  (ES10a)

Read / write the default SM-DP+ and root SM-DS FQDNs the eUICC hands the LPA.

- I/O format: `GetConfiguredAddresses()` <-- `{rootDS lpa.ds.gsma.com, defaultDP none}` ;
  `SetDefaultDpAddress("testdp.example.com")` <-- `{result 00}`

### Raw-Input/Input
#### Input
- get (BF3C):
```hex
81 E2 91 00 03 BF3C 00
```
- set (BF3F), address as UTF-8 in context tag 80:
```hex
81 E2 91 00 17 BF3F 14 80 12 74657374 6470 2E6578616D706C65 2E636F6D
                       │  │  └─ "testdp.example.com" (18 bytes)
                       │  └─ length 18 (12h)
                       └─ defaultDpAddress [0]
```
#### Output
```hex
get: BF3C 11 81 0F 6C70612E64732E67736D612E636F6D 9000
                 └─ 81 = rootDsAddress "lpa.ds.gsma.com"  (no 80/defaultDp present)
set: BF3F 03 80 01 00 9000        (80 = setDefaultDpAddressResult, 00 = OK)
```
### Expected Output
Get: `80` defaultDp (optional) + `81` rootDs. Set: result `00`. Matches; empty
string `80 00` clears the default. (Restored to empty after the test.)
### Notes
- The single highest-value adversary-model surface: rewriting the SM-DP+ address
  the eUICC advertises. Fully scriptable, reversible.

## `GetRAT()`  (ES10b)

Read the Rules Authorisation Table (which Profile Policy Rules are allowed and by
which operators).

- I/O format: `GetRAT()` <-- `{1 allocation, allowedMnoOids EEEEEE, no restricted PPRs}`

### Raw-Input/Input
#### Input
```hex
81 E2 91 00 03 BF43 00
```
#### Output
```hex
BF43 19 A0 17 30 15 8002 0560 A1 0B 30 09 8003 EEEEEE 8100 8200 8202 0780 9000
```
- Format: `A0`=RAT, `30`=one entry, `8002 0560`=pprIds, `8003 EEEEEE`=allowedMnoOids
  wildcard, empty `8100/8200`.
### Expected Output
A `BF43` table. Observed table imposes no operator-restricted policy rules.
### Notes
- `EEEEEE` = "any MNO" wildcard; the eUICC does not pre-restrict PPRs.

## `GetEUICCChallenge()`  (ES10b)

Ask the eUICC for a fresh 16-byte random challenge (first step of any RSP auth).

- I/O format: `GetEUICCChallenge()` <-- `{8010 <16 random bytes>}`

### Raw-Input/Input
#### Input
```hex
81 E2 91 00 03 BF2E 00
```
#### Output
```hex
BF2E 12 80 10 A55A7F4B948E551BB9C087802C1AA55B 9000
              └─ 16-byte euiccChallenge (new every call)
```
### Expected Output
`80` of exactly 16 random bytes. Matches; value differs each invocation.
### Notes
- Feeds `initiateAuthentication`; the server signs over it to prove freshness.

## `EnableProfile(iccid)` / `DisableProfile(iccid)`  (ES10c)

Switch a profile on/off (a REFRESH follows). Tested as a reversible cycle on
profile #2.

- I/O format: `EnableProfile(iccid)` <-- `{result 00}` ; `DisableProfile(iccid)` <-- `{result 00}`

### Raw-Input/Input
#### Input
```hex
enable : 81 E2 91 00 14 BF31 11 A0 0C 5A0A 984474560010158976F9 81 01 FF
disable: 81 E2 91 00 14 BF32 11 A0 0C 5A0A 984474560010158976F9 81 01 FF
                             │        └─ 5A = target ICCID
                             └─ A0 = profileIdentifier(iccid);  81 01 FF = refresh=true
```
#### Output
```hex
BF31 03 80 01 00 9000     (enableProfileResult = 00 OK)
BF32 03 80 01 00 9000     (disableProfileResult = 00 OK)
```
### Expected Output
Result `00`. Both observed `00`; profile returned to Disabled after the cycle.
### Notes
- `8101FF` requests an immediate REFRESH so the modem re-reads the SIM.

## `DeleteProfile(iccid)`  (ES10c) — structure only

Permanently delete a profile's ISD-P. **Not executed** (destructive; would remove a
safety-anchor profile).

- I/O format: `DeleteProfile(iccid)` <-- `{result 00}` *(expected)*

### Raw-Input/Input
#### Input
```hex
81 E2 91 00 0F BF33 0C 5A 0A <ICCID>       (BF33 = DeleteProfile, 5A = ICCID)
```
#### Output
```hex
BF33 03 80 01 00 9000       (00 = OK ; 3F1F if enabled/not-deletable)
```
### Expected Output
Result `00` on success. Not observed live by design.
### Notes
- `esimctl delete` refuses without `--yes` and guards the last/protected profile.

## `RemoveNotification(seq)` / `HandleNotification(seq)`

Delete a pending notification locally (ES10b BF30); or POST it to its SM-DP+ (ES9+).

- I/O format: `RemoveNotification(seq)` <-- `{result 00 / not-found}`

### Raw-Input/Input
#### Input
```hex
remove: 81 E2 91 00 06 BF30 03 80 01 <seq>      (BF30 RemoveNotificationFromList)
handle: (no single APDU — lpac reads the notification, POSTs ES9+ handleNotification,
         then RemoveNotificationFromList on success)
```
#### Output
```hex
BF30 03 80 01 00 9000     (deleteNotificationStatus 00 = OK; earlier this session
                           removed a real seq and the list count dropped 12→11)
```
### Expected Output
`00` when the seq exists, else a not-found status. Matches.
### Notes
- `handle` triggers a real network POST; bogus seq returns `handled=false` with no
  traffic.

## `eUICCMemoryReset()`  (ES10c) — structure only, GUARDED

Erase **all** profiles and reset. **Never executed** — `esimctl reset` refuses
without `--confirm-wipe`, and the activity refuses without `--es confirm RESET`.

### Raw-Input/Input
#### Input
```hex
81 E2 91 00 06 BF34 03 82 01 <bitmask>     (BF34; bitmask selects what to wipe)
```
#### Output
```hex
BF34 03 80 01 00 9000     (resetResult 00)  — expected, not observed
```
### Notes
- Would destroy both BetterRoaming profiles; deliberately left unexecuted.

## `SelectApplet(ECASD)` + `ECASD.GetData`

Open a fresh logical channel to a **different** applet (the eUICC Certificate
Authority Security Domain) and read identity/key material — outside the ISD-R.

- I/O format: `SelectApplet(A0000005591010FFFFFFFF8900000200)` <-- `{FCI}` ;
  `ECASD.GetData(66)` <-- `{Card Recognition Data}` ; `ECASD.GetData(E0)` <-- `{Key Info Template}`

### Raw-Input/Input
#### Input
```hex
SELECT : 00 A4 04 00 10 A0000005591010FFFFFFFF8900000200      (open channel, ISO SELECT)
GETDATA: 80 CA 00 66 00      (tag 66 = Card Recognition Data)
GETDATA: 80 CA 00 E0 00      (tag E0 = Key Information Template)
```
#### Output
```hex
SELECT FCI : 6F 48 84 10 A0000005591010FFFFFFFF8900000200 A5 34 73 2E
             06 07 2A864886FC6B01 … (GlobalPlatform OIDs) … 9F65 01 FF 9000
GETDATA 66 : 66 30 73 2E 06 07 2A864886FC6B01 … 9000
GETDATA E0 : E0 20 C006 0574B120F000 C006 017FB120F000 C006 00FEB040F000
             C006 01FEB040F000 9000        (4 key entries)
GETDATA 7F21 (certificate): 6A88 (referenced data not found — certs auth-protected)
```
### Expected Output
FCI with the AID + GP OIDs; readable card/key metadata; **certs refused (`6A88`)**
without authentication. Matches.
### Notes
- ARA-M (`A00000015141434C00`) is **not** selectable on this eUICC (NoSuchElement).
- The non-multiselectable limit is per-applet, so a non-ISD-R AID gets its own channel.

## `AuthenticateServer(server)`  — standalone CI-trust probe

Run challenge → `initiateAuthentication` → `authenticateServer` against a server and
report whether the **secure element accepts its CI**, without downloading.

- I/O format: `AuthenticateServer("rsp.truphone.com")` <-- `{ciTrusted true, stage accepted}`

### Raw-Input/Input
#### Input (to the eUICC, block-chained STORE DATA carrying the server's signed data + cert)
```hex
81 E2 11 00 3F BF38 8203 23 3047 8010 <transactionId> … <serverSigned1/sig/cert> …
81 E2 11 01 3F …            (P1=11 = more blocks; the SM-DS certificate streams in)
   ⋮
81 E2 91 0C 34 …            (P1=91 = last block)
```
#### Output — the eUICC's SIGNED (cryptographic) output
```hex
BF38 820597 A0 820593 3081CC 8010 <transactionId>
     830F 6C70612E64732E67736D612E636F6D          ← smdpAddress (PLAINTEXT part)
     8410 <serverChallenge> …                       ← euiccSigned1 (plaintext TLVs)
     … 5F37 <64-byte ECDSA euiccSignature1> …        ← SIGNED part (crypto)
     … BF21 <eUICC certificate> …                    ← eUICC cert chain
     9000
```
- Format: `A0` = AuthenticateServerResponse; inside, `euiccSigned1` (readable:
  transactionId, smdpAddress, eUICC info) + `euiccSignature1` (the ECDSA signature =
  the encrypted/cryptographic part) + the eUICC certificate.
### Expected Output
- **Production-CI server** (`lpa.ds.gsma.com`, `rsp.truphone.com`): `00` → eUICC
  signs and returns the response → `ciTrusted:true`, `stage:accepted`. **Observed.**
- **Test-CI server**: eUICC rejects with SGP.22 **`8.8.4 / 3.7`** (stage
  `authenticateServer_rejected`).
- **Google prod SM-DP+** (`prod.smdp-plus.rsp.goog`): passes TLS-bypass, then the
  **server** refuses the eUICC at initiateAuthentication with **`8.8.2 / 3.1`**
  (our euiccInfo1 lists no test CI).
### Notes
- The plaintext (transactionId, addresses, eUICC info) and the signed part
  (euiccSignature1) travel together in the same `BF38` response — the eUICC signs
  but does not encrypt this message.

## `Discovery(smds)`  (ES11)

Full SM-DS discovery: challenge → initiateAuthentication → authenticateServer →
`es11_authenticate_client`, asking the root SM-DS for pending download events.

- I/O format: `Discovery("lpa.ds.gsma.com")` <-- `{ok, 0 events}`

### Raw-Input/Input
#### Input
- eUICC APDUs (in order): `BF2E` GetChallenge, `BF20`/`BF22` GetInfo, `BF38`
  AuthenticateServer (block-chained), then `BF3B` (es11 authenticateClient data).
- ES9+ HTTP (plaintext, over TLS):
```
POST https://lpa.ds.gsma.com/gsma/rsp2/es9plus/initiateAuthentication
  {"smdpAddress":"lpa.ds.gsma.com","euiccChallenge":"PnB5fF0b7SxdplbxYZcKlA==","euiccInfo1":"vyA1…"}
POST https://lpa.ds.gsma.com/gsma/rsp2/es9plus/authenticateClient
  {"transactionId":"68DDE9B41DA346128593174F6417EC0C","authenticateServerResponse":"<base64 of the BF38 response above>"}
```
#### Output
```
esimctl: {"ok":true,"smds":"lpa.ds.gsma.com","events":[],"count":0}
```
### Expected Output
`ok:true` with a (possibly empty) list of SM-DP+ addresses that have events. **0
pending events is the correct real answer** — no operator staged one for this EID.
### Notes
- `authenticateServer` passes because the root SM-DS presents a **production-CI**
  cert. The `authenticateClient` body carries the eUICC's signed response as base64
  — plaintext HTTP wrapper around signed eUICC crypto.

## `Download(smdp, matchingId)`

Full RSP install: discovery of the bound package + ES8+ protected profile. Attempted
against a production SM-DP+ with a placeholder code (no free profile is bound to this
EID), to exercise the procedure and log the rejection.

- I/O format: `Download("rsp.truphone.com","IOTEST-NEW-FREE-0001")` <-- `{ok:false, EID Refused 8.1.1/3.8}`

### Raw-Input/Input
#### Input
- eUICC APDUs observed: `BF3E` GetEID (×3), `BF20`/`BF22` GetInfo (×5), `BF2E`
  GetChallenge, `BF28` ListNotification, `BF38` AuthenticateServer, then on failure
  `BF41` **CancelSession**.
- ES9+ HTTP reached: `initiateAuthentication`, then `authenticateClient` (carries the
  matchingId).
#### Output — the logged rejection (unencrypted server error)
```json
{"header":{"functionExecutionStatus":{"status":"Failed",
  "statusCodeData":{"subjectCode":"8.1.1","reasonCode":"3.8",
  "subjectIdentifier":"EID","message":"Refused"}}}}
```
- eUICC cancel exchange:
```hex
81 E2 91 00 .. BF41 …    → BF41 <signed CancelSessionResponse> 9000
```
### Expected Output
On success: `LoadBoundProfilePackage` streams the **ES8+ ENCRYPTED** BPP segments
into the eUICC and a profile installs. **Here** the SM-DP+ has no order for this EID,
so it refuses at `authenticateClient` (**`8.1.1/3.8`**) — the encrypted BPP never
flows, and lpac issues `CancelSession`.
### Notes
- We could not obtain a *new free* activation code bound to this EID, so a full
  successful install (with encrypted BPP capture) was not reproducible here. The
  earlier BetterRoaming installs (this project's dataset) captured the successful
  path. The **encrypted** direction (BPP → eUICC) only appears once
  `authenticateClient` succeeds; every failure short-circuits before it.
- Other rejection modes catalogued this project: matchingId refused `8.2.6/3.8`,
  pool empty `9.4/10.1`, test-CI `8.8.4/3.7`, Google test-profile server `8.8.2/3.1`.

## `fw.getEid()` / `fw.getEuiccInfo()`  (framework EuiccManager)

The Android framework path (`--backend fw`) via `EuiccManager`, routed through the
**stock** LPA. Reads succeed; RSP bodies are opaque (result codes only).

- I/O format: `fw.getEid()` <-- `{EID 89033023…6816, available=true}`

### Raw-Input/Input
#### Input
```
EuiccManager.getEid()        (binder call, no APDU visible to us)
EuiccManager.isEnabled       → available
```
#### Output
```json
{"eid":"89033023427100000000027143866816","available":true,"ok":true}
```
### Expected Output
Same EID as the lpac path. Matches — confirms both stacks see one eUICC.
### Notes
- Download/switch/delete via `fw` return only a framework `resultCode`; the ES9+
  plaintext is **not** observable on this path (use the lpac backend for that).

## `card.requestEuiccChallenge()` (framework IEuiccCardController — 2nd path)

The per-command card interface reached by reflecting `EuiccCardManager` from
OpenEUICC's process — an independent ES10 path through the stock card stack.

- I/O format: `card.requestEuiccChallenge()` <-- `{resultCode -3 RESULT_CALLER_NOT_ALLOWED}`

### Raw-Input/Input
#### Input
```
EuiccCardManager(context).requestEuiccChallenge(cardId=<EID>, executor, ResultCallback)
```
#### Output
```json
{"method":"requestEuiccChallenge","cardId":"89033023…6816","resultCode":-3,
 "resultName":"RESULT_CALLER_NOT_ALLOWED","ok":false}
```
### Expected Output
On the active LPA this would return the challenge bytes. **Here** the binder
transaction succeeds but the stock `EuiccCardController` gates every command on the
caller being the device's active LPA → **`-3`**.
### Notes
- Verified separately: raising OpenEUICC's `EuiccService` priority flips the gate
  (`-3 → -1`), but the stock card then dies on the RIL/QMI transport the Samsung
  modem doesn't expose — so this path yields nothing extra on this device.

---

## Capture environment

- Device: Pixel 7a (lynx), Android 17, Magisk root. eUICC EID
  `89033023427100000000027143866816`, ISD-R `A0000005591010FFFFFFFF8900000100`,
  SGP.22 v2.3, production CI `81370F…BEBFB`.
- Transport: **OMAPI** (Samsung S.LSI RIL exposes no QMI/AT to the eUICC).
- Tooling: `tools/esimctl/esimctl.py` (lpac backend) — every raw request/response
  pair above is logged verbatim by `OmapiApduInterface` in each op's
  `sessions/esimctl/<ts>-<op>/logcat.txt`; ES9+ plaintext by `HttpInterfaceImpl`.
- eUICC left clean after capture: 2 disabled BetterRoaming profiles, no nicknames,
  empty default SM-DP+ address.
