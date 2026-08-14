# Cellular IMEI: spoofing, rewrite, and cloning

Scope: the equipment IMEI the modem reports over the air at LTE/5G attach. This is a
different identifier from the RSP `deviceInfo` IMEI (`imei-deviceinfo-threat-model.md`).
Grounded in the baseband capture (`../../testbed/baseband-attach/`) and the Pixel 7a
Shannon modem recon.

## Two different IMEIs

- **deviceInfo IMEI** — a software field the LPA fills for the SM-DP+. Caller-controlled.
  The network never sees it.
- **Cellular IMEI / IMEISV** — the equipment identity the baseband reports to the
  MME/AMF, read from modem NV. The network's EIR uses this one for device blocklisting.

The capture showed the IMEISV leaving the device in the NAS Identity Response,
unciphered, before AS security. The network does not verify it. The IMEI is
self-asserted equipment identity with no cryptographic binding to the device.

## Can it be changed?

Two paths. Both are gated, and altering an IMEI is illegal in many jurisdictions. We
enumerated the surfaces read-only. We did not write to any of them.

1. **Rewrite the modem NV on your own device.** The recon found `/dev/umts_rfs0`
   (radio-uid EFS) and the Samsung OEM-hook AT path (`AT+EGMR`-style engineering write).
   Modern Pixels often sign or lock the IMEI in EFS, so an arbitrary rewrite may be
   refused. Writability on this unit is untested.
2. **A controllable UE stack.** An SDR UE (srsRAN, OpenAirInterface) or a modified
   baseband can place any IMEISV in the Identity Response. That message is
   unauthenticated and pre-security, so the network accepts it verbatim. Transmitting on
   licensed spectrum is separately restricted.

Reading the IMEI over the air is the easy half. A fake eNB solicits
`Identity Request(IMEISV)` and the UE answers in the clear — the IMEI-catcher primitive.

## What happens if an attacker copies your IMEI

The IMEI is equipment identity, not subscriber identity. Traffic routes by IMSI/GUTI,
bound to the SIM/eSIM key K through AKA. An attacker with your IMEI cannot derive K.

So they do **not** receive your calls, SMS, or data. No interception. No account
takeover.

What an IMEI collision does cause:

| Effect | Mechanism | Who it hurts |
|---|---|---|
| EIR blocklist evasion | attacker puts your clean IMEI on a stolen or blocked device to dodge the EIR | the classic cloning motive |
| Blocklisting you (DoS) | the operator sees one IMEI live in two places, flags cloning, blocklists the IMEI, and your device is denied | you |
| False attribution | logs, lawful intercept, and theft cases treat two devices as one; activity is misattributed to your equipment | you |

The collision works because the IMEI is self-asserted and unauthenticated. Your service
security rides on the SIM/eSIM AKA key, which none of this exposes.

## The multi-profile question

A single eSIM device reports the same IMEI across many profile IMSIs, yet does not trip
the cloning detector above. That interaction has its own analysis in
`esim-multiprofile-eir-cloning.md`.
