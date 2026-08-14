# eSIM multi-profile vs EIR cloning detection

Question: a single eSIM device presents the same IMEI and the same EID across many
profile IMSIs. If operators flag "same IMEI, different IMSI" as cloning, why is every
eSIM user not flagged? Researched against EIR cloning-detection patents, the GSMA
multi-SIM specs, and the Android MEP documentation.

## EIR pairing is anchored on the IMSI, not the IMEI

The EIR "married" pairing model is asymmetric:

- **Same IMSI, different IMEI, live at once → IMSI clone.** Once an IMSI is married to
  an IMEI, a mismatch on a live session means the subscriber identity was copied. This
  is a hard deny.
- **Same IMEI, different IMSI → further checking, not a block.** An IMEI seen with other
  IMSIs prompts a history search, not a denial. One handset serving many IMSIs is the
  expected case: every SIM swap, travel SIM, and eSIM profile.

Sequential profile switching — old IMSI detaches, new IMSI attaches, same IMEI, later in
time — is normal and resolves as legitimate.

## Concurrency uses a separate IMEI per radio

The only cloning-like signature is one IMEI live in two places at once. Multi-SIM
hardware avoids producing it:

- Dual-SIM devices carry **IMEI1 and IMEI2**, one per baseband. DSDS keeps one active at
  a time; DSDA/DSFA runs both, each on its own IMEI.
- **MEP** (Multiple Enabled Profiles, SGP.22 v3.1) maps each eUICC port 1:1 to a modem
  baseband. Two profiles enabled at once present two different IMEIs, not one twice.

A legitimate device never double-presents a single IMEI.

## The EID is not in this loop

The EID identifies the eUICC chip and lives in the RSP/provisioning plane (SM-DP+, LPA,
`deviceInfo`). The cellular attach and EIR path keys on IMEI and IMSI. It never sees the
EID. "Same EID across profiles" is invisible to the cellular EIR.

## Why your case differs from the attacker's

| Scenario | Network sees | EIR reaction |
|---|---|---|
| Switching eSIM profiles | 1 IMEI, many IMSIs, sequential | normal |
| DSDS / MEP, two profiles active | 2 IMEIs, one per baseband | normal |
| Attacker clones your IMEI | 1 IMEI in two places at once | cloning signature → scrutiny / blocklist |

The attack manufactures the exact simultaneity a legitimate device never creates. The
identifiers stay layered: subscriber security on the SIM/eSIM AKA key, equipment
tracking on the self-asserted IMEI, eUICC identity on the EID. One IMEI serving many
profile IMSIs is the intended model, not a cloning event.

## Sources

- US8010083B2 — Detection of cloned identifiers in communication systems.
  https://patents.google.com/patent/US8010083B2/en
- US11445375 — Systems and methods for network access security (EIR married-state
  pairing). https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/11445375
- GSMA TS.37 — Requirements for Multi-SIM Devices v9.0.
  https://www.gsma.com/newsroom/wp-content/uploads//TS.37-v9.0.pdf
- Amarisoft — LTE Dual SIM. https://tech-academy.amarisoft.com/LTE_DualSim.html
- Commsbrief — IMEI 1 and IMEI 2: why a phone has two IMEI numbers.
  https://commsbrief.com/imei-1-and-imei-2-why-my-phone-has-two-imei-numbers/
- Android — Multiple enabled profiles (MEP).
  https://source.android.com/docs/core/connect/esim-mep
- GSMA — What is MEP.
  https://www.gsma.com/get-involved/gsma-membership/gsma_resources/what-is-mep-comprion/
