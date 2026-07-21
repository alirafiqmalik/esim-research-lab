# Docs index

Canonical entry point: [reference/euicc-api.md](reference/euicc-api.md) — the
source-verified eUICC API layer map (command → APDU tag → exposure).

## reference/

- [euicc-api.md](reference/euicc-api.md) — every eUICC API layer reachable on the testbed, with exposure matrix and trust boundary.
- [euicc-api-capability-map.md](reference/euicc-api-capability-map.md) — higher-level narrative of the same capabilities.
- [eUICC-IO-mapping.md](reference/eUICC-IO-mapping.md) — index of eUICC input/output mappings.
- [default-lpa-exploration.md](reference/default-lpa-exploration.md) — unlocking the IEuiccCardController path on the stock LPA.

## research/

- [google-lpa-vs-openeuicc-rsp.md](research/google-lpa-vs-openeuicc-rsp.md) — stock Google LPA + Frida vs OpenEUICC for RSP capture.
- [research-aosp-esim-testing.md](research/research-aosp-esim-testing.md) — AOSP / Google eSIM test infrastructure.
- [research-gsma-ts48-test-profile.md](research/research-gsma-ts48-test-profile.md) — GSMA TS.48 generic eUICC test profile.
- [research-other-free-esim-codes.md](research/research-other-free-esim-codes.md) — other free production-CI eSIM activation codes.
- [research-repeatable-esim-issuer.md](research/research-repeatable-esim-issuer.md) — repeatable eSIM issuer for RSP protocol testing.
- [research-researcher-esim-access.md](research/research-researcher-esim-access.md) — researcher access to a production-CI SM-DP+.
- [research-rsp-testing-certificate-workarounds.md](research/research-rsp-testing-certificate-workarounds.md) — the CI-trust problem and workarounds.
- [rsp-dataset-analysis.md](research/rsp-dataset-analysis.md) — the RSP dataset we work with.

## testbed/

- [testbed-evaluation.md](testbed/testbed-evaluation.md) — evaluation of the RSP testbed.
- [testbed-fixes-spec.md](testbed/testbed-fixes-spec.md) — implementation spec for the testbed fixes.
- [testbed-test-report-2026-07-16.md](testbed/testbed-test-report-2026-07-16.md) — test report from 2026-07-16.
- [betterroaming-activation.md](testbed/betterroaming-activation.md) — BetterRoaming eSIM activation notes.

## Other locations

- `diagrams/` — RSP flow diagrams (`.dot` sources + rendered `.png`/`.svg`).
- `msd/` — message-sequence diagram for RSP download.
- `archive/` — frozen historical notes.
</content>
