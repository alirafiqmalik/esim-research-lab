# Round 0.5 — fidelity fixes (lead), grounded in spec-verifier + comanager review

Applied before any round-1 fuzzing so findings reflect the REAL protocol, not harness bugs:
- F1: LPA now consumes the mutated C1 InitiateAuthentication.req (was discarded → round-0 C1 challenge finding was a TESTBED-ARTIFACT). C1 request-side is now live.
- F2: C2b is now the real modem APDU transport. GET commands cross C2b→eUICC.dispatch_apdu (new ISO-7816 status-word parser). C2b flipped 40/40 accepted → 40/40 rejected (mutations now reach a real parser). Rooted-baseband threat model.
- F5 (subsumes F3): ctxParams1 modeled. eUICC signs it UNCHECKED per §5.7.13; SM-DP+ selects order by the signed matchingId and rejects unknown ids. ICCID now varies per run.
- F4: SmdpSigned2 = {transactionId, ccRequiredFlag, bppEuiccOtpk} per §5.7.5; profileMetadata deliberately NOT covered (the §4.4 plaintext-consent gap).

Post-fix baseline: 6 clean verified runs, 16 msgs/run, 21 invariant / 28 variable fields.
