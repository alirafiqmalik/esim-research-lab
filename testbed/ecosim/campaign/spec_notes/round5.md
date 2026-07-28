# Round 5 (final) — spec-grounded facts (SGP.22 v3.1)

## Q15 — Post-install profile lifecycle authorization: ZERO caller authentication, confirmed
§5.7.16-19 (EnableProfile BF31, DisableProfile BF32, DeleteProfile BF33, EuiccMemoryReset BF34),
§3.2.1-3 procedures. Every eUICC-side verification for these LPM (Local Profile Management) calls is
purely structural/policy-state: profile exists (else `iccidOrAidNotFound`), correct enable/disable state
(else `profileNotInDisabledState`/`profileNotInEnabledState`), Profile Policy Rules allow it (else
`disallowedByPolicy`, business-logic set by the carrier at install time, NOT caller authentication),
enterprise/test/MEP bookkeeping. **No PIN, no signed command, no confirmation-code equivalent, no
profile-owner cryptographic check anywhere in the local-call eUICC processing.** The only crypto/identity
check anywhere near these functions is on the structurally distinct RPM path (commands arrive wrapped in a
signed `LoadRpmPackageRequest` from a network SM-DP+) -- entirely absent from the local ES10c call path.

**"Authorization" for these operations exists only as an unenforceable Device/LPAd-side UX obligation**:
§3.2.1-3 "Start Conditions" require "User Intent... as defined in SGP.21" and Delete additionally requires
"Strong Confirmation by presenting the consequences" -- but this is a UI dialog the LPAd is supposed to show,
never passed to, encoded for, or verifiable by the eUICC. The eUICC has no way to know whether a caller is
the legitimate LPAd-after-consent or anything else capable of framing an ES10c command.

**No network/SM-DP+ involvement required at all** -- confirmed: the LPM procedures are pure local sequences
(End User -> LPAd -> ISD-R -> baseband), work in airplane mode, zero connectivity needed.

**EuiccMemoryReset (BF34) is even more permissive**: deletes entire profile *categories* (Operational/Test/
Provisioning) in one call "regardless of their enabled status or any Profile Policy Rules" -- bypasses even
the one soft protection (PPR) the other three respect.

**The only real access-control gate is outside SGP.22 entirely**: which caller may open a logical channel to
ISD-R at all is a Device/OS-level question (e.g. Android's `WRITE_EMBEDDED_SUBSCRIPTIONS` / system-LPA
privilege) -- platform security, not RSP protocol security, never referenced by SGP.22. On a rooted device
(this project's exact threat model), that gate is precisely what root access removes.

**Verdict**: confirmed as a high-confidence, high-severity finding -- arguably more severe than any
download-flow finding in this campaign, since it requires no signature forgery, no server impersonation, and
no network reachability at all. Once an attacker can frame raw ES10c APDUs (rooted local access, or a local
APDU-path MITM), there is categorically nothing left to forge or bypass for enable/disable/delete -- only
structural checks a well-formed malicious request satisfies trivially.

## Session close
Spec-verifier signed off after this round: "genuinely thorough five-round session." No further rounds planned.
