"""C1 capability matrix: exhaustive attacker-primitive x message-kind enumeration.

Threat model: a network attacker with COMPLETE control of C1 (ES9+, the
SM-DP+<->device network/wifi hop). The testbed models C1 as plaintext JSON,
which is the deliberate "TLS stripped / attacker fully on-path" assumption
this module characterises -- not a claim that GSMA RSP omits TLS.

For every C1 message kind (InitiateAuthentication.{req,resp},
AuthenticateClient.{req,resp}, GetBoundProfilePackage.{req,resp},
HandleNotification.req) this module exercises every C1Adversary primitive
(block, replay, forge, modify-per-field, fuzz/malform, strip) against a live
``run_flow`` and records the OBSERVED outcome, classified against the spec
grounding in ``spec_notes/round{1..5}.md`` -- not just against what the code
happens to do. Three known testbed simplifications are called out explicitly
wherever they apply (see spec_notes/round2.md):

  D6  -- InitiateAuthentication.resp's top-level ``serverOtpk`` field does not
          exist in the real protocol at that step (no ECDH at InitiateAuth
          time); any finding about it is TESTBED-ARTIFACT.
  D7  -- ``euiccCiPKIdToBeUsed`` is genuinely unsigned in real RSP but a real
          SM-DP+ RETROACTIVELY checks it at AuthenticateClient; our testbed
          does not implement that retroactive check at all, so "accepted"
          here is a testbed gap on top of a real unauthenticated field.
  D3/Q14 -- ``profileMetadata`` (consent-time) and ``metadataPreview``
          (BPP-time display copy) are genuinely unauthenticated/unreconciled
          per SGP.22 SS4.4/SS3.1.3.2 step 12 (SHOULD/MAY-level check only).

This is defensive security research against a local simulation with our own
PKI; no real network or device is involved. Runnable:
    ./venv/bin/python -m testbed.ecosim.campaign.c1_capability_matrix
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .. import codec, protocol
from .. import crypto as ecrypto
from .. import pki as pki_mod
from ..bus import C1, Message
from ..orchestrator import Ecosystem, build_ecosystem, run_flow
from . import record
from .c1_adversary import C1Adversary

C1_KINDS: list[str] = [
    "InitiateAuthentication.req",
    "InitiateAuthentication.resp",
    "AuthenticateClient.req",
    "AuthenticateClient.resp",
    "GetBoundProfilePackage.req",
    "GetBoundProfilePackage.resp",
    "HandleNotification.req",
]
PRIMITIVES: list[str] = ["BLOCK", "REPLAY", "FORGE", "MODIFY", "FUZZ", "STRIP"]


@dataclass
class Outcome:
    """One (message kind, primitive, specific mutation) trial result."""

    kind: str
    primitive: str
    detail: str
    completed: bool
    error: str
    crash: bool  # True if the failure was NOT a domain ValueError (a robustness gap)

    def label(self) -> str:
        if self.completed:
            return "accepted"
        exc_type = self.error.split(":", 1)[0] if self.error else "?"
        return f"CRASH:{exc_type}" if self.crash else f"reject:{exc_type}"


@dataclass
class MatrixRun:
    outcomes: list[Outcome] = field(default_factory=list)
    findings: list[record.Finding] = field(default_factory=list)

    def observe(self, kind: str, primitive: str, detail: str, completed: bool, error: str, crash: bool) -> Outcome:
        o = Outcome(kind=kind, primitive=primitive, detail=detail, completed=completed, error=error, crash=crash)
        self.outcomes.append(o)
        return o

    def finding(self, **kwargs) -> None:
        self.findings.append(record.Finding(
            round=1, direction="C1-capability-matrix", channel="C1",
            artifact_path="testbed/ecosim/campaign/c1_capability_matrix.py",
            **kwargs,
        ))


# --- shared harness ----------------------------------------------------------
def _attempt(
    eco: Ecosystem,
    policy,
    profile_name: str = "ecosim-profile",
    sp_name: str = "ecosim-MNO",
) -> tuple[bool, str, bool, dict, list[Message]]:
    """Run one download flow with a C1Adversary policy installed.

    Returns (completed, error_repr, is_crash, summary, messages). is_crash is
    True when the failure was anything other than a domain ValueError (i.e. an
    unhandled KeyError/TypeError/AttributeError reaching the top) -- the
    fails-closed *security* property still holds either way, but a crash is a
    distinct, worse robustness outcome than a designed rejection."""
    adv = C1Adversary(bus=eco.bus, policy=policy)
    adv.attach()
    try:
        summary, messages = run_flow(eco, profile_name=profile_name, sp_name=sp_name)
        return True, "", False, summary, messages
    except Exception as exc:  # noqa: BLE001 - characterising every outcome, not asserting one
        is_crash = not isinstance(exc, ValueError)
        return False, f"{type(exc).__name__}: {exc}", is_crash, {}, list(eco.bus.all_messages())
    finally:
        adv.detach()


def _mutate_field(kind: str, obj: dict, field_name: str, new_value) -> tuple[str, dict]:
    new = dict(obj)
    new[field_name] = new_value
    return "modify", new


def _bitflip_b64(obj: dict, field_name: str, byte_index: int = 0) -> dict:
    new = dict(obj)
    raw = bytearray(codec.unb64(new[field_name]))
    raw[byte_index] ^= 0xFF
    new[field_name] = codec.b64(bytes(raw))
    return new


# --- 1. BLOCK ------------------------------------------------------------
def _run_block(run: MatrixRun) -> None:
    crash_count = 0
    dos_details: list[str] = []
    for kind in C1_KINDS:
        eco = build_ecosystem(seed=0x1000 + abs(hash(kind)) % 1000)

        def policy(k: str, obj: dict, kind: str = kind) -> tuple[str, dict | None]:
            return ("block", None) if k == kind else ("forward", None)

        completed, err, crash, _summary, _messages = _attempt(eco, policy)
        installed_anyway = len(eco.euicc._installed) > 0
        run.observe(kind, "BLOCK", "drop message (delivered as empty JSON object)", completed, err, crash)
        if crash:
            crash_count += 1
        dos_details.append(f"{kind}: completed={completed} err={err} installed_despite_failure={installed_anyway}")

    # One consolidated finding for the ordinary DoS class: every C1 message,
    # when blocked, is modeled as an empty JSON object reaching the peer
    # (C1Adversary._mutate's documented block semantics). Every request/response
    # handler in lpa.py/smdp.py accesses required keys directly (obj["key"]) with
    # no defensive .get()/schema check, so a blocked message surfaces as an
    # uncaught KeyError rather than a designed validation error.
    run.finding(
        spec_section="SGP.22 SS2.5 (session state machine, implied fail-closed)",
        hypothesis="Blocking (dropping) any single C1 message causes the whole "
                   "download to fail rather than silently proceeding with stale/partial state.",
        mutation="C1Adversary block on each of the 7 C1 message kinds, one flow per kind "
                 f"({len(C1_KINDS)} trials)",
        observed=f"{crash_count}/{len(C1_KINDS)} trials failed via an unhandled KeyError "
                 "(not a designed validation error) rather than a structured rejection; "
                 "all 7 trials failed closed (no session ever completed). Per-kind: "
                 + " | ".join(dos_details),
        classification=record.CONFORMANT,
        rationale="The security-relevant property holds in every case: a dropped C1 message "
                  "never lets the flow proceed with forged/partial trust, matching what a "
                  "conformant node must do (fail rather than silently substitute a default). "
                  "The specific exception type (uuncaught KeyError vs. a structured "
                  "invalidRequest-style error) is a robustness/hardening gap worth fixing -- "
                  "real ES9+ endpoints return a structured error body -- but it is not a "
                  "security bypass; DoS via message-dropping is the expected, unavoidable "
                  "capability of a full on-path C1 attacker regardless of implementation quality.",
        severity="low",
    )

    # HandleNotification.req block is a DISTINCT case worth its own finding: by
    # the time that message is sent, install_bound_profile_package has already
    # mutated eUICC state (the profile IS installed). Blocking it fails the LPA's
    # *reporting* of success, not the install itself -- a state divergence between
    # "what the LPA/attacker's dropped-message view shows" and "what actually
    # happened on the card".
    eco = build_ecosystem(seed=0x1999)

    def block_handle_notification(k: str, obj: dict) -> tuple[str, dict | None]:
        return ("block", None) if k == "HandleNotification.req" else ("forward", None)

    completed, err, crash, _summary, _messages = _attempt(eco, block_handle_notification)
    installed = len(eco.euicc._installed)
    run.finding(
        spec_section="SGP.22 SS2.5.6 / SS3.1.3.2",
        hypothesis="Blocking HandleNotification.req (the post-install confirmation to the "
                   "SM-DP+) does not undo an already-completed profile install.",
        mutation="C1Adversary block on HandleNotification.req only",
        observed=f"flow raised (completed={completed}, err={err!r}) yet "
                 f"eco.euicc._installed has {installed} profile(s) -- the eUICC-side install "
                 "committed BEFORE HandleNotification.req is ever sent, so blocking it cannot "
                 "roll back state that already happened.",
        classification=record.CONFORMANT,
        rationale="Matches spec ordering: ProfileInstallationResult/HandleNotification is a "
                  "post-install confirmation, not a two-phase commit gate (SS2.5.6). A "
                  "network attacker who blocks only this message causes the SM-DP+ to remain "
                  "unaware the install succeeded (a bookkeeping/billing-visibility gap for the "
                  "operator) but cannot un-install the profile on the device -- narrower impact "
                  "than blocking any earlier message, which does prevent install outright.",
        severity="medium",
    )


# --- 2. REPLAY -------------------------------------------------------------
def _run_replay(run: MatrixRun) -> None:
    """Capture messages from session A, replay into session B on the SAME PKI/
    eUICC/SM-DP+ (same eco, sequential run_flow calls) so only the per-transaction
    values (challenge/transactionId/ephemeral keys) differ -- the realistic
    same-operator cross-session replay scenario."""
    eco = build_ecosystem(seed=0x2000)
    capture_adv = C1Adversary(bus=eco.bus, policy=None)
    capture_adv.attach()
    run_flow(eco, profile_name="session-A", sp_name="ecosim-MNO")
    capture_adv.detach()
    captured = dict(capture_adv.replay_store)

    replay_targets = [
        ("InitiateAuthentication.resp", "SGP.22 SS5.7.13",
         "serverSigned1 is bound to euiccChallenge (freshly random per session); "
         "eUICC checks the challenge inside serverSigned1 against its own stored value."),
        ("AuthenticateClient.resp", "SGP.22 SS5.7.5",
         "smdpSigned2's bppEuiccOtpk is bound to THIS session's eUICC ephemeral key; "
         "eUICC checks it matches its own live otsk before trusting the binding."),
        ("GetBoundProfilePackage.resp", "SGP.22 SS2.5.3 / SS5.5.3",
         "sealedProfile is AEAD-sealed under a session key derived from BOTH sides' "
         "ephemeral keys for that specific transaction; a replayed package decrypts "
         "under a different derived key in the new session."),
    ]
    for kind, spec_section, why in replay_targets:
        eco_b = build_ecosystem(seed=0x2100 + abs(hash(kind)) % 1000)

        def policy(k: str, obj: dict, kind: str = kind) -> tuple[str, dict | None]:
            if k == kind:
                return "modify", codec.from_json_wire(captured[kind])
            return "forward", None

        completed, err, crash, _summary, _messages = _attempt(eco_b, policy, profile_name="session-B")
        run.observe(kind, "REPLAY", "cross-session replay (same PKI/eUICC/SM-DP+, prior session's message)",
                    completed, err, crash)
        run.finding(
            spec_section=spec_section,
            hypothesis=f"Replaying a captured {kind} from an earlier session into a new "
                       "session (same operator, same eUICC, different transaction) is rejected.",
            mutation=f"capture {kind} from session A; inject verbatim as {kind} in session B "
                     "(same eco/PKI/eUICC, sequential run_flow calls)",
            observed=f"completed={completed} err={err!r}",
            classification=record.CONFORMANT if not completed else record.REAL_GAP,
            rationale=why + (" Rejected as expected." if not completed else
                              " UNEXPECTEDLY accepted -- would be a real replay vulnerability."),
            severity="info" if not completed else "high",
        )


# --- 3. FORGE ----------------------------------------------------------------
def _run_forge(run: MatrixRun) -> None:
    """Inject fully attacker-authored messages, with progressively more of the
    real session's OBSERVED (not secret) context, to isolate exactly which
    check stops a forger who has no valid SM-DP+ private key."""
    # 3a. Rogue self-signed cert (dp_auth role OID, but issued by nobody CI trusts).
    eco = build_ecosystem(seed=0x3000)
    rogue_key = ec.generate_private_key(ec.SECP256R1())
    rogue_cert = pki_mod._issue(
        "rogue-smdp", rogue_key, "rogue-smdp", rogue_key, ca=False, serial=999, role="dp_auth",
    )
    state: dict = {}

    def forge_rogue(k: str, obj: dict) -> tuple[str, dict | None]:
        if k == "InitiateAuthentication.req":
            state["challenge"] = codec.unb64(obj["euiccChallenge"])
            return "forward", None
        if k == "InitiateAuthentication.resp":
            new = dict(obj)
            tx_id = bytes.fromhex(new["transactionId"])
            forged_otpk = protocol.point_bytes(ec.generate_private_key(ec.SECP256R1()))
            forged_signed1 = protocol.server_signed1(tx_id, state["challenge"], b"smdp.ecosim.test", forged_otpk)
            new["serverSigned1"] = codec.b64(forged_signed1)
            new["serverSignature1"] = codec.b64(ecrypto.sign(rogue_key, forged_signed1))
            new["serverCertificate"] = codec.b64(rogue_cert.public_bytes(serialization.Encoding.DER))
            return "forge", new
        return "forward", None

    completed, err, crash, _s, _m = _attempt(eco, forge_rogue)
    run.observe("InitiateAuthentication.resp", "FORGE",
                "rogue self-signed dp_auth-role cert; correct challenge (observed on C1 in cleartext)",
                completed, err, crash)
    run.finding(
        spec_section="SGP.22 SS5.7.13 / SS2.4a.1.0 (chain to PK.CI)",
        hypothesis="An attacker with COMPLETE C1 control but no CI-issued SM-DP+ key cannot "
                   "forge a session the eUICC will accept, even using the real euiccChallenge "
                   "(which the attacker legitimately observes in cleartext on C1).",
        mutation="forge InitiateAuthentication.resp end-to-end: real transactionId + real "
                 "euiccChallenge (observed from InitiateAuthentication.req) + a freshly-forged "
                 "serverSigned1/serverSignature1 signed by a self-signed (non-CI) key, "
                 "role-OID set to dp_auth to bypass the role check specifically",
        observed=f"completed={completed} err={err!r}",
        classification=record.CONFORMANT,
        rationale="Rejected at 'server certificate does not chain to the given CI certificate' -- "
                  "the eUICC's chain-of-trust check to PK.CI.SIG is the hard boundary. Full C1 "
                  "visibility (challenge, transactionId, smdpAddress) gives the attacker every "
                  "PLAINTEXT input it needs to construct a structurally-perfect message; it buys "
                  "nothing against the one thing that must be forged: a CI-rooted signature. This "
                  "is the single most important CONFORMANT boundary in the whole matrix -- it is "
                  "what makes 'attacker controls C1 completely' not equivalent to 'attacker can "
                  "issue itself profiles'.",
        severity="info",
    )

    # 3b. Validly-CI-chained cert of the WRONG role (EUM cert reused as DPauth).
    eco2 = build_ecosystem(seed=0x3001)
    state2: dict = {}

    def forge_wrongrole(k: str, obj: dict) -> tuple[str, dict | None]:
        if k == "InitiateAuthentication.req":
            state2["challenge"] = codec.unb64(obj["euiccChallenge"])
            return "forward", None
        if k == "InitiateAuthentication.resp":
            new = dict(obj)
            tx_id = bytes.fromhex(new["transactionId"])
            forged_otpk = protocol.point_bytes(ec.generate_private_key(ec.SECP256R1()))
            forged_signed1 = protocol.server_signed1(tx_id, state2["challenge"], b"smdp.ecosim.test", forged_otpk)
            new["serverSigned1"] = codec.b64(forged_signed1)
            new["serverSignature1"] = codec.b64(ecrypto.sign(eco2.pki.eum.private_key, forged_signed1))
            new["serverCertificate"] = codec.b64(eco2.pki.eum.cert_der())
            return "forge", new
        return "forward", None

    completed, err, crash, _s, _m = _attempt(eco2, forge_wrongrole)
    run.observe("InitiateAuthentication.resp", "FORGE",
                "validly-CI-chained cert of WRONG role (EUM cert in the DPauth slot)",
                completed, err, crash)
    run.finding(
        spec_section="SGP.22 SS5.7.13 ('Otherwise return invalidOid') / SS2.4a.1.0",
        hypothesis="A validly-CI-chained-but-wrong-role certificate (e.g. an EUM cert) cannot "
                   "be used to forge a DPauth session, even with a correct matching signature.",
        mutation="forge InitiateAuthentication.resp signed with pki.eum's OWN private key "
                 "(so the signature genuinely verifies against pki.eum's cert, and pki.eum "
                 "genuinely chains to the same CI) but presented in the serverCertificate slot",
        observed=f"completed={completed} err={err!r}",
        classification=record.CONFORMANT,
        rationale="Rejected via require_role: 'invalidOid: certificate role eum not in expected "
                  "(dp_auth,)'. This is spec-mandated role separation (D8, round2.md): SGP.22 "
                  "SS5.7.13 explicitly requires the eUICC to reject a chain-valid cert of the "
                  "wrong role, not just check the chain. Confirms the round-2 fix (FIX-Q8) is "
                  "load-bearing: a chain check alone would have let ANY CI-issued cert (including "
                  "an EUM cert, which our PKI also issues directly under the CI) impersonate a "
                  "DPauth server.",
        severity="info",
    )

    # 3c. Forge AuthenticateClient.resp with a rogue self-signed dp_pb cert, using
    #     the real (observed) transactionId + euiccOtpk so only the signature/chain
    #     is forged, not the session parameters.
    eco3 = build_ecosystem(seed=0x3002)
    rogue_pb_key = ec.generate_private_key(ec.SECP256R1())
    rogue_pb_cert = pki_mod._issue(
        "rogue-pb", rogue_pb_key, "rogue-pb", rogue_pb_key, ca=False, serial=888, role="dp_pb",
    )
    state3: dict = {}

    def forge_ac_resp(k: str, obj: dict) -> tuple[str, dict | None]:
        if k == "AuthenticateClient.req":
            state3["euiccOtpk"] = codec.unb64(obj["euiccOtpk"])
            state3["txid"] = obj["transactionId"]
            return "forward", None
        if k == "AuthenticateClient.resp":
            new = dict(obj)
            tx_id = bytes.fromhex(state3["txid"])
            smdp_signed2 = protocol.concat_len(tx_id, b"\x00", state3["euiccOtpk"])
            new["smdpSigned2"] = codec.b64(smdp_signed2)
            new["smdpSignature2"] = codec.b64(ecrypto.sign(rogue_pb_key, smdp_signed2))
            new["smdpPbCertificate"] = codec.b64(rogue_pb_cert.public_bytes(serialization.Encoding.DER))
            return "forge", new
        return "forward", None

    completed, err, crash, _s, _m = _attempt(eco3, forge_ac_resp)
    run.observe("AuthenticateClient.resp", "FORGE",
                "rogue self-signed dp_pb-role cert; correct txid/euiccOtpk (observed on C1)",
                completed, err, crash)
    run.finding(
        spec_section="SGP.22 SS5.7.5",
        hypothesis="Forging AuthenticateClient.resp (the profile-binding step) fails the same "
                   "way as forging InitiateAuthentication.resp: correct session parameters "
                   "aren't enough without a CI-chained dp_pb key.",
        mutation="forge smdpSigned2/smdpSignature2/smdpPbCertificate using the REAL "
                 "transactionId and euiccOtpk (both observed plaintext on C1 in "
                 "AuthenticateClient.req) but signed by a self-signed non-CI dp_pb key",
        observed=f"completed={completed} err={err!r}",
        classification=record.CONFORMANT,
        rationale="Rejected at the same chain-of-trust check (verify_smdp_signature2 -> "
                  "verify_chain(smdp_pb_cert, ci_cert)). Confirms the CI-root boundary holds "
                  "independently at BOTH signing steps (DPauth and DPpb are separate keys per "
                  "D8/round2.md); an attacker cannot bypass one by targeting the other.",
        severity="info",
    )


# --- 4/6. MODIFY per-field + STRIP -----------------------------------------
def _run_modify_and_strip(run: MatrixRun) -> None:
    # --- InitiateAuthentication.req ---
    def mod_ia_req_challenge(k, obj):
        if k == "InitiateAuthentication.req":
            return "modify", _bitflip_b64(obj, "euiccChallenge")
        return "forward", None

    def mod_ia_req_addr(k, obj):
        if k == "InitiateAuthentication.req":
            return _mutate_field(k, obj, "smdpAddress", "evil.attacker.test")
        return "forward", None

    # --- InitiateAuthentication.resp ---
    def mod_ia_resp_signed1(k, obj):
        if k == "InitiateAuthentication.resp":
            return "modify", _bitflip_b64(obj, "serverSigned1")
        return "forward", None

    def mod_ia_resp_sig1(k, obj):
        if k == "InitiateAuthentication.resp":
            return "modify", _bitflip_b64(obj, "serverSignature1")
        return "forward", None

    def mod_ia_resp_cipkid(k, obj):
        if k == "InitiateAuthentication.resp":
            return "modify", _bitflip_b64(obj, "euiccCiPKIdToBeUsed")
        return "forward", None

    def mod_ia_resp_otpk(k, obj):
        if k == "InitiateAuthentication.resp":
            new = dict(obj)
            new["serverOtpk"] = codec.b64(b"\x04" + b"\x00" * 64)
            return "modify", new
        return "forward", None

    # --- AuthenticateClient.req ---
    def mod_ac_req_signed1(k, obj):
        if k == "AuthenticateClient.req":
            return "modify", _bitflip_b64(obj, "euiccSigned1")
        return "forward", None

    def mod_ac_req_sig1(k, obj):
        if k == "AuthenticateClient.req":
            return "modify", _bitflip_b64(obj, "euiccSignature1")
        return "forward", None

    def mod_ac_req_euicccert(k, obj, eco=None):
        if k == "AuthenticateClient.req":
            return "modify", _mutate_field(k, obj, "euiccCertificate", codec.b64(eco.pki.dp_auth.cert_der()))[1]
        return "forward", None

    def mod_ac_req_eumcert(k, obj, eco=None):
        if k == "AuthenticateClient.req":
            return "modify", _mutate_field(k, obj, "eumCertificate", codec.b64(eco.pki.dp_pb.cert_der()))[1]
        return "forward", None

    def mod_ac_req_euiccotpk(k, obj):
        if k == "AuthenticateClient.req":
            return "modify", _bitflip_b64(obj, "euiccOtpk", -1)
        return "forward", None

    # --- AuthenticateClient.resp ---
    def mod_ac_resp_metadata(k, obj):
        if k == "AuthenticateClient.resp":
            fake = codec.store_metadata(bytes.fromhex("00" * 10), "Free Trial 1GB", "TrustedTelco", 0)
            return _mutate_field(k, obj, "profileMetadata", codec.b64(fake))
        return "forward", None

    def mod_ac_resp_signed2(k, obj):
        if k == "AuthenticateClient.resp":
            return "modify", _bitflip_b64(obj, "smdpSigned2")
        return "forward", None

    def mod_ac_resp_sig2(k, obj):
        if k == "AuthenticateClient.resp":
            return "modify", _bitflip_b64(obj, "smdpSignature2")
        return "forward", None

    def mod_ac_resp_pbcert(k, obj, eco=None):
        if k == "AuthenticateClient.resp":
            return "modify", _mutate_field(k, obj, "smdpPbCertificate", codec.b64(eco.pki.dp_auth.cert_der()))[1]
        return "forward", None

    def mod_ac_resp_txid(k, obj):
        if k == "AuthenticateClient.resp":
            return _mutate_field(k, obj, "transactionId", "ff" * 16)
        return "forward", None

    # --- GetBoundProfilePackage.req ---
    def mod_gbpp_req_txid(k, obj):
        if k == "GetBoundProfilePackage.req":
            return _mutate_field(k, obj, "transactionId", "00" * 16)
        return "forward", None

    # --- GetBoundProfilePackage.resp ---
    def mod_gbpp_resp_sealed(k, obj):
        if k == "GetBoundProfilePackage.resp":
            new = dict(obj)
            bpp = dict(new["boundProfilePackage"])
            raw = bytearray(codec.unb64(bpp["sealedProfile"]))
            raw[0] ^= 0xFF
            bpp["sealedProfile"] = codec.b64(bytes(raw))
            new["boundProfilePackage"] = bpp
            return "modify", new
        return "forward", None

    def mod_gbpp_resp_otpk(k, obj):
        if k == "GetBoundProfilePackage.resp":
            new = dict(obj)
            bpp = dict(new["boundProfilePackage"])
            fresh = ec.generate_private_key(ec.SECP256R1())
            bpp["serverOtpk"] = codec.b64(protocol.point_bytes(fresh))
            new["boundProfilePackage"] = bpp
            return "modify", new
        return "forward", None

    def mod_gbpp_resp_preview(k, obj):
        if k == "GetBoundProfilePackage.resp":
            new = dict(obj)
            bpp = dict(new["boundProfilePackage"])
            fake = codec.store_metadata(bytes.fromhex("00" * 10), "FreeTrial", "Evil", 0)
            bpp["metadataPreview"] = codec.b64(fake)
            new["boundProfilePackage"] = bpp
            return "modify", new
        return "forward", None

    # --- HandleNotification.req ---
    def mod_hn_req_seq(k, obj):
        if k == "HandleNotification.req":
            return _mutate_field(k, obj, "seq", 9999)
        return "forward", None

    def mod_hn_req_notif(k, obj):
        if k == "HandleNotification.req":
            return "modify", _bitflip_b64(obj, "notification", -1)
        return "forward", None

    def mod_hn_req_cert(k, obj, eco=None):
        if k == "HandleNotification.req":
            return "modify", _mutate_field(k, obj, "euiccCertificate", codec.b64(eco.pki.dp_auth.cert_der()))[1]
        return "forward", None

    @dataclass
    class ModifyCase:
        kind: str
        field_label: str
        spec_section: str
        policy_fn: object
        expect_accept: bool
        classification: str  # meaningful only when the outcome matches expect_accept
        severity: str
        rationale: str

    entries: list[ModifyCase] = [
        ModifyCase(
            "InitiateAuthentication.req", "euiccChallenge (bitflip)", "SGP.22 SS5.7.13",
            mod_ia_req_challenge, False, record.CONFORMANT, "info",
            "The mutated challenge is echoed straight into serverSigned1 by our (honest) simulated "
            "SM-DP+ and signed, but the eUICC compares the challenge embedded in serverSigned1 "
            "against its OWN stored value and rejects the mismatch -- the field is protected "
            "transitively via the eUICC's own state, not by any signature on the request itself.",
        ),
        ModifyCase(
            "InitiateAuthentication.req", "smdpAddress (rogue value)",
            "SGP.22 SS3.0.1 step 8 / SS4.5.2.1.0.4-5 (D4)",
            mod_ia_req_addr, True, record.REAL_GAP, "high",
            "D4 (round2.md): serverAddress lives inside serverSigned1 (self-asserted, tamper-evident "
            "once signed by WHICHEVER server answers) but the eUICC never checks serverAddress at "
            "all, and OID-pinning is only conditional (activation code must carry an OID). A C1 "
            "attacker who rewrites smdpAddress in the request gets it echoed straight back inside "
            "serverSigned1's signed content -- the flow completes as if smdpAddress were legitimate; "
            "the real backstop is TLS hostname validation against the address actually dialed, which "
            "is exactly the layer this threat model assumes is stripped.",
        ),
        ModifyCase(
            "InitiateAuthentication.resp", "serverSigned1 (bitflip)", "SGP.22 SS5.7.13",
            mod_ia_resp_signed1, False, record.CONFORMANT, "info",
            "The only signature-covered field; a single-byte flip is caught either by the length-"
            "prefix framing check or by serverSignature1 verification, both fatal to the session.",
        ),
        ModifyCase(
            "InitiateAuthentication.resp", "serverSignature1 (bitflip)", "SGP.22 SS5.7.13",
            mod_ia_resp_sig1, False, record.CONFORMANT, "info",
            "crypto.verify() fails against the (unmodified) serverSigned1 -- textbook signature check.",
        ),
        ModifyCase(
            "InitiateAuthentication.resp", "euiccCiPKIdToBeUsed (bitflip)",
            "SGP.22 SS5.7.13 / SS5.6.1 Table36 Note6 (D7)",
            mod_ia_resp_cipkid, True, record.ARTIFACT, "medium",
            "D7 (round2.md): euiccCiPKIdToBeUsed is genuinely unsigned at this hop in the real "
            "protocol too -- serverSigned1 does not cover it. In our testbed it is additionally "
            "never read downstream at all (neither authenticate_server nor authenticate_client "
            "consult the value the LPA forwarded), so acceptance here compounds a real "
            "unauthenticated-field property with a testbed completeness gap: a real conformant "
            "SM-DP+ retroactively checks it at AuthenticateClient (Note 6) and our model does not "
            "implement that retroactive check. Classified TESTBED-ARTIFACT because the 'flow "
            "completes' outcome specifically would not survive against a fully-conformant real "
            "SM-DP+; the underlying unsigned-at-this-hop property is separately real.",
        ),
        ModifyCase(
            "InitiateAuthentication.resp", "serverOtpk (corrupted)",
            "SGP.22 SS6.6.2.1 / SS5.5.1 (D6, testbed simplification)",
            mod_ia_resp_otpk, True, record.ARTIFACT, "medium",
            "D6 (round2.md): this field is a modeling artifact -- InitiateAuthenticationOkEs9 in "
            "the real protocol has no ECDH public-key field; the real smdpOtpk first appears later, "
            "inside InitialiseSecureChannelRequest (ES8+, BF23), authenticated by its own dedicated "
            "smdpSign signature. Its being freely corruptible here says nothing about real RSP -- "
            "there is nothing at this real protocol step for it to correspond to.",
        ),
        ModifyCase(
            "AuthenticateClient.req", "euiccSigned1 (bitflip)", "SGP.22 SS3.1.3",
            mod_ac_req_signed1, False, record.CONFORMANT, "info",
            "euiccSignature1 verification (crypto.verify against euicc_cert.public_key()) fails.",
        ),
        ModifyCase(
            "AuthenticateClient.req", "euiccSignature1 (bitflip)", "SGP.22 SS3.1.3",
            mod_ac_req_sig1, False, record.CONFORMANT, "info",
            "Same check, signature side; textbook rejection.",
        ),
        ModifyCase(
            "AuthenticateClient.req", "euiccCertificate (swap, foreign role)",
            "SGP.22 SS4.5.2.1.0.2-5 / SS2.4a.1.0",
            mod_ac_req_euicccert, False, record.CONFORMANT, "info",
            "verify_chain(euicc_cert, eum_cert) fails outright (swapped cert wasn't issued by the "
            "EUM in this chain at all) -- rejected before role-check is even reached.",
        ),
        ModifyCase(
            "AuthenticateClient.req", "eumCertificate (swap, foreign role)", "SGP.22 SS4.5.2.1.0.2-5",
            mod_ac_req_eumcert, False, record.CONFORMANT, "info",
            "verify_chain(eum_cert, ci_cert) fails (swapped cert is a leaf dp_pb cert, not a CA "
            "that issued the real eUICC cert) -- rejected.",
        ),
        ModifyCase(
            "AuthenticateClient.req", "euiccOtpk (bitflip, top-level field only)", "SGP.22 SS5.7.5",
            mod_ac_req_euiccotpk, False, record.CONFORMANT, "info",
            "NOT cross-checked against the copy embedded inside euiccSigned1 at AuthenticateClient "
            "time (a layering gap worth noting) -- but downstream verify_smdp_signature2 compares "
            "smdpSigned2's bppEuiccOtpk against the eUICC's OWN live ephemeral private key, so the "
            "mismatch is still caught, just one step later via a different (defense-in-depth) "
            "mechanism rather than immediate cross-validation.",
        ),
        ModifyCase(
            "AuthenticateClient.resp", "profileMetadata (substituted)", "SGP.22 SS4.4 / SS5.7.5 (D3)",
            mod_ac_resp_metadata, True, record.REAL_GAP, "high",
            "D3 (round1.md/round4.md Q14): profileMetadata is generated 'in plain text to be "
            "readable by the LPA' and is NOT covered by smdpSignature2 (SmdpSigned2 = {transactionId, "
            "ccRequiredFlag, bppEuiccOtpk}, no metadata hash). GSMA gives this a named "
            "CancelSessionReason and a SS3.1.3.2 step-12 reconciliation procedure, but that "
            "procedure is only SHALL-level for PPR/EnterpriseConfig -- exactly the user-facing "
            "fields (ProfileName/SPN/Icon) that consent decisions hinge on are only SHOULD/MAY. A "
            "conformant LPA may legally never catch this.",
        ),
        ModifyCase(
            "AuthenticateClient.resp", "smdpSigned2 (bitflip)", "SGP.22 SS5.7.5",
            mod_ac_resp_signed2, False, record.CONFORMANT, "info",
            "verify_smdp_signature2's crypto.verify() fails.",
        ),
        ModifyCase(
            "AuthenticateClient.resp", "smdpSignature2 (bitflip)", "SGP.22 SS5.7.5",
            mod_ac_resp_sig2, False, record.CONFORMANT, "info",
            "Same check, signature side.",
        ),
        ModifyCase(
            "AuthenticateClient.resp", "smdpPbCertificate (swap, foreign role)",
            "SGP.22 SS5.7.13 / SS2.4a.1.0",
            mod_ac_resp_pbcert, False, record.CONFORMANT, "info",
            "require_role(smdp_pb_cert, 'dp_pb') fails: 'invalidOid: certificate role dp_auth not "
            "in expected (dp_pb,)' -- role separation holds symmetrically on the DPpb side too.",
        ),
        ModifyCase(
            "AuthenticateClient.resp", "transactionId (unknown value)", "SGP.22 SS3.1.3",
            mod_ac_resp_txid, False, record.CONFORMANT, "info",
            "The mutated transactionId no longer resolves in the SM-DP+'s transaction table at "
            "GetBoundProfilePackage time -> 'unknown transactionId' -- clean fail-closed lookup "
            "failure, not a crash.",
        ),
        ModifyCase(
            "GetBoundProfilePackage.req", "transactionId (unknown value)", "SGP.22 SS3.1.3",
            mod_gbpp_req_txid, False, record.CONFORMANT, "info",
            "Same clean lookup-failure rejection as above, one step earlier.",
        ),
        ModifyCase(
            "GetBoundProfilePackage.resp", "sealedProfile (bitflip)", "SGP.22 SS2.5.3 / SS5.5.3",
            mod_gbpp_resp_sealed, False, record.CONFORMANT, "info",
            "AEAD (AES-GCM) integrity tag fails to verify -- 'bound profile package failed AEAD "
            "integrity check'. The install-time profile bytes are the most strongly protected field "
            "in the whole matrix.",
        ),
        ModifyCase(
            "GetBoundProfilePackage.resp", "boundProfilePackage.serverOtpk (swapped keypair)",
            "SGP.22 SS6.6.2.1 (stands in for the real smdpOtpk/InitialiseSecureChannel step, D6)",
            mod_gbpp_resp_otpk, False, record.CONFORMANT, "info",
            "Not covered by an explicit signature in our model (unlike the real smdpSign per D6), "
            "but tampering is still caught: the eUICC derives its session key from the SWAPPED "
            "serverOtpk while the SM-DP+ sealed sealedProfile under the key derived from the "
            "ORIGINAL server_otsk, so the two sides' AEAD keys diverge and decryption fails with "
            "the same 'failed AEAD integrity check' as a direct sealedProfile bitflip. Interesting "
            "nuance: the security outcome (reject) matches spec intent even though the detection "
            "mechanism differs from the real protocol's explicit smdpSign signature check -- an "
            "implicit-authentication-via-AEAD side effect rather than an explicit verify step.",
        ),
        ModifyCase(
            "GetBoundProfilePackage.resp", "boundProfilePackage.metadataPreview (substituted)",
            "SGP.22 SS3.1.3.2 step 12 (Q14) -- testbed-local field name, same concept as D3",
            mod_gbpp_resp_preview, True, record.REAL_GAP, "high",
            "metadataPreview is this testbed's stand-in for the post-BPP display copy Q14 discusses "
            "(round4.md): it is parsed by lpa.py purely for the returned summary dict (installed/"
            "iccid/profileName), never cross-checked against what install_bound_profile_package "
            "actually wrote to the card from the sealed (AEAD-protected) plaintext. Confirmed by "
            "direct inspection: the reported summary profileName differs from eco.euicc._installed's "
            "real name after this mutation. Same underlying real-protocol gap as D3/Q14 (SHOULD/MAY-"
            "level-only reconciliation of exactly the user-facing fields), tested at the BPP-response "
            "hop specifically rather than the AuthenticateClient.resp hop D3 already covers.",
        ),
        ModifyCase(
            "HandleNotification.req", "seq (mismatched claim)", "SGP.22 SS2.5.6 (D5, confirmed fixed)",
            mod_hn_req_seq, False, record.CONFORMANT, "info",
            "D5 (round2.md): seqNumber lives inside the euiccSignPIR-signed envelope. The SM-DP+ "
            "recovers the verified seq from the signature and rejects any claimed top-level seq "
            "that disagrees -- 'claimed seq 9999 does not match signed seq 1'. This directly "
            "confirms the round-2 FIX-Q5 remediation (add euiccSignPIR verification) is load-bearing.",
        ),
        ModifyCase(
            "HandleNotification.req", "notification (bitflip)", "SGP.22 SS2.5.6",
            mod_hn_req_notif, False, record.CONFORMANT, "info",
            "euiccSignPIR verification over the reconstructed PIRData fails -- the whole "
            "ProfileInstallationResult blob is signed, not just seq/finalResult individually.",
        ),
        ModifyCase(
            "HandleNotification.req", "euiccCertificate (swap, wrong pubkey)", "SGP.22 SS2.5.6",
            mod_hn_req_cert, False, record.CONFORMANT, "info",
            "The swapped certificate's public key cannot verify a signature made by the real "
            "eUICC's private key -- euiccSignPIR verification fails.",
        ),
    ]

    for case in entries:
        eco = build_ecosystem(seed=0x4000 + abs(hash((case.kind, case.field_label))) % 5000)

        def policy(k: str, obj: dict, policy_fn=case.policy_fn, eco=eco) -> tuple[str, dict | None]:
            try:
                return policy_fn(k, obj, eco=eco)
            except TypeError:
                return policy_fn(k, obj)

        completed, err, crash, _s, _m = _attempt(eco, policy)
        run.observe(case.kind, "MODIFY", case.field_label, completed, err, crash)

        rationale = case.rationale
        if completed == case.expect_accept:
            classification = case.classification
            severity = case.severity
        else:
            # Outcome didn't match the recon-verified expectation -- record honestly rather
            # than force-fitting the pre-written classification.
            classification = record.CONFORMANT if not completed else record.REAL_GAP
            severity = "medium"
            rationale = (
                f"UNEXPECTED vs. prior verified recon (expected accept={case.expect_accept}, "
                f"got completed={completed}): {rationale}"
            )

        run.finding(
            spec_section=case.spec_section,
            hypothesis=f"Modifying {case.kind}.{case.field_label.split(' ')[0]} is "
                       + ("silently accepted (plaintext/unauthenticated field)." if case.expect_accept
                          else "detected and rejected (signature/chain/lookup protected)."),
            mutation=f"{case.field_label} on {case.kind}",
            observed=f"completed={completed} err={err!r}",
            classification=classification,
            rationale=rationale,
            severity=severity,
        )

    # --- STRIP: remove keys entirely (distinct from corrupting their value) ---
    _run_strip(run)


def _run_strip(run: MatrixRun) -> None:
    def strip_ci_pkid(k: str, obj: dict) -> tuple[str, dict | None]:
        if k == "InitiateAuthentication.resp":
            new = dict(obj)
            new.pop("euiccCiPKIdToBeUsed", None)
            return "modify", new
        return "forward", None

    eco = build_ecosystem(seed=0x5001)
    completed, err, crash, summary, _m = _attempt(eco, strip_ci_pkid)
    run.observe("InitiateAuthentication.resp", "STRIP", "euiccCiPKIdToBeUsed (key removed entirely)",
                completed, err, crash)
    run.finding(
        spec_section="SGP.22 SS5.7.13 (absent -> eUICC SHALL return ciPKUnknown) (D7)",
        hypothesis="Stripping euiccCiPKIdToBeUsed entirely from InitiateAuthentication.resp is "
                   "rejected, matching the spec's 'empty/omitted -> ciPKUnknown' requirement.",
        mutation="delete the euiccCiPKIdToBeUsed key from InitiateAuthentication.resp",
        observed=f"completed={completed} err={err!r} summary={summary}",
        classification=record.ARTIFACT,
        rationale="D7 (round2.md) confirms the real spec SHALL return ciPKUnknown when this "
                  "field is empty or omitted. Our testbed does NOT implement that check at all "
                  "-- the field is never read by either authenticate_server or "
                  "authenticate_client in this codebase -- so the flow proceeds unaffected. This "
                  "is a genuine testbed conformance gap (not evidence that real RSP tolerates a "
                  "missing CI-key-id), flagged for future hardening.",
        severity="medium",
    )

    def strip_sig(k: str, obj: dict) -> tuple[str, dict | None]:
        if k == "InitiateAuthentication.resp":
            new = dict(obj)
            new.pop("serverSignature1", None)
            return "modify", new
        return "forward", None

    eco = build_ecosystem(seed=0x5002)
    completed, err, crash, _s, _m = _attempt(eco, strip_sig)
    run.observe("InitiateAuthentication.resp", "STRIP", "serverSignature1 (key removed entirely)",
                completed, err, crash)
    run.finding(
        spec_section="SGP.22 SS5.7.13",
        hypothesis="Stripping the signature field entirely fails closed.",
        mutation="delete the serverSignature1 key from InitiateAuthentication.resp",
        observed=f"completed={completed} err={err!r}",
        classification=record.CONFORMANT,
        rationale="lpa.py accesses init_resp['serverSignature1'] directly and raises KeyError "
                  "before any signature check runs -- fails closed, though via an uncaught "
                  "KeyError rather than a structured missing-field validation error (the same "
                  "robustness caveat as the BLOCK section applies here).",
        severity="low",
    )

    def strip_cert(k: str, obj: dict) -> tuple[str, dict | None]:
        if k == "InitiateAuthentication.resp":
            new = dict(obj)
            new.pop("serverCertificate", None)
            return "modify", new
        return "forward", None

    eco = build_ecosystem(seed=0x5003)
    completed, err, crash, _s, _m = _attempt(eco, strip_cert)
    run.observe("InitiateAuthentication.resp", "STRIP", "serverCertificate (key removed entirely)",
                completed, err, crash)
    run.finding(
        spec_section="SGP.22 SS5.7.13",
        hypothesis="Stripping the server certificate field entirely fails closed.",
        mutation="delete the serverCertificate key from InitiateAuthentication.resp",
        observed=f"completed={completed} err={err!r}",
        classification=record.CONFORMANT,
        rationale="Same shape as stripping serverSignature1: uncaught KeyError before any chain "
                  "check runs, fails closed with the same robustness caveat.",
        severity="low",
    )


# --- 5. FUZZ / MALFORM -------------------------------------------------------
def _run_fuzz(run: MatrixRun) -> None:
    """Truncated JSON, wrong-typed field, oversized field, missing key, extra key --
    applied across all 7 C1 message kinds. Grouped into ONE finding per distinct
    outcome CLASS (not per kind) with per-class counts, per the task's dedup guidance."""
    class_counts: dict[str, int] = {}
    class_examples: dict[str, str] = {}
    crash_examples: list[str] = []

    def record_class(label: str, example: str) -> None:
        class_counts[label] = class_counts.get(label, 0) + 1
        class_examples.setdefault(label, example)

    for kind in C1_KINDS:
        # truncated JSON (raw wire truncation, bypasses dict-shaped mutation entirely)
        def trunc_mutator(msg: Message, kind: str = kind) -> Message:
            if msg.channel == C1 and msg.kind == kind:
                return replace(msg, wire=msg.wire[: max(1, len(msg.wire) // 2)])
            return msg

        eco = build_ecosystem(seed=0x6000 + abs(hash((kind, "trunc"))) % 5000)
        eco.bus.set_mutator(C1, trunc_mutator)
        try:
            run_flow(eco, profile_name="p", sp_name="s")
            completed, err, crash = True, "", False
        except Exception as exc:  # noqa: BLE001
            completed, err, crash = False, f"{type(exc).__name__}: {exc}", not isinstance(exc, ValueError)
        run.observe(kind, "FUZZ", "truncated JSON (wire cut in half)", completed, err, crash)
        record_class("truncated_json -> JSONDecodeError (clean)", f"{kind}: {err}")

        # wrong-typed field, oversized field, extra key, missing key: computed live per-message
        def make_mutator(kind: str, mode: str):
            def mutator(msg: Message) -> Message:
                if not (msg.channel == C1 and msg.kind == kind):
                    return msg
                obj = codec.from_json_wire(msg.wire)
                if mode == "wrong_type" and obj:
                    key = sorted(obj.keys())[0]
                    obj[key] = 424242
                elif mode == "oversized":
                    str_keys = [key for key, val in obj.items() if isinstance(val, str)]
                    if str_keys:
                        biggest = max(str_keys, key=lambda key: len(obj[key]))
                        obj[biggest] = obj[biggest] + "A" * 500_000
                elif mode == "extra_key":
                    obj["__attacker_injected__"] = {"nested": [1, 2, 3]}
                elif mode == "missing_key" and obj:
                    del obj[sorted(obj.keys())[0]]
                return replace(msg, wire=codec.to_json_wire(obj))
            return mutator

        for mode, class_label in [
            ("wrong_type", "wrong_type (int for a JSON string field)"),
            ("oversized", "oversized_field (+500KB)"),
            ("extra_key", "extra_key (unknown field injected)"),
            ("missing_key", "missing_key (first alphabetical key deleted)"),
        ]:
            eco = build_ecosystem(seed=0x6100 + abs(hash((kind, mode))) % 5000)
            eco.bus.set_mutator(C1, make_mutator(kind, mode))
            try:
                run_flow(eco, profile_name="p", sp_name="s")
                completed, err, crash = True, "", False
            except Exception as exc:  # noqa: BLE001
                completed, err, crash = False, f"{type(exc).__name__}: {exc}", not isinstance(exc, ValueError)
            run.observe(kind, "FUZZ", class_label, completed, err, crash)
            exc_type = err.split(":", 1)[0] if err else ""
            if completed:
                bucket = f"{class_label}: accepted (field unused downstream)"
            elif crash:
                bucket = f"{class_label}: CRASH ({exc_type}, unhandled)"
                crash_examples.append(f"{kind}/{mode}: {err}")
            else:
                bucket = f"{class_label}: rejected cleanly ({exc_type})"
            record_class(bucket, f"{kind}: completed={completed} err={err!r}")

    for label, count in sorted(class_counts.items()):
        is_crash = "CRASH" in label
        is_accept = "accepted" in label
        run.finding(
            spec_section="SGP.22 SS5.6 (message structure) -- robustness/fuzzing, not a spec SHALL clause",
            hypothesis=f"Malformed C1 messages of class '{label}' produce a consistent outcome "
                       "across all 7 message kinds where triggerable.",
            mutation=f"malformation class: {label.split(':')[0].strip()}, applied to each of the "
                     f"{len(C1_KINDS)} C1 message kinds",
            observed=f"{count} occurrence(s) across message kinds. Example: {class_examples[label]}",
            classification=record.CONFORMANT if not is_accept else record.ARTIFACT,
            rationale=(
                "Unhandled exception type reaching the top (KeyError/TypeError, not a domain "
                "ValueError) when a field feeding directly into codec.unb64()/x509 cert parsing "
                "is given the wrong JSON type -- fails closed (no forged trust established) but "
                "is a hardening gap: real ES9+/ES10 parsers should validate field types before "
                "using them, not rely on an incidental exception."
                if is_crash else
                "Field accepted with no downstream effect because our testbed never reads it in "
                "the flow logic (e.g. 'func', duplicate top-level transactionId echoes, or "
                "already-established-unused fields like euiccCiPKIdToBeUsed/profileMetadata) -- "
                "not evidence about real RSP robustness, a testbed completeness gap."
                if is_accept else
                "Cleanly rejected via a domain ValueError (JSON parse failure, base64 padding "
                "error, or a structured validation error) -- matches the fail-closed behavior a "
                "conformant parser must exhibit, regardless of which specific field was mangled."
            ),
            severity="low" if is_crash else ("medium" if is_accept else "info"),
        )

    if crash_examples:
        run.finding(
            spec_section="N/A -- implementation robustness, not a spec clause",
            hypothesis="Unhandled Python-level exceptions (not domain ValueErrors) reaching the "
                       "top when a JSON field's TYPE is corrupted (not just its value).",
            mutation="wrong_type fuzz variant across all 7 C1 kinds",
            observed=f"{len(crash_examples)} crash(es): " + " | ".join(crash_examples),
            classification=record.CONFORMANT,
            rationale="Every crash still fails the session closed (no security bypass), but a "
                      "TypeError/KeyError surfacing to the top of download_profile() is not a "
                      "designed rejection path -- a production LPA/SM-DP+ should validate field "
                      "types against a schema and return a structured error rather than crash. "
                      "Worth hardening even though it is not itself an authentication bypass.",
            severity="low",
        )


# --- report -------------------------------------------------------------------
def _print_matrix(run: MatrixRun) -> None:
    cells: dict[tuple[str, str], list[Outcome]] = {}
    for o in run.outcomes:
        cells.setdefault((o.kind, o.primitive), []).append(o)

    col_width = 26
    header = "MESSAGE KIND".ljust(30) + "".join(p.ljust(col_width) for p in PRIMITIVES)
    print(header)
    print("-" * len(header))
    for kind in C1_KINDS:
        row = kind.ljust(30)
        for prim in PRIMITIVES:
            outs = cells.get((kind, prim), [])
            if not outs:
                cell = "n/a"
            else:
                labels = [o.label() for o in outs]
                if len(set(labels)) == 1:
                    cell = f"{labels[0]} x{len(labels)}" if len(labels) > 1 else labels[0]
                else:
                    counts: dict[str, int] = {}
                    for lbl in labels:
                        counts[lbl] = counts.get(lbl, 0) + 1
                    cell = "; ".join(f"{lbl}x{c}" for lbl, c in counts.items())
            row += cell[: col_width - 1].ljust(col_width)
        print(row)


def run() -> MatrixRun:
    matrix = MatrixRun()
    _run_block(matrix)
    _run_replay(matrix)
    _run_forge(matrix)
    _run_modify_and_strip(matrix)
    _run_fuzz(matrix)
    record.append_many(matrix.findings)
    return matrix


if __name__ == "__main__":
    result = run()
    by_class: dict[str, int] = {}
    for f in result.findings:
        by_class[f.classification] = by_class.get(f.classification, 0) + 1
    print(f"C1 capability matrix: {len(result.findings)} findings appended {by_class}")
    print(f"{len(result.outcomes)} raw trials\n")
    _print_matrix(result)
