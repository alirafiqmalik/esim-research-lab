#!/usr/bin/env python3
"""Drive the full ES9+ download flow (InitiateAuthentication ->
AuthenticateClient -> GetBoundProfilePackage -> HandleNotification) through
the src/ request-builder library, over a real local HTTP socket, against the
local ecosim-backed shim server (scripts/local_sim_server.py).

Default target is always the local sim. To target a real provider you must
pass --target provider --provider-host <fqdn> AND --allow-live-fire, AND have
ESIM_MITM_ALLOW_LIVE_FIRE=1 set in the environment -- see src/client.py. None
of that is set anywhere in this repo; this script's default invocation only
ever talks to 127.0.0.1.

Run:
    ./venv/bin/python testbed/ping-live-servers/scripts/run_es9plus_flow.py
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[3]
PING_LIVE_SERVERS = HERE.parent
for p in (str(REPO_ROOT), str(PING_LIVE_SERVERS), str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

from local_sim_server import start_smdp_server  # noqa: E402
from src.client import RspHttpClient  # noqa: E402
from src.envelope import parse_response_header, path_for  # noqa: E402
from src.errors import RspClientError  # noqa: E402
from src.models import (  # noqa: E402
    AuthenticateClientRequest,
    AuthenticateClientResponse,
    GetBoundProfilePackageRequest,
    GetBoundProfilePackageResponse,
    HandleNotificationRequest,
    InitiateAuthenticationRequest,
    InitiateAuthenticationResponse,
)
from src.targets import Target  # noqa: E402
from testbed.ecosim import codec, tlv  # noqa: E402
from testbed.ecosim.orchestrator import build_ecosystem  # noqa: E402


def _extract_euicc_challenge(challenge_wire: bytes) -> bytes:
    top = tlv.find(tlv.walk(challenge_wire), codec.TAG_GET_EUICC_CHALLENGE)
    if top is None:
        raise RspClientError("GetEUICCChallenge response missing top-level tag")
    inner = tlv.find(top.children, 0x80)
    if inner is None:
        raise RspClientError("GetEUICCChallenge response missing challenge value")
    return inner.value


def run_against_local_sim() -> dict[str, object]:
    """Build a fresh ecosystem, stand up the SM-DP+ shim in-process, and drive
    the full flow through the HTTP request-builder library. Returns a summary
    dict on success; raises RspClientError (or lets an ecosim ValueError
    propagate) on any failure."""
    eco = build_ecosystem()
    activation = eco.mno.order_profile("ping-live-servers-validation", "ecosim-MNO", 0)

    httpd = start_smdp_server(eco.smdp, eco.pki.ci.certificate, eco.euicc.get_eid())
    try:
        target = Target(name="local-sim-smdp", base_url=f"http://127.0.0.1:{httpd.server_port}", is_local=True)
        client = RspHttpClient(target=target)

        euicc_challenge = _extract_euicc_challenge(eco.euicc.get_euicc_challenge())
        euicc_info1 = eco.euicc.get_euicc_info1(eco.pki.ci_public_key_id())

        req1 = InitiateAuthenticationRequest(
            euicc_challenge=euicc_challenge, euicc_info1=euicc_info1, smdp_address=activation.smdp_address
        )
        raw1 = client.call("ES9+", "InitiateAuthentication", path_for("ES9+", "InitiateAuthentication"), req1.to_wire())
        if not parse_response_header(raw1).ok:
            raise RspClientError(f"InitiateAuthentication failed: {raw1}")
        resp1 = InitiateAuthenticationResponse.from_wire(raw1)

        ctx_params1 = codec.ctx_params1(activation.matching_id)
        auth_fields = eco.euicc.authenticate_server(
            bytes.fromhex(resp1.transaction_id),
            resp1.server_signed1,
            resp1.server_signature1,
            resp1.server_certificate,
            eco.pki.ci.certificate,
            ctx_params1,
        )

        req2 = AuthenticateClientRequest(
            transaction_id=resp1.transaction_id,
            euicc_signed1=auth_fields["euiccSigned1"],
            euicc_signature1=auth_fields["euiccSignature1"],
            euicc_certificate=auth_fields["euiccCertificate"],
            eum_certificate=auth_fields["eumCertificate"],
            euicc_otpk=auth_fields["euiccOtpk"],
        )
        raw2 = client.call("ES9+", "AuthenticateClient", path_for("ES9+", "AuthenticateClient"), req2.to_wire())
        if not parse_response_header(raw2).ok:
            raise RspClientError(f"AuthenticateClient failed: {raw2}")
        resp2 = AuthenticateClientResponse.from_wire(raw2)

        eco.euicc.verify_smdp_signature2(
            resp2.smdp_signed2, resp2.smdp_signature2, resp2.smdp_pb_certificate, eco.pki.ci.certificate
        )

        req3 = GetBoundProfilePackageRequest(transaction_id=resp2.transaction_id)
        raw3 = client.call(
            "ES9+", "GetBoundProfilePackage", path_for("ES9+", "GetBoundProfilePackage"), req3.to_wire()
        )
        if not parse_response_header(raw3).ok:
            raise RspClientError(f"GetBoundProfilePackage failed: {raw3}")
        resp3 = GetBoundProfilePackageResponse.from_wire(raw3)

        bpp = {
            "transactionId": resp3.transaction_id,
            "serverOtpk": codec.b64(resp3.server_otpk),
            "sealedProfile": codec.b64(resp3.sealed_profile),
        }
        install_result_wire = eco.euicc.install_bound_profile_package(bpp)
        _txid, seq, ok, _sig = codec.parse_profile_installation_result(install_result_wire)

        req4 = HandleNotificationRequest(
            notification=install_result_wire, seq=seq, euicc_certificate=eco.pki.euicc.cert_der()
        )
        raw4 = client.call("ES9+", "HandleNotification", path_for("ES9+", "HandleNotification"), req4.to_wire())
        if not parse_response_header(raw4).ok:
            raise RspClientError(f"HandleNotification failed: {raw4}")

        return {
            "installed": ok,
            "transactionId": resp3.transaction_id,
            "iccid": activation.matching_id,  # matchingId used as the run identifier here
            "functions_exercised": [
                "InitiateAuthentication", "AuthenticateClient", "GetBoundProfilePackage", "HandleNotification",
            ],
            "target": target.base_url,
        }
    finally:
        httpd.shutdown()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--target", choices=["local", "provider"], default="local",
        help="default: local (the only target this script can actually reach today)",
    )
    parser.add_argument("--provider-host", default=None, help="FQDN, only used with --target provider")
    parser.add_argument("--allow-live-fire", action="store_true", help="required (with env var) for --target provider")
    args = parser.parse_args()

    if args.target == "provider":
        print(
            "Live-provider execution is gated by the orchestrating session and is not "
            "implemented as a runnable path here: RspHttpClient will refuse it "
            f"(needs allow_live_fire=True AND ESIM_MITM_ALLOW_LIVE_FIRE=1). "
            f"provider-host={args.provider_host!r} allow_live_fire={args.allow_live_fire} "
            f"env={os.environ.get('ESIM_MITM_ALLOW_LIVE_FIRE')!r}",
            file=sys.stderr,
        )
        return 2

    try:
        summary = run_against_local_sim()
    except RspClientError as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1

    print("OK -- full ES9+ flow round-tripped over real HTTP against the local sim:")
    for key, value in summary.items():
        print(f"  {key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
