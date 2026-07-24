"""Rogue SM-DS fuzz orchestrator — DESIGN + DRY-RUN. Live run is gated.

Stands up :class:`RogueSmdsServer` on a local port, points the LPA's ES11
discovery at it, iterates every :class:`Es11Mutation`, and records the eUICC's
``AuthenticateServer`` verdict plus the LPA's discovery outcome and logcat.

Safety gate: without ``--live`` this only DRY-RUNS — it builds the server + every
mutation's response body offline and writes them to a session dir for review. It
sends nothing to a device. ``--live`` is refused unless ``--i-have-safety-review``
is also passed, because a live run needs the human safety review + the TLS-trust
step (README) first.

Bypass detector:
- eUICC ACCEPTS a ci_trust mutation (discovery returns events / authServer rc 0)
  => CI-TRUST BYPASS, CRITICAL. Stop.
- LPA crash / hang / non-clean error on a parser mutation => candidate app bug,
  recorded.
- Everything else (clean reject) => expected.

Discovery returns event-record POINTERS only. This never proceeds to a profile
download/install. It performs no eUICC writes.
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
import sys
import threading
from dataclasses import asdict, dataclass
from pathlib import Path

# Reuse the fuzzer's ber codec (rsp_certs / es11_fuzz do `import ber`).
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "fuzzer"))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import es11_fuzz
from es11_fuzz import Es11FuzzSource, Es11Mutation, all_mutations
from smds_server import RogueSmdsServer

# The exact planned live discovery command (documented for the safety review).
LIVE_DISCOVERY_CMD = "esim euicc discovery --smds 127.0.0.1:{port}"
DEFAULT_SERIAL = "35181JEHN08662"


@dataclass(frozen=True)
class MutationOutcome:
    """One mutation's recorded result."""

    label: str
    category: str
    endpoint: str
    verdict: str  # "expected_reject" | "ci_trust_bypass" | "app_bug_candidate" | "dry_run"
    detail: str
    response_len: int


def write_tls_cert(cert_path: Path, key_path: Path, host: str = "127.0.0.1") -> None:
    """Write a self-signed TLS cert+key for ``host`` (SAN IP) to PEM files.

    This is the rogue SM-DS's TLS identity. OpenEUICC pins RSP TLS to the GSMA CI
    keystore, so the LPA accepts this only with the built-in ``ignore_tls_certificate``
    developer toggle enabled (see README).
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(host))]),
            critical=False,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )


def dry_run(mutation: Es11Mutation, session_dir: Path) -> MutationOutcome:
    """Build the mutation's response body offline and save it. No device."""
    from smds_server import (
        AuthenticateClientRequest,
        InitiateAuthRequest,
    )

    # A synthetic fresh request so the builder can echo a challenge / txid.
    if mutation.endpoint == es11_fuzz.INITIATE:
        req: object = InitiateAuthRequest(
            smdp_address="127.0.0.1",
            euicc_challenge=bytes.fromhex("0AE5502D276DA170928AB33246923A35"),
            euicc_info1=b"\xBF\x20\x00",
        )
    else:
        req = AuthenticateClientRequest(
            transaction_id="A1B2C3D4",
            authenticate_server_response=b"\xBF\x38\x00",
        )
    body = mutation.build(req)
    (session_dir / f"{mutation.label}.json").write_bytes(body)
    return MutationOutcome(
        label=mutation.label,
        category=mutation.category,
        endpoint=mutation.endpoint,
        verdict="dry_run",
        detail=f"response built offline ({len(body)} bytes), saved for review",
        response_len=len(body),
    )


def classify_live_result(mutation: Es11Mutation, discovery_result: dict) -> MutationOutcome:
    """Turn one live ``esim euicc discovery`` result dict into a verdict.

    ``discovery_result`` is the JSON the ESIMCTL activity returns (``ok``, ``smdp``
    list, ``error`` / rc). This is the bypass detector.
    """
    ok = bool(discovery_result.get("ok"))
    smdp = discovery_result.get("smdp") or []
    err = str(discovery_result.get("error", ""))

    if mutation.category == es11_fuzz.CI_TRUST:
        if ok or smdp:
            return MutationOutcome(
                mutation.label, mutation.category, mutation.endpoint,
                "ci_trust_bypass",
                f"CRITICAL: eUICC ACCEPTED a rogue-CI SM-DS (ok={ok}, smdp={smdp})",
                0,
            )
        return MutationOutcome(
            mutation.label, mutation.category, mutation.endpoint,
            "expected_reject", f"eUICC rejected rogue CI as expected ({err})", 0,
        )

    # parser / binding: a clean error is expected. A crash/hang/anomaly is a bug.
    if _looks_like_crash(err):
        return MutationOutcome(
            mutation.label, mutation.category, mutation.endpoint,
            "app_bug_candidate", f"LPA anomaly on malformed response: {err}", 0,
        )
    return MutationOutcome(
        mutation.label, mutation.category, mutation.endpoint,
        "expected_reject", f"clean reject ({err})", 0,
    )


def _looks_like_crash(err: str) -> bool:
    needles = ("SIGSEGV", "SIGABRT", "FATAL EXCEPTION", "ANR", "abort", "tombstone", "timed out")
    low = err.lower()
    return any(n.lower() in low for n in needles)


def _run_live(serial: str, session_dir: Path) -> list[MutationOutcome]:
    """Live loop. Only reached after the explicit safety gate. Imports esim lazily."""
    # Imported here so a dry-run never needs the device stack.
    from esim.euicc.backends import _activity  # type: ignore
    from esim.euicc.session import Session  # type: ignore

    cert_path = session_dir / "tls_cert.pem"
    key_path = session_dir / "tls_key.pem"
    write_tls_cert(cert_path, key_path)

    outcomes: list[MutationOutcome] = []
    sess = Session(serial)
    for mutation in all_mutations():
        source = Es11FuzzSource(mutation)
        server = RogueSmdsServer(source, str(cert_path), str(key_path), port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = _activity(
                serial, sess, "discovery", "lpac", timeout=120,
                raise_on_fail=False, smds=f"127.0.0.1:{server.port}",
            )
            outcome = classify_live_result(mutation, result)
            outcomes.append(outcome)
            (session_dir / f"{mutation.label}.result.json").write_text(json.dumps(result))
            if outcome.verdict == "ci_trust_bypass":
                # CRITICAL: stop immediately, do not run further mutations.
                break
        finally:
            server.shutdown()
    return outcomes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Rogue SM-DS ES11 fuzz orchestrator")
    parser.add_argument("--live", action="store_true", help="run against the device (gated)")
    parser.add_argument("--i-have-safety-review", action="store_true",
                        help="confirm the human safety review + TLS-trust step are done")
    parser.add_argument("--serial", default=DEFAULT_SERIAL)
    parser.add_argument("--session-dir", default=None)
    args = parser.parse_args(argv)

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    session_dir = Path(args.session_dir or f".sessions/rogue-smds-{stamp}")
    session_dir.mkdir(parents=True, exist_ok=True)

    if args.live:
        if not args.i_have_safety_review:
            print("REFUSED: --live requires --i-have-safety-review (do the safety "
                  "review + TLS-trust step first). See README.", file=sys.stderr)
            return 2
        outcomes = _run_live(args.serial, session_dir)
    else:
        outcomes = [dry_run(m, session_dir) for m in all_mutations()]

    summary = [asdict(o) for o in outcomes]
    (session_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    critical = [o for o in outcomes if o.verdict == "ci_trust_bypass"]
    bugs = [o for o in outcomes if o.verdict == "app_bug_candidate"]
    print(f"mutations: {len(outcomes)}  critical: {len(critical)}  "
          f"app-bug candidates: {len(bugs)}  session: {session_dir}")
    for o in critical:
        print(f"  CRITICAL {o.label}: {o.detail}")
    return 1 if critical else 0


if __name__ == "__main__":
    raise SystemExit(main())
