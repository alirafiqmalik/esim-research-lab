"""Bounded entrypoint for the length-parser acceptance campaign.

Default is dry-run: nothing is sent, the transport is never built. ``--live``
opts into sending, and only ALLOWED read-only candidates ever reach the card
(the safety gate inside the engine enforces this; this script cannot bypass it).

    # dry self-validation (no device):
    python3 run_lenient.py --out out/lenient.jsonl

    # bounded live run:
    python3 run_lenient.py --live --out out/lenient.jsonl \
        --summary out/lenient.summary.json --wall 120 --send-cap 300

The ``--out`` file holds only unique/unexpected behaviours (reuses
``reporting``/``novelty``). The full per-candidate log lands next to it as
``*.full.jsonl`` and drives ``lenient_map.json`` / ``lenient_map.md``.

Live mode reuses the CLI transport with ``python_executable="python3"`` because
the ``esim`` CLI needs system Python, not the fuzzer venv.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import lenient_parsing
from engine import FuzzEngine
from euicc_transport import ApduResult, EuiccTransport, TransportError

_REPO_ROOT = Path(__file__).resolve().parents[2]


class _CliTransport(EuiccTransport):
    """Parse the real ``esim euicc apdu`` output shape (resp only, no sw key)."""

    @staticmethod
    def _parse(stdout: str, apdu_hex: str) -> ApduResult:
        import json

        text = stdout.strip()
        if not text:
            raise TransportError(f"empty CLI output for APDU {apdu_hex}")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise TransportError(f"CLI output is not JSON: {text!r}") from exc
        if not isinstance(data, dict) or "resp" not in data:
            raise TransportError(f"CLI JSON missing 'resp': {text!r}")
        resp = str(data["resp"]).upper()
        sw = resp[-4:] if len(resp) >= 4 else ""
        return ApduResult(
            resp_hex=resp, sw=sw, ok=bool(data.get("ok", sw == "9000")), raw=data
        )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--live", action="store_true", help="send ALLOWED candidates (default: dry-run)")
    p.add_argument("--out", required=True, type=Path, help="unique/unexpected JSONL")
    p.add_argument("--summary", type=Path, default=None)
    p.add_argument("--full", type=Path, default=None, help="full per-candidate JSONL")
    p.add_argument("--map-json", type=Path, default=None)
    p.add_argument("--map-md", type=Path, default=None)
    p.add_argument("--wall", type=int, default=300)
    p.add_argument("--send-cap", type=int, default=None)
    args = p.parse_args()

    phase = "live" if args.live else "dry"
    summary_path = args.summary or args.out.with_name("lenient.summary.json")
    full_path = args.full or args.out.with_suffix(".full.jsonl")
    map_json = args.map_json or args.out.with_name("lenient_map.json")
    map_md = args.map_md or args.out.with_name("lenient_map.md")

    transport = (
        _CliTransport(repo_root=_REPO_ROOT, python_executable="python3")
        if args.live
        else None
    )
    engine = FuzzEngine(live=args.live, allow_destructive=False, transport=transport)

    summary = lenient_parsing.build_and_run(
        out_path=args.out,
        summary_path=summary_path,
        full_path=full_path,
        map_json=map_json,
        map_md=map_md,
        phase=phase,
        engine=engine,
        wall=args.wall,
        send_cap=args.send_cap,
    )
    sys.stderr.write(
        f"[lenient/{phase}] considered={summary['considered']} sent={summary['sent']} "
        f"unique_or_unexpected={summary['unique_or_unexpected_written']} "
        f"distinct_signatures={summary['distinct_signatures']}\n"
        f"[lenient/{phase}] full_log={full_path} map={map_md}\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
