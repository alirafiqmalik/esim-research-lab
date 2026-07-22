"""Bounded entrypoint for the deep read-only eUICC data extraction campaigns.

    run_deepdata.py --angle {getdata_enum,bf2d_disclosure}
                    [--dry-run | --live] --out <jsonl> --summary <json>
                    [--wall <sec>] [--send-cap <n>]

Defaults to ``--dry-run``: candidates are built and classified, nothing is sent.
``--live`` sends only allowlisted read-only candidates, each still routed through
``engine.FuzzEngine.consider`` -> ``safety.guard_send``. One angle per process.

``getdata_enum`` sweeps the GET DATA (CA/CB) object space and records every
readable data object in the summary's discovery list, keyed by tag. Feed that
JSONL to ``getdata_decode.py`` to turn the raw objects into eUICC facts.

``bf2d_disclosure`` sends BF2D framings that over-declare inner length / search
criteria / expected length and flags any response longer than the canonical
request.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import bf2d_disclosure
import getdata_enum
from engine import FuzzEngine
from euicc_transport import ApduResult, EuiccTransport, TransportError

_REPO_ROOT = Path(__file__).resolve().parents[2]


class _CliTransport(EuiccTransport):
    """Transport that parses the real ``esim euicc apdu`` output shape.

    The CLI returns ``resp`` (full ISD-R response, SW = trailing 2 bytes) and
    ``ok``, with no separate ``sw`` key. Only ALLOWED read-only candidates ever
    reach here; the safety gate is unchanged.
    """

    @staticmethod
    def _parse(stdout: str, apdu_hex: str) -> ApduResult:
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
        return ApduResult(resp_hex=resp, sw=sw, ok=bool(data.get("ok", sw == "9000")), raw=data)


def _build_engine(live: bool) -> FuzzEngine:
    transport = _CliTransport(repo_root=_REPO_ROOT, python_executable="python3") if live else None
    return FuzzEngine(live=live, allow_destructive=False, transport=transport)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Deep read-only eUICC data extraction.")
    parser.add_argument("--angle", required=True, choices=("getdata_enum", "bf2d_disclosure"))
    posture = parser.add_mutually_exclusive_group()
    posture.add_argument("--dry-run", dest="live", action="store_false", default=False)
    posture.add_argument("--live", dest="live", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--wall", type=int, default=300)
    parser.add_argument("--send-cap", dest="send_cap", type=int, default=None)
    args = parser.parse_args(argv)

    engine = _build_engine(args.live)
    phase = "live" if args.live else "dry"

    module = {"getdata_enum": getdata_enum, "bf2d_disclosure": bf2d_disclosure}[args.angle]
    summary = module.run(
        engine=engine,
        out_path=args.out,
        summary_path=args.summary,
        phase=phase,
        wall=args.wall,
        send_cap=args.send_cap,
    )

    sys.stderr.write(f"[deepdata/{args.angle}/{phase}] {json.dumps(summary)[:400]}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
