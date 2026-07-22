"""Bounded entrypoint for the read-only eUICC discovery campaigns.

    run_explore.py --angle {select,getdata,read,timing}
                   [--dry-run | --live] --out <jsonl> --summary <json>
                   [--wall <sec>] [--send-cap <n>]

Defaults to ``--dry-run``: candidates are built and classified, nothing is sent.
``--live`` sends only the allowlisted read-only candidates, and every one still
routes through ``engine.FuzzEngine.consider`` -> ``safety.guard_send``. The live
transport interpreter is pinned to ``python3`` (the CLI's deps live there).

One angle per process. ``--send-cap`` bounds live traffic; once hit the engine
keeps classifying without sending. ``--wall`` bounds wall-clock time.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import explore_getdata
import explore_read
import explore_select
import explore_timing
from engine import FuzzEngine
from euicc_transport import ApduResult, EuiccTransport, TransportError
from safety import ALLOWLIST_INS

_REPO_ROOT = Path(__file__).resolve().parents[2]


class _CliTransport(EuiccTransport):
    """Transport that parses the real `esim euicc apdu` output shape.

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


def _build_engine(live: bool, send_cap: int | None) -> FuzzEngine:
    transport = _CliTransport(repo_root=_REPO_ROOT, python_executable="python3") if live else None
    return FuzzEngine(live=live, allow_destructive=False, transport=transport)


def _run_timing(engine: FuzzEngine, args: argparse.Namespace) -> dict[str, object]:
    classes = explore_timing.default_classes()
    phase = "live" if args.live else "dry"

    if not args.live:
        # DRY self-validation: confirm every timed APDU is allowlisted, send none.
        validated: dict[str, list[str]] = {}
        for label, apdus in classes.items():
            for apdu in apdus:
                outcome = engine.consider(apdu)
                validated.setdefault(label, []).append(outcome.classification.value)
        summary: dict[str, object] = {
            "angle": "timing",
            "phase": phase,
            "note": "timing requires --live; dry-run only validates the allowlist",
            "classes": {label: sorted(set(v)) for label, v in validated.items()},
        }
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summary, indent=2) + "\n")
        return summary

    repeats = args.send_cap if args.send_cap is not None else 40
    probe = explore_timing.TimingProbe(engine=engine)
    series = probe.run_classes(classes, repeats=repeats)
    stats = {label: explore_timing.aggregate(label, lat) for label, lat in series.items()}
    comparison = explore_timing.compare(stats["fixed"], stats["varied"])
    summary = {
        "angle": "timing",
        "phase": phase,
        "repeats": repeats,
        "stats": {
            label: {
                "n": s.n,
                "median_ns": s.median_ns,
                "mad_ns": s.mad_ns,
                "min_ns": s.min_ns,
                "p90_ns": s.p90_ns,
                "outlier_count": s.outlier_count,
            }
            for label, s in stats.items()
        },
        "median_diff_ns": comparison.median_diff_ns,
        "robust_effect": comparison.robust_effect,
        "flagged": comparison.flagged,
        "allowlist_used": [f"INS_{i:02X}" for i in sorted(ALLOWLIST_INS)],
    }
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Read-only eUICC discovery campaigns.")
    parser.add_argument("--angle", required=True, choices=("select", "getdata", "read", "timing"))
    posture = parser.add_mutually_exclusive_group()
    posture.add_argument("--dry-run", dest="live", action="store_false", default=False)
    posture.add_argument("--live", dest="live", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--wall", type=int, default=300)
    parser.add_argument("--send-cap", dest="send_cap", type=int, default=None)
    args = parser.parse_args(argv)

    engine = _build_engine(args.live, args.send_cap)
    phase = "live" if args.live else "dry"

    if args.angle == "timing":
        summary = _run_timing(engine, args)
    else:
        module = {
            "select": explore_select,
            "getdata": explore_getdata,
            "read": explore_read,
        }[args.angle]
        summary = module.run(
            engine=engine,
            out_path=args.out,
            summary_path=args.summary,
            phase=phase,
            wall=args.wall,
            send_cap=args.send_cap,
        )

    sys.stderr.write(f"[explore/{args.angle}/{phase}] {json.dumps(summary)[:400]}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
