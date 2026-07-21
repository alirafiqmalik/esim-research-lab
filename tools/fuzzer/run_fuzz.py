"""Single entrypoint for the eUICC APDU fuzzer.

    run_fuzz.py --mode {prefix,afl,grammar} [--dry-run | --live] [--seeds DIR]

Defaults to ``--dry-run``: candidates are enumerated and classified, nothing is
sent. A live send requires ``--live`` and only allowlisted read-only tags leave
the host. Every mode routes candidates through ``safety`` via the shared engine.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from corpus import load_seeds
from engine import FuzzEngine
from euicc_transport import EuiccTransport

_DEFAULT_SEEDS = Path(__file__).resolve().parent / "seeds"
_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_OUT = Path(__file__).resolve().parent / "out" / "deep_unique.jsonl"
_DEFAULT_SUMMARY = Path(__file__).resolve().parent / "out" / "summary.json"

log = logging.getLogger("fuzzer.run")


def _parse_args(argv: list[str]) -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(description="eUICC APDU fuzzer (gated).")
    parser.add_argument("--mode", choices=("prefix", "afl", "grammar", "deep"), required=True)
    posture = parser.add_mutually_exclusive_group()
    posture.add_argument("--dry-run", dest="live", action="store_false", default=False)
    posture.add_argument("--live", dest="live", action="store_true")
    parser.add_argument("--seeds", type=Path, default=_DEFAULT_SEEDS)
    parser.add_argument("--repo-root", type=Path, default=_REPO_ROOT)
    parser.add_argument("--max-candidates", type=int, default=512)
    # Deep-campaign options (used only by --mode deep).
    parser.add_argument("--out", type=Path, default=_DEFAULT_OUT)
    parser.add_argument("--summary", type=Path, default=_DEFAULT_SUMMARY)
    parser.add_argument("--wall", type=int, default=300)
    parser.add_argument("--send-cap", dest="send_cap", type=int, default=None)
    parser.add_argument(
        "--i-understand-destructive",
        dest="allow_destructive",
        action="store_true",
        help="FORBIDDEN without maintainer sign-off. Never overrides the "
        "memory-reset/delete blocks and is not honored for live sends.",
    )
    return parser.parse_known_args(argv)


def _build_engine(args: argparse.Namespace) -> FuzzEngine:
    # The eUICC CLI (`esim.cli`) runs under the system python that has its deps
    # (click); the fuzzer's own venv does not, so pin the transport interpreter.
    transport = (
        EuiccTransport(repo_root=args.repo_root, python_executable="python3")
        if args.live
        else None
    )
    return FuzzEngine(
        live=args.live,
        allow_destructive=args.allow_destructive,
        transport=transport,
    )


def main(argv: list[str]) -> int:
    logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")
    args, passthrough = _parse_args(argv[1:])

    if args.live:
        log.warning("LIVE mode: only allowlisted read-only tags will be sent.")
    else:
        log.info("DRY-RUN: enumerating and classifying only, nothing is sent.")

    engine = _build_engine(args)

    if args.mode == "deep":
        import deep_campaign

        phase = "live" if args.live else "dry"
        summary = deep_campaign.build_and_run(
            out_path=args.out,
            summary_path=args.summary,
            phase=phase,
            engine=engine,
            wall=args.wall,
            send_cap=args.send_cap,
        )
        log.info("deep campaign summary: %s", summary)
        return 0

    if args.mode == "prefix":
        import fuzz_prefix

        fuzz_prefix.run(engine)
    elif args.mode == "grammar":
        import fuzz_grammar

        seeds = load_seeds(args.seeds)
        fuzz_grammar.run(engine, seeds, max_candidates=args.max_candidates)
    elif args.mode == "afl":
        import fuzz_afl

        if not fuzz_afl._HAVE_ATHERIS:
            raise RuntimeError("atheris not installed; cannot run AFL mode")
        import atheris

        target = fuzz_afl.make_target(engine)
        atheris.Setup([argv[0], *passthrough, str(args.seeds)], target)
        atheris.Fuzz()

    log.info("summary: %s", engine.summary())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
