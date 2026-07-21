"""Drive the three fuzzer modes and stream every candidate to JSONL.

One (mode, phase) per process. Streams each outcome to the shared JSONL file
immediately (flush per line) so nothing is lost if atheris exits the process.

Safety is unchanged: candidates route through the stock FuzzEngine, which routes
through safety.guard_send. Only allowlisted read-only tags reach the transport.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from corpus import load_seeds
from engine import CandidateOutcome, FuzzEngine
from euicc_transport import ApduResult, EuiccTransport, TransportError
from safety import classify


class _CliTransport(EuiccTransport):
    """Transport that parses the real `esim euicc apdu` output shape.

    The shipped adapter expects a separate ``sw`` key. This CLI returns ``resp``
    (full ISD-R response, SW is the trailing 2 bytes) and ``ok``, no ``sw``. This
    subclass derives SW from the response tail. Nothing about the safety gate
    changes: only ALLOWED read-only candidates ever reach here.
    """

    @staticmethod
    def _parse(stdout: str, apdu_hex: str) -> ApduResult:
        import json as _json

        text = stdout.strip()
        if not text:
            raise TransportError(f"empty CLI output for APDU {apdu_hex}")
        try:
            data = _json.loads(text)
        except _json.JSONDecodeError as exc:
            raise TransportError(f"CLI output is not JSON: {text!r}") from exc
        if not isinstance(data, dict) or "resp" not in data:
            raise TransportError(f"CLI JSON missing 'resp': {text!r}")
        resp = str(data["resp"]).upper()
        sw = resp[-4:] if len(resp) >= 4 else ""
        return ApduResult(resp_hex=resp, sw=sw, ok=bool(data.get("ok", sw == "9000")), raw=data)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SEEDS = Path(__file__).resolve().parent / "seeds"


def _fmt_tag(apdu_hex: str) -> str | None:
    try:
        v = classify(apdu_hex)
    except ValueError:
        return None
    if v.tag is None:
        return None
    return f"{v.tag:04X}" if v.tag > 0xFF else f"{v.tag:02X}"


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


class StreamingEngine(FuzzEngine):
    def __init__(self, *, mode: str, phase: str, out_fh, send_cap: int | None = None, **kw):
        super().__init__(**kw)
        self._mode = mode
        self._phase = phase
        self._out = out_fh
        self._send_cap = send_cap

    def consider(self, apdu_hex: str) -> CandidateOutcome:
        if self._send_cap is not None and self.sent >= self._send_cap:
            # Stop transmitting once the live cap is hit; classify only.
            saved = self.live
            self.live = False
            try:
                return super().consider(apdu_hex)
            finally:
                self.live = saved
        return super().consider(apdu_hex)

    def _record(self, outcome: CandidateOutcome) -> None:
        super()._record(outcome)
        sw = None
        resp = None
        ok = None
        if outcome.sent and outcome.resp_hex:
            full = outcome.resp_hex.upper()
            if len(full) >= 4:
                sw = full[-4:]
                resp = full[:-4]
                ok = sw == "9000"
            else:
                resp = full
        rec = {
            "ts": _now(),
            "mode": self._mode,
            "phase": self._phase,
            "apdu": outcome.apdu_hex.upper(),
            "tag": _fmt_tag(outcome.apdu_hex),
            "classification": outcome.classification.value,
            "sent": outcome.sent,
            "sw": sw,
            "resp": resp,
            "ok": ok,
            "error": outcome.error,
        }
        self._out.write(json.dumps(rec) + "\n")
        self._out.flush()


def _build_engine(mode: str, phase: str, out_fh, send_cap: int | None) -> StreamingEngine:
    live = phase == "live"
    transport = _CliTransport(repo_root=_REPO_ROOT, python_executable="python3") if live else None
    return StreamingEngine(
        mode=mode,
        phase=phase,
        out_fh=out_fh,
        send_cap=send_cap,
        live=live,
        allow_destructive=False,
        transport=transport,
    )


def _run_prefix(engine: StreamingEngine, budget: int, deadline: float) -> None:
    import fuzz_prefix

    candidates = fuzz_prefix.iter_prefix_apdus(
        cla_range=(0x80, 0x83), ins_range=(0x00, 0xFF), p1_range=(0x00, 0x00), p2_range=(0x00, 0x03)
    )
    for i, apdu in enumerate(candidates):
        if i >= budget or time.monotonic() > deadline:
            break
        engine.consider(apdu)


def _run_grammar(engine: StreamingEngine, budget: int, deadline: float) -> None:
    import fuzz_grammar

    grammar = fuzz_grammar.ApduGrammar.from_seeds(load_seeds(_SEEDS))
    candidates = fuzz_grammar.synthesize(grammar, max_candidates=budget)
    for apdu in candidates:
        if time.monotonic() > deadline:
            break
        engine.consider(apdu)


def _run_afl(engine: StreamingEngine, budget: int, wall: int) -> None:
    import atheris
    import fuzz_afl

    target = fuzz_afl.make_target(engine)
    atheris.Setup(
        [sys.argv[0], f"-runs={budget}", f"-max_total_time={wall}", "-print_final_stats=0", str(_SEEDS)],
        target,
    )
    try:
        atheris.Fuzz()
    except SystemExit:
        pass


def _run_deep(args) -> int:
    """Deep evolutionary campaign: writes ONLY unique/unexpected rows + summary."""
    import deep_campaign

    live = args.phase == "live"
    transport = _CliTransport(repo_root=_REPO_ROOT, python_executable="python3") if live else None
    engine = FuzzEngine(live=live, allow_destructive=False, transport=transport)
    summary_path = args.summary or args.out.with_name("summary.json")
    summary = deep_campaign.build_and_run(
        out_path=args.out,
        summary_path=summary_path,
        phase=args.phase,
        engine=engine,
        wall=args.wall,
        send_cap=args.send_cap,
    )
    sys.stderr.write(
        f"[deep/{args.phase}] considered={summary['considered']} sent={summary['sent']} "
        f"unique_or_unexpected={summary['unique_or_unexpected_written']} "
        f"distinct_signatures={summary['distinct_signatures']}\n"
    )
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--mode", required=True, choices=("prefix", "grammar", "afl", "deep"))
    p.add_argument("--phase", required=True, choices=("dry", "live"))
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--summary", type=Path, default=None)
    p.add_argument("--budget", type=int, default=4000)
    p.add_argument("--wall", type=int, default=150)
    p.add_argument("--send-cap", type=int, default=None)
    args = p.parse_args()

    if args.mode == "deep":
        return _run_deep(args)

    deadline = time.monotonic() + args.wall
    with args.out.open("a") as fh:
        engine = _build_engine(args.mode, args.phase, fh, args.send_cap)
        if args.mode == "prefix":
            _run_prefix(engine, args.budget, deadline)
        elif args.mode == "grammar":
            _run_grammar(engine, args.budget, deadline)
        else:
            _run_afl(engine, args.budget, args.wall)
        fh.flush()
    sys.stderr.write(
        f"[{args.mode}/{args.phase}] considered={engine.considered} sent={engine.sent} "
        f"distinct_sw={len(engine.seen_sw)}\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
