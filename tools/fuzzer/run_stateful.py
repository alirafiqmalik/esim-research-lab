"""Bounded runner for the stateful / sequence fuzzer.

Default is DRY-RUN: build every candidate sequence, classify every element
through the safety chokepoint, and send NOTHING. ``--live`` sends the guarded
sequences on the persistent ISD-R channel and writes the state-dependent
transitions plus the inferred Mealy model.

    # dry-run (no device): build + classify, send nothing
    python3 -m run_stateful --max-seqs 200

    # live (device): bounded send, write artefacts
    python3 -m run_stateful --live \
        --out .sessions/fuzzer/stateful/transitions.jsonl \
        --summary .sessions/fuzzer/stateful/summary.json \
        --mealy .sessions/fuzzer/stateful/mealy \
        --wall 900 --max-seqs 200

Nothing is sent unless ``--live`` is passed. Every element of every sequence is
guarded ALLOWED before any send; a BLOCKED/UNKNOWN element rejects the whole
sequence.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import time
from pathlib import Path

from stateful_fuzz import (
    LABEL_STATELESS,
    StatefulCampaign,
)
from seq_transport import SeqTransport


def _repo_root() -> Path:
    # tools/fuzzer/run_stateful.py -> repo root is three levels up.
    return Path(__file__).resolve().parents[2]


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="run_stateful", description=__doc__)
    ap.add_argument("--live", action="store_true",
                    help="actually send guarded sequences to the device")
    ap.add_argument("--out", type=Path,
                    default=Path(".sessions/fuzzer/stateful/transitions.jsonl"),
                    help="state-dependent / novel transitions JSONL")
    ap.add_argument("--summary", type=Path,
                    default=Path(".sessions/fuzzer/stateful/summary.json"),
                    help="run summary JSON")
    ap.add_argument("--mealy", type=Path,
                    default=Path(".sessions/fuzzer/stateful/mealy"),
                    help="output path stem for mealy.md and mealy.json")
    ap.add_argument("--wall", type=float, default=900.0,
                    help="wall-clock budget in seconds (live only)")
    ap.add_argument("--max-seqs", type=int, default=200,
                    help="cap on generated random sequences")
    ap.add_argument("--seed", type=int, default=0,
                    help="deterministic generation seed")
    ap.add_argument("--python", default="python3",
                    help="python executable the transport shells (default python3)")
    return ap.parse_args(argv)


def _dry_run(campaign: StatefulCampaign) -> int:
    probes, sequences = campaign.build()
    diff_seqs = 3 * len(probes)
    total_elements = sum(len(s) for s in sequences)
    total_elements += sum(
        len(p.seq_base) + len(p.seq_primed) + len(p.seq_reset) for p in probes
    )
    print(json.dumps({
        "mode": "dry-run",
        "ts": _now(),
        "differential_probes": len(probes),
        "differential_sequences": diff_seqs,
        "random_sequences": len(sequences),
        "total_sequences": diff_seqs + len(sequences),
        "total_guarded_elements": total_elements,
        "note": "every element classified ALLOWED; nothing sent",
    }, indent=2))
    return 0


def _write_transitions(path: Path, campaign: StatefulCampaign) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with path.open("w") as fh:
        for diff in campaign.differential_results:
            if diff.label == LABEL_STATELESS:
                continue
            fh.write(json.dumps({
                "ts": _now(),
                "kind": "differential",
                "a": diff.a_name,
                "b": diff.b_name,
                "base_output": diff.base_output,
                "primed_output": diff.primed_output,
                "reset_output": diff.reset_output,
                "label": diff.label,
            }) + "\n")
            written += 1
        state_dep = set(campaign.prefix_recorder.state_dependent_inputs())
        for tr in campaign.prefix_recorder.transitions:
            if tr.input_key not in state_dep:
                continue
            fh.write(json.dumps({
                "ts": _now(),
                "kind": "context_transition",
                "prefix": tr.prefix_signature,
                "input_symbol": tr.input_key,
                "output_symbol": tr.output_key,
                "example_apdu": tr.example_apdu,
            }) + "\n")
            written += 1
    return written


def _write_mealy(stem: Path, campaign: StatefulCampaign) -> None:
    stem.parent.mkdir(parents=True, exist_ok=True)
    rows = campaign.mealy.transition_rows()
    json_path = stem.with_suffix(".json")
    json_path.write_text(json.dumps({
        "states": sorted(campaign.mealy.states),
        "input_alphabet": sorted(campaign.mealy.input_alphabet),
        "output_alphabet": sorted(campaign.mealy.output_alphabet),
        "transitions": rows,
        "history_dependent_inputs": sorted(
            k for k in campaign.mealy.input_alphabet
            if campaign.mealy.input_is_history_dependent(k)
        ),
    }, indent=2) + "\n")

    lines = ["# eUICC Mealy model (inferred)", ""]
    lines.append(
        f"State = (selected AID, pending-response flag). "
        f"{len(campaign.mealy.states)} states, "
        f"{len(campaign.mealy.input_alphabet)} input symbols, "
        f"{len(rows)} transitions."
    )
    lines.append("")
    lines.append("## Transitions")
    lines.append("")
    lines.append("| state | input | output | count | history-dependent |")
    lines.append("|---|---|---|---|---|")
    for r in rows:
        flag = "yes" if r["history_dependent"] else "no"
        lines.append(
            f"| {r['state']} | `{r['input_symbol']}` | `{r['output_symbol']}` | "
            f"{r['count']} | {flag} |"
        )
    lines.append("")
    stem.with_suffix(".md").write_text("\n".join(lines) + "\n")


def _live_run(campaign: StatefulCampaign, args: argparse.Namespace) -> int:
    probes, sequences = campaign.build()
    deadline = time.monotonic() + args.wall

    # Differential probes first: the highest-signal state-dependence evidence.
    ran_probes = 0
    for probe in probes:
        if time.monotonic() > deadline:
            break
        campaign.run_differential([probe])
        ran_probes += 1

    ran_seqs = 0
    for seq in sequences:
        if time.monotonic() > deadline:
            break
        campaign.run_sequences([seq])
        ran_seqs += 1

    written = _write_transitions(args.out, campaign)
    _write_mealy(args.mealy, campaign)

    summary = {
        "mode": "live",
        "ts": _now(),
        "wall_budget_s": args.wall,
        "differential_probes_run": ran_probes,
        "random_sequences_run": ran_seqs,
        "sequences_sent": campaign.sequences_sent,
        "steps_observed": campaign.steps_observed,
        "transitions_written": written,
        "state_dependent_differentials": sum(
            1 for d in campaign.differential_results if d.label != LABEL_STATELESS
        ),
        "mealy_states": len(campaign.mealy.states),
        "mealy_transitions": len(campaign.mealy.transition_rows()),
        "history_dependent_inputs": sum(
            1 for k in campaign.mealy.input_alphabet
            if campaign.mealy.input_is_history_dependent(k)
        ),
    }
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0


def main(argv: list[str]) -> int:
    args = _parse_args(argv)
    root = _repo_root()

    if not args.live:
        campaign = StatefulCampaign(transport=None, seed=args.seed,
                                    max_seqs=args.max_seqs)
        return _dry_run(campaign)

    transport = SeqTransport(repo_root=root, python_executable=args.python)
    campaign = StatefulCampaign(transport=transport, seed=args.seed,
                                max_seqs=args.max_seqs)
    return _live_run(campaign, args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
