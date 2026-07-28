"""End-to-end driver: agentic verify-loop, field classification, targeted fuzzing.

Pipeline:
  1. Build the ecosystem once (custom PKI written to pki/).
  2. Agentic loop: run a full MNO->SM-DP+->LPA->eUICC download, run the structure
     VERIFIER against every message, and only accept the run if it conforms to the
     SGP.22 command structure. Repeat until N clean runs are banked (that is the
     "verifier for the exact cmd structure eSIM uses").
  3. Classify every field as invariant (same every run: tags, OIDs, cert bytes,
     placeholders, structure) or variable (challenges, ids, ephemeral keys, iccid).
  4. Fuzz ONLY the variable fields, per channel (C1/C2a/C2b/C3), through the bus
     mutation hook, and record which mutations the stack rejects vs silently accepts.
  5. Write everything under logs/.

Run:  ./venv/bin/python -m testbed.ecosim.testing.run_e2e
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from ..analyze import classify_fields, summarize, variable_fields
from ..bus import ALL_CHANNELS
from ..fuzz import FuzzCampaign
from ..orchestrator import build_ecosystem, run_flow, write_run_log
from ..verifier import verify_run

HERE = Path(__file__).resolve().parent
ECOSIM = HERE.parent
LOGS = ECOSIM / "logs"
PKI_DIR = ECOSIM / "pki"

CLEAN_RUNS_TARGET = 6
MAX_ATTEMPTS = 20
FUZZ_ITERATIONS_PER_CHANNEL = 40


def agentic_verify_loop(eco, target: int, max_attempts: int) -> list[list]:
    """Generate runs; accept only those that pass the structure verifier."""
    clean: list[list] = []
    attempts = 0
    while len(clean) < target and attempts < max_attempts:
        attempts += 1
        summary, messages = run_flow(eco, profile_name=f"profile-{attempts}")
        violations = verify_run(messages)
        if violations:
            path = LOGS / f"rejected-run-{attempts}.jsonl"
            write_run_log(messages, path)
            print(f"  attempt {attempts}: REJECTED ({len(violations)} violations) -> {path.name}")
            for v in violations[:5]:
                print(f"      - {v}")
            continue
        if not summary.get("installed"):
            print(f"  attempt {attempts}: flow did not install; skipping")
            continue
        idx = len(clean)
        write_run_log(messages, LOGS / f"clean-run-{idx}.jsonl")
        clean.append(messages)
        print(f"  attempt {attempts}: ACCEPTED clean run {idx} "
              f"(iccid={summary.get('iccid')}, {len(messages)} msgs)")
    return clean


def analyze_fields(runs: list[list]) -> tuple[list, list]:
    classes = classify_fields(runs)
    variables = variable_fields(classes)
    (LOGS / "field-classification.txt").write_text(summarize(classes))
    with (LOGS / "field-classification.jsonl").open("w") as fh:
        for c in classes:
            fh.write(json.dumps({
                "channel": c.channel, "kind": c.kind, "path": c.path,
                "invariant": c.invariant, "distinct_values": c.distinct_values,
                "example": c.example,
            }) + "\n")
    return classes, variables


def fuzz_variable_fields(eco, variables: list) -> dict:
    rng = random.Random(0xF0F0)
    results: dict = {}

    def run_flow_callable():
        _summary, messages = run_flow(eco)
        return messages

    all_records = []
    for channel in ALL_CHANNELS:
        targets = [v for v in variables if v.channel == channel]
        if not targets:
            print(f"  {channel}: no variable fields to fuzz")
            results[channel] = []
            continue
        campaign = FuzzCampaign(eco.bus, rng)
        records = campaign.run(
            target_channel=channel,
            targets=targets,
            iterations=FUZZ_ITERATIONS_PER_CHANNEL,
            run_flow=run_flow_callable,
            verify_run=verify_run,
        )
        results[channel] = records
        by_outcome: dict[str, int] = {}
        for r in records:
            by_outcome[r.outcome] = by_outcome.get(r.outcome, 0) + 1
        print(f"  {channel}: {len(records)} mutations -> {by_outcome} "
              f"(over {len(targets)} variable fields)")
        all_records.extend(records)

    with (LOGS / "fuzz-results.jsonl").open("w") as fh:
        for r in all_records:
            fh.write(json.dumps({
                "iteration": r.iteration, "channel": r.channel, "path": r.path,
                "mutation": r.mutation, "outcome": r.outcome, "detail": r.detail,
            }) + "\n")
    return results


def main() -> None:
    LOGS.mkdir(parents=True, exist_ok=True)
    print("== ecosim end-to-end testbed ==")
    print(f"[1] building ecosystem + custom PKI -> {PKI_DIR}")
    eco = build_ecosystem(pki_out=PKI_DIR)

    print(f"[2] agentic verify-loop (target {CLEAN_RUNS_TARGET} clean runs)")
    runs = agentic_verify_loop(eco, CLEAN_RUNS_TARGET, MAX_ATTEMPTS)
    if len(runs) < 2:
        raise SystemExit(f"only {len(runs)} clean runs; need >=2 to classify fields")

    print(f"[3] classifying fields across {len(runs)} runs")
    classes, variables = analyze_fields(runs)
    inv = [c for c in classes if c.invariant]
    print(f"    {len(inv)} invariant fields, {len(variables)} variable fields")
    print(f"    report -> {LOGS / 'field-classification.txt'}")

    print("[4] fuzzing ONLY variable fields, per channel")
    fuzz_variable_fields(eco, variables)

    print(f"[5] done. logs in {LOGS}")


if __name__ == "__main__":
    main()
