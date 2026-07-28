"""Higher-volume fuzz pass across all four channels, run mid-campaign once the
core model had absorbed several rounds of fidelity fixes (signed PIR, verified
smdpSigned2, cert-role checks, bounded TLV recursion). Reuses the same
analyze/fuzz machinery as testing/run_e2e.py but with far more iterations per
channel, to check for any newly-introduced or still-unexplained acceptance
after those fixes landed.

Runnable: ./venv/bin/python -m testbed.ecosim.campaign.big_fuzz_pass
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from ..analyze import classify_fields, variable_fields
from ..bus import ALL_CHANNELS
from ..fuzz import FuzzCampaign
from ..orchestrator import build_ecosystem, run_flow
from ..verifier import verify_run

CAMPAIGN = Path(__file__).resolve().parent
ITERATIONS_PER_CHANNEL = 400
CLEAN_RUNS = 8


def main() -> None:
    eco = build_ecosystem(seed=0xB16F022)
    runs = []
    for i in range(CLEAN_RUNS):
        summary, messages = run_flow(eco, profile_name=f"bigfuzz-profile-{i}")
        violations = verify_run(messages)
        if violations:
            raise SystemExit(f"unexpected verifier violation on clean run {i}: {violations}")
        if not summary.get("installed"):
            raise SystemExit(f"unexpected non-install on clean run {i}")
        runs.append(messages)

    classes = classify_fields(runs)
    variables = variable_fields(classes)

    rng = random.Random(0xB16F1E1D)
    all_records = []

    def run_flow_callable():
        _summary, messages = run_flow(eco)
        return messages

    for channel in ALL_CHANNELS:
        targets = [v for v in variables if v.channel == channel]
        if not targets:
            continue
        campaign = FuzzCampaign(eco.bus, rng)
        records = campaign.run(
            target_channel=channel, targets=targets,
            iterations=ITERATIONS_PER_CHANNEL, run_flow=run_flow_callable, verify_run=verify_run,
        )
        by_outcome: dict[str, int] = {}
        for r in records:
            by_outcome[r.outcome] = by_outcome.get(r.outcome, 0) + 1
        print(f"{channel}: {len(records)} mutations over {len(targets)} variable fields -> {by_outcome}")
        all_records.extend(records)

    out_path = CAMPAIGN / "big-fuzz-results.jsonl"
    with out_path.open("w") as fh:
        for r in all_records:
            fh.write(json.dumps({
                "iteration": r.iteration, "channel": r.channel, "path": r.path,
                "mutation": r.mutation, "outcome": r.outcome, "detail": r.detail[:500],
            }) + "\n")

    accepted_by_field: dict[tuple[str, str], int] = {}
    for r in all_records:
        if r.outcome == "accepted":
            key = (r.channel, r.path)
            accepted_by_field[key] = accepted_by_field.get(key, 0) + 1
    print(f"\ntotal: {len(all_records)} mutations, {sum(accepted_by_field.values())} accepted")
    print("accepted-by-field (channel, path): count")
    for key, count in sorted(accepted_by_field.items()):
        print(f"  {key}: {count}")
    print(f"\nfull results -> {out_path}")


if __name__ == "__main__":
    main()
