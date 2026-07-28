# Campaign ledger discipline

`findings.jsonl` is APPEND-ONLY. A worker in round 1 overwrote it via the Write
tool instead of `record.append_many`, silently dropping 12 findings from two
other concurrent workers; they were reconstructed from their task reports.

Rule for every future worker/module in this directory: only ever call
`record.append()` / `record.append_many()` from `record.py`. Never open
`findings.jsonl` with a file-write tool or `"w"` mode. If you need to inspect
existing findings, use `record.load_all()`.
