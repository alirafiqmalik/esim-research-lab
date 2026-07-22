"""Build the eUICC I/O symbol map from every fuzzer trace JSONL.

Reads all ``.sessions/fuzzer/**/*.jsonl`` traces, abstracts each row to an
input/output symbol, and writes the human map + machine map into
``.sessions/fuzzer/NOTES/``.

    python -m run_io_symbols

Prefers the FULL per-candidate logs; every JSONL under the fuzzer session tree
is ingested. Nothing here touches a device.
"""

from __future__ import annotations

import sys
from pathlib import Path

from io_symbols import build_map, write_outputs

# Files that are not per-exchange trace logs and must be skipped.
_SKIP_NAMES: frozenset[str] = frozenset()


def _repo_root() -> Path:
    # tools/fuzzer/run_io_symbols.py -> repo root is three levels up.
    return Path(__file__).resolve().parents[2]


def main(argv: list[str]) -> int:
    root = _repo_root()
    sessions = root / ".sessions" / "fuzzer"
    notes = sessions / "NOTES"

    paths = sorted(p for p in sessions.rglob("*.jsonl") if p.name not in _SKIP_NAMES)
    if not paths:
        print(f"no trace JSONLs under {sessions}", file=sys.stderr)
        return 1

    io = build_map(paths)
    md_path = notes / "io-symbol-map.md"
    json_path = notes / "io-symbol-map.json"
    write_outputs(io, md_path=md_path, json_path=json_path)

    print(
        f"ingested {io.rows_ingested} rows from {len(paths)} files, "
        f"{io.rows_used} used; input alphabet {len(io.input_alphabet)}, "
        f"output alphabet {len(io.output_alphabet)}, "
        f"{io.distinct_mappings()} distinct mappings, "
        f"{len(io.nondeterministic())} nondeterministic input symbols."
    )
    print(f"wrote {md_path}")
    print(f"wrote {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
