#!/usr/bin/env bash
# Extract the ordered message list from an MSD .dot for correctness-checking
# against the source notes. Prints: seq  sender -> receiver  : label
# Message edges MUST carry kind="msg" and seq="<n>"; lifelines use kind="life".
# Usage: tools/msd/analyze.sh path/to/diagram.dot
set -euo pipefail

DOT="${1:?usage: analyze.sh <file.dot>}"
[ -f "$DOT" ] || { echo "msd analyze: no such file: $DOT" >&2; exit 1; }

dot -Tcanon "$DOT" >/dev/null   # fail fast on syntax errors

echo "== message sequence (extracted from DOT) =="
gvpr 'E[kind=="msg"]{ printf("%4s  %s -> %s  :  %s\n",
        (string)seq, tail.name, head.name, label); }' "$DOT" | sort -n

echo ""
echo "== participants (lifelines) =="
gvpr 'N[role=="actor"]{ printf("  %s = %s\n", name, label); }' "$DOT"

echo ""
n=$(gvpr 'BEG_G{ int c=0; } E[kind=="msg"]{ c++; } END_G{ print(c); }' "$DOT")
echo "== $n message(s). Cross-check each against the source notes: same count, same order, same sender/receiver. =="
