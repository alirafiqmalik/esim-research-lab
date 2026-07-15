#!/usr/bin/env bash
# Validate + render a Graphviz message-sequence-diagram (.dot) to SVG and PNG.
# Usage: tools/msd/render.sh path/to/diagram.dot
set -euo pipefail

DOT="${1:?usage: render.sh <file.dot>}"
[ -f "$DOT" ] || { echo "msd render: no such file: $DOT" >&2; exit 1; }
base="${DOT%.dot}"

# 1. Syntax validation — dot -Tcanon fails (nonzero) on malformed input.
if ! err="$(dot -Tcanon "$DOT" 2>&1 >/dev/null)"; then
  echo "msd render: SYNTAX ERROR in $DOT" >&2
  echo "$err" >&2
  exit 2
fi

# 2. Render SVG, then PNG (rsvg-convert preferred for sharp text; dot -Tpng fallback).
dot -Tsvg "$DOT" -o "${base}.svg"
if command -v rsvg-convert >/dev/null 2>&1; then
  rsvg-convert -z 2 "${base}.svg" -o "${base}.png"
else
  dot -Tpng -Gdpi=150 "$DOT" -o "${base}.png"
fi
echo "msd render: ok -> ${base}.svg ${base}.png"
