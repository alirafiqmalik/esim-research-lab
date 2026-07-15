#!/usr/bin/env bash
# Parse an RSP capture log -> DOT MSD -> SVG+PNG.
# Usage: render_msd.sh <capture.log> <out-basename> ["Title"]
set -euo pipefail
LOG="$1"; OUT="$2"; TITLE="${3:-}"
DIR="$(cd "$(dirname "$0")" && pwd)"
ARGS=(-o "${OUT}.dot"); [ -n "$TITLE" ] && ARGS+=(--title "$TITLE")
python3 "${DIR}/rsp_to_msd.py" "$LOG" "${ARGS[@]}"
dot -Tsvg "${OUT}.dot" -o "${OUT}.svg"
dot -Tpng -Gdpi=140 "${OUT}.dot" -o "${OUT}.png"
echo "rendered: ${OUT}.svg ${OUT}.png"
