#!/usr/bin/env bash
# Spec query helper: navigate the GSMA graphify graph, prefer gsma/core sources.
# Usage: specq.sh "question" [budget]
SRC="/home/ahm/Desktop/project/Research/exp/eSim-ecosystem-testbed/sources"
PY="$(cat "$SRC/graphify-out/.graphify_python")"
Q="$1"; BUD="${2:-800}"
cd "$SRC" || exit 1
timeout 220 "$PY" -m graphify query "$Q" --budget "$BUD" 2>&1
