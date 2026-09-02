#!/usr/bin/env bash
# Decode a Shannon .sdm into a GSMTAP pcap + NAS/RRC text logs.
# Usage: ./decode_nas_rrc.sh <cap.sdm> [layers]
#   layers default: nas,rrc  (add pdcp,rlc,mac,ip for lower layers)
set -euo pipefail

SDM="${1:?usage: decode_nas_rrc.sh <cap.sdm> [layers]}"
LAYERS="${2:-nas,rrc}"
BASE="${SDM%.sdm}"
SCAT_PY="${SCAT_PY:-./venv/bin/python3}"

echo "[*] SCAT decode ($LAYERS) -> ${BASE}.pcap"
"$SCAT_PY" -m scat.main -t sec -d "$SDM" -F "${BASE}.pcap" -L "$LAYERS" >/dev/null 2>&1 || \
"$SCAT_PY" -m scat.main -t sec -d "$SDM" -F "${BASE}.pcap" -L "$LAYERS"

echo "[*] per-frame summary -> ${BASE}.summary.txt"
tshark -r "${BASE}.pcap" -T fields -e frame.number -e frame.time_relative \
  -e _ws.col.Protocol -e _ws.col.Info > "${BASE}.summary.txt"

echo "[*] full verbose decode -> ${BASE}.detail.txt"
tshark -r "${BASE}.pcap" -V > "${BASE}.detail.txt"

echo "[*] NAS-only (EMM/ESM/5GMM) -> ${BASE}.nas.txt"
tshark -r "${BASE}.pcap" -Y 'nas-eps || nas-5gs' -V > "${BASE}.nas.txt" 2>/dev/null || true

echo
echo "=== message inventory (control plane) ==="
tshark -r "${BASE}.pcap" -T fields -e _ws.col.Info 2>/dev/null \
  | grep -viE '^Paging' | sort | uniq -c | sort -rn | head -40
echo
echo "=== unprotected NAS (security-header type 0, pre-security) ==="
tshark -r "${BASE}.pcap" -Y '(nas-eps || nas-5gs)' -V 2>/dev/null \
  | grep -iE 'security header type|Identity type|IMEISV|SUCI|SUPI|Registration request|Attach request' | head -20
echo
echo "=== NR / EN-DC present? ==="
echo -n "nr-rrc frames: "; tshark -r "${BASE}.pcap" -Y 'nr-rrc' 2>/dev/null | wc -l
echo "[+] outputs: ${BASE}.{pcap,summary.txt,detail.txt,nas.txt}"
echo "    open in wireshark: wireshark ${BASE}.pcap"
