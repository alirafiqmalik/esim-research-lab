#!/usr/bin/env bash
# capture_esim_rsp.sh — host-side eSIM RSP capture for a NON-rooted Android phone.
#
# Runs on your computer, drives the phone over USB adb. No root, no app install.
# It captures what stock Android exposes during an eSIM add/download:
#   - the LPA download flow (EuiccService/EuiccController and OEM equivalents)
#   - the SM-DP+ address, matchingId, and download result/error codes
#   - profile-install notification handling
#   - the modem attach/registration after the new profile enables
#   - before/after subscription state
#
# It CANNOT capture ES9+/ES8+ plaintext, the eUICC-signed deviceInfo, or the IMEI/TAC
# on the RSP wire. The stock LPA pins TLS to the GSMA CI and never logs those. That
# level needs a privileged lpac/OpenEUICC stack on a rooted device.
#
# Usage:
#   ./capture_esim_rsp.sh [-s SERIAL] [-o OUTDIR] [--bugreport]
#     -s SERIAL     target device (required if more than one device is attached)
#     -o OUTDIR     output directory (default ./esim-rsp-capture/<timestamp>)
#     --bugreport   also pull an adb bugreport after capture (== the *#9900# "Run
#                   dumpstate/logcat" bundle: all buffers + every dumpsys)
#     --pull-logs   after capture, pull on-device SysDump / modem-log dirs
#                   (/sdcard/log etc.) and any .sdm/dumpState files. Use this to
#                   harvest logs written by *#9900# on Samsung (incl. modem .sdm,
#                   which plain adb cannot enable without root — you toggle it in
#                   the SysDump menu, this pulls the result)
#     --pcapdroid   start/stop PCAPdroid capture around the window via its adb control
#                   API, then pull the .pcap. One-time on-phone setup required first
#                   (see README). Captures SM-DP+ SNI/IP + timing; cannot decrypt the
#                   pinned RSP TLS. Implies --pull-logs.

set -euo pipefail

SERIAL=""
OUTDIR=""
DO_BUGREPORT=0
DO_PULL=0
DO_PCAP=0
PCAP_CTRL="com.emanuelef.remote_capture/.activities.CaptureCtrl"

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    -s) SERIAL="${2:?serial}"; shift 2 ;;
    -o) OUTDIR="${2:?dir}"; shift 2 ;;
    --bugreport) DO_BUGREPORT=1; shift ;;
    --pull-logs) DO_PULL=1; shift ;;
    --pcapdroid) DO_PCAP=1; DO_PULL=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo "unknown arg: $1" >&2; usage 1 ;;
  esac
done

command -v adb >/dev/null || { echo "adb not found on PATH" >&2; exit 1; }

adb_() { if [ -n "$SERIAL" ]; then adb -s "$SERIAL" "$@"; else adb "$@"; fi; }

# --- device selection ---------------------------------------------------------
mapfile -t DEVS < <(adb devices | awk 'NR>1 && $2=="device"{print $1}')
if [ "${#DEVS[@]}" -eq 0 ]; then
  echo "No authorized device. Enable USB debugging and accept the RSA prompt." >&2
  exit 1
fi
if [ -z "$SERIAL" ] && [ "${#DEVS[@]}" -gt 1 ]; then
  echo "Multiple devices attached — pick one with -s SERIAL:" >&2
  for d in "${DEVS[@]}"; do
    m=$(adb -s "$d" shell getprop ro.product.model 2>/dev/null | tr -d '\r')
    echo "  $d  ($m)" >&2
  done
  exit 1
fi
[ -z "$SERIAL" ] && SERIAL="${DEVS[0]}"

MODEL=$(adb_ shell getprop ro.product.model | tr -d '\r')
REL=$(adb_ shell getprop ro.build.version.release | tr -d '\r')
echo "Target: $MODEL  (Android $REL, serial $SERIAL)"
printf "Capture on THIS device? [y/N] "
read -r ans
case "$ans" in y|Y) ;; *) echo "aborted"; exit 0 ;; esac

# --- session dir --------------------------------------------------------------
TS=$(date +%Y%m%d-%H%M%S)
OUTDIR="${OUTDIR:-./esim-rsp-capture/$TS}"
mkdir -p "$OUTDIR"
echo "Session: $OUTDIR"

# radio buffer is readable via adb on most devices; fall back if not
if adb_ logcat -b radio -d -t 1 >/dev/null 2>&1; then
  BUFS=(-b main -b system -b radio -b crash)
else
  echo "note: radio buffer not readable on this device; capturing main/system only" >&2
  BUFS=(-b main -b system -b crash)
fi

# state snapshot: $1 = label (before|after)
snapshot() {
  local label="$1"
  local dir="$OUTDIR/state-$label"
  mkdir -p "$dir"
  adb_ shell date                              >"$dir/device-clock.txt"      2>&1 || true
  adb_ shell dumpsys isub                      >"$dir/isub.txt"              2>&1 || true
  adb_ shell dumpsys telephony.registry        >"$dir/telephony-registry.txt" 2>&1 || true
  adb_ shell cmd phone get-esim-lpa-mode       >"$dir/lpa-mode.txt"          2>&1 || true
  adb_ shell pm list packages -f 'euicc'       >"$dir/euicc-packages.txt"    2>&1 || true
  adb_ shell "getprop | grep -iE 'euicc|esim|lpa'" >"$dir/euicc-props.txt"   2>&1 || true
  adb_ shell settings get global euicc_provisioned >"$dir/euicc-provisioned.txt" 2>&1 || true
}

# --- capture ------------------------------------------------------------------
adb_ logcat -c 2>/dev/null || true   # best effort; clearing radio may be refused
echo "Host start: $(date -u +%FT%TZ)" >"$OUTDIR/host-clock.txt"
snapshot before

if [ "$DO_PCAP" -eq 1 ]; then
  echo "Starting PCAPdroid capture (accept the VPN / control prompt on the phone if shown)..."
  adb_ shell am start -W \
    -e action start \
    -e pcap_dump_mode pcap_file \
    -e pcap_name "esim-$TS.pcap" \
    -n "$PCAP_CTRL" >/dev/null 2>&1 || echo "  note: PCAPdroid control failed — is it installed and control approved?" >&2
fi

LOGPID=""
finished=0
finish() {
  [ "$finished" -eq 1 ] && return
  finished=1
  [ -n "$LOGPID" ] && kill "$LOGPID" 2>/dev/null || true
  wait "$LOGPID" 2>/dev/null || true
  echo
  echo "Stopping capture, snapshotting after-state..."
  [ "$DO_PCAP" -eq 1 ] && adb_ shell am start -W -e action stop -n "$PCAP_CTRL" >/dev/null 2>&1 || true
  snapshot after
  [ "$DO_BUGREPORT" -eq 1 ] && { echo "Pulling bugreport (this takes a minute)..."; adb_ bugreport "$OUTDIR/bugreport" || true; }

  if [ "$DO_PULL" -eq 1 ]; then
    echo "Harvesting on-device log dirs (SysDump / modem logs)..."
    local dst="$OUTDIR/pulled-logs"; mkdir -p "$dst"
    for d in /sdcard/log /sdcard/debug_log /sdcard/dumpstate /sdcard/Download/log /sdcard/Download/PCAPdroid; do
      adb_ pull "$d" "$dst/" >/dev/null 2>&1 || true
    done
    adb_ shell "find /sdcard -maxdepth 4 \\( -iname '*.sdm' -o -iname 'dumpState*' -o -iname '*.dm' -o -iname 'sbuff_*' -o -iname '*.pcap' -o -iname '*.pcapng' \\) 2>/dev/null" \
      | tr -d '\r' | while IFS= read -r f; do
        [ -n "$f" ] && adb_ pull "$f" "$dst/" >/dev/null 2>&1 || true
      done
  fi

  # focused RSP view out of the full log
  local RE='euicc|LPA[^a-z]|SM-?DP|smdp|es9|es10|es11|[^a-z]RSP|activation ?code|matchingId|DownloadableSubscription|downloadSubscription|BoundProfile|[^a-z]BPP|EuiccService|EuiccController|EuiccConnector|EuiccCardController|Notification|ODSA|SGP|profileClass|profileInstall|SubscriptionController|carrierConfig'
  grep -iE "$RE" "$OUTDIR/logcat-full.txt" >"$OUTDIR/logcat-rsp.txt" 2>/dev/null || true

  # pull out the interesting values
  {
    echo "## URLs / hosts";       grep -hoE 'https?://[^ "'\''"]+' "$OUTDIR/logcat-full.txt" | sort -u
    echo; echo "## SM-DP+ candidates"; grep -ihoE '([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+(smdp|rsp|ondemandconnectivity|gsma|esim)[a-z0-9.-]*' "$OUTDIR/logcat-full.txt" | sort -u
    echo; echo "## matchingId";    grep -ihoE 'matchingId["= :]+[A-Za-z0-9._-]+' "$OUTDIR/logcat-rsp.txt" | sort -u
    echo; echo "## result / error codes"; grep -ihoE '(OPERATION|ERROR|RESULT|resolvableError)[_A-Z]*[ =:][A-Za-z0-9_-]+' "$OUTDIR/logcat-rsp.txt" | sort | uniq -c | sort -rn | head -40
  } >"$OUTDIR/summary.txt" 2>/dev/null || true

  echo
  echo "Done. Artifacts in $OUTDIR :"
  echo "  logcat-full.txt   full system+radio log for the window"
  echo "  logcat-rsp.txt    lines filtered to eSIM/RSP tags"
  echo "  summary.txt       extracted hosts, SM-DP+, matchingId, result codes"
  echo "  state-before/  state-after/   subscription + telephony snapshots"
  [ "$DO_BUGREPORT" -eq 1 ] && echo "  bugreport*        full adb bugreport (== *#9900# dumpstate/logcat)"
  [ "$DO_PULL" -eq 1 ] && echo "  pulled-logs/      on-device SysDump / modem / PCAPdroid files (.sdm, .pcap) if any"
  exit 0
}
trap finish INT TERM

adb_ logcat "${BUFS[@]}" -v threadtime >"$OUTDIR/logcat-full.txt" &
LOGPID=$!

cat <<EOF

Capturing. On the phone now:
  Settings > Network & internet > SIMs > Add eSIM   (scan the QR / enter the code)
Let the download AND activation finish.

Press ENTER when done (or Ctrl-C) to stop and process.
EOF
read -r _
finish
