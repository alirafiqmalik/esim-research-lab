#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
E="python3 esimctl.py"
fail=0
check() { # name  expected_exit  jq_filter  (reads stdin json)
  local name="$1" exp="$2" filt="$3"; shift 3
  if [ "$rc" = "$exp" ] && echo "$out" | python3 -c "import json,sys;d=json.load(sys.stdin);sys.exit(0 if ($filt) else 1)" 2>/dev/null; then
    echo "PASS $name"; else echo "FAIL $name (rc=$rc exp=$exp)"; fail=1; fi
}
out=$($E list); rc=$?;  check "list"  0 "d['count']>=0 and 'profiles' in d"
out=$($E eid);  rc=$?;  check "eid"   0 "len(d.get('eid') or '')==32"
out=$($E info); rc=$?;  check "info"  0 "d.get('ok') is True"
out=$($E download 'LPA:1$rsp-eu.redteamobile.com$5901981126831169'); rc=$?
check "download-capture" 2 "d.get('ok') is False and len(d.get('rsp',[]))>=2"
# cycle must be wired on the default backend (was the silent regression)
$E --help >/dev/null 2>&1
out=$($E cycle --code 'LPA:1$rsp-eu.redteamobile.com$5901981126831169' --times 1); rc=$?
check "cycle-default-backend" 0 "d.get('op')=='cycle' and len(d['iterations'])==1"
# framework EuiccManager backend (sync read + async action via a mutable PendingIntent)
out=$($E --backend fw eid); rc=$?
check "fw-eid" 0 "len(d.get('eid') or '')==32 and d.get('ok') is True"
out=$($E --backend fw download 'LPA:1$rsp-eu.redteamobile.com$5901981126831169'); rc=$?
check "fw-download" 2 "d.get('ok') is False and 'resultCode' in d"
# unbridged commands surfaced via raw ES10x over the ISD-R (channel reuse)
out=$($E apdu 81E2910006BF3E035C015A); rc=$?
check "apdu-geteid" 0 "d.get('ok') is True and 'BF3E125A10' in (d.get('resp') or '')"
out=$($E get-addresses); rc=$?
check "get-addresses" 0 "d.get('ok') is True and 'rootDsAddress' in d"
out=$($E get-rat); rc=$?
check "get-rat" 0 "d.get('ok') is True and (d.get('resp') or '').startswith('BF43')"
# reset must refuse to wipe without the explicit opt-in flag
out=$($E reset); rc=$?
check "reset-guarded" 2 "d.get('ok') is False and 'confirm-wipe' in (d.get('error') or '')"
# frontier: more raw ES10x + a different applet (ECASD) + the two network probes
out=$($E info1); rc=$?
check "info1" 0 "d.get('ok') is True and (d.get('resp') or '').startswith('BF20')"
out=$($E challenge); rc=$?
check "challenge" 0 "d.get('ok') is True and (d.get('resp') or '').startswith('BF2E')"
out=$($E select-aid A0000005591010FFFFFFFF8900000200); rc=$?
check "ecasd-select" 0 "d.get('ok') is True and len(d.get('selectResponse') or '')>0"
# card backend reaches the framework but is authz-gated to the active LPA
out=$($E card-challenge); rc=$?
check "card-authz-gated" 2 "d.get('resultName')=='RESULT_CALLER_NOT_ALLOWED'"
# ES11 discovery + AuthenticateServer against the production-CI root SM-DS (network)
out=$($E discovery); rc=$?
check "es11-discovery" 0 "d.get('ok') is True and 'events' in d"
out=$($E authenticate lpa.ds.gsma.com); rc=$?
check "authenticate-prod-ci" 0 "d.get('ciTrusted') is True and d.get('stage')=='accepted'"
[ $fail -eq 0 ] && echo "ALL PASS" || echo "SOME FAILED"
exit $fail
