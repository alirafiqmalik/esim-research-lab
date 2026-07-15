#!/usr/bin/env bash
# Guarantee exactly one healthy frida-server on the device. Idempotent.
set -u
serial="${ESIMCTL_SERIAL:-$(adb devices | awk '$2=="device"{print $1;exit}')}"
[ -z "$serial" ] && { echo "ensure_frida: no device" >&2; exit 1; }
ADB="adb -s $serial"
$ADB shell "su -c 'ls /data/local/tmp/frida-server' " >/dev/null 2>&1 || {
  echo "ensure_frida: /data/local/tmp/frida-server missing (run setup_testbed.sh)" >&2; exit 1; }
$ADB shell "su -c 'pkill -9 -f frida-server'" 2>/dev/null; sleep 1
$ADB shell "su -c 'nohup /data/local/tmp/frida-server -l 127.0.0.1:27042 >/data/local/tmp/frida.log 2>&1 &'"
for _ in $(seq 1 12); do
  if frida-ps -U >/dev/null 2>&1; then echo "ensure_frida: ready"; exit 0; fi
  sleep 1
done
echo "ensure_frida: frida-server not healthy after 12s" >&2
$ADB shell "su -c 'cat /data/local/tmp/frida.log'" >&2 2>/dev/null
exit 1
