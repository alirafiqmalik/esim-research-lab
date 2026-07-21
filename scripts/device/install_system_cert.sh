#!/system/bin/sh
# Installs a CA cert into the Android 14+ conscrypt system trust store at runtime.
# Apps run in mount namespaces forked from zygote, so a bind mount must be applied
# in each relevant namespace. Run as root on the device.
#
# Usage: install_system_cert.sh <hash>.0   (cert file already in /data/local/tmp)
set -u

CERT_NAME="$1"
CERT_SRC="/data/local/tmp/${CERT_NAME}"
TMPCERTS="/data/local/tmp/system-cacerts"
APEX_DIR="/apex/com.android.conscrypt/cacerts"
LEGACY_DIR="/system/etc/security/cacerts"

[ -f "$CERT_SRC" ] || { echo "missing $CERT_SRC"; exit 1; }

rm -rf "$TMPCERTS"
mkdir -p "$TMPCERTS"
cp "$APEX_DIR"/* "$TMPCERTS"/ 2>/dev/null
cp "$CERT_SRC" "$TMPCERTS"/
chown root:root "$TMPCERTS"/*
chmod 644 "$TMPCERTS"/*
chcon u:object_r:system_security_cacerts_file:s0 "$TMPCERTS"/*

apply() {
  pid="$1"
  [ -e "/proc/$pid/ns/mnt" ] || return 0
  nsenter --mount="/proc/$pid/ns/mnt" -- /system/bin/mount --bind "$TMPCERTS" "$APEX_DIR" 2>/dev/null
  nsenter --mount="/proc/$pid/ns/mnt" -- /system/bin/mount --bind "$TMPCERTS" "$LEGACY_DIR" 2>/dev/null
}

# Global namespace + zygotes (new app forks inherit the mount)
apply 1
for z in $(pgrep -f zygote); do apply "$z"; done

# Already-running processes that originate eSIM/RSP and test traffic
for proc in system_server com.android.phone com.google.android.euicc \
            com.android.settings com.android.chrome; do
  for p in $(pgrep -f "$proc"); do apply "$p"; done
done

echo "installed ${CERT_NAME} into system trust store"
echo "apex count: $(ls "$APEX_DIR" | wc -l)"
ls "$APEX_DIR" | grep -q "$CERT_NAME" && echo "VERIFY: ${CERT_NAME} present in apex view" || echo "VERIFY: NOT visible in this namespace (expected if su uses a different ns)"
