#!/usr/bin/env bash
# Sets up the full MITM capture pipeline for the ROOTED Pixel 7a over USB.
# No hotspot, no Wi-Fi proxy, no firewall changes: traffic reaches mitmproxy
# through an adb-reverse USB tunnel, and TLS is decrypted via a system-trusted
# CA cert installed into the conscrypt APEX store.
#
# Prereqs: device rooted (Magisk), mitmproxy CA in ~/.mitmproxy, adb authorized.
set -euo pipefail

SERIAL="${1:-35181JEHN08662}"
PORT="${2:-8083}"
CONFDIR="${HOME}/.mitmproxy"
SESS="sessions/pixel7a-$(date +%Y%m%d)"
ADB="adb -s ${SERIAL}"

mkdir -p "${SESS}"

# 1. CA cert into the system trust store (Android 14+ conscrypt APEX).
HASH=$(openssl x509 -inform PEM -subject_hash_old -noout -in "${CONFDIR}/mitmproxy-ca-cert.pem")
cp "${CONFDIR}/mitmproxy-ca-cert.pem" "/tmp/${HASH}.0" 2>/dev/null || cp "${CONFDIR}/mitmproxy-ca-cert.pem" "./tmp/${HASH}.0"
SRC="/tmp/${HASH}.0"; [ -f "$SRC" ] || SRC="./tmp/${HASH}.0"
${ADB} push "${SRC}" "/data/local/tmp/${HASH}.0"
${ADB} push tools/install_system_cert.sh /data/local/tmp/install_system_cert.sh
${ADB} shell "su -c 'sh /data/local/tmp/install_system_cert.sh ${HASH}.0'"

# 2. USB reverse tunnel: device 127.0.0.1:PORT -> laptop mitmproxy.
${ADB} reverse "tcp:${PORT}" "tcp:${PORT}"

# 3. Route device app traffic through the tunnel.
${ADB} shell "su -c 'settings put global http_proxy 127.0.0.1:${PORT}'"

echo "Pipeline ready. Start mitmproxy on the laptop:"
echo "  mitmdump --listen-host 127.0.0.1 --listen-port ${PORT} -w ${SESS}/traffic.mitm --set confdir=${CONFDIR}"
echo
echo "Tear down when done (RESTORES phone internet):"
echo "  ${ADB} shell \"su -c 'settings delete global http_proxy'\""
echo "  ${ADB} reverse --remove tcp:${PORT}"
