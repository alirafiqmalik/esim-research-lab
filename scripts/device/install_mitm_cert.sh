#!/usr/bin/env bash
# Prints step-by-step CA cert install instructions for the connected Android device.
set -euo pipefail

PORT="${1:-8080}"
IFACE="${2:-wlan0}"
PC_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1 || echo "<PC_IP>")

cat <<EOF
=== mitmproxy CA Certificate — Installation Steps ===

1. Run the hotspot:        ./scripts/setup/setup_hotspot.sh
2. Start mitmproxy:        mitmdump --listen-port $PORT
3. Connect phone to the 'esim-research' Wi-Fi network.
4. On phone: Settings → Wi-Fi → long-press network → Modify
   Proxy: Manual  Host: $PC_IP  Port: $PORT
5. On phone browser: http://mitm.it → download Android cert
6. Settings → Security → Encryption & credentials →
   Install a certificate → CA certificate → select downloaded file

Note: Android 7+ does not trust user CA certs for apps targeting API 24+.
If ES9+/ES11 flows do not appear in mitmproxy after triggering eSIM activity,
the LPA is enforcing TLS pinning.
EOF
