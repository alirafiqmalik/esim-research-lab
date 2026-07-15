#!/usr/bin/env bash
# Sets up a Wi-Fi hotspot using NetworkManager. Requires a Wi-Fi adapter in AP mode.
set -euo pipefail

SSID="${1:-esim-research}"
PASSWORD="${2:-esimresearch}"
IFACE="${3:-wlan0}"

nmcli connection delete "esim-hotspot" 2>/dev/null || true

nmcli connection add \
    type wifi ifname "$IFACE" con-name "esim-hotspot" autoconnect no ssid "$SSID" \
    -- wifi-sec.key-mgmt wpa-psk wifi-sec.psk "$PASSWORD" \
    802-11-wireless.mode ap 802-11-wireless.band bg \
    ipv4.method shared

nmcli connection up "esim-hotspot"

PC_IP=$(ip -4 addr show "$IFACE" | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1)
echo "Hotspot '$SSID' active on $IFACE (password: $PASSWORD)"
echo "Set phone Wi-Fi proxy → Manual → Host: $PC_IP  Port: 8080"
