#!/usr/bin/env bash
# ==============================================================================
# MVT Android Auto-Runner Uninstallation Script
# ==============================================================================

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Must be executed with root privileges (sudo ./uninstall.sh)" >&2
    exit 1
fi

echo "[*] Stopping and disabling mvt-watcher.service..."
systemctl stop mvt-watcher.service 2>/dev/null || true
systemctl disable mvt-watcher.service 2>/dev/null || true
rm -f /etc/systemd/system/mvt-watcher.service
systemctl daemon-reload

echo "[*] Removing /opt/mvt..."
rm -rf /opt/mvt

echo "[+] Uninstallation complete."
