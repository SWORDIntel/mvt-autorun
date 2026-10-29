#!/usr/bin/env bash
# ==============================================================================
# MVT Android Auto-Runner Installation Script
# Automated deployment of MVT + AndroidQF + ADB Watcher daemon + Persistent UI Toasts
# ==============================================================================

set -euo pipefail

# Ensure running with sudo/root
if [ "$(id -u)" -ne 0 ]; then
    echo "[-] This installer must be executed with root privileges (e.g. sudo ./install.sh)" >&2
    exit 1
fi

TARGET_USER="${SUDO_USER:-$USER}"
if [ "$TARGET_USER" = "root" ]; then
    # Fallback to user 1000 if running directly as root
    TARGET_USER=$(id -nu 1000 2>/dev/null || echo "root")
fi
TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)

echo "[*] Target user: $TARGET_USER (home: $TARGET_HOME)"
echo "[*] Target installation prefix: /opt/mvt"

# 1. Package Dependencies
echo "[*] Installing required system packages..."
if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y --no-install-recommends \
        adb \
        fastboot \
        python3 \
        python3-venv \
        python3-pip \
        libnotify-bin \
        apksigner \
        zipalign \
        curl \
        wget \
        rsync \
        libusb-1.0-0
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y android-tools python3 libnotify apksigner zipalign curl wget rsync libusbx
elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm android-tools python libnotify android-sdk-build-tools curl wget rsync libusb
fi

# 2. Directory Structure
echo "[*] Initializing /opt/mvt directories..."
mkdir -p /opt/mvt/{bin,indicators,cache/apks,output/latest,logs,state}

# 3. AndroidQF Binary
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "/opt/mvt/bin/androidqf" ]; then
    echo "[+] Found existing androidqf binary in /opt/mvt/bin/androidqf"
elif [ -f "$SCRIPT_DIR/bin/androidqf" ]; then
    echo "[+] Installing androidqf binary from bundle..."
    cp -f "$SCRIPT_DIR/bin/androidqf" /opt/mvt/bin/androidqf
else
    echo "[*] Downloading latest androidqf binary release from GitHub..."
    LATEST_AQF_URL="https://github.com/AmnestyTech/androidqf/releases/latest/download/androidqf"
    curl -sSL -o /opt/mvt/bin/androidqf "$LATEST_AQF_URL" || {
        echo "[-] Failed downloading from GitHub. Checking fallback..."
    }
fi
chmod 755 /opt/mvt/bin/androidqf

# 4. Python Virtual Environment & MVT
echo "[*] Setting up MVT virtual environment in /opt/mvt/venv..."
if [ ! -d "/opt/mvt/venv" ]; then
    python3 -m venv /opt/mvt/venv
fi

# Upgrade packaging tools and install mvt
/opt/mvt/venv/bin/pip install --upgrade pip wheel setuptools
/opt/mvt/venv/bin/pip install mvt

# Symlink mvt-android
ln -sf /opt/mvt/venv/bin/mvt-android /opt/mvt/bin/mvt-android

# 5. STIX2 Threat Indicators
echo "[*] Fetching latest STIX2 indicators of compromise..."
sudo -u "$TARGET_USER" HOME="$TARGET_HOME" /opt/mvt/venv/bin/mvt-android download-iocs || true
if [ -d "$TARGET_HOME/.local/share/mvt/indicators" ]; then
    cp -u "$TARGET_HOME/.local/share/mvt/indicators/"*.stix2 /opt/mvt/indicators/ 2>/dev/null || true
fi

# 6. Install Autorun Scripts
echo "[*] Installing pipeline binaries..."
cp -f "$SCRIPT_DIR/bin/mvt-autorun.py" /opt/mvt/bin/mvt-autorun.py
cp -f "$SCRIPT_DIR/bin/mvt-autorun.sh" /opt/mvt/bin/mvt-autorun.sh
cp -f "$SCRIPT_DIR/bin/adb-device-watcher.py" /opt/mvt/bin/adb-device-watcher.py
chmod 755 /opt/mvt/bin/*.py /opt/mvt/bin/*.sh

# Set ownership
chown -R "$TARGET_USER:$TARGET_USER" /opt/mvt

# 7. Systemd Service
echo "[*] Deploying systemd service..."
cat > /etc/systemd/system/mvt-watcher.service << EOF
[Unit]
Description=MVT Android Device Watcher and Auto-Runner
After=network.target

[Service]
Type=simple
User=$TARGET_USER
Group=$TARGET_USER
WorkingDirectory=/opt/mvt
ExecStart=/opt/mvt/bin/adb-device-watcher.py
Restart=always
RestartSec=5
Environment=PATH=/opt/mvt/venv/bin:/opt/mvt/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=HOME=$TARGET_HOME

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now mvt-watcher.service

echo ""
echo "=============================================================================="
echo "[+] MVT Android Auto-Runner successfully installed and running!"
echo "[+] Watcher Status: $(systemctl is-active mvt-watcher.service)"
echo "[+] Output Directory: /opt/mvt/output/latest"
echo "[+] Activity Log:     /opt/mvt/logs/mvt-autorun.log"
echo "=============================================================================="
