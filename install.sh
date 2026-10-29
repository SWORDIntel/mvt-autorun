#!/usr/bin/env bash
# ==============================================================================
# MVT Android Auto-Runner Installation Script
# Automated deployment of MVT + AndroidQF + ADB & Platform Tools + Daemon + Toasts
# ==============================================================================

set -euo pipefail

# Auto-elevate with sudo if not root
if [ "$(id -u)" -ne 0 ]; then
    echo "[*] Non-root execution detected. Auto-elevating via sudo..."
    exec sudo --preserve-env=DISPLAY,XDG_RUNTIME_DIR,DBUS_SESSION_BUS_ADDRESS bash "$0" "$@"
fi

TARGET_USER="${SUDO_USER:-$USER}"
if [ "$TARGET_USER" = "root" ]; then
    TARGET_USER=$(id -nu 1000 2>/dev/null || echo "root")
fi
TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)

echo "[*] Target user: $TARGET_USER (home: $TARGET_HOME)"
echo "[*] Target installation prefix: /opt/mvt"

# 1. System Package Dependencies
echo "[*] Installing required system packages and development tooling..."
if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y --no-install-recommends \
        adb \
        fastboot \
        android-sdk-platform-tools-common \
        python3 \
        python3-venv \
        python3-pip \
        python3-dev \
        build-essential \
        libusb-1.0-0 \
        libusb-1.0-0-dev \
        libnotify-bin \
        apksigner \
        zipalign \
        curl \
        wget \
        rsync \
        jq \
        unzip
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y android-tools python3 python3-devel gcc libusb-devel libnotify apksigner zipalign curl wget rsync jq unzip
elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm android-tools python base-devel libusb libnotify android-sdk-build-tools curl wget rsync jq unzip
fi

# 2. ADB & Platform-Tools Verification (with Google SDK fallback)
if ! command -v adb >/dev/null 2>&1; then
    echo "[!] adb not found via package manager. Downloading Google Platform-Tools..."
    TMP_PT=$(mktemp -d)
    curl -sSL -o "$TMP_PT/platform-tools.zip" "https://dl.google.com/android/repository/platform-tools-latest-linux.zip"
    unzip -q "$TMP_PT/platform-tools.zip" -d "$TMP_PT"
    install -m 755 "$TMP_PT/platform-tools/adb" /usr/local/bin/adb
    install -m 755 "$TMP_PT/platform-tools/fastboot" /usr/local/bin/fastboot
    rm -rf "$TMP_PT"
    echo "[+] adb successfully installed to /usr/local/bin/adb"
else
    echo "[+] adb found: $(command -v adb) ($(adb version 2>&1 | head -n1))"
fi

# 3. Android USB Udev Rules & User Groups
echo "[*] Configuring Android USB udev permissions..."
groupadd -f plugdev
groupadd -f adbusers
usermod -aG plugdev,adbusers "$TARGET_USER" 2>/dev/null || true

UDEV_RULE_FILE="/etc/udev/rules.d/51-android.rules"
if [ ! -f "$UDEV_RULE_FILE" ]; then
    echo "[*] Installing universal Android udev rules..."
    cat > "$UDEV_RULE_FILE" << 'EOF'
# Universal Android USB Debugging Rules
SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", MODE="0666", GROUP="plugdev" # Google / Pixel
SUBSYSTEM=="usb", ATTR{idVendor}=="04e8", MODE="0666", GROUP="plugdev" # Samsung
SUBSYSTEM=="usb", ATTR{idVendor}=="2717", MODE="0666", GROUP="plugdev" # Xiaomi
SUBSYSTEM=="usb", ATTR{idVendor}=="22d9", MODE="0666", GROUP="plugdev" # OnePlus / Oppo
SUBSYSTEM=="usb", ATTR{idVendor}=="12d1", MODE="0666", GROUP="plugdev" # Huawei
SUBSYSTEM=="usb", ATTR{idVendor}=="2a70", MODE="0666", GROUP="plugdev" # OnePlus
SUBSYSTEM=="usb", ATTR{idVendor}=="0bb4", MODE="0666", GROUP="plugdev" # HTC
SUBSYSTEM=="usb", ATTR{idVendor}=="22b8", MODE="0666", GROUP="plugdev" # Motorola
SUBSYSTEM=="usb", ATTR{idVendor}=="0fce", MODE="0666", GROUP="plugdev" # Sony
SUBSYSTEM=="usb", ATTR{idVendor}=="1004", MODE="0666", GROUP="plugdev" # LG
SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_device", MODE="0666", GROUP="plugdev"
EOF
    if command -v udevadm >/dev/null 2>&1; then
        udevadm control --reload-rules 2>/dev/null || true
        udevadm trigger 2>/dev/null || true
    fi
fi

# 4. Directory Structure
echo "[*] Initializing /opt/mvt directory tree..."
mkdir -p /opt/mvt/{bin,indicators,cache/apks,output/latest,logs,state}

# 5. AndroidQF Binary (Acquisition tool)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64) AQF_ARCH="amd64" ;;
    aarch64|arm64) AQF_ARCH="arm64" ;;
    *) AQF_ARCH="amd64" ;;
esac

if [ -f "/opt/mvt/bin/androidqf" ]; then
    echo "[+] Found existing androidqf binary in /opt/mvt/bin/androidqf"
elif [ -f "$SCRIPT_DIR/bin/androidqf" ]; then
    echo "[+] Installing bundled androidqf binary..."
    cp -f "$SCRIPT_DIR/bin/androidqf" /opt/mvt/bin/androidqf
else
    echo "[*] Fetching latest androidqf ($AQF_ARCH) from mvt-project/androidqf..."
    DOWNLOAD_URL=$(curl -sSL "https://api.github.com/repos/mvt-project/androidqf/releases/latest" 2>/dev/null \
        | jq -r --arg arch "$AQF_ARCH" '.assets[] | select(.name | test("linux_" + $arch)) | .browser_download_url' 2>/dev/null | head -n1 || true)

    if [ -n "$DOWNLOAD_URL" ] && [ "$DOWNLOAD_URL" != "null" ]; then
        curl -sSL -o /opt/mvt/bin/androidqf "$DOWNLOAD_URL"
    else
        # Direct release fallback
        curl -sSL -o /opt/mvt/bin/androidqf "https://github.com/mvt-project/androidqf/releases/download/v1.8.3/androidqf_linux_${AQF_ARCH}_1.8.3"
    fi
fi
chmod 755 /opt/mvt/bin/androidqf

# 6. Python Virtual Environment & MVT (Mobile Verification Toolkit)
echo "[*] Installing Mobile Verification Toolkit (MVT)..."
if [ ! -d "/opt/mvt/venv" ]; then
    python3 -m venv /opt/mvt/venv
fi

/opt/mvt/venv/bin/pip install --upgrade pip wheel setuptools
/opt/mvt/venv/bin/pip install mvt

# Verify MVT installation
if [ ! -f "/opt/mvt/venv/bin/mvt-android" ]; then
    echo "[-] Error: mvt-android binary not found in virtualenv!" >&2
    exit 1
fi
ln -sf /opt/mvt/venv/bin/mvt-android /opt/mvt/bin/mvt-android
echo "[+] Mobile Verification Toolkit ($(/opt/mvt/bin/mvt-android --version 2>&1 | head -n1)) ready."

# 7. STIX2 Threat Indicators
echo "[*] Downloading STIX2 indicators of compromise (Pegasus, Predator, Candiru, Stalkerware, etc.)..."
sudo -u "$TARGET_USER" HOME="$TARGET_HOME" /opt/mvt/venv/bin/mvt-android download-iocs || true
if [ -d "$TARGET_HOME/.local/share/mvt/indicators" ]; then
    cp -u "$TARGET_HOME/.local/share/mvt/indicators/"*.stix2 /opt/mvt/indicators/ 2>/dev/null || true
fi

# 8. Install Pipeline Binaries
echo "[*] Installing autorun orchestrator and watcher daemon..."
cp -f "$SCRIPT_DIR/bin/mvt-autorun.py" /opt/mvt/bin/mvt-autorun.py
cp -f "$SCRIPT_DIR/bin/mvt-autorun.sh" /opt/mvt/bin/mvt-autorun.sh
cp -f "$SCRIPT_DIR/bin/adb-device-watcher.py" /opt/mvt/bin/adb-device-watcher.py
chmod 755 /opt/mvt/bin/*.py /opt/mvt/bin/*.sh

# Set ownership
chown -R "$TARGET_USER:$TARGET_USER" /opt/mvt

# 9. Systemd Service
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

# Start ADB server under user session
sudo -u "$TARGET_USER" HOME="$TARGET_HOME" adb start-server >/dev/null 2>&1 || true

echo ""
echo "=============================================================================="
echo "[+] MVT Android Auto-Runner and complete Android tooling installed!"
echo "[+] ADB:              $(command -v adb)"
echo "[+] MVT Android:      /opt/mvt/bin/mvt-android"
echo "[+] AndroidQF:        /opt/mvt/bin/androidqf"
echo "[+] Watcher Status:   $(systemctl is-active mvt-watcher.service)"
echo "[+] Output Directory: /opt/mvt/output/latest"
echo "[+] Activity Log:     /opt/mvt/logs/mvt-autorun.log"
echo "=============================================================================="
