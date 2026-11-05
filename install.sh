#!/usr/bin/env bash
# ==============================================================================
# MVT Android Auto-Runner Installation Script
# Automated deployment of MVT + AndroidQF + ADB & Platform Tools + Daemon + Toasts
# ==============================================================================

set -euo pipefail
umask 022
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
TARGET_GROUP=$(id -gn "$TARGET_USER")

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
        libssl-dev \
        openssl \
        pkg-config \
        libusb-1.0-0 \
        libusb-1.0-0-dev \
        libnotify-bin \
        libglib2.0-bin \
        apksigner \
        zipalign \
        curl \
        wget \
        rsync \
        jq \
        unzip
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y android-tools python3 python3-devel openssl openssl-devel gcc make pkgconf libusb-devel libnotify glib2 apksigner zipalign curl wget rsync jq unzip
elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm android-tools python openssl base-devel pkgconf libusb libnotify glib2 android-sdk-build-tools curl wget rsync jq unzip
else
    echo "[-] Unsupported package manager; install the documented OS dependencies first." >&2
    exit 1
fi

# 2. Only distribution-managed ADB is supported; no unverified SDK fallback.
ADB_BIN=/usr/bin/adb
if [ ! -x "$ADB_BIN" ]; then
    echo "[-] OS-managed adb is required; no verified fallback is configured." >&2
    exit 1
fi
echo "[+] adb found: $ADB_BIN ($("$ADB_BIN" version 2>&1 | head -n1))"

# Validate the lock/architecture before publishing tools, then build the SHA backend.
python3 "$SCRIPT_DIR/tools/install_dependencies.py" validate --source "$SCRIPT_DIR"
mkdir -p /opt/mvt/{bin,indicators,cache/apks,output,logs,state}
make -C "$SCRIPT_DIR" native
install -m 755 "$SCRIPT_DIR/bin/mvt-hash" /opt/mvt/bin/mvt-hash
/opt/mvt/bin/mvt-hash --self-test
ln -sf "$ADB_BIN" /opt/mvt/bin/adb

# 3. Android USB Udev Rules & User Groups
echo "[*] Configuring Android USB udev permissions..."
groupadd -f adbusers
usermod -aG adbusers "$TARGET_USER"
python3 "$SCRIPT_DIR/tools/install_dependencies.py" udev --source "$SCRIPT_DIR"
if command -v udevadm >/dev/null 2>&1; then
    udevadm control --reload-rules
    udevadm trigger --subsystem-match=usb
fi

# 4. Directory Structure
echo "[*] Initializing /opt/mvt directory tree..."
mkdir -p /opt/mvt/{bin,indicators,cache/apks,output,logs,state}

# 5. AndroidQF: reuse only matching pins; stage, verify, chmod, then atomically publish.
python3 "$SCRIPT_DIR/tools/install_dependencies.py" androidqf --source "$SCRIPT_DIR"

# 6. Python Virtual Environment & MVT (Mobile Verification Toolkit)
echo "[*] Installing Mobile Verification Toolkit (MVT)..."
if [ ! -d "/opt/mvt/venv" ]; then
    python3 -m venv /opt/mvt/venv
fi

/opt/mvt/venv/bin/python -m pip --isolated install \
    --index-url https://pypi.org/simple --disable-pip-version-check \
    --timeout 30 --retries 2 --require-hashes --only-binary=:all: --force-reinstall \
    -r "$SCRIPT_DIR/requirements-pinned.txt"
/opt/mvt/venv/bin/python -m pip --isolated check

# Verify MVT installation
if [ ! -f "/opt/mvt/venv/bin/mvt-android" ]; then
    echo "[-] Error: mvt-android binary not found in virtualenv!" >&2
    exit 1
fi
ln -sf /opt/mvt/venv/bin/mvt-android /opt/mvt/bin/mvt-android
echo "[+] Mobile Verification Toolkit ($(/opt/mvt/bin/mvt-android --version 2>&1 | head -n1)) ready."

# 7. STIX2 Threat Indicators
echo "[*] Downloading STIX2 indicators of compromise (Pegasus, Predator, Candiru, Stalkerware, etc.)..."
if ! sudo -u "$TARGET_USER" HOME="$TARGET_HOME" /opt/mvt/venv/bin/mvt-android download-iocs; then
    echo "[!] Indicator refresh failed; retaining existing local indicators. Check freshness with doctor." >&2
fi
(
    shopt -s nullglob
    indicators=("$TARGET_HOME/.local/share/mvt/indicators/"*.stix2)
    if [ "${#indicators[@]}" -gt 0 ]; then
        cp -u -- "${indicators[@]}" /opt/mvt/indicators/
    fi
)
if [ -z "$(find /opt/mvt/indicators -type f -name '*.stix2' -print -quit)" ]; then
    echo "[!] No indicator files are available. Scans will fail closed until indicators are added; run doctor." >&2
fi

# 8. Install Pipeline Binaries
echo "[*] Installing autorun orchestrator, speedup utility, and watcher daemon..."
cp -f "$SCRIPT_DIR/bin/mvt-autorun.py" /opt/mvt/bin/mvt-autorun.py
cp -f "$SCRIPT_DIR/bin/mvt-autorun.sh" /opt/mvt/bin/mvt-autorun.sh
cp -f "$SCRIPT_DIR/bin/adb-device-watcher.py" /opt/mvt/bin/adb-device-watcher.py
cp -f "$SCRIPT_DIR/bin/system_speedup.py" /opt/mvt/bin/system_speedup.py
install -m 644 "$SCRIPT_DIR/bin/mvt_hash.py" /opt/mvt/bin/mvt_hash.py
install -m 755 "$SCRIPT_DIR/bin/mvt_doctor.py" /opt/mvt/bin/mvt_doctor.py
install -m 644 "$SCRIPT_DIR/bin/mvt_evidence.py" /opt/mvt/bin/mvt_evidence.py
install -m 644 "$SCRIPT_DIR/dependencies.json" "$SCRIPT_DIR/requirements-pinned.txt" /opt/mvt/
# Record real installed versions/digests and the source locks, after checking MVT's schema.
python3 "$SCRIPT_DIR/tools/install_dependencies.py" record --source "$SCRIPT_DIR"
chmod 755 /opt/mvt/bin/*.py /opt/mvt/bin/*.sh
ln -sf /opt/mvt/bin/system_speedup.py /usr/local/bin/system_speedup 2>/dev/null || true

# Preserve the licence and version archive with installed copies.
install -m 644 "$SCRIPT_DIR/LICENSE" /opt/mvt/LICENSE
mkdir -p /opt/mvt/LICENSES
install -m 644 "$SCRIPT_DIR/LICENSES/"*.txt /opt/mvt/LICENSES/

# Set ownership
chown -R "$TARGET_USER:$TARGET_GROUP" /opt/mvt

# Create/reuse a machine-named Ed25519 evidence-signing identity; never overwrite keys.
SIGNING_IDENTITY=$(python3 "$SCRIPT_DIR/tools/install_dependencies.py" signing-key \
    --source "$SCRIPT_DIR" --root /opt/mvt --home "$TARGET_HOME" \
    --user "$TARGET_USER" --hostname "$(hostname -s)")
MACHINE_KEY_NAME=$(printf '%s' "$SIGNING_IDENTITY" | jq -r '.machine_key_name')
echo "[+] Evidence signing key: $TARGET_HOME/.ssh/$MACHINE_KEY_NAME.pem"
echo "[+] Machine audit label:  $MACHINE_KEY_NAME"
echo "[!] Review incidents after each positive scan. Remove unwanted cases manually from /opt/mvt/output/incidents/<incident-id>/flagged_apks; these suspicious APKs are intentionally retained."

# 9. Systemd Service
echo "[*] Deploying systemd service..."
cat > /etc/systemd/system/mvt-watcher.service << EOF
[Unit]
Description=MVT Android Device Watcher and Auto-Runner
After=network.target

[Service]
Type=simple
User=$TARGET_USER
Group=$TARGET_GROUP
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
sudo -u "$TARGET_USER" HOME="$TARGET_HOME" "$ADB_BIN" start-server >/dev/null 2>&1 || true

echo ""
echo "=============================================================================="
echo "[+] MVT Android Auto-Runner and complete Android tooling installed!"
echo "[+] ADB:              $ADB_BIN"
echo "[+] MVT Android:      /opt/mvt/bin/mvt-android"
echo "[+] AndroidQF:        /opt/mvt/bin/androidqf"
echo "[+] Watcher Status:   $(systemctl is-active mvt-watcher.service)"
echo "[+] Output Directory: /opt/mvt/output/latest"
echo "[+] Activity Log:     /opt/mvt/logs/mvt-autorun.log"
echo "=============================================================================="
