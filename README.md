# MVT Android Auto-Runner & Forensics Pipeline

Automated, daemonized Android spyware and compromise verification pipeline powered by **Amnesty International's Mobile Verification Toolkit (MVT)** and **Android Quick Forensics (`androidqf`)**.

Triggers automatically whenever an Android device with USB debugging authorized connects to the machine.

---

## Key Features

1. **Automatic Device Detection (`adb-device-watcher.py`)**:
   - Runs as a `systemd` daemon listening to `adb track-devices`.
   - Fires immediately when a connected device transitions into the `device` (authorized debug) state.

2. **Shared Cross-PC Rate Limiting (`/sdcard/Documents/.mvt_last_check`)**:
   - Stores the last execution timestamp directly on the device's external storage.
   - Enforces a 24-hour verification window (resetting at 00:00 midnight).
   - Allows seamless device hand-offs between multiple PCs (e.g. Workstation and Proxmox server) without duplicate scans or maintaining centralized serial databases.

3. **Differential Package Inventory & Hashing (`/sdcard/Documents/.mvt_pkg_hashes`)**:
   - Calculates SHA-256 digests of installed 3rd-party and non-system packages directly on the device using native POSIX shell expansion (~0.3s execution time).
   - Compares against the device baseline:
     - **Unchanged packages**: Skipped from redundant USB download; linked/served from local host cache at `/opt/mvt/cache/apks/`.
     - **New / Modified packages**: Pulled over ADB, cached locally, and enriched into `packages.json` alongside cryptographic certificate fingerprints extracted with `apksigner`.
   - Prevents USB transfer bottlenecks while ensuring modified or sideloaded APKs are immediately captured for STIX2 indicator analysis.

4. **Persistent Desktop Toast Notifications**:
   - Delivers notifications to the host PC's graphical monitor (`DISPLAY=:0`, `/run/user/*/bus`):
     - **0% (Start)**: Triggered upon connection, detailing target serial.
     - **50% (Acquisition Complete)**: Reports package count, differential additions, and initiates IOC checking.
     - **100% (Finished)**: Summarizes scan alerts (Clean / Threat alerts) and points to result logs.
   - Configured with `-t 0`, `-u critical`, and FreeDesktop hint `-h boolean:resident:true` to ensure notifications remain visible until manually dismissed.

5. **Storage & Space Protection**:
   - Overwrites previous scan results (`/opt/mvt/output/latest/`) on each execution.
   - Raw and analysis folders stay lean and bounded.

---

## Architecture Flow

```
                      +-----------------------------+
                      |   Android Device Connects   |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |   adb-device-watcher.py     |
                      |  (Monitors track-devices)   |
                      +--------------+--------------+
                                     | state == "device"
                                     v
                      +-----------------------------+
                      |      mvt-autorun.sh         |
                      +--------------+--------------+
                                     |
           +-------------------------+-------------------------+
           |                                                   |
           v                                                   v
[Already Checked Today?]                                 [New Check Window]
/sdcard/Documents/.mvt_last_check                              |
starts with $(date +%Y-%m-%d)                                  v
           |                                     +---------------------------+
         (YES)                                   | TOAST (0%): Scan Started  |
           |                                     +-------------+-------------+
           v                                                   |
       [EXIT 0]                                                v
                                                 +---------------------------+
                                                 | Package Differential Hash |
                                                 | Compares vs device state: |
                                                 | .mvt_pkg_hashes           |
                                                 +-------------+-------------+
                                                               |
                                                               v
                                                 +---------------------------+
                                                 | Pull New/Modified APKs    |
                                                 | Cache locally /opt/mvt/   |
                                                 +-------------+-------------+
                                                               |
                                                               v
                                                 +---------------------------+
                                                 | Fast AndroidQF Dump       |
                                                 | (Dumpsys, props, files)   |
                                                 +-------------+-------------+
                                                               |
                                                               v
                                                 +---------------------------+
                                                 | TOAST (50%): Acq Complete |
                                                 +-------------+-------------+
                                                               |
                                                               v
                                                 +---------------------------+
                                                 | MVT STIX2 IOC Analysis    |
                                                 | (Pegasus, Predator, etc.) |
                                                 +-------------+-------------+
                                                               |
                                                               v
                                                 +---------------------------+
                                                 | Write timestamp to phone: |
                                                 | .mvt_last_check           |
                                                 +-------------+-------------+
                                                               |
                                                               v
                                                 +---------------------------+
                                                 | TOAST (100%): Persistent  |
                                                 | Summary & Results Ready   |
                                                 +---------------------------+
```

---

## Directory Structure

```
/opt/mvt/
├── bin/
│   ├── androidqf                  # Android Quick Forensics x86_64 ELF
│   ├── mvt-android                # Symlink to /opt/mvt/venv/bin/mvt-android
│   ├── mvt-autorun.py             # Core pipeline orchestrator
│   ├── mvt-autorun.sh             # Execution wrapper
│   └── adb-device-watcher.py      # Background device state daemon
├── cache/
│   └── apks/                      # Host-side persistent APK cache
├── indicators/                    # Downloaded STIX2 threat signatures
├── logs/
│   ├── mvt-autorun.log            # Execution timeline and triage log
│   └── mvt-watcher.log            # Device connect/disconnect log
├── output/
│   └── latest/                    # Overwritten on each scan
│       ├── raw/                   # Acquired androidqf dumps & packages
│       └── analysis/              # MVT JSON detection reports
└── venv/                          # Python 3 virtualenv with MVT
```

---

## Installation

Run the automated installer as root:

```bash
git clone https://github.com/SWORDIntel/mvt-autorun.git
cd mvt-autorun
sudo ./install.sh
```

The installer configures:
- Package dependencies (`adb`, `libnotify-bin`, `apksigner`, `zipalign`, `python3-venv`, etc.)
- Python virtual environment with `mvt`
- Current STIX2 threat indicators
- Systemd service `mvt-watcher.service` (enabled and started)

---

## Manual Verification & CLI Usage

To manually trigger a verification against a connected device (e.g. bypassing the 24-hour rate limit):

```bash
# Force run bypass 24h limit
/opt/mvt/bin/mvt-autorun.sh --force

# Target specific device serial
/opt/mvt/bin/mvt-autorun.sh -s <SERIAL> --force
```

To monitor watcher status:

```bash
systemctl status mvt-watcher.service
tail -f /opt/mvt/logs/mvt-autorun.log
```

---

## Uninstallation

```bash
sudo ./uninstall.sh
```
