#!/usr/bin/env python3
"""
MVT Android Auto-Runner & Forensics Pipeline
- Enforces shared 24h rate limiting across hosts via /sdcard/Documents/.mvt_last_check
- Performs differential package hashing against /sdcard/Documents/.mvt_pkg_hashes
- Selectively downloads new and modified packages to save time and bandwidth
- Runs Android Quick Forensics (androidqf) and Mobile Verification Toolkit (MVT)
- Delivers persistent desktop toast notifications (0%, 50%, 100%) that stay until closed
- Automatically archives forensic evidence to /opt/mvt/output/incidents/ if threats detected
- Uses per-device locking to support concurrent multi-device scanning
"""

import sys
import os
import glob
import json
import time
import fcntl
import argparse
import subprocess
from datetime import datetime

MVT_ROOT = "/opt/mvt"
MVT_BIN = f"{MVT_ROOT}/bin/mvt-android"
AQF_BIN = f"{MVT_ROOT}/bin/androidqf"
INDICATORS_DIR = f"{MVT_ROOT}/indicators"
CACHE_DIR = f"{MVT_ROOT}/cache/apks"
OUTPUT_DIR = f"{MVT_ROOT}/output/latest"
RAW_DIR = f"{OUTPUT_DIR}/raw"
ANALYSIS_DIR = f"{OUTPUT_DIR}/analysis"
INCIDENTS_DIR = f"{MVT_ROOT}/output/incidents"
LOG_FILE = f"{MVT_ROOT}/logs/mvt-autorun.log"


def log(msg: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"[{timestamp}] {msg}"
    print(formatted, flush=True)
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(formatted + "\n")
    except Exception:
        pass


def send_toast(title: str, message: str, urgency: str = "critical"):
    """
    Broadcasts persistent desktop notifications that remain on-screen until closed.
    Uses -t 0 (no timeout) and -h boolean:resident:true.
    """
    bus_patterns = ["/run/user/*/bus"]
    buses = []
    for p in bus_patterns:
        buses.extend(glob.glob(p))

    current_uid = os.getuid()

    for bus in set(buses):
        try:
            parts = bus.split("/")
            if len(parts) >= 4:
                uid = int(parts[3])
            else:
                continue

            username_proc = subprocess.run(
                ["id", "-nu", str(uid)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )
            username = username_proc.stdout.strip()
            if not username:
                continue

            notify_cmd = [
                "notify-send",
                "-t", "0",
                "-u", urgency,
                "-h", "boolean:resident:true",
                "-a", "MVT Forensics",
                "-i", "security-high",
                title,
                message
            ]

            if current_uid == uid:
                env = os.environ.copy()
                env["DISPLAY"] = ":0"
                env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus}"
                subprocess.run(notify_cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.run(
                    ["sudo", "-u", username, "env", "DISPLAY=:0", f"DBUS_SESSION_BUS_ADDRESS=unix:path={bus}"] + notify_cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
        except Exception as e:
            log(f"Failed to send toast to {bus}: {e}")


def run_adb(cmd: list[str], serial: str | None = None, input_data: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    base = ["adb"]
    if serial:
        base.extend(["-s", serial])
    base.extend(cmd)
    return subprocess.run(base, input=input_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=check)


def get_connected_devices() -> list[str]:
    res = subprocess.run(["adb", "devices"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    devices = []
    for line in res.stdout.splitlines()[1:]:
        parts = line.strip().split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    return devices


def read_device_file(serial: str, remote_path: str) -> str:
    res = run_adb(["shell", f"cat {remote_path} 2>/dev/null || true"], serial=serial, check=False)
    return res.stdout.strip()


def write_device_file(serial: str, remote_path: str, content: str):
    temp_local = f"/tmp/.mvt_sync_{int(time.time()*1000)}"
    try:
        with open(temp_local, "w") as f:
            f.write(content)
        run_adb(["push", temp_local, remote_path], serial=serial, check=False)
    finally:
        if os.path.exists(temp_local):
            os.remove(temp_local)


def check_rate_limit(serial: str, force: bool = False) -> bool:
    """
    Returns True if verification should proceed, False if already verified today.
    Rate limit resets at 00:00 midnight (checked via YYYY-MM-DD prefix).
    """
    if force:
        log("Force flag specified. Bypassing 24h rate limit.")
        return True

    today_str = datetime.now().strftime("%Y-%m-%d")
    last_check = read_device_file(serial, "/sdcard/Documents/.mvt_last_check")

    if last_check.startswith(today_str):
        log(f"Device {serial} was already verified today ({last_check}). Skipping scan.")
        return False

    return True


def get_device_pkg_hashes(serial: str) -> dict[str, dict]:
    """
    Computes SHA256 hashes of packages directly on device via stdin script.
    """
    log("Computing package SHA256 hashes on device...")
    script = """
pm list packages -3 -f | while read -r line; do
    line="${line#package:}"
    apk="${line%=*}"
    pkg="${line##*=}"
    if [ -f "$apk" ]; then
        h=$(sha256sum "$apk" 2>/dev/null)
        echo "$pkg\t${h%% *}\t$apk"
    fi
done
"""
    res = run_adb(["shell", "sh"], serial=serial, input_data=script, check=False)

    current_hashes = {}
    for line in res.stdout.splitlines():
        parts = line.strip().split("\t")
        if len(parts) >= 3:
            pkg_name, sha256, apk_path = parts[0], parts[1], parts[2]
            current_hashes[pkg_name] = {
                "sha256": sha256,
                "apk_path": apk_path
            }
    log(f"Computed SHA256 for {len(current_hashes)} 3rd-party packages on device.")
    return current_hashes


def compare_and_sync_packages(serial: str, current_hashes: dict[str, dict], raw_apk_dir: str):
    """
    Compares current package hashes against /sdcard/Documents/.mvt_pkg_hashes.
    Downloads only new or modified packages; links/copies cached packages if unchanged.
    Updates the device baseline afterwards.
    """
    os.makedirs(CACHE_DIR, exist_ok=True)
    os.makedirs(raw_apk_dir, exist_ok=True)

    old_raw = read_device_file(serial, "/sdcard/Documents/.mvt_pkg_hashes")
    old_hashes = {}
    if old_raw:
        for line in old_raw.splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                old_hashes[parts[0]] = parts[1]

    new_pkgs = []
    changed_pkgs = []
    unchanged_pkgs = []

    for pkg_name, data in current_hashes.items():
        sha = data["sha256"]
        if pkg_name not in old_hashes:
            new_pkgs.append((pkg_name, data))
        elif old_hashes[pkg_name] != sha:
            changed_pkgs.append((pkg_name, data))
        else:
            unchanged_pkgs.append((pkg_name, data))

    log(f"Package Inventory: {len(new_pkgs)} new, {len(changed_pkgs)} modified, {len(unchanged_pkgs)} unchanged.")

    # Pull new or changed packages
    to_pull = new_pkgs + changed_pkgs
    for pkg_name, data in to_pull:
        remote_apk = data["apk_path"]
        local_target = f"{raw_apk_dir}/{pkg_name}.apk"
        cached_apk = f"{CACHE_DIR}/{pkg_name}_{data['sha256']}.apk"
        log(f"Pulling APK for {pkg_name} ({remote_apk})...")
        run_adb(["pull", remote_apk, local_target], serial=serial, check=False)
        if os.path.exists(local_target):
            try:
                subprocess.run(["cp", "-f", local_target, cached_apk], check=False)
            except Exception:
                pass

    # For unchanged packages, link or copy from local cache if available
    for pkg_name, data in unchanged_pkgs:
        cached_apk = f"{CACHE_DIR}/{pkg_name}_{data['sha256']}.apk"
        local_target = f"{raw_apk_dir}/{pkg_name}.apk"
        if os.path.exists(cached_apk):
            try:
                if not os.path.exists(local_target):
                    os.link(cached_apk, local_target)
            except Exception:
                subprocess.run(["cp", "-f", cached_apk, local_target], check=False)
        else:
            log(f"Host caching package {pkg_name}...")
            run_adb(["pull", data["apk_path"], local_target], serial=serial, check=False)
            if os.path.exists(local_target):
                subprocess.run(["cp", "-f", local_target, cached_apk], check=False)

    lines = [f"{pkg}\t{info['sha256']}\t{info['apk_path']}" for pkg, info in current_hashes.items()]
    new_baseline = "\n".join(lines)
    write_device_file(serial, "/sdcard/Documents/.mvt_pkg_hashes", new_baseline)
    log("Synchronized package hash baseline to /sdcard/Documents/.mvt_pkg_hashes.")

    return len(new_pkgs), len(changed_pkgs), len(unchanged_pkgs)


def enrich_packages_json(raw_dir: str, current_hashes: dict[str, dict]):
    """
    Injects sha256 digests and certificate digests into packages.json for MVT analysis.
    """
    pkg_json_path = os.path.join(raw_dir, "packages.json")
    if not os.path.exists(pkg_json_path):
        return

    try:
        with open(pkg_json_path, "r") as f:
            packages = json.load(f)

        for pkg in packages:
            name = pkg.get("name")
            if name in current_hashes:
                sha = current_hashes[name]["sha256"]
                files = pkg.get("files", [])
                if not files:
                    files = [{}]
                    pkg["files"] = files

                for f_info in files:
                    f_info["sha256"] = sha

                apk_file = os.path.join(raw_dir, "apks", f"{name}.apk")
                if os.path.exists(apk_file):
                    cert_res = subprocess.run(
                        ["apksigner", "verify", "--print-certs", apk_file],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        text=True
                    )
                    cert_data = {"Md5": "", "Sha1": "", "Sha256": ""}
                    for line in cert_res.stdout.splitlines():
                        if "Signer #1 certificate SHA-256 digest:" in line:
                            cert_data["Sha256"] = line.split(":", 1)[1].strip()
                        elif "Signer #1 certificate SHA-1 digest:" in line:
                            cert_data["Sha1"] = line.split(":", 1)[1].strip()
                        elif "Signer #1 certificate MD5 digest:" in line:
                            cert_data["Md5"] = line.split(":", 1)[1].strip()

                    for f_info in files:
                        f_info["certificate"] = cert_data

        with open(pkg_json_path, "w") as f:
            json.dump(packages, f, indent=2)
        log("Enriched packages.json with SHA256 and certificate signatures.")
    except Exception as e:
        log(f"Failed to enrich packages.json: {e}")


def run_androidqf(serial: str, raw_dir: str):
    """
    Runs Android Quick Forensics (androidqf) in fast mode.
    Selects 'No backup' and 'Do not download any' packages since we pulled them differentially.
    """
    log("Executing androidqf extraction...")
    os.makedirs(raw_dir, exist_ok=True)
    cwd = raw_dir

    nav_input = b"\x1b[B\x1b[B\r\n\x1b[B\x1b[B\r\n\r\n\r\n"
    cmd = [AQF_BIN, "-fast", "-s", serial, "-o", raw_dir]
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
    )
    stdout, _ = proc.communicate(input=nav_input, timeout=600)
    log("androidqf acquisition completed.")


def run_mvt_analysis(raw_dir: str, analysis_dir: str) -> dict:
    """
    Runs mvt-android check-androidqf against the acquired raw data.
    """
    log("Executing MVT IOC analysis...")
    os.makedirs(analysis_dir, exist_ok=True)
    cmd = [
        MVT_BIN,
        "check-androidqf",
        "-o", analysis_dir,
        "-n",
        raw_dir
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    log_output = proc.stdout
    with open(f"{analysis_dir}/mvt_run.log", "w") as f:
        f.write(log_output)

    alerts = {"INFORMATIONAL": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for line in log_output.splitlines():
        for k in alerts.keys():
            if "MVT produced" in line and f"{k} alerts." in line:
                try:
                    num = int(line.split("produced")[1].split(k)[0].strip())
                    alerts[k] = num
                except Exception:
                    pass
    return alerts


def main():
    parser = argparse.ArgumentParser(description="MVT Android Auto-Runner Pipeline")
    parser.add_argument("-s", "--serial", help="Target device serial number")
    parser.add_argument("-f", "--force", action="store_true", help="Bypass 24h rate limit")
    args = parser.parse_args()

    serial = args.serial
    if not serial:
        devs = get_connected_devices()
        if not devs:
            log("No connected Android device in 'device' state. Exiting.")
            sys.exit(0)
        serial = devs[0]

    # Per-device exclusive process lock (allows concurrent multi-device execution)
    os.makedirs("/run/lock", exist_ok=True)
    lock_file = f"/run/lock/mvt-autorun-{serial}.lock"
    lock_fd = open(lock_file, "w")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        log(f"Another MVT verification process is currently active for device {serial}. Exiting.")
        sys.exit(0)

    try:
        # Verify device state
        state_proc = run_adb(["get-state"], serial=serial, check=False)
        if state_proc.stdout.strip() != "device":
            log(f"Device {serial} state is '{state_proc.stdout.strip()}'. Not ready. Exiting.")
            sys.exit(0)

        # Check rate limit (shared across PCs via /sdcard/Documents/.mvt_last_check)
        if not check_rate_limit(serial, force=args.force):
            sys.exit(0)

        # TOAST 1: 0% Started (Persistent)
        log(f"Starting forensic pipeline for {serial}...")
        send_toast(
            "MVT Forensics (0%)",
            f"Device connected ({serial}).\nStarting forensic verification...",
            urgency="critical"
        )

        # Storage cleanup: overwrite previous scan results for routine scans
        subprocess.run(["rm", "-rf", OUTPUT_DIR], check=False)
        raw_apk_dir = f"{RAW_DIR}/apks"
        os.makedirs(raw_apk_dir, exist_ok=True)
        os.makedirs(ANALYSIS_DIR, exist_ok=True)

        # Step 1: Differential package inventory and hash comparison
        current_hashes = get_device_pkg_hashes(serial)
        n_new, n_changed, n_unchanged = compare_and_sync_packages(serial, current_hashes, raw_apk_dir)

        # Step 2: AndroidQF Acquisition
        run_androidqf(serial, RAW_DIR)

        # Step 3: Enrich packages.json with computed hashes & certs
        enrich_packages_json(RAW_DIR, current_hashes)

        # TOAST 2: 50% Acquisition Complete / IOC Analysis Starting (Persistent)
        pkg_summary = f"{len(current_hashes)} apps evaluated ({n_new} new, {n_changed} modified)"
        send_toast(
            "MVT Forensics (50%)",
            f"Acquisition complete ({pkg_summary}).\nAnalyzing indicators of compromise...",
            urgency="critical"
        )

        # Step 4: Run MVT Analysis
        alerts = run_mvt_analysis(RAW_DIR, ANALYSIS_DIR)

        # Step 5: Update device rate-limit token
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        write_device_file(serial, "/sdcard/Documents/.mvt_last_check", now_str)
        log(f"Updated /sdcard/Documents/.mvt_last_check with timestamp: {now_str}")

        # TOAST 3: 100% Verification Complete (Persistent)
        crit = alerts["CRITICAL"]
        high = alerts["HIGH"]
        med = alerts["MEDIUM"]
        if crit > 0 or high > 0:
            status_msg = f"THREAT DETECTED: {crit} CRITICAL, {high} HIGH alerts!"
            urgency = "critical"
            # Forensic Preservation: Archive immutable copy of malicious evidence
            timestamp_tag = datetime.now().strftime("%Y%m%d_%H%M%S")
            incident_dir = f"{INCIDENTS_DIR}/incident_{timestamp_tag}_{serial}"
            os.makedirs(os.path.dirname(incident_dir), exist_ok=True)
            subprocess.run(["cp", "-a", OUTPUT_DIR, incident_dir], check=False)
            log(f"[INCIDENT PRESERVED] Malicious scan archived to {incident_dir}")
        elif med > 0:
            status_msg = f"Completed with {med} suspicious items."
            urgency = "normal"
        else:
            status_msg = "Clean. No indicators of compromise detected."
            urgency = "normal"

        send_toast(
            "MVT Forensics (100%)",
            f"Verification complete: {status_msg}\nResults saved to {OUTPUT_DIR}",
            urgency="critical"
        )
        log(f"Pipeline finished successfully. Status: {status_msg}")

    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()


if __name__ == "__main__":
    main()
