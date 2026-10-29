#!/usr/bin/env python3
"""
ADB Device Watcher Daemon
Monitors ADB device connection states and triggers /opt/mvt/bin/mvt-autorun.sh
whenever an Android device enters the 'device' (debug mode authorized) state.
"""

import sys
import os
import time
import subprocess
from datetime import datetime

AUTORUN_SCRIPT = "/opt/mvt/bin/mvt-autorun.sh"
LOG_FILE = "/opt/mvt/logs/mvt-watcher.log"


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


def trigger_mvt(serial: str):
    log(f"Device {serial} entered 'device' state. Spawning MVT autorun...")
    subprocess.Popen([AUTORUN_SCRIPT, "-s", serial])


def watch_devices():
    known_states = {}

    while True:
        log("Connecting to adb track-devices...")
        proc = None
        try:
            # Make sure adb server is running
            subprocess.run(["adb", "start-server"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            proc = subprocess.Popen(
                ["adb", "track-devices"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            while True:
                # First 4 bytes are hex length of the payload
                hex_len = proc.stdout.read(4)
                if not hex_len or len(hex_len) < 4:
                    log("track-devices connection closed or empty. Reconnecting...")
                    break

                try:
                    payload_len = int(hex_len.decode("ascii"), 16)
                except ValueError:
                    log(f"Malformed packet header: {hex_len}")
                    break

                if payload_len == 0:
                    current_devices = {}
                else:
                    payload = proc.stdout.read(payload_len).decode("utf-8", errors="replace")
                    current_devices = {}
                    for line in payload.splitlines():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            current_devices[parts[0]] = parts[1]

                # Check for transitions
                for serial, state in current_devices.items():
                    old_state = known_states.get(serial)
                    if state == "device" and old_state != "device":
                        trigger_mvt(serial)

                known_states = current_devices

        except Exception as e:
            log(f"Watcher error: {e}")
        finally:
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except Exception:
                    pass
            time.sleep(3)


if __name__ == "__main__":
    log("Starting ADB Device Watcher Daemon...")
    watch_devices()
