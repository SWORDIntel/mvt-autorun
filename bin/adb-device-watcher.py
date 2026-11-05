#!/usr/bin/env python3
"""
ADB Device Watcher Daemon
Monitors ADB device connection states and triggers /opt/mvt/bin/mvt-autorun.sh
whenever an Android device enters the 'device' (debug mode authorized) state.
Alerts the user via desktop toast if a device connects in 'unauthorized' state.
"""

import glob
import os
import subprocess
import sys
import time
from datetime import datetime

AUTORUN_SCRIPT = "/opt/mvt/bin/mvt-autorun.sh"
LOG_FILE = "/opt/mvt/logs/mvt-watcher.log"


def log(msg: str):
    timestamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"[{timestamp}] {msg}"
    print(formatted, flush=True)
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(formatted + "\n")
    except OSError as error:
        print(f"Could not write watcher log: {error}", file=sys.stderr, flush=True)


def send_toast(title: str, message: str, urgency: str = "normal"):
    """
    Sends a short-lived desktop notification; the notification daemon controls display.
    """
    for bus in glob.glob("/run/user/*/bus"):
        try:
            parts = bus.split("/")
            if len(parts) >= 4:
                uid = int(parts[3])
                res = subprocess.run(
                    ["id", "-nu", str(uid)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                username = res.stdout.strip()
                if not username:
                    continue

                cmd = [
                    "notify-send",
                    "-t",
                    "3000",
                    "-u",
                    "normal",
                    "-a",
                    "MVT Forensics",
                    "-i",
                    "security-high",
                    title,
                    message,
                ]

                if os.getuid() == uid:
                    env = {
                        **os.environ,
                        "DISPLAY": ":0",
                        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={bus}",
                    }
                    subprocess.run(
                        cmd,
                        env=env,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=5,
                        check=False,
                    )
                else:
                    subprocess.run(
                        [
                            "sudo",
                            "-u",
                            username,
                            "env",
                            "DISPLAY=:0",
                            f"DBUS_SESSION_BUS_ADDRESS=unix:path={bus}",
                        ]
                        + cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=5,
                        check=False,
                    )
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            log(f"Could not send notification to {bus}: {error}")


def trigger_mvt(serial: str):
    log(f"Device {serial} entered 'device' state. Spawning MVT autorun...")
    subprocess.Popen([AUTORUN_SCRIPT, "-s", serial])


def watch_devices():
    known_states = {}

    while True:
        log("Connecting to adb track-devices...")
        proc = None
        try:
            subprocess.run(
                ["adb", "start-server"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
            proc = subprocess.Popen(
                ["adb", "track-devices"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )

            while True:
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
                    payload = proc.stdout.read(payload_len).decode(
                        "utf-8", errors="replace"
                    )
                    current_devices = {}
                    for line in payload.splitlines():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            current_devices[parts[0]] = parts[1]

                # Check for state transitions
                for serial, state in current_devices.items():
                    old_state = known_states.get(serial)
                    if state == "device" and old_state != "device":
                        trigger_mvt(serial)
                    elif state == "unauthorized" and old_state != "unauthorized":
                        log(
                            f"Device {serial} connected in unauthorized state. Displaying prompt."
                        )
                        send_toast(
                            "Android Debugging Unauthorized",
                            f"Device {serial} requires USB authorization.\nPlease unlock your phone and tap 'Allow USB debugging' on screen.",
                            urgency="normal",
                        )

                known_states = current_devices

        except (OSError, ValueError, subprocess.SubprocessError) as e:
            log(f"Watcher error: {e}")
        finally:
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except (OSError, subprocess.SubprocessError) as error:
                    log(f"Could not stop adb tracking process: {error}")
            time.sleep(3)


if __name__ == "__main__":
    log("Starting ADB Device Watcher Daemon...")
    watch_devices()
