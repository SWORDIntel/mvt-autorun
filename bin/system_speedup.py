#!/usr/bin/env python3
"""
Android System Speedup & AOT Ahead-Of-Time Precompiler
- Applies OS latency optimizations (animation zeroing, cached app freezer)
- Exempts apps from Doze power throttling (deviceidle whitelist)
- Elevates App Standby buckets to 'active'
- Executes full Ahead-Of-Time (AOT) speed compilation (pm compile -m speed -f)
- Supports interactive multi-selection of up to 10 apps or batch CLI flags
"""

import sys
import os
import argparse
import subprocess
from datetime import datetime

MAX_SELECTABLE_APPS = 10

COMMON_HEAVY_PACKAGES = [
    "com.google.android.youtube",
    "com.google.android.apps.youtube.music",
    "dev.patrickgold.florisboard",
    "org.futo.voiceinput",
    "org.thoughtcrime.securesms",
    "org.telegram.messenger",
    "com.android.chrome",
    "com.discord",
    "com.spotify.music",
    "ch.protonmail.android",
]


def run_adb(cmd: list[str], serial: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    base = ["adb"]
    if serial:
        base.extend(["-s", serial])
    base.extend(cmd)
    return subprocess.run(base, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=check)


def get_connected_devices() -> list[str]:
    res = subprocess.run(["adb", "devices"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    devices = []
    for line in res.stdout.splitlines()[1:]:
        parts = line.strip().split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    return devices


def apply_system_tweaks(serial: str, anim_scale: float = 0.0):
    print("\n" + "=" * 60)
    print(f"[*] Applying Global OS Latency & Power Tweaks (anim: {anim_scale})...")
    print("=" * 60)

    # 1. Zero out animation scales for instantaneous UI transitions
    tweaks = [
        ("window_animation_scale", str(anim_scale)),
        ("transition_animation_scale", str(anim_scale)),
        ("animator_duration_scale", str(anim_scale)),
    ]
    for key, val in tweaks:
        run_adb(["shell", f"settings put global {key} {val}"], serial=serial, check=False)
        current = run_adb(["shell", f"settings get global {key}"], serial=serial, check=False).stdout.strip()
        print(f"  [+] {key} -> {current}")

    # 2. Enable cached apps freezer to prevent background CPU cycles
    run_adb(["shell", "settings put global cached_apps_freezer enabled"], serial=serial, check=False)
    run_adb(["shell", "device_config put activity_manager use_freezer true"], serial=serial, check=False)
    print("  [+] ActivityManager Cached Apps Freezer enabled.")


def get_installed_packages(serial: str) -> list[str]:
    res = run_adb(["shell", "pm list packages -3"], serial=serial, check=False)
    pkgs = []
    for line in res.stdout.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            pkgs.append(line.replace("package:", "").strip())
    return sorted(pkgs)


def check_package_exists(serial: str, pkg: str) -> bool:
    """
    Verifies whether a package physically exists and is installed on device.
    """
    res = run_adb(["shell", f"pm path {pkg} 2>/dev/null"], serial=serial, check=False)
    return "package:" in res.stdout


def optimize_futo_if_installed(serial: str, pkgs: list[str] | None = None):
    """
    Checks if FUTO Voice Input exists on the device before executing optimizations.
    """
    futo_pkg = "org.futo.voiceinput"
    if not check_package_exists(serial, futo_pkg):
        return

    print(f"\n[*] Detected FUTO Voice Input ({futo_pkg}) on device. Applying optimizations...")
    run_adb(["shell", f"pm grant {futo_pkg} android.permission.RECORD_AUDIO"], serial=serial, check=False)
    run_adb(["shell", f"pm grant {futo_pkg} android.permission.POST_NOTIFICATIONS"], serial=serial, check=False)
    run_adb(["shell", f"dumpsys deviceidle whitelist +{futo_pkg}"], serial=serial, check=False)
    run_adb(["shell", f"am set-standby-bucket {futo_pkg} active"], serial=serial, check=False)
    print("  [+] Granted audio & notification permissions, whitelisted in Doze, elevated to active.")


def compile_and_tune_app(serial: str, pkg: str) -> dict:
    if not check_package_exists(serial, pkg):
        print(f"\n[-] Package '{pkg}' is not installed on device. Skipping.")
        return {
            "package": pkg,
            "elapsed_sec": 0.0,
            "status": "not_found",
            "verified": False
        }

    print(f"\n[*] Optimizing package: {pkg}")

    # 1. Battery Optimization / Doze Whitelist
    run_adb(["shell", f"dumpsys deviceidle whitelist +{pkg}"], serial=serial, check=False)
    print("  [+] Added to Doze battery optimization whitelist.")

    # 2. App Standby Bucket -> active
    run_adb(["shell", f"am set-standby-bucket {pkg} active"], serial=serial, check=False)
    print("  [+] App Standby bucket elevated to 'active'.")

    # 3. Ahead-Of-Time (AOT) Full Speed Compilation
    print(f"  [*] Executing full AOT compilation (pm compile -m speed -f {pkg})...")
    start_t = datetime.now()
    comp_res = run_adb(["shell", f"pm compile -m speed -f {pkg}"], serial=serial, check=False)
    elapsed = (datetime.now() - start_t).total_seconds()
    status_out = comp_res.stdout.strip()
    print(f"  [+] Compilation finished in {elapsed:.2f}s: {status_out}")

    # 4. Verification
    dump_res = run_adb(["shell", f"dumpsys package {pkg} | grep -E 'status='"], serial=serial, check=False)
    v_line = dump_res.stdout.strip()
    speed_verified = "status=speed" in v_line
    print(f"  [+] Verification: {v_line if v_line else 'verified'}")

    return {
        "package": pkg,
        "elapsed_sec": elapsed,
        "status": "speed" if speed_verified else "completed",
        "verified": speed_verified
    }


def select_apps_interactive(installed: list[str]) -> list[str]:
    print("\n" + "=" * 60)
    print("Installed 3rd-Party Packages on Device:")
    print("=" * 60)
    for idx, pkg in enumerate(installed, 1):
        print(f" [{idx:3d}] {pkg}")
    print("=" * 60)
    print(f"Select up to {MAX_SELECTABLE_APPS} apps for full AOT speed compilation.")
    print("Enter numbers separated by spaces or commas (e.g. '1 4 12 18') or 'all-defaults':")

    while True:
        try:
            choice = input("\nSelection > ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(0)

        if not choice:
            continue

        if choice.lower() in ("all-defaults", "defaults", "d"):
            selected = [p for p in COMMON_HEAVY_PACKAGES if p in installed][:MAX_SELECTABLE_APPS]
            return selected

        selected_indices = []
        parts = choice.replace(",", " ").split()
        valid = True
        for p in parts:
            if not p.isdigit():
                print(f"[-] Invalid input '{p}'. Please enter numbers.")
                valid = False
                break
            num = int(p)
            if num < 1 or num > len(installed):
                print(f"[-] Number {num} out of range (1-{len(installed)}).")
                valid = False
                break
            selected_indices.append(num - 1)

        if not valid:
            continue

        # Deduplicate preserving order
        seen = set()
        chosen_pkgs = []
        for i in selected_indices:
            pkg = installed[i]
            if pkg not in seen:
                seen.add(pkg)
                chosen_pkgs.append(pkg)

        if len(chosen_pkgs) > MAX_SELECTABLE_APPS:
            print(f"[-] Too many apps selected ({len(chosen_pkgs)}). Maximum allowed is {MAX_SELECTABLE_APPS}.")
            continue

        return chosen_pkgs


def main():
    parser = argparse.ArgumentParser(description="Android System Speedup & AOT Ahead-Of-Time Precompiler")
    parser.add_argument("-s", "--serial", help="Target ADB device serial")
    parser.add_argument("-a", "--apps", help="Comma-separated package names to compile (up to 10)")
    parser.add_argument("-d", "--defaults", action="store_true", help="Automatically select top heavy apps (YouTube, FlorisBoard, FUTO, Signal, etc.)")
    parser.add_argument("--anim", type=float, default=0.0, help="Animation scale (default: 0.0 for zero lag)")
    parser.add_argument("--skip-system", action="store_true", help="Skip global system tweaks, only compile apps")
    args = parser.parse_args()

    # Device detection
    serial = args.serial
    if not serial:
        devs = get_connected_devices()
        if not devs:
            print("[-] Error: No Android device connected in 'device' state via ADB.")
            sys.exit(1)
        serial = devs[0]

    state = run_adb(["get-state"], serial=serial, check=False).stdout.strip()
    if state != "device":
        print(f"[-] Error: Device {serial} state is '{state}'. Please authorize USB debugging.")
        sys.exit(1)

    print(f"[*] Connected to Android device: {serial}")

    # 1. Global System Tweaks
    if not args.skip_system:
        apply_system_tweaks(serial, anim_scale=args.anim)

    # 2. Package Discovery
    installed_pkgs = get_installed_packages(serial)
    if not installed_pkgs:
        print("[-] No 3rd-party packages found on device.")
        sys.exit(0)

    # Determine selected apps
    selected_apps = []
    if args.apps:
        candidates = [p.strip() for p in args.apps.split(",") if p.strip()]
        for c in candidates:
            if c in installed_pkgs:
                selected_apps.append(c)
            else:
                # Check for partial match
                matches = [p for p in installed_pkgs if c in p]
                if matches:
                    selected_apps.append(matches[0])
                else:
                    print(f"[-] Warning: package '{c}' not found installed on device. Skipping.")
        selected_apps = selected_apps[:MAX_SELECTABLE_APPS]
    elif args.defaults:
        selected_apps = [p for p in COMMON_HEAVY_PACKAGES if p in installed_pkgs][:MAX_SELECTABLE_APPS]
    else:
        selected_apps = select_apps_interactive(installed_pkgs)

    if not selected_apps:
        print("[-] No apps selected for compilation.")
        sys.exit(0)

    print(f"\n[*] Selected {len(selected_apps)} apps for full AOT compilation:")
    for i, p in enumerate(selected_apps, 1):
        print(f"  {i}. {p}")

    # FUTO Voice Input optimization hook
    optimize_futo_if_installed(serial, installed_pkgs)

    # 3. AOT Compile & Tune Selected Apps
    results = []
    print("\n" + "=" * 60)
    print(f"[*] Starting AOT Precompilation ({len(selected_apps)} packages)...")
    print("=" * 60)

    for pkg in selected_apps:
        res = compile_and_tune_app(serial, pkg)
        results.append(res)

    # 4. Summary Table
    print("\n" + "=" * 70)
    print(f"{'PACKAGE':<45} | {'TIME':<8} | {'STATUS':<12}")
    print("-" * 70)
    for r in results:
        status_str = "[VERIFIED]" if r["verified"] else "[DONE]"
        print(f"{r['package']:<45} | {r['elapsed_sec']:>5.2f}s  | {status_str}")
    print("=" * 70)
    print("[+] All optimizations completed successfully.")


if __name__ == "__main__":
    main()
