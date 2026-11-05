#!/usr/bin/env python3
"""MVT Android Auto-Runner & Forensics Pipeline."""

import argparse
import fcntl
import glob
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, time, timedelta, timezone
from pathlib import Path

import mvt_doctor
import mvt_evidence
import mvt_hash

MVT_ROOT = "/opt/mvt"
MVT_BIN = f"{MVT_ROOT}/bin/mvt-android"
AQF_BIN = f"{MVT_ROOT}/bin/androidqf"
INDICATORS_DIR = f"{MVT_ROOT}/indicators"
OUTPUT_ROOT = f"{MVT_ROOT}/output"
RUNS_DIR = f"{OUTPUT_ROOT}/runs"
LATEST_LINK = f"{OUTPUT_ROOT}/latest"
LOCK_DIR = f"{MVT_ROOT}/state/locks"
CACHE_DIR = f"{MVT_ROOT}/cache/apks"
INCIDENTS_DIR = f"{OUTPUT_ROOT}/incidents"
LOG_FILE = f"{MVT_ROOT}/logs/mvt-autorun.log"
AQF_TIMEOUT = 600
MVT_TIMEOUT = 600
ADB_TIMEOUT = 60


def log(msg: str):
    timestamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"[{timestamp}] {msg}"
    print(formatted, flush=True)
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(formatted + "\n")
    except OSError as e:
        print(f"Could not write log: {e}", file=sys.stderr, flush=True)


def send_toast(title: str, message: str, urgency: str = "normal"):
    # Critical urgency may bypass the notification daemon's expiry timeout.
    urgency = "normal"
    buses = glob.glob("/run/user/*/bus")
    for bus in set(buses):
        try:
            uid = int(bus.split("/")[3])
            username_proc = subprocess.run(
                ["id", "-nu", str(uid)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=ADB_TIMEOUT,
                check=False,
            )
            username = username_proc.stdout.strip()
            if not username:
                continue
            notify_cmd = [
                "notify-send",
                "-t",
                "3000",
                "-u",
                urgency,
                "-a",
                "MVT Forensics",
                "-i",
                "security-high",
                title,
                message,
            ]
            env = os.environ.copy()
            env.update(DISPLAY=":0", DBUS_SESSION_BUS_ADDRESS=f"unix:path={bus}")
            command = (
                notify_cmd
                if os.getuid() == uid
                else [
                    "sudo",
                    "-u",
                    username,
                    "env",
                    "DISPLAY=:0",
                    f"DBUS_SESSION_BUS_ADDRESS=unix:path={bus}",
                ]
                + notify_cmd
            )
            subprocess.run(
                command,
                env=env if os.getuid() == uid else None,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=ADB_TIMEOUT,
                check=False,
            )
        except (OSError, ValueError, subprocess.SubprocessError) as e:
            log(f"Failed to send toast to {bus}: {e}")


def run_adb(
    cmd: list[str],
    serial: str | None = None,
    input_data: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    base = ["adb"]
    if serial:
        base.extend(["-s", serial])
    base.extend(cmd)
    result = subprocess.run(
        base,
        input=input_data,
        capture_output=True,
        text=True,
        check=False,
        timeout=ADB_TIMEOUT,
    )
    if check and result.returncode:
        raise RuntimeError(
            f"adb {' '.join(cmd)} failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result


def get_connected_devices() -> list[str]:
    res = subprocess.run(
        ["adb", "devices"],
        capture_output=True,
        text=True,
        check=False,
        timeout=ADB_TIMEOUT,
    )
    if res.returncode:
        raise RuntimeError(f"adb devices failed: {res.stderr.strip()}")
    return [
        p[0]
        for line in res.stdout.splitlines()[1:]
        if len(p := line.strip().split()) >= 2 and p[1] == "device"
    ]


def read_device_file(serial: str, remote_path: str) -> str:
    res = run_adb(["shell", "cat", remote_path], serial=serial, check=False)
    if res.returncode:
        text = (res.stderr + res.stdout).lower()
        if "no such file" in text or "not found" in text:
            return ""
        raise RuntimeError(
            f"Could not read device state {remote_path}: {res.stderr.strip()}"
        )
    return res.stdout.strip()


def machine_key_name(config):
    label = config.get("machine_key_name")
    if label is None:
        label = re.sub(r"[^A-Za-z0-9_.-]+", "-", os.uname().nodename).strip(".-_")
        label = (label[:100].rstrip(".-_") or "machine") + "-mvt-signing"
    if not isinstance(label, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", label
    ):
        raise ValueError("Invalid configured machine signing-key name")
    return label


def updated_audit_history(serial: str, config: dict, run_id: str):
    raw = read_device_file(serial, "/sdcard/Documents/.mvt_audit_history")
    if raw:
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as error:
            raise RuntimeError(f"Device audit history is malformed: {error}") from error
        if (
            not isinstance(value, dict)
            or value.get("schema") != 1
            or not isinstance(value.get("entries"), list)
            or len(value["entries"]) > 5
        ):
            raise RuntimeError("Device audit history has an unsupported format")
        entries = value["entries"]
        for entry in entries:
            if (
                not isinstance(entry, dict)
                or set(entry) != {"machine_key_name", "audited_at_utc", "run_id"}
                or not isinstance(entry["machine_key_name"], str)
                or not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", entry["machine_key_name"]
                )
                or not isinstance(entry["run_id"], str)
                or not re.fullmatch(r"run-[A-Za-z0-9_.-]{1,180}", entry["run_id"])
            ):
                raise RuntimeError("Device audit history contains an invalid entry")
            try:
                stamp = datetime.fromisoformat(
                    entry["audited_at_utc"].replace("Z", "+00:00")
                )
            except (AttributeError, ValueError) as error:
                raise RuntimeError(
                    "Device audit history contains an invalid timestamp"
                ) from error
            if stamp.tzinfo is None or stamp.utcoffset() != timedelta(0):
                raise RuntimeError("Device audit-history timestamps must be UTC")
    else:
        entries = []
    current = {
        "machine_key_name": machine_key_name(config),
        "audited_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "run_id": run_id,
    }
    return (entries + [current])[-5:]


def prune_previous_apk_cache(
    current_hashes: dict[str, dict],
) -> tuple[list[str], list[str]]:
    """Keep this run's cache entries; preserve all independent evidence/incident copies."""
    keep = {
        f"{data['local_name'][:-4]}_{data['sha256']}.apk"
        for package, info in current_hashes.items()
        for data in _package_files(package, info)
    }
    removed, warnings = [], []
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        os.makedirs(LOCK_DIR, exist_ok=True)
        with open(os.path.join(LOCK_DIR, "maintenance.lock"), "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            for name in os.listdir(CACHE_DIR):
                path = os.path.join(CACHE_DIR, name)
                try:
                    info = os.lstat(path)
                    if (
                        name.endswith(".apk")
                        and stat.S_ISREG(info.st_mode)
                        and name not in keep
                    ):
                        os.unlink(path)
                        removed.append(path)
                except OSError as error:
                    warning = f"Could not prune cached APK {path}: {error}"
                    warnings.append(warning)
                    log(f"Warning: {warning}")
    except (OSError, RuntimeError) as error:
        warning = f"Previous-run APK cache pruning failed: {error}"
        warnings.append(warning)
        log(f"Warning: {warning}")
    return removed, warnings


def write_device_file(serial: str, remote_path: str, content: str):
    token = uuid.uuid4().hex
    remote_tmp = f"{remote_path}.mvt-tmp-{token}"
    fd, local = tempfile.mkstemp(prefix="mvt-state-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        run_adb(["push", local, remote_tmp], serial=serial)
        run_adb(
            ["shell", f"mv -f -- {shlex.quote(remote_tmp)} {shlex.quote(remote_path)}"],
            serial=serial,
        )
    except (OSError, RuntimeError, subprocess.SubprocessError):
        try:
            run_adb(["shell", "rm", "-f", remote_tmp], serial=serial, check=False)
        except (OSError, RuntimeError, subprocess.SubprocessError) as cleanup_error:
            log(
                f"Could not remove temporary device state file {remote_tmp}: {cleanup_error}"
            )
        raise
    finally:
        os.unlink(local)


def scan_schedule(
    last_check: str, now: datetime | None = None
) -> tuple[datetime | None, datetime]:
    now_utc = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if last_check:
        try:
            if len(last_check) < 19:
                raise ValueError("expected a complete date and time")
            parsed = datetime.fromisoformat(last_check.replace("Z", "+00:00"))
            # astimezone treats legacy timezone-less records as host-local time.
            parsed = parsed.astimezone(timezone.utc)
            next_due = datetime.combine(
                parsed.date() + timedelta(days=1), time.min, timezone.utc
            )
        except (OverflowError, OSError, ValueError):
            log(f"Warning: malformed last-scan record {last_check!r}; scan is due.")
        else:
            return parsed, next_due
    return None, datetime.combine(now_utc.date(), time.min, timezone.utc)


def _gmt(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S GMT")


def check_rate_limit(serial: str, force: bool = False) -> bool:
    last_check = read_device_file(serial, "/sdcard/Documents/.mvt_last_check")
    now = datetime.now(timezone.utc)
    last, next_due = scan_schedule(last_check, now)
    valid_record = last is not None
    details = (
        f"Device: {serial}\n"
        + (
            f"Last scanned: {_gmt(last)}\n"
            if valid_record
            else "Last scanned: no usable record\n"
        )
        + f"Next due: {_gmt(next_due)}"
    )
    due = not valid_record or now >= next_due
    if force:
        log("Force flag specified. Bypassing daily rate limit.")
        send_toast("MVT Forensics (0%)", f"{details}\nStarting scan (forced).")
        return True
    if not due:
        remaining = next_due - now
        send_toast(
            "MVT Forensics (Not due)",
            f"{details}\nNext scan in {remaining.days}d {remaining.seconds // 3600}h.",
        )
        log(f"Device {serial} is not due; next scan at {_gmt(next_due)}.")
        return False
    send_toast("MVT Forensics (0%)", f"{details}\nStarting scan.")
    return True


def get_device_pkg_hashes(serial: str) -> dict[str, dict]:
    log("Computing package SHA256 hashes on device...")
    script = """packages=$(pm list packages -3) || exit 1
[ -n "$packages" ] || exit 0
printf '%s\\n' "$packages" | while IFS= read -r line; do
    case "$line" in package:*) entry=${line#package:}; pkg=${entry##*=} ;; *) exit 1 ;; esac
    case "$pkg" in ''|*[!A-Za-z0-9_.]*) exit 1 ;; esac
    paths=$(pm path "$pkg") || exit 1
    [ -n "$paths" ] || exit 1
    printf '%s\\n' "$paths" | while IFS= read -r item; do
        case "$item" in package:/*) apk=${item#package:} ;; *) exit 1 ;; esac
        [ -f "$apk" ] || exit 1
        hash=$(sha256sum "$apk") || exit 1
        size=$(stat -c %s "$apk") || exit 1
        printf '%s\\t%s\\t%s\\t%s\\n' "$pkg" "${hash%% *}" "$apk" "$size" || exit 1
    done || exit 1
done"""
    res = run_adb(["shell", "sh"], serial=serial, input_data=script, check=False)
    if res.returncode:
        raise RuntimeError(f"Device package inventory failed: {res.stderr.strip()}")
    inventory = {}
    for line in res.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 4 or not re.fullmatch(r"[0-9]+", parts[3]):
            raise RuntimeError(f"Malformed device package inventory row: {line!r}")
        package, digest, path, size = parts
        info = inventory.setdefault(package, {"files": []})
        info["files"].append({"path": path, "sha256": digest, "size": int(size)})
    for package, info in inventory.items():
        base = next(
            (f for f in info["files"] if Path(f["path"]).name == "base.apk"),
            info["files"][0],
        )
        info.update(sha256=base["sha256"].lower(), apk_path=base["path"])
        info["files"] = _package_files(package, info)
    log(f"Computed SHA256 for {len(inventory)} 3rd-party packages on device.")
    return inventory


def _package_files(package, info):
    """Normalize legacy single-APK inventories and distrust remote filenames."""
    if not re.fullmatch(r"[A-Za-z0-9_.]+", package) or not isinstance(info, dict):
        raise RuntimeError(f"Invalid package inventory entry: {package!r}")
    prefix = (
        package
        if len(package) <= 100
        else package[:64] + "-" + hashlib.sha256(package.encode()).hexdigest()[:32]
    )
    files = info.get("files")
    if files is None:
        files = [
            {"path": info.get("apk_path"), "sha256": info.get("sha256"), "size": None}
        ]
    if not isinstance(files, list) or not files:
        raise RuntimeError(f"Empty or invalid APK inventory: {package}")
    result, seen = [], set()
    for item in files:
        if not isinstance(item, dict):
            raise TypeError(f"Invalid APK file record: {package!r}")
        path, digest, size = item.get("path"), item.get("sha256"), item.get("size")
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or any(c in path for c in "\t\r\n\0")
            or not re.fullmatch(r"[0-9a-fA-F]{64}", str(digest))
            or (size is not None and (type(size) is not int or size < 0))
            or path in seen
        ):
            raise RuntimeError(f"Invalid APK inventory entry: {package!r} {item!r}")
        seen.add(path)
        name = (
            prefix + ".apk"
            if path == info.get("apk_path")
            else prefix + "-split-" + hashlib.sha256(path.encode()).hexdigest() + ".apk"
        )
        result.append(
            {"path": path, "sha256": digest.lower(), "size": size, "local_name": name}
        )
    if info.get("apk_path") not in seen or not any(
        f["path"] == info["apk_path"]
        and f["sha256"] == str(info.get("sha256", "")).lower()
        for f in result
    ):
        raise RuntimeError(f"Base APK inconsistent with file inventory: {package}")
    return result


def _sha256(path):
    return mvt_hash.hash_file(path)


def _pull_verified(serial, data, target):
    os.makedirs(os.path.dirname(target), exist_ok=True)
    expected = data["sha256"].lower()
    fd, partial = tempfile.mkstemp(
        prefix=f".{os.path.basename(target)}-partial-", dir=os.path.dirname(target)
    )
    os.close(fd)
    # On failure, retain partial acquisition evidence in the run directory; it is never cached.
    remote = data.get("path", data.get("apk_path"))
    run_adb(["pull", remote, partial], serial=serial)
    if (
        not os.path.isfile(partial)
        or _sha256(partial) != expected
        or (data.get("size") is not None and os.path.getsize(partial) != data["size"])
    ):
        raise RuntimeError(f"Pulled APK failed SHA256/size verification: {remote}")
    os.replace(partial, target)


def compare_and_sync_packages(
    serial: str, current_hashes: dict[str, dict], raw_apk_dir: str
):
    for pkg, info in current_hashes.items():
        info["files"] = _package_files(pkg, info)
    os.makedirs(CACHE_DIR, exist_ok=True)
    os.makedirs(raw_apk_dir, exist_ok=True)
    old_raw = read_device_file(serial, "/sdcard/Documents/.mvt_pkg_hashes")
    old = {}
    for line in old_raw.splitlines():
        fields = line.split("\t")
        if len(fields) in (2, 3) and re.fullmatch(r"[0-9a-fA-F]{64}", fields[1]):
            path = (
                fields[2]
                if len(fields) == 3
                else current_hashes.get(fields[0], {}).get("apk_path")
            )
            old.setdefault(fields[0], set()).add((path, fields[1].lower()))
    new = changed = unchanged = 0
    for pkg, info in current_hashes.items():
        entries = {(f["path"], f["sha256"]) for f in info["files"]}
        if pkg not in old:
            new += 1
        elif old[pkg] != entries:
            changed += 1
        else:
            unchanged += 1
        for data in info["files"]:
            sha = data["sha256"]
            stem = data["local_name"][:-4]
            cached = os.path.join(CACHE_DIR, f"{stem}_{sha}.apk")
            local = os.path.join(raw_apk_dir, data["local_name"])
            if (
                not os.path.islink(cached)
                and os.path.isfile(cached)
                and _sha256(cached) == sha
            ):
                fd, temporary = tempfile.mkstemp(prefix=".cache-copy-", dir=raw_apk_dir)
                os.close(fd)
                try:
                    shutil.copyfile(cached, temporary)
                    if _sha256(temporary) != sha or (
                        data["size"] is not None
                        and os.path.getsize(temporary) != data["size"]
                    ):
                        raise RuntimeError(
                            f"Cached APK changed during copy: {data['path']}"
                        )
                    os.replace(temporary, local)
                finally:
                    if os.path.exists(temporary):
                        os.unlink(temporary)
                continue
            log(f"Pulling APK for {pkg} ({data['path']})...")
            _pull_verified(serial, data, local)
            fd, temporary = tempfile.mkstemp(
                prefix=".apk-cache-", suffix=".tmp", dir=CACHE_DIR
            )
            os.close(fd)
            try:
                shutil.copyfile(local, temporary)
                if _sha256(temporary) != sha:
                    raise RuntimeError(f"APK changed while caching: {pkg}")
                os.replace(temporary, cached)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
    log(f"Package Inventory: {new} new, {changed} modified, {unchanged} unchanged.")
    return new, changed, unchanged


def enrich_packages_json(raw_dir: str, current_hashes: dict[str, dict]):
    path = os.path.join(raw_dir, "packages.json")
    if not os.path.exists(path):
        return
    try:
        with open(path) as f:
            packages = json.load(f)
        if not isinstance(packages, list):
            raise TypeError("packages.json must contain a list")
        for pkg in packages:
            name = pkg.get("name")
            if name in current_hashes:
                files = pkg.setdefault("files", [])
                if not isinstance(files, list):
                    raise TypeError("package files must contain a list")
                for data in _package_files(name, current_hashes[name]):
                    matches = [
                        item for item in files if item.get("path") == data["path"]
                    ]
                    if not matches:
                        matches = [{"path": data["path"]}]
                        files.extend(matches)
                    apk = os.path.join(raw_dir, "apks", data["local_name"])
                    if _sha256(apk) != data["sha256"]:
                        raise RuntimeError(
                            f"Collected APK changed before enrichment: {data['path']}"
                        )
                    result = subprocess.run(
                        ["apksigner", "verify", "--print-certs", apk],
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=ADB_TIMEOUT,
                    )
                    if result.returncode:
                        raise RuntimeError(
                            f"apksigner failed for {name}: {result.stderr.strip()}"
                        )
                    cert = {"Md5": "", "Sha1": "", "Sha256": ""}
                    for line in result.stdout.splitlines():
                        for alg, key in (
                            ("SHA-256", "Sha256"),
                            ("SHA-1", "Sha1"),
                            ("MD5", "Md5"),
                        ):
                            if f"Signer #1 certificate {alg} digest:" in line:
                                cert[key] = line.split(":", 1)[1].strip()
                    if not re.fullmatch(r"[0-9a-fA-F]{64}", cert["Sha256"]):
                        raise RuntimeError(
                            f"Missing valid signer SHA256 certificate: {data['path']}"
                        )
                    for item in matches:
                        item["sha256"] = data["sha256"]
                        item["certificate"] = cert
                        item["local_name"] = data["local_name"]
                        item["size"] = os.path.getsize(apk)
        with open(path, "w") as f:
            json.dump(packages, f, indent=2)
        log("Enriched packages.json with SHA256 and certificate signatures.")
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        RuntimeError,
        subprocess.SubprocessError,
    ) as e:
        raise RuntimeError(f"Failed to enrich packages.json: {e}") from e


def run_androidqf(serial: str, raw_dir: str):
    log("Executing androidqf extraction...")
    os.makedirs(raw_dir, exist_ok=True)
    cmd = [AQF_BIN, "-fast", "-s", serial, "-o", raw_dir]
    log_path = os.path.join(raw_dir, "androidqf_run.log")
    with open(log_path, "w") as output:
        try:
            proc = subprocess.run(
                cmd,
                cwd=raw_dir,
                input=b"\x1b[B\x1b[B\r\n\x1b[B\x1b[B\r\n\r\n\r\n",
                stdout=output,
                stderr=subprocess.STDOUT,
                timeout=AQF_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            if e.stdout:
                output.write(
                    e.stdout.decode(errors="replace")
                    if isinstance(e.stdout, bytes)
                    else e.stdout
                )
            raise RuntimeError(
                f"androidqf timed out after {AQF_TIMEOUT}s; log: {log_path}"
            ) from e
    if proc.returncode:
        raise RuntimeError(
            f"androidqf failed with exit status {proc.returncode}; log: {log_path}"
        )
    log("androidqf acquisition completed.")


def run_mvt_analysis(
    raw_dir: str, analysis_dir: str, indicator_dir: str | None = None
) -> dict:
    log("Executing MVT IOC analysis...")
    os.makedirs(analysis_dir, exist_ok=True)
    indicators = sorted(Path(indicator_dir or INDICATORS_DIR).rglob("*.stix2"))
    if not indicators:
        raise RuntimeError("No recorded STIX2 indicators available for analysis")
    cmd = [MVT_BIN, "check-androidqf", "-o", analysis_dir, "-n"]
    for indicator in indicators:
        cmd.extend(["-i", str(indicator)])
    cmd.append(raw_dir)
    data_home = Path(analysis_dir).parent / "mvt-environment" / "data"
    data_home.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.update(MVT_STIX2="", XDG_DATA_HOME=str(data_home))
    log_path = os.path.join(analysis_dir, "mvt_run.log")
    with open(log_path, "w") as output:
        try:
            proc = subprocess.run(
                cmd,
                env=environment,
                stdout=output,
                stderr=subprocess.STDOUT,
                timeout=MVT_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            if e.stdout:
                output.write(
                    e.stdout.decode(errors="replace")
                    if isinstance(e.stdout, bytes)
                    else e.stdout
                )
            raise RuntimeError(
                f"MVT timed out after {MVT_TIMEOUT}s; log: {log_path}"
            ) from e
    if proc.returncode:
        raise RuntimeError(
            f"MVT failed with exit status {proc.returncode}; log: {log_path}"
        )
    with open(log_path, errors="replace") as f:
        text = f.read()
    alerts = {
        level: None for level in ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    }
    ansi = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
    pattern = re.compile(
        r"MVT\s+produced\s+(\d+)\s+(INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL)\s+alerts\s*\.",
        re.IGNORECASE,
    )
    for line in ansi.sub("", text).splitlines():
        match = pattern.search(line)
        if match:
            level, count = match.group(2).upper(), int(match.group(1))
            if alerts[level] is not None:
                raise RuntimeError(
                    f"Duplicate MVT summary for {level}; log: {log_path}"
                )
            alerts[level] = count
    missing = [level for level, count in alerts.items() if count is None]
    if missing:
        raise RuntimeError(
            f"Missing valid MVT alert summaries for {', '.join(missing)}; log: {log_path}"
        )
    return alerts


def _alert_records(run_dir: str, warnings: list[str]) -> list[dict]:
    aggregate = os.path.join(run_dir, "analysis", "alerts.json")
    paths = (
        [aggregate]
        if os.path.exists(aggregate)
        else sorted(glob.glob(os.path.join(run_dir, "analysis", "*_detected.json")))
    )
    records = []
    if not paths:
        warnings.append("No structured alert data was available")
    for path in paths:
        try:
            with open(path) as source:
                payload = json.load(source)
            if not isinstance(payload, list):
                raise TypeError("expected a list of alert records")
            for index, record in enumerate(payload):
                if not isinstance(record, dict):
                    warnings.append(f"Unsupported alert record {index} in {path}")
                    continue
                if not isinstance(record.get("level"), str):
                    warnings.append(
                        f"Alert without a valid level in {path} (index {index})"
                    )
                    continue
                records.append(record)
        except (OSError, ValueError, TypeError) as error:
            warnings.append(f"Could not read structured alert data {path}: {error}")
    return records


def prepare_flagged_apks(
    run_dir: str, current_hashes: dict, alert_counts: dict
) -> tuple[str, int]:
    """Preserve verified APKs with explicit HIGH/CRITICAL MVT attribution."""
    destination = os.path.join(run_dir, "flagged_apks")
    warnings: list[str] = []
    alerts = _alert_records(run_dir, warnings)
    known_hashes, known_paths, package_files, inventory = {}, {}, {}, {}
    for package, info in current_hashes.items():
        for data in _package_files(package, info):
            key = (package, data["path"])
            inventory[key] = data
            package_files.setdefault(package, set()).add(key)
            known_hashes.setdefault(data["sha256"], set()).add(key)
            known_paths.setdefault(data["path"], set()).add(key)
    findings, file_findings, unmatched = [], {}, []
    for alert in alerts:
        level = alert["level"].upper()
        if level not in ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            warnings.append(f"Unsupported alert level {alert['level']!r}")
            continue
        if level not in ("HIGH", "CRITICAL"):
            continue
        event = alert.get("event")
        if not isinstance(event, dict):
            event = {}
        candidates = set()
        indicator = alert.get("matched_indicator")
        indicator_values = [indicator]
        while indicator_values:
            value = indicator_values.pop()
            if isinstance(value, dict):
                indicator_values.extend(value.values())
            elif isinstance(value, list):
                indicator_values.extend(value)
            elif isinstance(value, str):
                candidates.update(known_hashes.get(value.lower(), set()))
                candidates.update(known_paths.get(value, set()))
                if "certificate" not in value.lower():
                    for digest in re.findall(
                        r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", value.lower()
                    ):
                        candidates.update(known_hashes.get(digest, set()))
        for key in ("sha256", "hash", "path"):
            value = event.get(key)
            if isinstance(value, str):
                candidates.update(known_hashes.get(value.lower(), set()))
                candidates.update(known_paths.get(value, set()))
        # A matched file indicator is more specific than its enclosing package event.
        if not candidates:
            keys = ["package_name", "package"]
            if alert.get("module") == "aqf_packages":
                keys.append("name")
            for key in keys:
                value = event.get(key)
                if isinstance(value, str):
                    candidates.update(package_files.get(value, set()))
        if not candidates:
            files = event.get("files", [])
            if isinstance(files, list):
                for item in files:
                    if not isinstance(item, dict):
                        warnings.append("Unsupported alert files record")
                        continue
                    digest, path = item.get("sha256"), item.get("path")
                    if isinstance(digest, str):
                        candidates.update(known_hashes.get(digest.lower(), set()))
                    if isinstance(path, str):
                        candidates.update(known_paths.get(path, set()))
        finding = {
            key: alert.get(key)
            for key in ("level", "module", "message", "event", "matched_indicator")
        }
        finding_index = len(findings)
        findings.append(finding)
        if candidates:
            for key in sorted(candidates):
                file_findings.setdefault(key, []).append(finding_index)
        else:
            unmatched.append(
                {
                    "finding": finding_index,
                    "reason": "No exact current inventory attribution",
                }
            )

    if alert_counts.get("HIGH", 0) or alert_counts.get("CRITICAL", 0):
        if not findings:
            warnings.append(
                "MVT reported HIGH/CRITICAL alerts, but no explicit supported structured findings were available"
            )
        elif unmatched:
            warnings.append(
                "Some HIGH/CRITICAL findings could not be attributed to collected packages"
            )
    copied = []
    raw_dir = os.path.join(run_dir, "raw", "apks")
    for key, indexes in sorted(file_findings.items()):
        package, remote_path = key
        data = inventory[key]
        expected = data["sha256"]
        source = os.path.join(raw_dir, data["local_name"])
        try:
            if os.path.commonpath(
                (os.path.realpath(raw_dir), os.path.realpath(source))
            ) != os.path.realpath(raw_dir):
                raise RuntimeError("APK escapes raw acquisition directory")
            source_fd = os.open(
                source,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
            )
            if not stat.S_ISREG(os.fstat(source_fd).st_mode):
                os.close(source_fd)
                raise RuntimeError("collected APK is not a regular file")
            try:
                os.makedirs(destination, exist_ok=True)
                fd, temporary = tempfile.mkstemp(prefix=f".{package}-", dir=destination)
            except OSError:
                os.close(source_fd)
                raise
            try:
                with os.fdopen(source_fd, "rb") as apk, os.fdopen(fd, "wb") as output:
                    shutil.copyfileobj(apk, output, 1024 * 1024)
                    output.flush()
                    os.fsync(output.fileno())
                if _sha256(temporary) != expected:
                    raise RuntimeError("copied APK SHA256 mismatch")
                filename = data["local_name"]
                os.replace(temporary, os.path.join(destination, filename))
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            copied.append(
                {
                    "package": package,
                    "path": remote_path,
                    "sha256": expected,
                    "filename": filename,
                    "findings": indexes,
                }
            )
        except (OSError, RuntimeError) as error:
            raise RuntimeError(
                f"Could not preserve flagged APK {package}: {error}"
            ) from error
    os.makedirs(destination, exist_ok=True)
    report = {
        "summary": alert_counts,
        "apks": copied,
        "findings": findings,
        "unmatched": unmatched,
        "warnings": warnings,
    }
    fd, temporary = tempfile.mkstemp(prefix=".findings-", dir=destination)
    try:
        with os.fdopen(fd, "w") as output:
            json.dump(report, output, indent=2)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, os.path.join(destination, "findings.json"))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return destination, len(copied)


def open_results_folder(folder: str) -> bool:
    """Ask the current user's desktop file manager to show a results directory."""
    uid = os.getuid()
    runtime_dir = f"/run/user/{uid}"
    bus = os.path.join(runtime_dir, "bus")
    try:
        if not os.path.exists(bus):
            raise OSError(f"current-user session bus unavailable: {bus}")
        path = os.path.realpath(folder)
        if not os.path.isdir(path):
            raise OSError(f"results folder does not exist: {folder}")
        env = os.environ.copy()
        env.update(
            DBUS_SESSION_BUS_ADDRESS=f"unix:path={bus}", XDG_RUNTIME_DIR=runtime_dir
        )
        result = subprocess.run(
            [
                "gdbus",
                "call",
                "--session",
                "--dest",
                "org.freedesktop.FileManager1",
                "--object-path",
                "/org/freedesktop/FileManager1",
                "--method",
                "org.freedesktop.FileManager1.ShowFolders",
                json.dumps([Path(path).as_uri()]),
                "",
            ],
            env=env,
            timeout=10,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            raise RuntimeError(
                result.stderr.strip() or f"gdbus exited {result.returncode}"
            )
        return True
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        log(f"Warning: could not open results folder {folder}: {error}")
        return False


def write_run_metadata(run_dir: str, metadata: dict):
    fd, temporary = tempfile.mkstemp(
        prefix=".run-metadata-", suffix=".tmp", dir=run_dir
    )
    try:
        with os.fdopen(fd, "w") as output:
            json.dump(metadata, output, indent=2)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, os.path.join(run_dir, "run.json"))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def publish_latest(run_dir: str):
    os.makedirs(OUTPUT_ROOT, exist_ok=True)
    os.makedirs(RUNS_DIR, exist_ok=True)
    lock_path = os.path.join(LOCK_DIR, "publication.lock")
    os.makedirs(LOCK_DIR, exist_ok=True)
    with open(lock_path, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if os.path.lexists(LATEST_LINK) and not os.path.islink(LATEST_LINK):
            legacy = os.path.join(RUNS_DIR, f"legacy-{uuid.uuid4().hex}")
            os.replace(LATEST_LINK, legacy)
        link_tmp = os.path.join(OUTPUT_ROOT, f".latest-{uuid.uuid4().hex}")
        try:
            os.symlink(os.path.relpath(run_dir, OUTPUT_ROOT), link_tmp)
            os.replace(link_tmp, LATEST_LINK)
        finally:
            if os.path.lexists(link_tmp):
                os.unlink(link_tmp)


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "doctor":
        return mvt_doctor.main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] in ("verify", "prune"):
        return mvt_evidence.main(sys.argv[1:])
    parser = argparse.ArgumentParser(description="MVT Android Auto-Runner Pipeline")
    parser.add_argument("-s", "--serial", help="Target device serial number")
    parser.add_argument(
        "-f", "--force", action="store_true", help="Bypass daily rate limit"
    )
    args = parser.parse_args()
    run_dir = None
    serial = args.serial
    try:
        if not serial:
            devices = get_connected_devices()
            if not devices:
                log("No connected Android device in 'device' state. Exiting.")
                return 0
            serial = devices[0]
        config = mvt_evidence.load_config(MVT_ROOT)
        if config["auto_prune"]:
            maintenance = mvt_evidence.prune_storage(
                MVT_ROOT,
                run_days=config["run_retention_days"],
                cache_days=config["cache_retention_days"],
                apply=True,
            )
            for path in maintenance["deleted"]:
                log(f"Storage retention removed {path}")
            for error in maintenance["errors"]:
                log(f"Warning: storage retention: {error}")
        safe_id = hashlib.sha256(serial.encode()).hexdigest()[:24]
        os.makedirs(LOCK_DIR, exist_ok=True)
        with open(os.path.join(LOCK_DIR, f"device-{safe_id}.lock"), "a") as lock_file:
            try:
                fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                log(
                    f"Another MVT verification process is currently active for device {serial}. Exiting."
                )
                return 0
            try:
                state = run_adb(["get-state"], serial=serial, check=False)
                if state.returncode or state.stdout.strip() != "device":
                    raise RuntimeError(
                        f"Device {serial} is not ready: {state.stdout.strip()} {state.stderr.strip()}"
                    )
                if not check_rate_limit(serial, args.force):
                    return 0
                mvt_evidence.check_free_space(RUNS_DIR, config["min_free_bytes"])
                os.makedirs(RUNS_DIR, exist_ok=True)
                run_dir = tempfile.mkdtemp(prefix=f"run-{safe_id}-", dir=RUNS_DIR)
                raw_dir, analysis_dir = (
                    os.path.join(run_dir, "raw"),
                    os.path.join(run_dir, "analysis"),
                )
                os.makedirs(raw_dir)
                os.makedirs(analysis_dir)
                log(f"Starting forensic pipeline for {serial}; evidence: {run_dir}")
                write_run_metadata(
                    run_dir,
                    {
                        "serial": serial,
                        "status": "acquiring",
                        "started_at": datetime.now(timezone.utc).isoformat(),
                    },
                )
                current = get_device_pkg_hashes(serial)
                required = 4 * sum(
                    f["size"] or 0
                    for pkg, info in current.items()
                    for f in _package_files(pkg, info)
                )
                mvt_evidence.check_free_space(
                    RUNS_DIR, config["min_free_bytes"], required_bytes=required
                )
                mvt_evidence.check_free_space(
                    CACHE_DIR, config["min_free_bytes"], required_bytes=required
                )
                with open(
                    os.path.join(LOCK_DIR, "maintenance.lock"), "a"
                ) as maintenance:
                    fcntl.flock(maintenance, fcntl.LOCK_SH)
                    counts = compare_and_sync_packages(
                        serial, current, os.path.join(raw_dir, "apks")
                    )
                send_toast(
                    "MVT Forensics (25%)",
                    f"Package inventory and verified APK sync complete ({len(current)} apps).",
                )
                run_androidqf(serial, raw_dir)
                enrich_packages_json(raw_dir, current)
                send_toast(
                    "MVT Forensics (50%)",
                    f"Acquisition complete ({len(current)} apps evaluated).\nAnalyzing indicators of compromise...",
                    "normal",
                )
                provenance = mvt_evidence.capture_provenance(
                    MVT_ROOT,
                    run_dir,
                    tools={
                        "adb": "adb",
                        "androidqf": AQF_BIN,
                        "mvt": MVT_BIN,
                        "apksigner": "apksigner",
                        "mvt-hash": os.environ.get(
                            "MVT_HASH_BIN", str(Path(__file__).with_name("mvt-hash"))
                        ),
                    },
                    indicators_dir=INDICATORS_DIR,
                    script_path=__file__,
                )
                alerts = run_mvt_analysis(
                    raw_dir, analysis_dir, indicator_dir=provenance["indicators_dir"]
                )
                send_toast(
                    "MVT Forensics (75%)",
                    "MVT analysis complete. Finalizing results and device state...",
                )
                audit_history = updated_audit_history(
                    serial, config, os.path.basename(run_dir)
                )
                metadata = {
                    "serial": serial,
                    "machine_key_name": audit_history[-1]["machine_key_name"],
                    "device_audit_history": audit_history,
                    "status": "analysis_completed",
                    "analysis_completed_at": datetime.now(timezone.utc).isoformat(),
                    "package_counts": counts,
                    "alerts": alerts,
                    "provenance": provenance,
                    "packages": current,
                }
                positive = alerts["CRITICAL"] > 0 or alerts["HIGH"] > 0
                flagged_count = 0
                if positive:
                    _, flagged_count = prepare_flagged_apks(run_dir, current, alerts)
                write_run_metadata(run_dir, metadata)
                mvt_evidence.write_evidence_manifest(
                    run_dir, metadata, signing_key=config["signing_key"]
                )
                if positive:
                    os.makedirs(INCIDENTS_DIR, exist_ok=True)
                    incident = os.path.join(
                        INCIDENTS_DIR,
                        f"incident_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}_{safe_id}_{uuid.uuid4().hex[:8]}",
                    )
                    shutil.copytree(run_dir, incident)
                    log(f"[INCIDENT PRESERVED] Malicious scan archived to {incident}")
                baseline = "\n".join(
                    f"{pkg}\t{data['sha256']}\t{data['path']}"
                    for pkg, info in current.items()
                    for data in _package_files(pkg, info)
                )
                write_device_file(serial, "/sdcard/Documents/.mvt_pkg_hashes", baseline)
                write_device_file(
                    serial,
                    "/sdcard/Documents/.mvt_audit_history",
                    json.dumps({"schema": 1, "entries": audit_history}, sort_keys=True),
                )
                cache_warning = ""
                try:
                    pruned, prune_warnings = prune_previous_apk_cache(current)
                    if pruned:
                        cache_warning = (
                            f" Pruned {len(pruned)} APK(s) from the old cache."
                        )
                    if prune_warnings:
                        cache_warning += " WARNING: " + "; ".join(prune_warnings)
                except OSError as error:
                    cache_warning = f" WARNING: APK cache cleanup failed ({error})."
                    log(cache_warning.strip())
                now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                write_device_file(serial, "/sdcard/Documents/.mvt_last_check", now)
                metadata_warning = ""
                try:
                    write_run_metadata(
                        run_dir,
                        {
                            **metadata,
                            "status": "completed",
                            "completed_at": datetime.now(timezone.utc).isoformat(),
                        },
                    )
                except OSError as e:
                    metadata_warning = f" WARNING: final run metadata could not be updated ({e}); use run directory {run_dir}."
                    log(metadata_warning.strip())
                try:
                    publish_latest(run_dir)
                    latest_warning = ""
                except (OSError, RuntimeError) as e:
                    latest_warning = f" WARNING: latest pointer could not be updated ({e}); use run directory {run_dir}."
                    log(latest_warning.strip())
                crit, high, med = alerts["CRITICAL"], alerts["HIGH"], alerts["MEDIUM"]
                if crit or high:
                    if flagged_count:
                        message = f"THREAT DETECTED: {crit} CRITICAL, {high} HIGH alerts; {flagged_count} flagged APK(s) preserved at {os.path.join(incident, 'flagged_apks')}"
                    else:
                        message = f"THREAT DETECTED: {crit} CRITICAL, {high} HIGH alerts; no collected APK identified. Review {os.path.join(incident, 'flagged_apks')}"
                    urgency = "normal"
                elif med:
                    message, urgency = (
                        f"Completed with {med} suspicious items.",
                        "normal",
                    )
                else:
                    message, urgency = "No medium/high/critical alerts.", "normal"
                results_folder = (
                    os.path.join(incident, "flagged_apks") if positive else run_dir
                )
                open_warning = ""
                if positive and not open_results_folder(results_folder):
                    open_warning = f" WARNING: could not open flagged results folder {results_folder}."
                send_toast(
                    "MVT Forensics (100%)",
                    f"Verification complete: {message}\nResults saved to {run_dir}.{metadata_warning}{latest_warning}{cache_warning}{open_warning}",
                    urgency,
                )
                log(
                    f"Pipeline finished successfully. Status: {message}; results: {run_dir}"
                )
                return 0
            finally:
                fcntl.flock(lock_file, fcntl.LOCK_UN)
    except (
        OSError,
        RuntimeError,
        ValueError,
        TypeError,
        subprocess.SubprocessError,
    ) as e:
        log(f"Pipeline failed for {serial or 'unknown device'}: {e}")
        if run_dir:
            try:
                write_run_metadata(
                    run_dir,
                    {
                        "serial": serial,
                        "status": "failed",
                        "error": str(e),
                        "failed_at": datetime.now(timezone.utc).isoformat(),
                    },
                )
            except OSError as metadata_error:
                log(f"Could not write failure metadata: {metadata_error}")
        send_toast(
            "MVT Forensics (Failed)",
            f"Verification failed for {serial or 'device'}; evidence retained at {run_dir or 'unknown location'}.",
            "normal",
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
