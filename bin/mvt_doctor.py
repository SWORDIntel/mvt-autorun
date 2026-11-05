#!/usr/bin/env python3
"""Read-only installation diagnostics. WARN (including unavailable) does not fail exit.

Only existing files, an existing local ADB server, systemd properties, and the
caller's own desktop bus are inspected. No pipeline modules are imported: their
initialization must not create state while diagnosing a broken installation.
"""

import argparse
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

TIMEOUT = 5
JSON_LIMIT = 16 * 1024 * 1024
NATIVE_NAME = "mvt-hash"


def result(name, status, details, availability="available"):
    return {
        "name": name,
        "status": status,
        "availability": availability,
        "details": details,
    }


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"Duplicate JSON key: {key}")
        value[key] = item
    return value


def _invalid_constant(value):
    raise ValueError(f"Non-finite JSON number: {value}")


def read_json(path):
    with path.open("rb") as stream:
        raw = stream.read(JSON_LIMIT + 1)
    if len(raw) > JSON_LIMIT:
        raise ValueError(f"JSON exceeds {JSON_LIMIT} bytes")
    return json.loads(
        raw, object_pairs_hook=_unique_object, parse_constant=_invalid_constant
    )


def command(argv):
    return subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env={**os.environ, "LC_ALL": "C", "SYSTEMD_PAGER": "cat"},
    )


def same_bytes(left, right):
    # Compare content, not stat-cache results; readiness cannot depend on hashing.
    with left.open("rb") as first, right.open("rb") as second:
        while True:
            chunk = first.read(65536)
            other = second.read(65536)
            if chunk != other:
                return False
            if not chunk:
                return True


def installed_files(root, source):
    names = {
        "mvt-autorun.py",
        "mvt-autorun.sh",
        "adb-device-watcher.py",
        "system_speedup.py",
        "mvt_doctor.py",
        "mvt_hash.py",
        "mvt_evidence.py",
        NATIVE_NAME,
    }
    if (source / "bin").is_dir():
        names.update(p.name for p in (source / "bin").glob("mvt_*.py"))
    files = []
    for name in sorted(names):
        installed, repo = root / "bin" / name, source / "bin" / name
        item = {"file": name, "installed": str(installed), "source": str(repo)}
        if not installed.is_file():
            item.update(status="FAIL", comparison="installed_missing")
        elif root.resolve() == source.resolve():
            item.update(status="WARN", comparison="source_is_installation")
        elif not repo.is_file():
            item.update(status="WARN", comparison="source_unavailable")
        elif same_bytes(installed, repo):
            item.update(status="PASS", comparison="identical")
        else:
            item.update(status="WARN", comparison="different")
        files.append(item)
    status = (
        "FAIL"
        if any(f["status"] == "FAIL" for f in files)
        else ("WARN" if any(f["status"] == "WARN" for f in files) else "PASS")
    )
    return result(
        "installed_files", status, {"method": "byte_comparison", "files": files}
    )


def configuration(root):
    path = root / "config.json"
    if path.is_symlink():
        raise ValueError("config.json must be a regular nonsymlink file")
    if not path.is_file():
        return result(
            "configuration",
            "WARN",
            {"path": str(path), "message": "No configuration file; nothing written"},
            "unavailable",
        ), {}
    config = read_json(path)
    if type(config) is not dict:
        raise ValueError("Configuration must be a JSON object")
    allowed = {
        "min_free_bytes",
        "run_retention_days",
        "cache_retention_days",
        "auto_prune",
        "signing_key",
    }
    if config.keys() - allowed:
        raise ValueError(
            "Unknown configuration keys: " + ", ".join(sorted(config.keys() - allowed))
        )
    for name in ("min_free_bytes", "run_retention_days", "cache_retention_days"):
        if name not in config or (name != "min_free_bytes" and config[name] is None):
            continue
        if type(config[name]) is not int or config[name] < 0:
            raise ValueError(f"{name} must be a nonnegative integer")
    if "auto_prune" in config and type(config["auto_prune"]) is not bool:
        raise ValueError("auto_prune must be a boolean")
    key = config.get("signing_key")
    if key is not None and (
        type(key) is not str or not key or not Path(key).is_absolute()
    ):
        raise ValueError("signing_key must be an absolute path or null")
    if key is not None:
        info = Path(key).lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.geteuid()
        ):
            raise ValueError(
                "signing_key must be an owned regular nonsymlink 0600 file"
            )
    return result(
        "configuration", "PASS", {"path": str(path), "keys": sorted(config)}
    ), config


def metadata(root, source):
    path = root / "installed-tools.json"
    if not path.is_file():
        return result(
            "metadata",
            "WARN",
            {
                "path": str(path),
                "message": "Installation version/lock metadata unavailable",
            },
            "unavailable",
        )
    data = read_json(path)
    if not isinstance(data, dict) or not data:
        raise ValueError("installed-tools.json must be a nonempty JSON object")
    issues = []
    tools = data.get("tools")
    if data.get("schema") != 1 or not isinstance(tools, dict):
        issues.append("Unsupported or missing installation metadata schema/tools")
        tools = {}
    for name in ("mvt", "androidqf", "adb", "mvt-hash"):
        tool = tools.get(name)
        if not isinstance(tool, dict) or not all(
            isinstance(tool.get(key), str) and tool[key]
            for key in ("path", "version", "sha256")
        ):
            issues.append(f"Missing version/path/hash record: {name}")
    locks = []
    for name in ("dependencies.json", "requirements-pinned.txt"):
        installed, repo = root / name, source / name
        item = {"file": name}
        if not installed.is_file():
            item["comparison"] = "installed_missing"
        elif root.resolve() == source.resolve():
            item["comparison"] = "source_is_installation"
        elif not repo.is_file():
            item["comparison"] = "source_unavailable"
        else:
            item["comparison"] = (
                "identical" if same_bytes(installed, repo) else "different"
            )
        if installed.is_file() and name.endswith(".json"):
            item["metadata"] = read_json(installed)
        locks.append(item)
    dependency_lock = next(
        (item.get("metadata") for item in locks if item["file"] == "dependencies.json"),
        None,
    )
    if isinstance(dependency_lock, dict):
        for name in ("mvt", "androidqf"):
            pin, tool = dependency_lock.get(name), tools.get(name)
            if (
                isinstance(pin, dict)
                and isinstance(tool, dict)
                and pin.get("version") != tool.get("version")
            ):
                issues.append(f"Recorded {name} version differs from dependency lock")
    return result(
        "metadata",
        "WARN"
        if issues or any(item["comparison"] != "identical" for item in locks)
        else "PASS",
        {
            "path": str(path),
            "installed_tools": data,
            "locks": locks,
            "issues": issues,
            "hashes": "recorded metadata only; source files compared directly",
        },
    )


def service(root):
    proc = command(
        [
            "systemctl",
            "show",
            "mvt-watcher.service",
            "--no-pager",
            "--property=LoadState,ActiveState,SubState,MainPID,ExecMainStartTimestampMonotonic",
        ]
    )
    if proc.returncode:
        return result(
            "service",
            "WARN",
            {
                "error": proc.stderr.strip(),
                "returncode": proc.returncode,
                "restart_needed": None,
            },
            "unavailable",
        )
    fields = dict(
        line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line
    )
    details = {
        "unit": "mvt-watcher.service",
        "properties": fields,
        "restart_needed": None,
    }
    if fields.get("LoadState") == "not-found" or fields.get("ActiveState") in {
        "failed",
        "inactive",
        "activating",
        "deactivating",
    }:
        return result("service", "FAIL", details)
    if fields.get("ActiveState") != "active":
        return result("service", "WARN", details, "unknown")
    started = int(fields.get("ExecMainStartTimestampMonotonic", "0"))
    if started <= 0 or int(fields.get("MainPID", "0")) <= 0:
        return result("service", "WARN", details, "unknown")
    started_wall = time.time() - time.monotonic() + started / 1_000_000
    changed = sorted(
        str(path)
        for path in (root / "bin").iterdir()
        if path.is_file() and path.stat().st_mtime > started_wall
    )
    details.update(restart_needed=bool(changed), newer_files=changed)
    return result("service", "WARN" if changed else "PASS", details)


def adb_devices(serial=None):
    # Invoking `adb devices` may start its server. Speak only to an existing one.
    deadline = time.monotonic() + TIMEOUT
    with socket.create_connection(("127.0.0.1", 5037), timeout=TIMEOUT) as client:

        def receive(size):
            chunks = bytearray()
            while len(chunks) < size:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("ADB listing deadline exceeded")
                client.settimeout(remaining)
                part = client.recv(size - len(chunks))
                if not part:
                    raise ValueError("Truncated ADB server response")
                chunks.extend(part)
            return bytes(chunks)

        request = b"host:devices-l"
        client.sendall(f"{len(request):04x}".encode("ascii") + request)
        reply = receive(4)
        if reply not in (b"OKAY", b"FAIL"):
            raise ValueError("Invalid ADB server status")
        header = receive(4)
        if any(value not in b"0123456789abcdefABCDEF" for value in header):
            raise ValueError("Invalid ADB payload length")
        size = int(header, 16)
        payload = receive(size).decode("utf-8", errors="strict")
        if reply == b"FAIL":
            return result(
                "adb", "WARN", {"error": payload, "devices": []}, "unavailable"
            )
    devices = []
    for line in payload.splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) < 2:
            raise ValueError("Malformed ADB device listing")
        if serial is None or fields[0] == serial:
            devices.append(
                {
                    "serial": fields[0],
                    "state": fields[1],
                    "description": " ".join(fields[2:]),
                }
            )
    return result(
        "adb",
        "PASS" if devices and all(d["state"] == "device" for d in devices) else "WARN",
        {
            "devices": devices,
            "serial_filter": serial,
            "message": "Host listing only; no device operations",
        },
    )


def iocs(root, config):
    directory = root / "indicators"
    if not directory.is_dir():
        return result(
            "iocs",
            "WARN",
            {"directory": str(directory), "file_count": 0},
            "unavailable",
        )
    files = sorted(set(directory.glob("*.stix2")) | set(directory.glob("*.json")))
    entries = []
    status = "PASS" if files else "WARN"
    for path in files:
        item = {"file": path.name}
        try:
            bundle = read_json(path)
            if (
                not isinstance(bundle, dict)
                or bundle.get("type") != "bundle"
                or not isinstance(bundle.get("objects"), list)
            ):
                raise ValueError("Expected a STIX bundle with an objects list")
            if not all(
                isinstance(obj, dict) and isinstance(obj.get("type"), str)
                for obj in bundle["objects"]
            ):
                raise ValueError("Invalid STIX object")
            age = max(0, time.time() - path.stat().st_mtime) / 86400
            count = sum(obj["type"] == "indicator" for obj in bundle["objects"])
            item.update(
                parse="valid",
                object_count=len(bundle["objects"]),
                indicator_count=count,
                age_days=round(age, 2),
            )
            if age > 30 or count == 0:
                status = "WARN" if status != "FAIL" else status
        except (OSError, ValueError, UnicodeError) as error:
            item.update(parse="invalid", error=str(error))
            status = "FAIL"
        entries.append(item)
    return result(
        "iocs",
        status,
        {
            "directory": str(directory),
            "file_count": len(files),
            "indicator_count": sum(i.get("indicator_count", 0) for i in entries),
            "max_age_days": 30,
            "files": entries,
        },
    )


def storage(root, config):
    target = root
    while not target.exists() and target != target.parent:
        target = target.parent
    free = shutil.disk_usage(target).free
    minimum = config.get("min_free_bytes", 1024**3)
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 0:
        raise ValueError("min_free_bytes must be a nonnegative integer")
    return result(
        "storage",
        "PASS" if free >= minimum else "FAIL",
        {
            "path": str(target),
            "free_bytes": free,
            "min_free_bytes": minimum,
            "policy_source": "config" if "min_free_bytes" in config else "default",
            "root_exists": root.exists(),
        },
    )


def desktop():
    uid = os.getuid()
    bus = Path(f"/run/user/{uid}/bus")
    executable = shutil.which("gdbus")
    details = {"uid": uid, "bus": str(bus), "gdbus": executable, "backends": {}}
    if not executable:
        return result("desktop", "WARN", details, "unavailable")
    try:
        info = bus.stat()
    except FileNotFoundError:
        return result("desktop", "WARN", details, "unavailable")
    if info.st_uid != uid or not stat.S_ISSOCK(info.st_mode):
        details["error"] = "Own-user bus is not an owned socket"
        return result("desktop", "WARN", details, "unavailable")
    for backend in ("org.freedesktop.Notifications", "org.freedesktop.FileManager1"):
        proc = command(
            [
                executable,
                "call",
                "--address",
                f"unix:path={bus}",
                "--dest",
                "org.freedesktop.DBus",
                "--object-path",
                "/org/freedesktop/DBus",
                "--method",
                "org.freedesktop.DBus.NameHasOwner",
                backend,
            ]
        )
        details["backends"][backend] = (
            proc.stdout.strip() == "(true,)"
            if proc.returncode == 0 and proc.stdout.strip() in {"(true,)", "(false,)"}
            else None
        )
    available = all(value is True for value in details["backends"].values())
    return result(
        "desktop",
        "PASS" if available else "WARN",
        details,
        "available" if available else "unavailable",
    )


def native(root):
    path = root / "bin" / NATIVE_NAME
    if not path.is_file() or not os.access(path, os.X_OK):
        return result(
            "native",
            "FAIL",
            {
                "path": str(path),
                "message": "Native hash binary missing or not executable",
            },
            "unavailable",
        )
    proc = command([str(path), "--self-test"])
    return result(
        "native",
        "PASS" if proc.returncode == 0 else "FAIL",
        {
            "path": str(path),
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip()[:4096],
            "stderr": proc.stderr.strip()[:4096],
        },
    )


def collect(root, source, serial=None):
    checks = [
        result(
            "python",
            "PASS" if sys.version_info >= (3, 10) else "FAIL",
            {"version": sys.version.split()[0], "required": ">=3.10"},
        )
    ]
    config = {}
    try:
        config_check, config = configuration(root)
        checks.append(config_check)
    except (OSError, ValueError, UnicodeError) as error:
        checks.append(result("configuration", "FAIL", {"error": str(error)}))
    operations = [
        ("installed_files", lambda: installed_files(root, source)),
        ("metadata", lambda: metadata(root, source)),
        ("service", lambda: service(root)),
        ("adb", lambda: adb_devices(serial)),
        ("iocs", lambda: iocs(root, config)),
        ("storage", lambda: storage(root, config)),
        ("desktop", desktop),
        ("native", lambda: native(root)),
    ]
    for name, operation in operations:
        try:
            checks.append(operation())
        except (OSError, subprocess.SubprocessError) as error:
            checks.append(
                result(
                    name,
                    "FAIL" if name == "native" else "WARN",
                    {"error": str(error)},
                    "unavailable",
                )
            )
        except (ValueError, UnicodeError) as error:
            checks.append(result(name, "FAIL", {"error": str(error)}, "unknown"))
    return {
        "schema_version": 1,
        "root": str(root),
        "source": str(source),
        "checks": checks,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("/opt/mvt"),
        help="Installed prefix (default: /opt/mvt)",
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository prefix (default: derived from this script)",
    )
    parser.add_argument(
        "--serial", help="Filter the existing ADB host listing by serial"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit stable JSON checks; WARN does not fail exit",
    )
    args = parser.parse_args(argv)
    report = collect(args.root.absolute(), args.source.absolute(), args.serial)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for check in report["checks"]:
            print(
                f"{check['status']} {check['name']} ({check['availability']}): {json.dumps(check['details'], sort_keys=True)}"
            )
    return int(any(check["status"] == "FAIL" for check in report["checks"]))


if __name__ == "__main__":
    sys.exit(main())
