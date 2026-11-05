"""Locked installer operations. No deployment happens merely by importing this module."""

import argparse
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

MAX_DOWNLOAD = 128 * 1024 * 1024
DOWNLOAD_SECONDS = 180
SHA256 = re.compile(r"[0-9a-f]{64}")
# Byte-for-byte fingerprint of the old installer-owned file, not a general rule match.
LEGACY_RULES = b"""# Universal Android USB Debugging Rules
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
"""


def target_key(machine=None):
    machine = platform.machine() if machine is None else machine
    architectures = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
    if machine not in architectures:
        raise ValueError(f"Unsupported CPU architecture: {machine}; no amd64 fallback")
    return "linux-" + architectures[machine]


def run(argv, timeout=60):
    return subprocess.run(
        argv, check=True, capture_output=True, text=True, timeout=timeout
    ).stdout.strip()


def native_sha256(path, hash_bin):
    """Reuse the project's required native SHA wrapper, including its strict protocol."""
    module_dir = str(Path(__file__).resolve().parents[1] / "bin")
    if module_dir not in sys.path:
        sys.path.insert(0, module_dir)
    from mvt_hash import hash_file

    return hash_file(path, binary=hash_bin)


def locked_requirements(path):
    lines = path.read_text().replace("\\\n", " ").splitlines()
    packages = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(
            r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)((?:\s+--hash=sha256:[0-9a-f]{64})+)",
            line,
        )
        if not match:
            raise ValueError(f"Unpinned or unhashed requirement: {line}")
        name = re.sub(r"[-_.]+", "-", match[1]).lower()
        if name in packages:
            raise ValueError(f"Duplicate requirement: {name}")
        packages[name] = match[2]
    if not {"mvt", "pip", "wheel", "setuptools"}.issubset(packages):
        raise ValueError("Lock omits MVT or pinned bootstrap packages")
    return packages


def load_lock(source):
    data = json.loads((source / "dependencies.json").read_text())
    if (
        data.get("schema") != 1
        or data["mvt"]["requirements"] != "requirements-pinned.txt"
    ):
        raise ValueError("Unsupported dependency lock schema")
    packages = locked_requirements(source / data["mvt"]["requirements"])
    if packages["mvt"] != data["mvt"]["version"]:
        raise ValueError("MVT lock version mismatch")
    aqf = data["androidqf"]
    if set(aqf["assets"]) != {"linux-amd64", "linux-arm64"}:
        raise ValueError("AndroidQF lock must include both supported architectures")
    for key, asset in aqf["assets"].items():
        arch = key.removeprefix("linux-")
        expected_url = (
            "https://github.com/mvt-project/androidqf/releases/download/"
            f"v{aqf['version']}/androidqf_linux_{arch}_{aqf['version']}"
        )
        if asset["url"] != expected_url or not SHA256.fullmatch(asset["sha256"]):
            raise ValueError("Invalid AndroidQF release URL or checksum")
    if "platform_tools" in data:
        raise ValueError(
            "No verified platform-tools fallback is supported; use OS-managed adb"
        )
    return data


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def download(url, output):
    if not url.startswith("https://"):
        raise ValueError("Downloads require HTTPS")
    deadline = time.monotonic() + DOWNLOAD_SECONDS
    request = urllib.request.Request(
        url, headers={"User-Agent": "mvt-autorun-locked-installer/1"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        if not response.url.startswith("https://"):
            raise ValueError("Download redirected away from HTTPS")
        length = response.headers.get("Content-Length")
        if length is not None and int(length) > MAX_DOWNLOAD:
            raise ValueError("Download exceeds size limit")
        total = 0
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError("Download exceeded wall-clock deadline")
            block = response.read1(65536)
            if not block:
                break
            total += len(block)
            if total > MAX_DOWNLOAD:
                raise ValueError("Download exceeds size limit")
            output.write(block)


def install_androidqf(lock, source, root, hash_bin, machine=None):
    asset = lock["androidqf"]["assets"][target_key(machine)]
    destination = root / "bin" / "androidqf"
    destination.parent.mkdir(parents=True, exist_ok=True)
    if (
        destination.is_file()
        and not destination.is_symlink()
        and native_sha256(destination, hash_bin) == asset["sha256"]
    ):
        destination.chmod(0o755)
        return
    candidate = source / "bin" / "androidqf"
    if candidate.is_symlink() or not candidate.is_file():
        candidate = None
    elif native_sha256(candidate, hash_bin) != asset["sha256"]:
        print(
            "[!] Bundled AndroidQF does not match this target's pin; downloading verified release",
            file=sys.stderr,
        )
        candidate = None
    fd, staged_name = tempfile.mkstemp(prefix=".androidqf-", dir=destination.parent)
    staged = Path(staged_name)
    try:
        with os.fdopen(fd, "wb") as output:
            if candidate is not None:
                with candidate.open("rb") as bundled:
                    shutil.copyfileobj(bundled, output)
            else:
                download(asset["url"], output)
            output.flush()
            os.fsync(output.fileno())
        if native_sha256(staged, hash_bin) != asset["sha256"]:
            raise ValueError(
                "AndroidQF SHA256 mismatch; existing binary was not replaced"
            )
        staged.chmod(0o755)
        os.replace(staged, destination)
        sync_directory(destination.parent)
    finally:
        staged.unlink(missing_ok=True)


def atomic_bytes(destination, data, mode=0o644):
    fd, name = tempfile.mkstemp(
        prefix="." + destination.name + "-", dir=destination.parent
    )
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(name, mode)
        os.replace(name, destination)
        sync_directory(destination.parent)
    finally:
        Path(name).unlink(missing_ok=True)


def machine_key_label(hostname=None):
    hostname = platform.node() if hostname is None else hostname
    label = re.sub(r"[^A-Za-z0-9_.-]+", "-", hostname).strip(".-_")
    if not label:
        raise ValueError("Machine hostname cannot form a signing-key name")
    return (label[:100].rstrip(".-_") or "machine") + "-mvt-signing"


def install_signing_identity(root, home, user, hostname=None):
    """Create/reuse a host-named Ed25519 signing key and merge runtime config."""
    label = machine_key_label(hostname)
    home, root = Path(home), Path(root)
    if home.is_symlink() or not home.is_dir():
        raise ValueError("Target home must be an existing nonsymlink directory")
    ssh = home / ".ssh"
    if ssh.is_symlink():
        raise ValueError("Refusing a symlinked target .ssh directory")
    ssh.mkdir(mode=0o700, exist_ok=True)
    if not ssh.is_dir():
        raise ValueError("Target .ssh path is not a directory")
    os.chmod(ssh, 0o700)
    uid = __import__("pwd").getpwnam(user).pw_uid
    gid = __import__("pwd").getpwnam(user).pw_gid
    os.chown(ssh, uid, gid)
    private = ssh / f"{label}.pem"
    public = ssh / f"{label}.pub.pem"
    if private.is_symlink() or public.is_symlink():
        raise ValueError("Signing key paths must not be symlinks")
    if private.exists():
        info = private.stat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ValueError(
                "Existing signing private key must be user-owned mode 0600"
            )
        der = subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private),
                "-passin",
                "pass:",
                "-pubout",
                "-outform",
                "DER",
            ],
            check=True,
            capture_output=True,
            timeout=15,
        ).stdout
        checked = subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private),
                "-passin",
                "pass:",
                "-check",
                "-noout",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if (
            checked.returncode
            or len(der) != 44
            or not der.startswith(bytes.fromhex("302a300506032b6570032100"))
        ):
            raise ValueError("Existing named signing key is invalid or is not Ed25519")
    elif public.exists():
        raise ValueError(
            "Public signing key exists without its private key; refusing replacement"
        )
    else:
        fd, temporary = tempfile.mkstemp(prefix=f".{label}-", dir=ssh)
        os.close(fd)
        os.unlink(temporary)
        try:
            run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", temporary])
            os.chmod(temporary, 0o600)
            os.chown(temporary, uid, gid)
            # link() publishes only if no concurrently-created key already exists.
            os.link(temporary, private, follow_symlinks=False)
        finally:
            Path(temporary).unlink(missing_ok=True)
    derived = subprocess.run(
        ["openssl", "pkey", "-in", str(private), "-passin", "pass:", "-pubout"],
        check=True,
        capture_output=True,
        timeout=15,
    ).stdout
    if public.exists():
        if (
            public.stat().st_uid != uid
            or not stat.S_ISREG(public.stat().st_mode)
            or public.read_bytes() != derived
        ):
            raise ValueError(
                "Existing public key does not match the private signing key"
            )
        os.chmod(public, 0o644)
    else:
        atomic_bytes(public, derived, 0o644)
        os.chown(public, uid, gid)
    config_path = root / "config.json"
    if config_path.is_symlink():
        raise ValueError("Refusing symlinked /opt/mvt/config.json")
    try:
        config = json.loads(config_path.read_text()) if config_path.exists() else {}
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(
            f"Cannot safely merge existing config.json: {error}"
        ) from error
    if not isinstance(config, dict):
        raise TypeError("Existing config.json must contain an object")
    config.update(signing_key=str(private), machine_key_name=label)
    atomic_bytes(
        config_path,
        (json.dumps(config, sort_keys=True, indent=2) + "\n").encode(),
        0o600,
    )
    os.chown(config_path, uid, gid)
    return {
        "machine_key_name": label,
        "private_key": str(private),
        "public_key": str(public),
    }


def install_udev(source, rules_dir):
    rules_dir.mkdir(parents=True, exist_ok=True)
    legacy = rules_dir / "51-android.rules"
    if legacy.is_symlink():
        print(f"[!] Leaving administrator symlink untouched: {legacy}", file=sys.stderr)
    elif legacy.is_file():
        content = legacy.read_bytes()
        if content == LEGACY_RULES:
            fd, backup_name = tempfile.mkstemp(
                prefix="51-android.rules.mvt-backup-", dir=rules_dir
            )
            with os.fdopen(fd, "wb") as backup:
                backup.write(content)
                backup.flush()
                os.fsync(backup.fileno())
            print(f"[*] Backed up exact installer legacy rule to {backup_name}")
            # Recheck before unlinking: never intentionally remove administrator changes.
            if legacy.read_bytes() != LEGACY_RULES:
                raise RuntimeError("Legacy udev file changed while backing it up")
            legacy.unlink()
            sync_directory(rules_dir)
        elif any(
            int(mode, 8) & 2
            for mode in re.findall(rb'MODE\s*[:+]?=\s*"(0?[0-7]{3})"', content)
        ):
            print(
                f"[!] Administrator rule {legacy} is world-writable; left unchanged, review it",
                file=sys.stderr,
            )
    atomic_bytes(
        rules_dir / "70-mvt-android.rules",
        (source / "udev" / "70-mvt-android.rules").read_bytes(),
    )


def package_owner(path):
    if shutil.which("dpkg-query"):
        return run(["dpkg-query", "-S", str(path)])
    if shutil.which("rpm"):
        return run(["rpm", "-qf", str(path)])
    if shutil.which("pacman"):
        return run(["pacman", "-Qo", str(path)])
    raise RuntimeError("Cannot verify ADB is owned by an OS package")


def os_packages():
    if shutil.which("dpkg-query"):
        output = run(
            [
                "dpkg-query",
                "-W",
                "-f=${db:Status-Abbrev}\t${binary:Package}\t${Version}\n",
            ]
        )
        return {
            "manager": "dpkg",
            "versions": {
                fields[1]: fields[2]
                for line in output.splitlines()
                if len(fields := line.split("\t")) == 3 and fields[0].startswith("ii")
            },
        }
    if shutil.which("rpm"):
        output = run(
            [
                "rpm",
                "-qa",
                "--queryformat",
                "%{NAME}.%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n",
            ]
        )
        return {
            "manager": "rpm",
            "versions": dict(line.split("\t", 1) for line in output.splitlines()),
        }
    if shutil.which("pacman"):
        output = run(["pacman", "-Q"])
        return {
            "manager": "pacman",
            "versions": dict(line.split(" ", 1) for line in output.splitlines()),
        }
    raise RuntimeError("Cannot record installed OS package versions")


MVT_PROBE = """import importlib.metadata as m, json, re
from mvt.common.alerts import AlertLevel, AlertStore
expected = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
if [x.name for x in AlertLevel] != expected:
    raise SystemExit("MVT alert severity schema incompatible")
store = AlertStore()
for name in ["info", "low", "medium", "high", "critical"]:
    getattr(store, name)("installer schema probe", "", {})
if [x["level"] for x in store.as_json()] != expected:
    raise SystemExit("MVT JSON alert severity schema incompatible")
print(json.dumps({re.sub(r"[-_.]+", "-", d.metadata["Name"]).lower(): d.version for d in m.distributions()}))
"""


def record_install(lock, source, root, hash_bin):
    python = root / "venv" / "bin" / "python"
    installed = json.loads(run([str(python), "-c", MVT_PROBE]))
    for name, version in locked_requirements(
        source / lock["mvt"]["requirements"]
    ).items():
        if installed.get(name) != version:
            raise ValueError(
                f"Installed Python version does not match lock: {name}=={version}"
            )
    adb = root / "bin" / "adb"
    if not adb.is_file():
        raise RuntimeError("OS-managed adb is required; no unverified fallback")
    adb_package = package_owner(adb.resolve())
    paths = {
        "mvt": (root / "venv/bin/mvt-android", installed["mvt"]),
        "androidqf": (root / "bin/androidqf", lock["androidqf"]["version"]),
        "mvt-hash": (Path(hash_bin), run([str(hash_bin), "--version"])),
        "adb": (adb.resolve(), run([str(adb), "version"])),
        "python": (python.resolve(), run([str(python), "--version"])),
    }
    tools = {
        name: {
            "path": str(path),
            "version": version,
            "sha256": native_sha256(path, hash_bin),
        }
        for name, (path, version) in paths.items()
    }
    asset = lock["androidqf"]["assets"][target_key()]
    if tools["androidqf"]["sha256"] != asset["sha256"]:
        raise ValueError("Installed AndroidQF no longer matches lock")
    tools["androidqf"]["url"] = asset["url"]
    tools["adb"]["source"] = "os-package"
    tools["adb"]["package"] = adb_package
    locks = {
        name: native_sha256(source / name, hash_bin)
        for name in ("dependencies.json", "requirements-pinned.txt")
    }
    for name, digest in locks.items():
        if native_sha256(root / name, hash_bin) != digest:
            raise ValueError(f"Installed lock copy differs from source: {name}")
    record = {
        "schema": 1,
        "tools": tools,
        "python_packages": installed,
        "locks": locks,
        "sources": {
            str(path.relative_to(source)): native_sha256(path, hash_bin)
            for path in sorted((source / "bin").glob("*.py"))
        },
        "os_packages": os_packages(),
        "os_release": Path("/etc/os-release").read_text(),
        "reproducibility": "Python and AndroidQF pinned; OS packages are managed by the host distribution, not bit-reproducible.",
    }
    atomic_bytes(
        root / "installed-tools.json",
        (json.dumps(record, indent=2, sort_keys=True) + "\n").encode(),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=["validate", "androidqf", "udev", "record", "signing-key"]
    )
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path("/opt/mvt"))
    parser.add_argument("--hash-bin", type=Path, default=Path("/opt/mvt/bin/mvt-hash"))
    parser.add_argument("--rules-dir", type=Path, default=Path("/etc/udev/rules.d"))
    parser.add_argument("--home", type=Path)
    parser.add_argument("--user")
    parser.add_argument("--hostname")
    args = parser.parse_args()
    minimum_python = (3, 10)
    if sys.version_info < minimum_python:
        parser.error("Python 3.10 or newer is required")
    try:
        lock = load_lock(args.source)
        target_key()
        if args.action == "androidqf":
            install_androidqf(lock, args.source, args.root, args.hash_bin)
        elif args.action == "udev":
            install_udev(args.source, args.rules_dir)
        elif args.action == "record":
            record_install(lock, args.source, args.root, args.hash_bin)
        elif args.action == "signing-key":
            if not args.home or not args.user:
                raise ValueError("signing-key requires --home and --user")
            identity = install_signing_identity(
                args.root, args.home, args.user, args.hostname
            )
            print(json.dumps(identity, sort_keys=True))
    except (
        OSError,
        ValueError,
        KeyError,
        RuntimeError,
        subprocess.SubprocessError,
    ) as error:
        print(f"[-] {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
