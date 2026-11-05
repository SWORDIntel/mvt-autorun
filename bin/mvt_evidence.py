"""Sealed evidence, recorded IOC inputs, and opt-in conservative storage maintenance."""

import argparse
import fcntl
import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import tempfile
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path

import mvt_hash

RESERVE_BYTES = 1024**3
MANIFEST = "evidence-manifest.json"
SIGNATURE = "evidence-manifest.sig"
PUBLIC_KEY = "evidence-public-key.pem"
EXCLUSIONS = ["run.json", MANIFEST, SIGNATURE, PUBLIC_KEY]
DEFAULTS = {
    "min_free_bytes": RESERVE_BYTES,
    "run_retention_days": None,
    "cache_retention_days": None,
    "auto_prune": False,
    "signing_key": None,
    "machine_key_name": None,
}
LEVELS = ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def _utc(value=None):
    return (
        datetime.fromtimestamp(value, timezone.utc).isoformat()
        if value is not None
        else datetime.now(timezone.utc).isoformat()
    )


def _json_bytes(value):
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique)


def _atomic(path, content, mode=0o600):
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), mode)
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        if os.path.lexists(name):
            os.unlink(name)


def _integer(name, value, nullable=False):
    if nullable and value is None:
        return
    if type(value) is not int or value < 0:
        raise ValueError(
            f"{name} must be a nonnegative integer" + (" or null" if nullable else "")
        )


def _private_key(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError(
            "signing_key must be a regular, nonsymlink file with permissions 0600"
        )
    if info.st_uid != os.geteuid():
        raise ValueError("signing_key must be owned by the current user")
    return path.resolve(strict=True)


def load_config(root):
    """Read optional root/config.json; never create or rewrite configuration."""
    path = Path(root) / "config.json"
    config = dict(DEFAULTS)
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file():
            raise ValueError("config.json must be a regular nonsymlink file")
        try:
            supplied = _read_json(path)
        except (OSError, ValueError) as error:
            raise ValueError(f"Invalid config.json: {error}") from error
        if not isinstance(supplied, dict):
            raise ValueError("config.json must contain an object")
        unknown = supplied.keys() - DEFAULTS.keys()
        if unknown:
            raise ValueError(
                f"Unknown configuration keys: {', '.join(sorted(unknown))}"
            )
        config.update(supplied)
    _integer("min_free_bytes", config["min_free_bytes"])
    for name in ("run_retention_days", "cache_retention_days"):
        _integer(name, config[name], nullable=True)
    if type(config["auto_prune"]) is not bool:
        raise ValueError("auto_prune must be a boolean")
    machine_key_name = config["machine_key_name"]
    if machine_key_name is not None and (
        not isinstance(machine_key_name, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", machine_key_name)
    ):
        raise ValueError("machine_key_name must be a safe, non-empty key label")
    key = config["signing_key"]
    if key is not None:
        if not isinstance(key, str) or not key or not Path(key).is_absolute():
            raise ValueError("signing_key must be an absolute file path or null")
        try:
            _private_key(key)
        except OSError as error:
            raise ValueError(f"Invalid signing_key: {error}") from error
    return config


def check_free_space(path, min_free_bytes=RESERVE_BYTES, required_bytes=0):
    """Check an existing ancestor without creating a nonexistent destination."""
    _integer("min_free_bytes", min_free_bytes)
    _integer("required_bytes", required_bytes)
    ancestor = Path(path).absolute()
    while not ancestor.exists():
        if ancestor.is_symlink() or ancestor == ancestor.parent:
            raise ValueError(f"Cannot find existing storage ancestor for {path}")
        ancestor = ancestor.parent
    if not ancestor.is_dir():
        ancestor = ancestor.parent
    usage = shutil.disk_usage(ancestor)
    result = {
        "path": str(ancestor),
        "free_bytes": usage.free,
        "min_free_bytes": min_free_bytes,
        "required_bytes": required_bytes,
    }
    if usage.free < min_free_bytes + required_bytes:
        raise RuntimeError(
            f"Insufficient free space at {ancestor}: {usage.free} bytes available; reserve {min_free_bytes} + estimated {required_bytes} bytes required"
        )
    return result


def _bounded(root, path):
    """Reject symlink components, including directory links inside a storage root."""
    root, path = Path(root), Path(path)
    relative = path.relative_to(root)
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"Symlink storage path is not permitted: {current}")
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"Path escapes storage root: {path}")
    return path


def _file_record(path):
    resolved = Path(path).resolve(strict=True)
    info = resolved.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"Not a regular file: {path}")
    return {
        "path": str(path),
        "resolved_path": str(resolved),
        "sha256": mvt_hash.hash_file(str(resolved)),
        "size": info.st_size,
        "mtime_utc": _utc(info.st_mtime),
    }


def _version_record(records, name, actual):
    tools = records.get("tools", {}) if isinstance(records, dict) else {}
    record = tools.get(name, {}) if isinstance(tools, dict) else {}
    if (
        isinstance(record, dict)
        and record.get("sha256") == actual["sha256"]
        and record.get("version")
    ):
        recorded_path = record.get("path", record.get("resolved_path"))
        if recorded_path and Path(recorded_path).resolve() == Path(
            actual["resolved_path"]
        ):
            return str(record["version"])
    return "unknown"


def _walk_error(error):
    raise error


def capture_provenance(root, run_dir, tools, indicators_dir, script_path):
    """Freeze independent, verified IOC copies before analysis; never execute tools."""
    root, run = Path(root).resolve(), Path(run_dir).resolve(strict=True)
    source = Path(indicators_dir)
    if source.is_symlink() or not source.is_dir():
        raise ValueError(
            "Configured indicators directory must be an ordinary directory"
        )
    source = source.resolve()
    inputs = []
    for directory, dirs, files in os.walk(
        source, followlinks=False, onerror=_walk_error
    ):
        for name in dirs:
            if (Path(directory) / name).is_symlink():
                raise ValueError("Symlink indicator directories are not permitted")
        for name in sorted(files):
            path = Path(directory) / name
            if path.suffix.lower() != ".stix2":
                continue
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(source) or not resolved.is_file():
                raise ValueError(
                    f"Indicator symlink escape or nonregular source: {path}"
                )
            inputs.append((path, resolved))
    if not inputs:
        raise RuntimeError("No configured STIX2 indicator source files are present")
    destination = run / "indicators"
    if destination.exists() or destination.is_symlink():
        raise ValueError("Run indicator snapshot already exists")
    staging = Path(tempfile.mkdtemp(prefix=".indicators-", dir=run))
    snapshots = []
    try:
        for original, resolved in sorted(inputs):
            relative = original.relative_to(source)
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            before = _file_record(resolved)
            with resolved.open("rb") as reader, target.open("xb") as writer:
                shutil.copyfileobj(reader, writer)
                writer.flush()
                os.fsync(writer.fileno())
            after = _file_record(resolved)
            copied = _file_record(target)
            if (
                before != after
                or copied["sha256"] != before["sha256"]
                or original.resolve(strict=True) != resolved
            ):
                raise RuntimeError(f"Indicator changed during snapshot: {original}")
            contents = _read_json(target)
            if (
                not isinstance(contents, dict)
                or contents.get("type") != "bundle"
                or not isinstance(contents.get("objects"), list)
            ):
                raise ValueError(f"Invalid STIX2 bundle: {original}")
            snapshots.append(
                {
                    "source": str(original),
                    "path": str(destination / relative),
                    "relative_path": relative.as_posix(),
                    "sha256": before["sha256"],
                    "size": before["size"],
                    "source_mtime_utc": before["mtime_utc"],
                    "bundle_id": contents.get("id"),
                    "spec_version": contents.get("spec_version"),
                    "object_versions": [
                        {
                            key: obj[key]
                            for key in ("id", "spec_version", "modified", "created")
                            if key in obj
                        }
                        for obj in contents["objects"]
                        if isinstance(obj, dict)
                    ],
                }
            )
        os.replace(staging, destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    warnings = []
    installed = None
    installed_path = root / "installed-tools.json"
    if installed_path.exists():
        if installed_path.is_symlink():
            raise ValueError("installed-tools.json must not be a symlink")
        installed = {
            "file": _file_record(installed_path),
            "contents": _read_json(installed_path),
        }
    else:
        warnings.append(
            "installed-tools.json absent; tool versions are explicitly unknown"
        )
    tool_records = {}
    for name, executable in sorted(tools.items()):
        resolved = shutil.which(str(executable))
        if resolved is None:
            raise RuntimeError(f"Tool executable not found: {name}: {executable}")
        record = _file_record(resolved)
        record["version"] = _version_record(
            installed["contents"] if installed else {}, name, record
        )
        if record["version"] == "unknown":
            warnings.append(
                f"{name}: version unknown (no matching verified installation record)"
            )
        tool_records[name] = record
    native = os.environ.get(
        "MVT_HASH_BIN", str(Path(mvt_hash.__file__).resolve().with_name("mvt-hash"))
    )
    native_resolved = shutil.which(native)
    if native_resolved is None:
        raise RuntimeError("Required native hash executable is missing")
    runtime_records = {
        "script": _file_record(script_path),
        "hash_wrapper": _file_record(mvt_hash.__file__),
        "native_hash": _file_record(native_resolved),
    }
    environment_root = run / "mvt-environment"
    _bounded(run, environment_root)
    environment = {
        "XDG_DATA_HOME": str(environment_root / "data"),
        "MVT_STIX2": "",
    }
    Path(environment["XDG_DATA_HOME"]).mkdir(parents=True, exist_ok=False)
    return {
        "captured_at": _utc(),
        "indicators_dir": str(destination),
        "indicators": [item["path"] for item in snapshots],
        "ioc_files": snapshots,
        "tools": tool_records,
        "runtime": runtime_records,
        "installed_tools": installed,
        "environment": environment,
        "warnings": warnings,
    }


def _scan(run):
    entries, regular, stamps = {}, [], {}
    for directory, dirs, files in os.walk(run, followlinks=False, onerror=_walk_error):
        for name in sorted(dirs + files):
            path = Path(directory) / name
            relative = path.relative_to(run).as_posix()
            info = path.lstat()
            if relative in EXCLUSIONS:
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError(
                        f"Excluded lifecycle/output path must be a regular file: {relative}"
                    )
                continue
            if stat.S_ISLNK(info.st_mode):
                entries[relative] = {"type": "symlink", "target": os.readlink(path)}
                if name in dirs:
                    dirs.remove(name)
            elif stat.S_ISDIR(info.st_mode):
                entries[relative] = {"type": "directory"}
            elif stat.S_ISREG(info.st_mode):
                entries[relative] = {"type": "file", "size": info.st_size}
                regular.append(str(path))
                stamps[str(path)] = (
                    info.st_dev,
                    info.st_ino,
                    info.st_size,
                    info.st_mtime_ns,
                    info.st_ctime_ns,
                )
            else:
                raise ValueError(f"Unsupported special evidence file: {relative}")
    return entries, regular, stamps


def _inventory(run):
    entries, regular, stamps = _scan(run)
    hashes = mvt_hash.hash_files(regular) if regular else {}
    after_entries, _, after_stamps = _scan(run)
    if entries != after_entries or stamps != after_stamps:
        raise RuntimeError("Evidence changed while hashing")
    for path in regular:
        entries[Path(path).relative_to(run).as_posix()]["sha256"] = hashes[path]
    return entries


def _openssl(args):
    executable = shutil.which("openssl")
    if not executable:
        raise RuntimeError("OpenSSL executable is required for Ed25519 signatures")
    try:
        result = subprocess.run(
            [executable, *map(str, args)],
            input=b"",
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeError(f"OpenSSL failed: {error}") from error
    if result.returncode:
        raise RuntimeError(
            f"OpenSSL failed: {result.stderr.decode(errors='replace').strip()}"
        )
    return result.stdout


def _ed25519_key(path, public=False):
    args = ["pkey", "-in", path, "-pubout", "-outform", "DER"]
    if public:
        args.insert(1, "-pubin")
    else:
        args.extend(["-passin", "pass:"])
    der = _openssl(args)
    # RFC 8410 Ed25519 SubjectPublicKeyInfo: OID 1.3.101.112, 32-byte key.
    if len(der) != 44 or not der.startswith(bytes.fromhex("302a300506032b6570032100")):
        raise ValueError("Only Ed25519 keys are supported")
    return der


def write_evidence_manifest(run_dir, metadata, signing_key=None):
    run = Path(run_dir).resolve(strict=True)
    if not run.is_dir() or not isinstance(metadata, dict):
        raise ValueError("Evidence requires a run directory and metadata object")
    entries = _inventory(run)
    manifest = {
        "schema_version": 1,
        "hash_algorithm": "sha256",
        "created_at": _utc(),
        "exclusions": EXCLUSIONS,
        "metadata": metadata,
        "files": entries,
        "signature": {
            "algorithm": "Ed25519",
            "file": SIGNATURE,
            "public_key": PUBLIC_KEY,
        }
        if signing_key
        else None,
    }
    content = _json_bytes(manifest)
    if signing_key:
        key = _private_key(signing_key)
        _ed25519_key(key)
        with tempfile.TemporaryDirectory(prefix=".signing-", dir=run) as temporary:
            temp = Path(temporary)
            (temp / "manifest").write_bytes(content)
            public = _openssl(["pkey", "-in", key, "-passin", "pass:", "-pubout"])
            _openssl(
                [
                    "pkeyutl",
                    "-sign",
                    "-rawin",
                    "-inkey",
                    key,
                    "-passin",
                    "pass:",
                    "-in",
                    temp / "manifest",
                    "-out",
                    temp / "signature",
                ]
            )
            signature = (temp / "signature").read_bytes()
            if len(signature) != 64:
                raise RuntimeError("OpenSSL did not produce an Ed25519 signature")
            _atomic(run / PUBLIC_KEY, public)
            _atomic(run / SIGNATURE, signature)
    else:
        for name in (PUBLIC_KEY, SIGNATURE):
            if os.path.lexists(run / name):
                if (run / name).is_dir() and not (run / name).is_symlink():
                    raise ValueError(f"Invalid evidence output directory: {name}")
                (run / name).unlink()
    _atomic(run / MANIFEST, content)
    return manifest


def _validate_manifest(value):
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or value.get("hash_algorithm") != "sha256"
        or value.get("exclusions") != EXCLUSIONS
    ):
        raise ValueError("Unsupported manifest schema, hash algorithm or exclusions")
    entries = value.get("files")
    if not isinstance(entries, dict):
        raise TypeError("Manifest files must be an object")
    for relative, entry in entries.items():
        if (
            not isinstance(relative, str)
            or not relative
            or "\x00" in relative
            or "\\" in relative
            or any(part in ("", ".", "..") for part in relative.split("/"))
            or Path(relative).is_absolute()
            or relative in EXCLUSIONS
        ):
            raise ValueError(f"Unsafe manifest path: {relative!r}")
        if not isinstance(entry, dict) or entry.get("type") not in (
            "file",
            "directory",
            "symlink",
        ):
            raise ValueError(f"Invalid manifest entry: {relative}")
        if entry["type"] == "file" and (
            not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256")))
            or type(entry.get("size")) is not int
            or entry["size"] < 0
        ):
            raise ValueError(f"Invalid file fingerprint: {relative}")
        if entry["type"] == "symlink" and not isinstance(entry.get("target"), str):
            raise ValueError(f"Invalid symlink target: {relative}")
    return entries


def verify_evidence_manifest(run_dir, public_key=None, require_signature=False):
    result = {
        "ok": False,
        "errors": [],
        "signature": {"status": "unsigned", "authenticated": False},
    }
    try:
        run = Path(run_dir).resolve(strict=True)
        manifest_path = run / MANIFEST
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise ValueError("Manifest must be a regular nonsymlink file")
        manifest = _read_json(manifest_path)
        expected = _validate_manifest(manifest)
        actual = _inventory(run)
        for name in sorted(expected.keys() - actual.keys()):
            result["errors"].append(f"Missing evidence: {name}")
        for name in sorted(actual.keys() - expected.keys()):
            result["errors"].append(f"Added evidence: {name}")
        for name in sorted(expected.keys() & actual.keys()):
            if expected[name] != actual[name]:
                result["errors"].append(f"Modified evidence: {name}")
        signature = manifest.get("signature")
        if signature is not None:
            result["signature"]["status"] = "untrusted"
            if signature != {
                "algorithm": "Ed25519",
                "file": SIGNATURE,
                "public_key": PUBLIC_KEY,
            }:
                raise ValueError("Invalid signature metadata")
            if public_key is None:
                result["errors"].append(
                    "Signed evidence requires an explicit trusted public key; bundled public key is not a trust anchor"
                )
            else:
                _ed25519_key(public_key, public=True)
                sig_path = run / SIGNATURE
                if (
                    sig_path.is_symlink()
                    or not sig_path.is_file()
                    or sig_path.stat().st_size != 64
                ):
                    raise ValueError("Missing or invalid detached signature")
                _openssl(
                    [
                        "pkeyutl",
                        "-verify",
                        "-rawin",
                        "-pubin",
                        "-inkey",
                        public_key,
                        "-sigfile",
                        sig_path,
                        "-in",
                        manifest_path,
                    ]
                )
                result["signature"] = {"status": "verified", "authenticated": True}
        elif require_signature:
            result["errors"].append(
                "A trusted signature is required, but the manifest is unsigned"
            )
        else:
            result["signature"]["note"] = (
                "Content hashes verified only; unsigned evidence is not authenticated"
            )
        result["ok"] = not result["errors"]
    except (OSError, ValueError, RuntimeError, TypeError) as error:
        result["errors"].append(str(error))
    return result


def _lock(root, name, stack):
    directory = _bounded(root, root / "state" / "locks")
    directory.mkdir(parents=True, exist_ok=True)
    path = _bounded(root, directory / name)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    stream = stack.enter_context(os.fdopen(fd, "a"))
    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return stream


def _time_value(value):
    if not isinstance(value, str):
        raise TypeError("Missing UTC completion timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Completion timestamp must include timezone")
    return parsed.timestamp()


def _negative_completed(path):
    metadata_path = path / "run.json"
    if metadata_path.is_symlink() or not metadata_path.is_file():
        raise ValueError("unknown legacy run")
    meta = _read_json(metadata_path)
    if not isinstance(meta, dict) or meta.get("status") != "completed":
        raise ValueError("active, failed or unknown run status")
    alerts = meta.get("alerts", {})
    if not isinstance(alerts, dict) or any(
        type(alerts.get(level)) is not int or alerts[level] < 0 for level in LEVELS
    ):
        raise ValueError("unknown alert status")
    if (
        alerts["HIGH"]
        or alerts["CRITICAL"]
        or meta.get("positive") not in (None, False)
    ):
        raise ValueError("positive incident source")
    serial = meta.get("serial")
    if not isinstance(serial, str) or not serial:
        raise ValueError("unknown device identity")
    manifest_path = path / MANIFEST
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("unsealed or unknown legacy run")
    manifest = _read_json(manifest_path)
    _validate_manifest(manifest)
    sealed = manifest.get("metadata")
    if (
        not isinstance(sealed, dict)
        or sealed.get("serial") != serial
        or sealed.get("alerts") != alerts
    ):
        raise ValueError("lifecycle metadata disagrees with sealed evidence")
    if sealed.get("positive") not in (None, False):
        raise ValueError("sealed positive incident source")
    finished = next(
        (
            meta[key]
            for key in ("completed_at", "finished_at", "analysis_completed_at")
            if key in meta
        ),
        None,
    )
    return serial, _time_value(finished)


def _references(paths, cache, protected):
    """Protect recorded hashes and live cache links, including in unsealed runs."""
    hashes = set()
    cache = cache.resolve()
    for path in paths:
        if path.is_symlink():
            return None
        if path.is_file():
            continue
        if not path.is_dir():
            return None
        manifest_path = path / MANIFEST
        if not manifest_path.is_symlink() and manifest_path.is_file():
            try:
                entries = _validate_manifest(_read_json(manifest_path))
            except (OSError, ValueError, TypeError) as error:
                protected.append(
                    {
                        "path": str(manifest_path),
                        "reason": f"Invalid manifest; inspecting actual cache links: {error}",
                    }
                )
            else:
                hashes.update(
                    entry["sha256"]
                    for entry in entries.values()
                    if entry["type"] == "file"
                )
        try:
            # Missing manifests do not make independent raw copies depend on cache.
            # Inspect actual links so failed/legacy runs still retain their data.
            for directory, dirs, files in os.walk(
                path, followlinks=False, onerror=_walk_error
            ):
                for name in dirs + files:
                    link = Path(directory) / name
                    if not link.is_symlink():
                        continue
                    target = link.resolve()
                    if cache.is_relative_to(target):
                        return None
                    if target.parent == cache:
                        match = re.fullmatch(
                            r"(?:[A-Za-z0-9_.-]+_)?([0-9a-f]{64})\.apk", target.name
                        )
                        if match:
                            hashes.add(match[1])
        except (OSError, RuntimeError) as error:
            protected.append(
                {
                    "path": str(path),
                    "reason": f"Cannot inspect cache references: {error}",
                }
            )
            return None
    return hashes


def prune_storage(root, run_days=None, cache_days=None, apply=False, now=None):
    """Plan by default; delete only aged, provably ordinary and unreferenced data."""
    _integer("run_days", run_days, nullable=True)
    _integer("cache_days", cache_days, nullable=True)
    if type(apply) is not bool:
        raise ValueError("apply must be a boolean")
    result = {"candidates": [], "deleted": [], "protected": [], "errors": []}
    if run_days is None and cache_days is None:
        return result
    root = Path(root).absolute()
    if root.is_symlink() or not root.is_dir():
        result["errors"].append("Storage root must be an existing nonsymlink directory")
        return result
    root = root.resolve()
    timestamp = (
        datetime.now(timezone.utc).timestamp()
        if now is None
        else (now.timestamp() if isinstance(now, datetime) else float(now))
    )
    if not math.isfinite(timestamp):
        raise ValueError("now must be a finite timestamp")
    with ExitStack() as stack:
        try:
            # Publication order matches runtime; maintenance protects cache verified-copy consumers.
            _lock(root, "publication.lock", stack)
            _lock(root, "maintenance.lock", stack)
            runs = _bounded(root, root / "output" / "runs")
            incidents = _bounded(root, root / "output" / "incidents")
            cache = _bounded(root, root / "cache" / "apks")
            latest = (root / "output" / "latest").resolve()
            retained = []
            if incidents.exists():
                retained.extend(incidents.iterdir())
                result["protected"].extend(
                    {
                        "path": str(p),
                        "reason": "incident evidence is never automatically released",
                    }
                    for p in incidents.iterdir()
                )
            run_candidates = []
            device_locks = set()
            for path in sorted(runs.iterdir()) if runs.exists() else []:
                reason = None
                try:
                    _bounded(root, path)
                    if not path.is_dir():
                        raise ValueError("not an ordinary run directory")
                    if path.resolve() == latest:
                        raise ValueError("latest run")
                    serial, completed = _negative_completed(path)
                    device_id = hashlib.sha256(serial.encode()).hexdigest()[:24]
                    if device_id not in device_locks:
                        _lock(root, f"device-{device_id}.lock", stack)
                        device_locks.add(device_id)
                    if (
                        run_days is None
                        or timestamp - max(completed, path.stat().st_mtime)
                        <= run_days * 86400
                    ):
                        raise ValueError("run retention disabled or not aged")
                    run_candidates.append(path)
                except (OSError, ValueError, TypeError) as error:
                    reason = str(error)
                if reason:
                    retained.append(path)
                    result["protected"].append({"path": str(path), "reason": reason})
            references = _references(retained, cache, result["protected"])
            candidates = [(path, "run") for path in run_candidates]
            for path in sorted(cache.iterdir()) if cache.exists() else []:
                try:
                    _bounded(root, path)
                    info = path.lstat()
                    match = re.fullmatch(
                        r"(?:[A-Za-z0-9_.-]+_)?([0-9a-f]{64})\.apk", path.name
                    )
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or not match
                        or info.st_nlink != 1
                    ):
                        raise ValueError("not an ordinary independent cache APK")
                    if (
                        cache_days is None
                        or timestamp - max(info.st_atime, info.st_mtime, info.st_ctime)
                        <= cache_days * 86400
                    ):
                        raise ValueError("cache retention disabled or not aged")
                    if references is None or match[1] in references:
                        raise ValueError("cache may be referenced by retained evidence")
                    if mvt_hash.hash_file(str(path)) != match[1]:
                        raise ValueError(
                            "cache fingerprint does not match its content address"
                        )
                    candidates.append((path, "cache"))
                except (OSError, ValueError, RuntimeError) as error:
                    result["protected"].append(
                        {"path": str(path), "reason": str(error)}
                    )
            for path, kind in candidates:
                result["candidates"].append({"path": str(path), "kind": kind})
                if apply:
                    try:
                        _bounded(root, path)
                        if kind == "run":
                            if path.resolve() == (root / "output" / "latest").resolve():
                                raise ValueError(
                                    "latest run changed during maintenance"
                                )
                            shutil.rmtree(path)
                        else:
                            path.unlink()
                        result["deleted"].append(str(path))
                    except (OSError, ValueError) as error:
                        result["errors"].append(f"{path}: {error}")
        except (OSError, ValueError) as error:
            result["errors"].append(f"Storage maintenance unavailable: {error}")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser(
        "verify", help="Check hashes and optional trusted Ed25519 signature"
    )
    verify.add_argument("path")
    verify.add_argument("--public-key")
    verify.add_argument("--require-signature", action="store_true")
    prune = commands.add_parser(
        "prune", help="Plan retention; deletion requires --apply"
    )
    prune.add_argument("--root", default="/opt/mvt")
    prune.add_argument("--run-days", type=int)
    prune.add_argument("--cache-days", type=int)
    prune.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            result = verify_evidence_manifest(
                args.path, args.public_key, args.require_signature
            )
            status = 0 if result["ok"] else 1
        else:
            result = prune_storage(
                args.root, args.run_days, args.cache_days, args.apply
            )
            status = 1 if result["errors"] else 0
    except (OSError, ValueError, RuntimeError) as error:
        result, status = {"errors": [str(error)]}, 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
