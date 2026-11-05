"""Offline end-to-end checks using real subprocesses and disposable fake tools."""

import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APK = b"offline APK fixture\x00\x01"

FAKE_TOOL = r"""
import hashlib
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path

root = Path(os.environ["FAKE_ROOT"])
mode = os.environ.get("FAKE_MODE", "success")
args = sys.argv[1:]
name = Path(sys.argv[0]).name
serial = ""
if "-s" in args:
    index = args.index("-s")
    serial = args[index + 1]
    if name == "adb":
        args = args[:index] + args[index + 2:]

def record(**entry):
    entry.update(tool=name, serial=serial, args=args)
    fd = os.open(root / "trace.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (json.dumps(entry) + "\n").encode())
    finally:
        os.close(fd)

def state_path(remote):
    key = hashlib.sha256((serial + "\0" + remote).encode()).hexdigest()
    directory = root / "device-state"
    directory.mkdir(exist_ok=True)
    return directory / key

if name == "adb":
    record()
    if args == ["get-state"]:
        print("device")
    elif args[:1] == ["pull"]:
        target = Path(args[-1])
        if mode in {"bad-apk", "pull-fail"}:
            target.write_bytes(b"incomplete APK")
        else:
            shutil.copyfile(Path(args[1]), target)
        if mode == "pull-fail":
            sys.exit(9)
    elif args[:1] == ["push"]:
        if mode == "state-push-fail":
            print("fake state push failure", file=sys.stderr)
            sys.exit(14)
        shutil.copyfile(args[1], state_path(args[2]))
    elif args[:1] == ["shell"]:
        command = shlex.split(args[1]) if len(args) == 2 else args[1:]
        if command == ["sh"]:
            result = subprocess.run(["/bin/sh"], input=sys.stdin.read(), text=True, check=False)
            sys.exit(result.returncode)
        elif command and command[0] == "cat":
            remote = next(value for value in command[1:] if value.startswith("/sdcard/"))
            path = state_path(remote)
            if path.exists():
                print(path.read_text(), end="")
            else:
                print("cat: " + remote + ": No such file or directory", file=sys.stderr)
                sys.exit(1)
        elif command and command[0] == "mv":
            paths = [value for value in command[1:] if value not in {"--", "-f"}]
            if mode == "state-rename-fail" or (mode == "token-rename-fail" and paths[-1].endswith(".mvt_last_check")):
                print("fake state rename failure", file=sys.stderr)
                sys.exit(15)
            state_path(paths[-2]).replace(state_path(paths[-1]))
        elif command and command[0] == "rm":
            for value in command[1:]:
                if value.startswith("/sdcard/"):
                    state_path(value).unlink(missing_ok=True)
        else:
            raise SystemExit("unexpected fake adb shell arguments: " + repr(command))
    else:
        raise SystemExit("unexpected fake adb arguments: " + repr(args))
elif name == "pm":
    record()
    if mode == "inventory-fail":
        print("fake package manager failure", file=sys.stderr)
        sys.exit(12)
    if mode != "inventory-empty":
        apk = root / ("missing.apk" if mode == "missing-apk" else "fixture== with space.apk")
        if args == ["list", "packages", "-3"]:
            print("package:org.example.fixture")
            if mode in {"threat", "open-fail", "non-apk-threat"}:
                print("package:org.example.benign")
        elif args == ["path", "org.example.fixture"]:
            if mode == "path-fail":
                sys.exit(17)
            print("package:" + str(apk))
            if mode == "split-threat":
                print("package:" + str(root / "split== with space.apk"))
        elif args == ["path", "org.example.benign"]:
            print("package:" + str(root / "benign.apk"))
        else:
            raise SystemExit("unexpected pm arguments: " + repr(args))
elif name == "stat":
    record()
    if mode == "stat-fail":
        sys.exit(18)
    print(Path(args[-1]).stat().st_size)
elif name == "sha256sum":
    record()
    if mode == "hash-fail":
        print("fake hashing failure", file=sys.stderr)
        sys.exit(13)
    print(hashlib.sha256(Path(args[-1]).read_bytes()).hexdigest() + "  " + args[-1])
elif name == "androidqf":
    record()
    output = Path(args[args.index("-o") + 1])
    output.mkdir(parents=True, exist_ok=True)
    (output / "device.txt").write_text(serial)
    packages = [{"name": "org.example.fixture", "files": [{"path": str(root / "fixture== with space.apk")}]}]
    if mode == "split-threat":
        packages[0]["files"].append({"path": str(root / "split== with space.apk")})
    if mode in {"threat", "open-fail", "non-apk-threat"}:
        packages.append({"name": "org.example.benign", "files": [{"path": str(root / "benign.apk")}]})
    (output / "packages.json").write_text(json.dumps(packages))
    print("fake acquisition output", flush=True)
    if mode == "aqf-fail":
        print("fake acquisition failed", file=sys.stderr, flush=True)
        sys.exit(7)
    if mode == "aqf-timeout":
        threading.Event().wait(30)
    barrier = os.environ.get("FAKE_BARRIER")
    if barrier:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(60)
            connection.connect(barrier)
            connection.sendall(serial.encode() + b"\n")
            if connection.recv(1) != b"x":
                raise SystemExit("barrier closed")
elif name == "mvt-android":
    record(environment={key: os.environ.get(key) for key in ("MVT_STIX2", "XDG_DATA_HOME")})
    indicator_paths = [args[i + 1] for i, value in enumerate(args) if value == "-i"]
    assert indicator_paths and all(Path(path).is_file() for path in indicator_paths)
    assert os.environ.get("MVT_STIX2") == ""
    assert str(root / "output" / "runs") in os.environ["XDG_DATA_HOME"]
    output = Path(args[args.index("-o") + 1])
    output.mkdir(parents=True, exist_ok=True)
    raw = Path(args[-1])
    (output / "device.txt").write_text((raw / "device.txt").read_text())
    print("fake analysis output", flush=True)
    if mode == "mvt-fail":
        print("fake analysis failed", file=sys.stderr, flush=True)
        sys.exit(8)
    if mode == "mvt-timeout":
        threading.Event().wait(30)
    if mode in {"threat", "open-fail", "non-apk-threat", "split-threat"}:
        event = json.loads((raw / "packages.json").read_text())[0]
        module = "aqf_packages"
        if mode == "non-apk-threat":
            module = "aqf_files"
            event = {"path": "/data/local/tmp/payload.bin"}
        (output / "alerts.json").write_text(json.dumps([{
            "level": "HIGH", "module": module, "message": "Offline positive fixture",
            "event": event, "matched_indicator": {"sha256": event["files"][1]["sha256"]} if mode == "split-threat" else {"id": "test-indicator"}
        }]))
    for level in ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        if mode == "partial-summary" and level == "CRITICAL":
            continue
        count = int((mode in {"threat", "open-fail", "non-apk-threat", "split-threat"} and level == "HIGH") or (mode == "medium" and level == "MEDIUM"))
        print(f"MVT produced {count} {level} alerts.")
elif name == "gdbus":
    record()
elif name == "apksigner":
    record()
    for algorithm, length in (("MD5", 32), ("SHA-1", 40), ("SHA-256", 64)):
        print(f"Signer #1 certificate {algorithm} digest: " + "a" * length)
else:
    raise SystemExit("unexpected fake executable")
"""

BOOTSTRAP = r"""
import importlib.util
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[1]).parent))
spec = importlib.util.spec_from_file_location("pipeline", sys.argv[1])
pipeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pipeline)
root = Path(os.environ["FAKE_ROOT"])
paths = {
    "MVT_ROOT": root,
    "INDICATORS_DIR": root / "indicators",
    "OUTPUT_ROOT": root / "output",
    "RUNS_DIR": root / "output" / "runs",
    "LATEST_LINK": root / "output" / "latest",
    "LOCK_DIR": root / "state" / "locks",
    "CACHE_DIR": root / "cache" / "apks",
    "INCIDENTS_DIR": root / "output" / "incidents",
    "LOG_FILE": root / "logs" / "pipeline.log",
    "AQF_BIN": root / "bin" / "androidqf",
    "MVT_BIN": root / "bin" / "mvt-android",
}
for name, value in paths.items():
    setattr(pipeline, name, str(value))
(root / "config.json").write_text(json.dumps({"machine_key_name": "mvt-test-machine"}))
pipeline.AQF_TIMEOUT = float(os.environ.get("FAKE_AQF_TIMEOUT", "10"))
pipeline.MVT_TIMEOUT = float(os.environ.get("FAKE_MVT_TIMEOUT", "10"))
pipeline.ADB_TIMEOUT = 10

def toast(title, message, urgency="critical"):
    entry = json.dumps({"serial": sys.argv[2], "title": title, "message": message}) + "\n"
    fd = os.open(root / "notifications.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, entry.encode())
    finally:
        os.close(fd)
    trace_entry = json.loads(entry)
    trace_entry.update(tool="notification", args=[])
    fd = os.open(root / "trace.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (json.dumps(trace_entry) + "\n").encode())
    finally:
        os.close(fd)

def open_folder(folder):
    entry = {"tool": "filemanager", "serial": sys.argv[2], "args": [str(folder)]}
    fd = os.open(root / "trace.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (json.dumps(entry) + "\n").encode())
    finally:
        os.close(fd)
    return os.environ.get("FAKE_MODE") != "open-fail"

pipeline.send_toast = toast
pipeline.open_results_folder = open_folder
serial = sys.argv[2]
sys.argv = ["mvt-autorun", "--serial", serial]
if os.environ.get("FAKE_FORCE", "1") == "1":
    sys.argv.append("--force")
raise SystemExit(pipeline.main())
"""


class PipelineIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        binary_dir = self.root / "bin"
        binary_dir.mkdir()
        for name in (
            "adb",
            "androidqf",
            "mvt-android",
            "apksigner",
            "pm",
            "sha256sum",
            "stat",
            "gdbus",
        ):
            executable = binary_dir / name
            executable.write_text(f"#!{sys.executable} -S\n" + FAKE_TOOL)
            executable.chmod(0o700)
        mvt = binary_dir / "mvt-android"
        (self.root / "installed-tools.json").write_text(
            json.dumps(
                {
                    "schema": 1,
                    "tools": {
                        "mvt": {
                            "path": str(mvt),
                            "sha256": hashlib.sha256(mvt.read_bytes()).hexdigest(),
                            "version": "fixture-mvt-1",
                        }
                    },
                }
            )
        )
        (self.root / "fixture== with space.apk").write_bytes(APK)
        (self.root / "benign.apk").write_bytes(b"unrelated benign APK fixture")
        (self.root / "split== with space.apk").write_bytes(b"split APK content")
        indicators = self.root / "indicators"
        indicators.mkdir()
        (indicators / "fixture.stix2").write_text(
            json.dumps(
                {
                    "type": "bundle",
                    "id": "bundle--c393a3d0-2e41-4444-8179-53587f912305",
                    "objects": [
                        {
                            "type": "indicator",
                            "spec_version": "2.1",
                            "id": "indicator--38f6413d-9391-44eb-8a05-b76f1ed80b0e",
                            "created": "2025-01-01T00:00:00Z",
                            "modified": "2025-01-01T00:00:00Z",
                            "valid_from": "2025-01-01T00:00:00Z",
                            "pattern_type": "stix",
                            "pattern": "[file:hashes.'SHA-256' = '" + "f" * 64 + "']",
                        }
                    ],
                }
            )
        )

    def environment(self, mode="success", **overrides):
        return {
            **os.environ,
            "PATH": str(self.root / "bin") + os.pathsep + os.environ.get("PATH", ""),
            "PYTHONDONTWRITEBYTECODE": "1",
            "MVT_HASH_BIN": str(ROOT / "bin" / "mvt-hash"),
            "FAKE_ROOT": str(self.root),
            "FAKE_MODE": mode,
            **overrides,
        }

    def command(self, serial="serial-A"):
        return [
            sys.executable,
            "-B",
            "-S",
            "-c",
            BOOTSTRAP,
            str(ROOT / "bin" / "mvt-autorun.py"),
            serial,
        ]

    def run_pipeline(self, mode="success", **overrides):
        return subprocess.run(
            self.command(),
            env=self.environment(mode, **overrides),
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )

    def entries(self, name):
        path = self.root / name
        return (
            [json.loads(line) for line in path.read_text().splitlines()]
            if path.exists()
            else []
        )

    def assert_no_committed_state(self):
        for entry in self.entries("trace.jsonl"):
            if entry["tool"] == "adb" and entry["args"][:1] == ["push"]:
                self.fail(f"failed pipeline attempted state commit: {entry}")

    def test_success_preserves_legacy_latest_and_independent_verified_apk(self):
        latest = self.root / "output" / "latest"
        latest.mkdir(parents=True)
        (latest / "keep.txt").write_text("previous evidence")
        result = self.run_pipeline()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(latest.is_symlink())
        self.assertEqual((latest / "raw" / "device.txt").read_text(), "serial-A")
        self.assertEqual(
            len(list((self.root / "output" / "runs").rglob("keep.txt"))), 1
        )
        apk = latest / "raw" / "apks" / "org.example.fixture.apk"
        cache = (
            self.root
            / "cache"
            / "apks"
            / f"org.example.fixture_{hashlib.sha256(APK).hexdigest()}.apk"
        )
        self.assertEqual(apk.read_bytes(), APK)
        self.assertEqual(cache.read_bytes(), APK)
        self.assertNotEqual(apk.stat().st_ino, cache.stat().st_ino)
        notifications = self.entries("notifications.jsonl")
        percentages = [
            int(re.search(r"\((\d+)%\)", item["title"]).group(1))
            for item in notifications
        ]
        self.assertEqual(percentages, [0, 25, 50, 75, 100])
        trace = self.entries("trace.jsonl")
        notice = next(
            index
            for index, entry in enumerate(trace)
            if entry["tool"] == "notification"
        )
        inventory = next(
            index for index, entry in enumerate(trace) if entry["tool"] == "pm"
        )
        self.assertLess(notice, inventory)
        analysis = next(
            index for index, entry in enumerate(trace) if entry["tool"] == "mvt-android"
        )
        pushes = [
            index
            for index, entry in enumerate(trace)
            if entry["tool"] == "adb" and entry["args"][:1] == ["push"]
        ]
        self.assertTrue(pushes)
        self.assertTrue(all(index > analysis for index in pushes))
        self.assertIn(".mvt_last_check", str(trace[pushes[-1]]["args"]))
        history_key = hashlib.sha256(
            b"serial-A\0/sdcard/Documents/.mvt_audit_history"
        ).hexdigest()
        history = json.loads((self.root / "device-state" / history_key).read_text())
        self.assertEqual(len(history["entries"]), 1)
        self.assertEqual(history["entries"][0]["machine_key_name"], "mvt-test-machine")
        self.assertEqual(
            json.loads((latest / "evidence-manifest.json").read_text())["metadata"][
                "device_audit_history"
            ],
            history["entries"],
        )
        stages = {
            int(re.search(r"\((\d+)%\)", entry["title"]).group(1)): index
            for index, entry in enumerate(trace)
            if entry["tool"] == "notification"
        }
        pull = next(
            index
            for index, entry in enumerate(trace)
            if entry["tool"] == "adb" and entry["args"][:1] == ["pull"]
        )
        acquisition = next(
            index for index, entry in enumerate(trace) if entry["tool"] == "androidqf"
        )
        enrichment = next(
            index for index, entry in enumerate(trace) if entry["tool"] == "apksigner"
        )
        token_commit = next(
            index
            for index, entry in enumerate(trace)
            if entry["tool"] == "adb"
            and "mv -f" in " ".join(entry["args"])
            and ".mvt_last_check" in " ".join(entry["args"])
        )
        self.assertLess(pull, stages[25])
        self.assertLess(stages[25], acquisition)
        self.assertLess(acquisition, enrichment)
        self.assertLess(enrichment, stages[50])
        self.assertLess(stages[50], analysis)
        self.assertLess(analysis, stages[75])
        self.assertLess(stages[75], pushes[0])
        self.assertLess(token_commit, stages[100])
        self.assertFalse(any(entry["tool"] == "filemanager" for entry in trace))

    def test_failures_retain_evidence_without_committing_or_publishing(self):
        for mode in (
            "aqf-fail",
            "mvt-fail",
            "partial-summary",
            "bad-apk",
            "pull-fail",
            "inventory-fail",
            "hash-fail",
            "missing-apk",
            "path-fail",
            "stat-fail",
        ):
            with self.subTest(mode=mode):
                cached = (
                    self.root
                    / "cache"
                    / "apks"
                    / f"org.example.fixture_{hashlib.sha256(APK).hexdigest()}.apk"
                )
                cached.unlink(missing_ok=True)
                result = self.run_pipeline(mode)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertFalse((self.root / "output" / "latest").exists())
                self.assert_no_committed_state()
        self.assertEqual(len(list((self.root / "output" / "runs").iterdir())), 10)
        logs = "\n".join(
            path.read_text() for path in (self.root / "output" / "runs").rglob("*.log")
        )
        self.assertIn("fake acquisition failed", logs)
        self.assertIn("fake analysis failed", logs)
        self.assertFalse(
            any(entry["tool"] == "filemanager" for entry in self.entries("trace.jsonl"))
        )
        self.assertFalse(
            any("100%" in item["title"] for item in self.entries("notifications.jsonl"))
        )

    def test_timeouts_retain_partial_tool_logs(self):
        for mode, variable in (
            ("aqf-timeout", "FAKE_AQF_TIMEOUT"),
            ("mvt-timeout", "FAKE_MVT_TIMEOUT"),
        ):
            with self.subTest(mode=mode):
                result = self.run_pipeline(mode, **{variable: "1"})
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assert_no_committed_state()
        logs = "\n".join(
            path.read_text() for path in (self.root / "output" / "runs").rglob("*.log")
        )
        self.assertIn("fake acquisition output", logs)
        self.assertIn("fake analysis output", logs)

    def test_state_commit_failures_do_not_publish_or_claim_scan_completion(self):
        for mode in ("state-push-fail", "state-rename-fail", "token-rename-fail"):
            with self.subTest(mode=mode):
                result = self.run_pipeline(mode)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertFalse((self.root / "output" / "latest").exists())
                key = hashlib.sha256(
                    b"serial-A\0/sdcard/Documents/.mvt_last_check"
                ).hexdigest()
                self.assertFalse((self.root / "device-state" / key).exists())
                if mode == "token-rename-fail":
                    baseline_key = hashlib.sha256(
                        b"serial-A\0/sdcard/Documents/.mvt_pkg_hashes"
                    ).hexdigest()
                    self.assertIn(
                        "org.example.fixture",
                        (self.root / "device-state" / baseline_key).read_text(),
                    )
        self.assertFalse(
            any(entry["tool"] == "filemanager" for entry in self.entries("trace.jsonl"))
        )
        self.assertFalse(
            any("100%" in item["title"] for item in self.entries("notifications.jsonl"))
        )

    def test_threat_evidence_is_copied_before_device_state_is_committed(self):
        result = self.run_pipeline("threat")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        incidents = list((self.root / "output" / "incidents").iterdir())
        self.assertEqual(len(incidents), 1)
        incident = incidents[0]
        self.assertEqual(
            json.loads((incident / "run.json").read_text())["status"],
            "analysis_completed",
        )
        self.assertEqual(
            json.loads((self.root / "output" / "latest" / "run.json").read_text())[
                "status"
            ],
            "completed",
        )
        self.assertEqual((incident / "raw" / "device.txt").read_text(), "serial-A")
        self.assertEqual(
            (incident / "raw" / "apks" / "org.example.fixture.apk").read_bytes(), APK
        )
        self.assertIn(
            "MVT produced 1 HIGH alerts.",
            (incident / "analysis" / "mvt_run.log").read_text(),
        )
        notification = self.entries("notifications.jsonl")[-1]
        self.assertIn("THREAT DETECTED", notification["message"])
        flagged = incident / "flagged_apks"
        self.assertEqual(
            {path.name for path in flagged.glob("*.apk")}, {"org.example.fixture.apk"}
        )
        self.assertEqual((flagged / "org.example.fixture.apk").read_bytes(), APK)
        self.assertNotEqual(
            (flagged / "org.example.fixture.apk").stat().st_ino,
            (incident / "raw" / "apks" / "org.example.fixture.apk").stat().st_ino,
        )
        report = json.loads((flagged / "findings.json").read_text())
        self.assertEqual(
            [item["package"] for item in report["apks"]], ["org.example.fixture"]
        )
        trace = self.entries("trace.jsonl")
        opened = [
            (index, entry)
            for index, entry in enumerate(trace)
            if entry["tool"] == "filemanager"
        ]
        self.assertEqual(len(opened), 1)
        self.assertEqual(Path(opened[0][1]["args"][0]), flagged)
        token_commit = next(
            index
            for index, entry in enumerate(trace)
            if entry["tool"] == "adb"
            and "mv -f" in " ".join(entry["args"])
            and ".mvt_last_check" in " ".join(entry["args"])
        )
        self.assertGreater(opened[0][0], token_commit)
        self.assertIn(str(flagged), notification["message"])

    def test_split_hash_finding_preserves_only_matching_apk_and_sealed_manifest(self):
        result = self.run_pipeline("split-threat")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        latest = (self.root / "output/latest").resolve()
        incident = next((self.root / "output/incidents").iterdir())
        report = json.loads((incident / "flagged_apks/findings.json").read_text())
        self.assertEqual(len(report["apks"]), 1)
        selected = report["apks"][0]
        self.assertEqual(selected["path"], str(self.root / "split== with space.apk"))
        self.assertNotEqual(selected["filename"], "org.example.fixture.apk")
        self.assertEqual(
            (incident / "flagged_apks" / selected["filename"]).read_bytes(),
            b"split APK content",
        )
        self.assertEqual(len(list((latest / "raw/apks").glob("*.apk"))), 2)
        manifest = json.loads((latest / "evidence-manifest.json").read_text())
        self.assertIn("run.json", manifest["exclusions"])
        self.assertEqual(manifest["metadata"]["status"], "analysis_completed")
        self.assertEqual(
            manifest["metadata"]["provenance"]["tools"]["mvt"]["version"],
            "fixture-mvt-1",
        )
        self.assertEqual(len(manifest["metadata"]["provenance"]["ioc_files"]), 1)
        self.assertIn("flagged_apks/" + selected["filename"], manifest["files"])
        self.assertEqual(
            (incident / "evidence-manifest.json").read_bytes(),
            (latest / "evidence-manifest.json").read_bytes(),
        )
        key = hashlib.sha256(b"serial-A\0/sdcard/Documents/.mvt_pkg_hashes").hexdigest()
        self.assertEqual(
            len((self.root / "device-state" / key).read_text().splitlines()), 2
        )
        sys.path.insert(0, str(ROOT / "bin"))
        from unittest.mock import patch

        import mvt_evidence

        with patch.dict(os.environ, {"MVT_HASH_BIN": str(ROOT / "bin/mvt-hash")}):
            self.assertTrue(mvt_evidence.verify_evidence_manifest(latest)["ok"])
            self.assertTrue(mvt_evidence.verify_evidence_manifest(incident)["ok"])

    def test_positive_non_apk_finding_opens_report_only_folder(self):
        result = self.run_pipeline("non-apk-threat")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        opened = [
            entry
            for entry in self.entries("trace.jsonl")
            if entry["tool"] == "filemanager"
        ]
        self.assertEqual(len(opened), 1)
        folder = Path(opened[0]["args"][0])
        self.assertFalse(list(folder.glob("*.apk")))
        report = json.loads((folder / "findings.json").read_text())
        self.assertFalse(report["apks"])
        self.assertTrue(report["unmatched"])
        self.assertTrue(folder.is_relative_to(self.root / "output" / "incidents"))

    def test_file_manager_failure_does_not_invalidate_positive_scan(self):
        result = self.run_pipeline("open-fail")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        latest = self.root / "output" / "latest"
        self.assertEqual(
            json.loads((latest / "run.json").read_text())["status"], "completed"
        )
        opened = [
            entry
            for entry in self.entries("trace.jsonl")
            if entry["tool"] == "filemanager"
        ]
        self.assertEqual(len(opened), 1)
        self.assertTrue(
            (Path(opened[0]["args"][0]) / "org.example.fixture.apk").is_file()
        )
        self.assertIn("WARNING", self.entries("notifications.jsonl")[-1]["message"])

    def test_medium_only_scan_does_not_open_or_label_apks(self):
        result = self.run_pipeline("medium")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(
            any(entry["tool"] == "filemanager" for entry in self.entries("trace.jsonl"))
        )
        self.assertFalse(list((self.root / "output" / "runs").glob("*/flagged_apks")))
        self.assertFalse((self.root / "output" / "incidents").exists())

    def test_empty_third_party_inventory_is_valid(self):
        result = self.run_pipeline("inventory-empty")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(
            any(
                entry["tool"] == "adb" and entry["args"][:1] == ["pull"]
                for entry in self.entries("trace.jsonl")
            )
        )

    def test_not_due_connection_shows_gmt_schedule_without_another_scan(self):
        success = self.run_pipeline()
        self.assertEqual(success.returncode, 0, success.stdout + success.stderr)
        previous = (self.root / "output" / "latest").resolve()
        skipped = self.run_pipeline(FAKE_FORCE="0")
        self.assertEqual(skipped.returncode, 0, skipped.stdout + skipped.stderr)
        self.assertEqual((self.root / "output" / "latest").resolve(), previous)
        self.assertEqual(len(list((self.root / "output" / "runs").iterdir())), 1)
        notice = self.entries("notifications.jsonl")[-1]
        self.assertIn("Not due", notice["title"])
        self.assertIn("Last scanned", notice["message"])
        self.assertIn("Next due", notice["message"])
        self.assertGreaterEqual(notice["message"].count("GMT"), 2)
        self.assertEqual(
            sum(entry["tool"] == "androidqf" for entry in self.entries("trace.jsonl")),
            1,
        )

    def test_failed_run_does_not_replace_previous_completed_latest(self):
        success = self.run_pipeline()
        self.assertEqual(success.returncode, 0, success.stdout + success.stderr)
        latest = self.root / "output" / "latest"
        previous = latest.resolve()
        failure = self.run_pipeline("mvt-fail")
        self.assertEqual(failure.returncode, 1, failure.stdout + failure.stderr)
        self.assertEqual(latest.resolve(), previous)

    def test_simultaneous_devices_have_isolated_evidence_and_shared_verified_cache(
        self,
    ):
        address = str(self.root / "barrier.sock")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(address)
            listener.listen(2)
            listener.settimeout(60)
            children = []
            connections = []
            try:
                for serial in ("serial-A", "serial-B"):
                    children.append(
                        subprocess.Popen(
                            self.command(serial),
                            env=self.environment(FAKE_BARRIER=address),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                        )
                    )
                entered = set()
                for _ in children:
                    connection, _ = listener.accept()
                    connections.append(connection)
                    connection.settimeout(60)
                    entered.add(connection.recv(1024).decode().strip())
                self.assertEqual(entered, {"serial-A", "serial-B"})
                for connection in connections:
                    connection.sendall(b"x")
                for child in children:
                    stdout, stderr = child.communicate(timeout=90)
                    self.assertEqual(child.returncode, 0, stdout + stderr)
            finally:
                for connection in connections:
                    connection.close()
                for child in children:
                    if child.poll() is None:
                        child.kill()
                    child.communicate(timeout=5)
        runs = list((self.root / "output" / "runs").iterdir())
        self.assertEqual(len(runs), 2)
        serials = set()
        inodes = set()
        for run in runs:
            serial = (run / "raw" / "device.txt").read_text()
            serials.add(serial)
            self.assertEqual((run / "analysis" / "device.txt").read_text(), serial)
            apk = run / "raw" / "apks" / "org.example.fixture.apk"
            self.assertEqual(apk.read_bytes(), APK)
            inodes.add(apk.stat().st_ino)
        self.assertEqual(serials, {"serial-A", "serial-B"})
        self.assertEqual(len(inodes), 2)
        self.assertIn((self.root / "output" / "latest").resolve(), runs)


if __name__ == "__main__":
    unittest.main()
