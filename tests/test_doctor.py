"""Doctor tests never contact host services or run installed tools."""

import contextlib
import importlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

BIN = Path(__file__).resolve().parents[1] / "bin"


class FakeSocket:
    def __init__(self, payload=b"", status=b"OKAY", fragmented=False):
        self.data = status + f"{len(payload):04x}".encode() + payload
        self.fragmented = fragmented
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def settimeout(self, timeout):
        if not 0 < timeout <= 5:
            raise AssertionError("Socket must have a bounded timeout")

    def sendall(self, payload):
        self.sent.append(payload)

    def recv(self, size):
        if self.fragmented:
            size = min(size, 1)
        chunk, self.data = self.data[:size], self.data[size:]
        return chunk


class DoctorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Standalone scripts import their siblings from bin, as installed CLI does.
        sys.path.insert(0, str(BIN))
        cls.doctor = importlib.import_module("mvt_doctor")

    @classmethod
    def tearDownClass(cls):
        sys.path.remove(str(BIN))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "installed"
        self.source = Path(self.temp.name) / "source"
        self.root.mkdir()
        self.source.mkdir()
        self.commands = []
        self.socket = FakeSocket(b"A\tdevice product:phone\nB\tunauthorized\n")
        self.runner = mock.patch.object(
            self.doctor.subprocess, "run", side_effect=self.run_command
        )
        self.runner.start()
        self.addCleanup(self.runner.stop)
        self.connector = mock.patch.object(
            self.doctor.socket, "create_connection", return_value=self.socket
        )
        self.connect = self.connector.start()
        self.addCleanup(self.connector.stop)
        self.which = mock.patch.object(self.doctor.shutil, "which", return_value=None)
        self.which.start()
        self.addCleanup(self.which.stop)
        self.disk = mock.patch.object(
            self.doctor.shutil,
            "disk_usage",
            return_value=types.SimpleNamespace(free=10 * 1024**3),
        )
        self.disk.start()
        self.addCleanup(self.disk.stop)

    def run_command(self, argv, **kwargs):
        self.commands.append(argv)
        self.assertEqual(kwargs["timeout"], 5)
        self.assertIs(kwargs["check"], False)
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        if argv[0] == "systemctl":
            self.assertEqual(argv[1:3], ["show", "mvt-watcher.service"])
            return subprocess.CompletedProcess(
                argv,
                0,
                "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=123\nExecMainStartTimestampMonotonic=1\n",
                "",
            )
        if Path(argv[0]).name == "mvt-hash":
            self.assertEqual(argv[1:], ["--self-test"])
            return subprocess.CompletedProcess(argv, 0, "self-test passed", "")
        if argv[0] == "/mock/gdbus":
            self.assertIn("org.freedesktop.DBus.NameHasOwner", argv)
            return subprocess.CompletedProcess(argv, 0, "(true,)\n", "")
        self.fail(f"Unexpected or mutating command: {argv!r}")

    def write_json(self, path, value):
        path.write_text(json.dumps(value))

    def populated(self):
        for prefix in (self.root, self.source):
            (prefix / "bin").mkdir()
            for name in (
                "mvt-autorun.py",
                "mvt-autorun.sh",
                "adb-device-watcher.py",
                "system_speedup.py",
                "mvt_doctor.py",
                "mvt_hash.py",
                "mvt_evidence.py",
                "mvt-hash",
            ):
                path = prefix / "bin" / name
                path.write_bytes(b"identical content\n")
                path.chmod(0o755)
            self.write_json(
                prefix / "dependencies.json",
                {
                    "schema": 1,
                    "mvt": {"version": "2026.10.26"},
                    "androidqf": {"version": "1.8.3"},
                },
            )
            (prefix / "requirements-pinned.txt").write_text("mvt==2026.10.26\n")
        self.write_json(
            self.root / "installed-tools.json",
            {
                "schema": 1,
                "tools": {
                    name: {
                        "version": version,
                        "path": str(self.root / "bin" / name),
                        "sha256": "a" * 64,
                    }
                    for name, version in (
                        ("mvt", "2026.10.26"),
                        ("androidqf", "1.8.3"),
                        ("adb", "version"),
                        ("mvt-hash", "1"),
                    )
                },
            },
        )
        self.write_json(self.root / "config.json", {"min_free_bytes": 100})
        (self.root / "indicators").mkdir()
        self.write_json(
            self.root / "indicators" / "sample.stix2",
            {
                "type": "bundle",
                "objects": [{"type": "indicator", "id": "indicator--test"}],
            },
        )

    def check_map(self):
        report = self.doctor.collect(self.root, self.source)
        return {check["name"]: check for check in report["checks"]}

    def test_json_partial_install_does_not_create_files_or_abort(self):
        self.connect.side_effect = ConnectionRefusedError("No ADB server")
        before = sorted(str(p) for p in Path(self.temp.name).rglob("*"))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = self.doctor.main(
                ["--root", str(self.root), "--source", str(self.source), "--json"]
            )
        self.assertEqual(code, 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report["schema_version"], 1)
        checks = {item["name"]: item for item in report["checks"]}
        self.assertEqual(checks["native"]["status"], "FAIL")
        self.assertEqual(checks["adb"]["availability"], "unavailable")
        self.assertEqual(checks["storage"]["status"], "PASS")
        self.assertEqual(
            before, sorted(str(p) for p in Path(self.temp.name).rglob("*"))
        )
        self.assertEqual([cmd[0] for cmd in self.commands], ["systemctl"])

    def test_matching_scripts_and_native_are_independent(self):
        self.populated()
        (self.root / "bin" / "mvt-hash").unlink()
        checks = self.check_map()
        self.assertEqual(checks["native"]["status"], "FAIL")
        files = checks["installed_files"]["details"]["files"]
        self.assertTrue(any(f["comparison"] == "identical" for f in files))
        self.assertEqual(checks["metadata"]["status"], "PASS")
        self.assertEqual(checks["iocs"]["details"]["indicator_count"], 1)
        self.assertFalse(any(Path(cmd[0]).name == "mvt-hash" for cmd in self.commands))

    def test_source_mismatch_uses_bytes_even_when_stat_matches(self):
        self.populated()
        installed = self.root / "bin" / "mvt_hash.py"
        original = installed.stat()
        installed.write_bytes(b"different content\n")
        os.utime(installed, ns=(original.st_atime_ns, original.st_mtime_ns))
        check = self.doctor.installed_files(self.root, self.source)
        self.assertEqual(check["status"], "WARN")
        self.assertEqual(
            next(i for i in check["details"]["files"] if i["file"] == "mvt_hash.py")[
                "comparison"
            ],
            "different",
        )

    def test_adb_protocol_is_host_listing_only_and_filters_after_listing(self):
        self.socket.fragmented = True
        check = self.doctor.adb_devices("A")
        self.assertEqual(check["status"], "PASS")
        self.assertEqual(check["details"]["devices"][0]["serial"], "A")
        self.connect.assert_called_once_with(("127.0.0.1", 5037), timeout=5)
        self.assertEqual(self.socket.sent, [b"000ehost:devices-l"])
        self.assertFalse(self.commands)

    def test_unauthorized_offline_empty_or_missing_serial_warn(self):
        for payload, serial in (
            (b"A\tunauthorized\n", None),
            (b"A\toffline\n", None),
            (b"", None),
            (b"A\tdevice\n", "missing"),
        ):
            with self.subTest(payload=payload):
                self.connect.return_value = FakeSocket(payload)
                self.assertEqual(self.doctor.adb_devices(serial)["status"], "WARN")

    def test_broken_protocol_fails_without_stopping_other_checks(self):
        self.socket.data = b"OKAY0010short"
        checks = self.check_map()
        self.assertEqual(checks["adb"]["status"], "FAIL")
        self.assertEqual(checks["adb"]["availability"], "unknown")
        self.assertIn("storage", checks)

    def test_adb_rejects_signed_whitespace_and_nonhex_lengths(self):
        for header in (b"-001", b"+001", b" 001", b"ZZZZ"):
            with self.subTest(header=header):
                self.socket.data = b"OKAY" + header + b"a"
                with self.assertRaisesRegex(ValueError, "Invalid ADB payload length"):
                    self.doctor.adb_devices()

    def test_server_fail_and_connection_timeout_are_unavailable(self):
        self.connect.return_value = FakeSocket(b"not supported", status=b"FAIL")
        self.assertEqual(self.doctor.adb_devices()["availability"], "unavailable")
        self.connect.side_effect = TimeoutError("timeout")
        self.assertEqual(self.check_map()["adb"]["availability"], "unavailable")

    def test_service_restart_needed_for_updated_files(self):
        self.populated()
        check = self.doctor.service(self.root)
        self.assertTrue(check["details"]["restart_needed"])
        self.assertEqual(check["status"], "WARN")
        self.assertIn(
            str(self.root / "bin" / "mvt_doctor.py"), check["details"]["newer_files"]
        )

    def test_service_unknown_start_is_not_a_pass(self):
        with mock.patch.object(
            self.doctor,
            "command",
            return_value=subprocess.CompletedProcess(
                [], 0, "ActiveState=active\nMainPID=123\n", ""
            ),
        ):
            check = self.doctor.service(self.root)
        self.assertEqual(check["status"], "WARN")
        self.assertIsNone(check["details"]["restart_needed"])

    def test_failed_service_is_failure_and_unavailable_is_warning(self):
        with mock.patch.object(
            self.doctor,
            "command",
            return_value=subprocess.CompletedProcess([], 0, "ActiveState=failed\n", ""),
        ):
            self.assertEqual(self.doctor.service(self.root)["status"], "FAIL")
        with mock.patch.object(
            self.doctor, "command", side_effect=FileNotFoundError("systemctl")
        ):
            self.assertEqual(self.check_map()["service"]["availability"], "unavailable")

    def test_config_strict_parse_rejects_duplicate_keys_and_nonfinite(self):
        for content in (
            '{"min_free_bytes":1,"min_free_bytes":2}',
            '{"min_free_bytes":NaN}',
            "[]",
        ):
            (self.root / "config.json").write_text(content)
            self.assertEqual(self.check_map()["configuration"]["status"], "FAIL")

    def test_storage_policy_and_missing_root_never_create_directories(self):
        missing = self.root / "does-not-exist" / "nested"
        check = self.doctor.storage(missing, {"min_free_bytes": 11 * 1024**3})
        self.assertEqual(check["status"], "FAIL")
        self.assertFalse(missing.exists())
        with self.assertRaises(ValueError):
            self.doctor.storage(self.root, {"min_free_bytes": True})

    def test_ioc_parse_errors_age_and_count_are_reported(self):
        self.populated()
        path = self.root / "indicators" / "sample.stix2"
        os.utime(path, (time.time() - 40 * 86400,) * 2)
        check = self.doctor.iocs(self.root, {})
        self.assertEqual(check["status"], "WARN")
        self.assertGreater(check["details"]["files"][0]["age_days"], 30)
        path.write_text("broken JSON")
        check = self.doctor.iocs(self.root, {})
        self.assertEqual(check["status"], "FAIL")
        self.assertEqual(check["details"]["files"][0]["parse"], "invalid")

    def test_desktop_only_queries_own_bus_without_activating_backends(self):
        with (
            mock.patch.object(self.doctor.shutil, "which", return_value="/mock/gdbus"),
            mock.patch.object(
                Path,
                "stat",
                return_value=types.SimpleNamespace(
                    st_uid=os.getuid(), st_mode=stat.S_IFSOCK
                ),
            ),
        ):
            check = self.doctor.desktop()
        self.assertEqual(check["status"], "PASS")
        self.assertEqual(len(self.commands), 2)
        for argv in self.commands:
            self.assertIn(f"unix:path=/run/user/{os.getuid()}/bus", argv)
            self.assertNotIn("Notify", " ".join(argv))
            self.assertNotIn("ShowFolders", " ".join(argv))
            self.assertNotIn("StartServiceByName", " ".join(argv))

    def test_desktop_never_uses_another_users_bus(self):
        with (
            mock.patch.object(self.doctor.shutil, "which", return_value="/mock/gdbus"),
            mock.patch.object(
                Path,
                "stat",
                return_value=types.SimpleNamespace(
                    st_uid=os.getuid() + 1, st_mode=stat.S_IFSOCK
                ),
            ),
        ):
            self.assertEqual(self.doctor.desktop()["availability"], "unavailable")
        self.assertFalse(self.commands)

    def test_native_self_test_bounded_failure_and_timeout(self):
        self.populated()
        self.assertEqual(self.doctor.native(self.root)["status"], "PASS")
        with mock.patch.object(
            self.doctor,
            "command",
            return_value=subprocess.CompletedProcess([], 1, "", "failed"),
        ):
            self.assertEqual(self.doctor.native(self.root)["status"], "FAIL")
        with mock.patch.object(
            self.doctor, "command", side_effect=subprocess.TimeoutExpired("mvt-hash", 5)
        ):
            self.assertEqual(self.check_map()["native"]["status"], "FAIL")

    def test_help_does_not_run_diagnostics(self):
        with (
            contextlib.redirect_stdout(io.StringIO()) as output,
            self.assertRaises(SystemExit) as raised,
        ):
            self.doctor.main(["--help"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("--serial", output.getvalue())
        self.assertIn("WARN", output.getvalue())
        self.connect.assert_not_called()
        self.assertFalse(self.commands)

    def test_metadata_unknown_schema_and_version_mismatch_warn(self):
        self.populated()
        record = self.doctor.read_json(self.root / "installed-tools.json")
        record["tools"]["mvt"]["version"] = "old-version"
        self.write_json(self.root / "installed-tools.json", record)
        check = self.doctor.metadata(self.root, self.source)
        self.assertEqual(check["status"], "WARN")
        self.assertIn(
            "Recorded mvt version differs from dependency lock",
            check["details"]["issues"],
        )
        self.write_json(self.root / "installed-tools.json", {"unexpected": True})
        self.assertEqual(self.doctor.metadata(self.root, self.source)["status"], "WARN")

    def test_self_comparison_is_not_reported_as_repository_match(self):
        self.populated()
        check = self.doctor.installed_files(self.root, self.root)
        self.assertEqual(check["status"], "WARN")
        self.assertTrue(
            all(
                item["comparison"] == "source_is_installation"
                for item in check["details"]["files"]
            )
        )
        self.assertEqual(self.doctor.metadata(self.root, self.root)["status"], "WARN")

    def test_valid_install_no_mutation_and_all_available_can_pass(self):
        self.populated()
        for path in (self.root / "bin").iterdir():
            os.utime(path, (1, 1))
        before = {
            str(path): path.read_bytes()
            for path in self.root.rglob("*")
            if path.is_file()
        }
        with mock.patch.object(
            self.doctor,
            "desktop",
            return_value=self.doctor.result("desktop", "PASS", {}),
        ):
            report = self.doctor.collect(self.root, self.source, "A")
        self.assertTrue(
            all(check["status"] == "PASS" for check in report["checks"]), report
        )
        self.assertEqual(
            before,
            {
                str(path): path.read_bytes()
                for path in self.root.rglob("*")
                if path.is_file()
            },
        )
        self.assertTrue(
            all(
                cmd[0] == "systemctl" or cmd[1:] == ["--self-test"]
                for cmd in self.commands
            )
        )

    def test_config_validates_policy_and_signing_key_without_writing(self):
        for value in (
            {"min_free_bytes": True},
            {"auto_prune": "false"},
            {"run_retention_days": -1},
            {"unexpected": 1},
            {"signing_key": "/nonexistent/mvt-doctor-key.pem"},
        ):
            self.write_json(self.root / "config.json", value)
            self.assertEqual(self.check_map()["configuration"]["status"], "FAIL")
        self.assertEqual(
            self.doctor.storage(self.root, {})["details"]["min_free_bytes"], 1024**3
        )

    def test_warning_only_exit_is_success(self):
        with (
            mock.patch.object(
                self.doctor,
                "collect",
                return_value={
                    "checks": [self.doctor.result("adb", "WARN", {}, "unavailable")]
                },
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(self.doctor.main(["--json"]), 0)


if __name__ == "__main__":
    unittest.main()
