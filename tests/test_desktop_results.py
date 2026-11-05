import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


autorun = load_module("desktop_results_autorun", "bin/mvt-autorun.py")


class DesktopResultsTests(unittest.TestCase):
    def setUp(self):
        self.log_patch = patch.object(autorun, "log")
        self.log_patch.start()
        self.addCleanup(self.log_patch.stop)

    def bus_fixture(self, temp_dir, uid=1234):
        bus_dir = Path(temp_dir) / "runtime"
        bus_dir.mkdir()
        socket_path = bus_dir / "bus"
        bus_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        bus_socket.bind(str(socket_path))
        self.addCleanup(bus_socket.close)
        bus = f"/run/user/{uid}/bus"
        real_stat = os.stat

        def mapped_stat(path, *args, **kwargs):
            if isinstance(path, (str, bytes, os.PathLike)) and os.fspath(path) == bus:
                path = socket_path
            return real_stat(path, *args, **kwargs)

        return bus, patch.object(autorun.os, "stat", side_effect=mapped_stat)

    def test_opens_resolved_folder_uri_with_own_session_bus(self):
        with tempfile.TemporaryDirectory(prefix="résultats ") as temp_dir:
            folder = Path(temp_dir) / "case résumé"
            folder.mkdir()
            expected_uri = folder.resolve().as_uri()
            uid = 1234
            bus, stat_patch = self.bus_fixture(temp_dir, uid)
            completed = subprocess.CompletedProcess(["gdbus"], 0, "", "")

            with (
                patch.object(autorun.os, "getuid", return_value=uid),
                stat_patch,
                patch.dict(
                    os.environ,
                    {
                        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/foreign/bus",
                        "XDG_RUNTIME_DIR": "/foreign/runtime",
                    },
                ),
                patch.object(autorun.subprocess, "run", return_value=completed) as run,
            ):
                self.assertTrue(autorun.open_results_folder(str(folder)))

            run.assert_called_once()
            args, kwargs = run.call_args
            command = args[0]
            self.assertEqual(
                command[:7],
                [
                    "gdbus",
                    "call",
                    "--session",
                    "--dest",
                    "org.freedesktop.FileManager1",
                    "--object-path",
                    "/org/freedesktop/FileManager1",
                ],
            )
            self.assertEqual(command[7], "--method")
            self.assertEqual(command[8], "org.freedesktop.FileManager1.ShowFolders")
            self.assertEqual(json.loads(command[9]), [expected_uri])
            self.assertEqual(command[10], "")
            self.assertNotIn(".apk", expected_uri.lower())
            self.assertIsInstance(command, list)
            self.assertNotIn("shell", kwargs)
            self.assertEqual(kwargs["timeout"], 10)
            self.assertFalse(kwargs["check"])
            self.assertTrue(kwargs["capture_output"])
            self.assertTrue(kwargs["text"])
            self.assertEqual(
                kwargs["env"]["DBUS_SESSION_BUS_ADDRESS"], f"unix:path={bus}"
            )
            self.assertEqual(kwargs["env"]["XDG_RUNTIME_DIR"], f"/run/user/{uid}")
            self.assertEqual(kwargs["env"]["PATH"], os.environ["PATH"])

    def test_missing_own_bus_skips_launch(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder = Path(temp_dir) / "results"
            folder.mkdir()
            bus, _stat_patch = self.bus_fixture(temp_dir, 4321)
            real_stat = os.stat

            def missing_bus_stat(path, *args, **kwargs):
                if (
                    isinstance(path, (str, bytes, os.PathLike))
                    and os.fspath(path) == bus
                ):
                    raise FileNotFoundError(bus)
                return real_stat(path, *args, **kwargs)

            with (
                patch.object(autorun.os, "getuid", return_value=4321),
                patch.object(autorun.os, "stat", side_effect=missing_bus_stat),
                patch.object(autorun.subprocess, "run") as run,
            ):
                self.assertFalse(autorun.open_results_folder(str(folder)))
            run.assert_not_called()

    def test_dbus_failure_returns_false(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder = Path(temp_dir) / "results"
            folder.mkdir()
            _bus, stat_patch = self.bus_fixture(temp_dir)
            completed = subprocess.CompletedProcess(["gdbus"], 1, "", "no file manager")
            with (
                patch.object(autorun.os, "getuid", return_value=1234),
                stat_patch,
                patch.object(autorun.subprocess, "run", return_value=completed),
            ):
                self.assertFalse(autorun.open_results_folder(str(folder)))

    def test_timeout_returns_false(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder = Path(temp_dir) / "results"
            folder.mkdir()
            _, stat_patch = self.bus_fixture(temp_dir)
            with (
                patch.object(autorun.os, "getuid", return_value=1234),
                stat_patch,
                patch.object(
                    autorun.subprocess,
                    "run",
                    side_effect=subprocess.TimeoutExpired("gdbus", 10),
                ),
            ):
                self.assertFalse(autorun.open_results_folder(str(folder)))

    def test_missing_gdbus_returns_false(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder = Path(temp_dir) / "results"
            folder.mkdir()
            _, stat_patch = self.bus_fixture(temp_dir)
            with (
                patch.object(autorun.os, "getuid", return_value=1234),
                stat_patch,
                patch.object(
                    autorun.subprocess, "run", side_effect=FileNotFoundError("gdbus")
                ),
            ):
                self.assertFalse(autorun.open_results_folder(str(folder)))

    def test_missing_folder_returns_false_without_launch(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder = Path(temp_dir) / "does not exist"
            _, stat_patch = self.bus_fixture(temp_dir)
            with (
                patch.object(autorun.os, "getuid", return_value=1234),
                stat_patch,
                patch.object(autorun.subprocess, "run") as run,
            ):
                self.assertFalse(autorun.open_results_folder(str(folder)))
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
