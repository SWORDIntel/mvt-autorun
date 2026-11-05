import importlib.util
import subprocess
import sys
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


autorun = load_module("notification_autorun", "bin/mvt-autorun.py")
watcher = load_module("notification_watcher", "bin/adb-device-watcher.py")


class NotificationTests(unittest.TestCase):
    def assert_notification_command(self, module, urgency):
        bus = "/run/user/1000/bus"
        username = subprocess.CompletedProcess(["id"], 0, "tester\n", "")
        with (
            patch.object(module.glob, "glob", return_value=[bus]),
            patch.object(module.os, "getuid", return_value=1000),
            patch.object(module.subprocess, "run", return_value=username) as run,
        ):
            module.send_toast("Title", "Message", urgency=urgency)
        calls = run.call_args_list
        notify = [call for call in calls if call.args[0][0] == "notify-send"]
        self.assertEqual(len(notify), 1)
        command = notify[0].args[0]
        self.assertEqual(command[1:5], ["-t", "3000", "-u", "normal"])
        self.assertEqual(command[-2:], ["Title", "Message"])
        self.assertNotIn("resident", command)

    def test_pipeline_notification_is_short_lived_normal_urgency(self):
        self.assert_notification_command(autorun, "critical")

    def test_watcher_notification_is_short_lived_normal_urgency(self):
        self.assert_notification_command(watcher, "critical")


if __name__ == "__main__":
    unittest.main()
