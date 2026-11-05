import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
SPEC = importlib.util.spec_from_file_location(
    "mvt_autorun", ROOT / "bin" / "mvt-autorun.py"
)
autorun = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(autorun)


class AutorunTests(unittest.TestCase):
    def setUp(self):
        log = patch.object(autorun, "log")
        log.start()
        self.addCleanup(log.stop)
        toast = patch.object(autorun, "send_toast")
        toast.start()
        self.addCleanup(toast.stop)

    def test_device_selection_includes_only_authorized_devices(self):
        result = autorun.subprocess.CompletedProcess(
            ["adb", "devices"],
            0,
            "List of devices attached\nauthorized\tdevice\nwaiting\tunauthorized\noffline\toffline\n",
            "",
        )
        with patch.object(autorun.subprocess, "run", return_value=result):
            self.assertEqual(autorun.get_connected_devices(), ["authorized"])

    def test_rate_limit_uses_current_date_and_force_bypasses(self):
        class FrozenDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                value = datetime(2025, 2, 3, 12, 0, tzinfo=timezone.utc)
                return value.astimezone(tz) if tz else value

        with (
            patch.object(autorun, "datetime", FrozenDateTime),
            patch.object(
                autorun, "read_device_file", return_value="2025-02-03T01:02:03Z"
            ),
        ):
            self.assertFalse(autorun.check_rate_limit("device"))
        with (
            patch.object(autorun, "datetime", FrozenDateTime),
            patch.object(
                autorun, "read_device_file", return_value="2025-02-02T23:59:59Z"
            ),
        ):
            self.assertTrue(autorun.check_rate_limit("device"))

    def test_force_reads_and_shows_existing_scan_record(self):
        with (
            patch.object(
                autorun,
                "datetime",
                type(
                    "FrozenDateTime",
                    (datetime,),
                    {
                        "now": classmethod(
                            lambda cls, tz=None: datetime(
                                2025, 2, 3, 12, tzinfo=timezone.utc
                            )
                        )
                    },
                ),
            ),
            patch.object(
                autorun, "read_device_file", return_value="2025-02-03T01:02:03Z"
            ) as read,
            patch.object(autorun, "send_toast") as toast,
        ):
            self.assertTrue(autorun.check_rate_limit("device", force=True))
        read.assert_called_once()
        self.assertIn("2025-02-03 01:02:03 GMT", toast.call_args.args[1])

    def test_schedule_due_at_utc_calendar_midnight(self):
        last, due = autorun.scan_schedule(
            "2025-02-02T23:59:59Z", datetime(2025, 2, 3, 0, tzinfo=timezone.utc)
        )
        self.assertEqual(last, datetime(2025, 2, 2, 23, 59, 59, tzinfo=timezone.utc))
        self.assertEqual(due, datetime(2025, 2, 3, 0, tzinfo=timezone.utc))

    def test_schedule_offsets_and_utc_date_boundary(self):
        last, due = autorun.scan_schedule(
            "2025-02-03T00:30:00+02:00", datetime(2025, 2, 2, 23, tzinfo=timezone.utc)
        )
        self.assertEqual(last, datetime(2025, 2, 2, 22, 30, tzinfo=timezone.utc))
        self.assertEqual(due, datetime(2025, 2, 3, 0, tzinfo=timezone.utc))

    def test_legacy_naive_record_uses_host_local_timezone(self):
        old_tz = os.environ.get("TZ")
        try:
            os.environ["TZ"] = "Etc/GMT+5"
            if hasattr(time, "tzset"):
                time.tzset()
            last, _ = autorun.scan_schedule(
                "2025-02-03 01:02:03",
                datetime(2025, 2, 3, 12, tzinfo=timezone.utc),
            )
            self.assertEqual(last, datetime(2025, 2, 3, 6, 2, 3, tzinfo=timezone.utc))
        finally:
            if old_tz is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = old_tz
            if hasattr(time, "tzset"):
                time.tzset()

    def test_missing_and_malformed_records_are_due_at_current_midnight(self):
        now = datetime(2025, 2, 3, 12, tzinfo=timezone.utc)
        expected = datetime(2025, 2, 3, 0, tzinfo=timezone.utc)
        for token in (
            "",
            "not-a-timestamp",
            "2025-02-03",
            "9999-12-31T23:59:59Z",
            "0001-01-01T00:00:00+14:00",
        ):
            with self.subTest(token=token):
                last, due = autorun.scan_schedule(token, now)
                self.assertIsNone(last)
                self.assertEqual(due, expected)

    def test_future_timestamp_is_aware_utc_and_not_due(self):
        now = datetime(2025, 2, 3, 12, tzinfo=timezone.utc)
        last, due = autorun.scan_schedule("2025-02-04T01:00:00+03:00", now)
        self.assertEqual(last.tzinfo, timezone.utc)
        self.assertEqual(last, datetime(2025, 2, 3, 22, tzinfo=timezone.utc))
        self.assertFalse(now >= due)

    def test_not_due_notice_contains_device_and_both_gmt_times(self):
        now = datetime(2025, 2, 3, 12, tzinfo=timezone.utc)

        class FrozenDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                return now.astimezone(tz) if tz else now

        with (
            patch.object(autorun, "datetime", FrozenDateTime),
            patch.object(
                autorun, "read_device_file", return_value="2025-02-03T08:00:00Z"
            ),
            patch.object(autorun, "send_toast") as toast,
        ):
            self.assertFalse(autorun.check_rate_limit("serial-1"))
        title, message = toast.call_args.args[:2]
        self.assertIn("Not due", title)
        self.assertIn("serial-1", message)
        self.assertIn("2025-02-03 08:00:00 GMT", message)
        self.assertIn("2025-02-04 00:00:00 GMT", message)

    def test_missing_rate_limit_token_allows_scan(self):
        with patch.object(autorun, "read_device_file", return_value=""):
            self.assertTrue(autorun.check_rate_limit("device"))

    def test_package_enrichment_missing_file_is_noop(self):
        with tempfile.TemporaryDirectory() as temp:
            autorun.enrich_packages_json(temp, {})
            self.assertEqual(os.listdir(temp), [])

    def test_package_enrichment_adds_hash_and_certificate_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            apk_dir = Path(temp) / "apks"
            apk_dir.mkdir()
            (apk_dir / "sample.apk").write_bytes(b"fixture")
            packages_file = Path(temp) / "packages.json"
            packages_file.write_text(
                json.dumps(
                    [
                        {"name": "sample", "files": [{"path": "/device/sample.apk"}]},
                        {"name": "other"},
                    ]
                )
            )
            signer_output = (
                "Signer #1 certificate MD5 digest: md5\nSigner #1 certificate SHA-1 digest: sha1\nSigner #1 certificate SHA-256 digest: "
                + "c" * 64
                + "\n"
            )
            completed = autorun.subprocess.CompletedProcess(
                ["apksigner"], 0, signer_output, ""
            )
            digest = hashlib.sha256(b"fixture").hexdigest()
            real_run = autorun.subprocess.run
            with patch.object(
                autorun.subprocess,
                "run",
                side_effect=lambda cmd, **kwargs: (
                    completed if cmd[0] == "apksigner" else real_run(cmd, **kwargs)
                ),
            ) as run:
                autorun.enrich_packages_json(
                    temp,
                    {"sample": {"sha256": digest, "apk_path": "/device/sample.apk"}},
                )
            packages = json.loads(packages_file.read_text())
            self.assertEqual(packages[0]["files"][0]["sha256"], digest)
            self.assertEqual(
                packages[0]["files"][0]["certificate"],
                {"Md5": "md5", "Sha1": "sha1", "Sha256": "c" * 64},
            )
            self.assertNotIn("sha256", packages[1])
            self.assertEqual(
                sum(call.args[0][0] == "apksigner" for call in run.call_args_list), 1
            )

    def test_package_enrichment_missing_collected_apk_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            Path(temp, "packages.json").write_text(json.dumps([{"name": "sample"}]))
            with self.assertRaises(RuntimeError):
                autorun.enrich_packages_json(
                    temp,
                    {"sample": {"sha256": "a" * 64, "apk_path": "/device/sample.apk"}},
                )
            self.assertNotIn(
                "files", json.loads(Path(temp, "packages.json").read_text())[0]
            )


if __name__ == "__main__":
    unittest.main()
