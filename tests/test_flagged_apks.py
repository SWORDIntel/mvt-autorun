"""Offline tests for preserving APKs tied to high-severity MVT findings."""

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
SPEC = importlib.util.spec_from_file_location(
    "mvt_autorun_flagged_apks", ROOT / "bin" / "mvt-autorun.py"
)
pipeline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pipeline)


class FlaggedApkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        native = patch.dict(
            os.environ, {"MVT_HASH_BIN": str(ROOT / "bin" / "mvt-hash")}
        )
        native.start()
        self.addCleanup(native.stop)
        self.run_dir = self.root / "run"
        self.raw = self.run_dir / "raw"
        self.raw.mkdir(parents=True)
        self.analysis = self.run_dir / "analysis"
        self.analysis.mkdir()
        self.output = self.run_dir / "flagged_apks"
        self.payloads = {
            "com.example.alpha": b"alpha apk fixture",
            "com.example.beta": b"beta apk fixture",
            "com.example.other": b"unrelated apk fixture",
        }
        self.hashes = {}
        for package, payload in self.payloads.items():
            path = self.raw / "apks" / f"{package}.apk"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            self.hashes[package] = {
                "sha256": hashlib.sha256(payload).hexdigest(),
                "apk_path": f"/data/app/{package}/base.apk",
            }
        self.alert_counts = {"HIGH": 0, "CRITICAL": 0, "MEDIUM": 0, "LOW": 0}
        self.log_patch = patch.object(pipeline, "log")
        self.log_patch.start()
        self.addCleanup(self.log_patch.stop)

    def alert(self, level="HIGH", **values):
        event = values.pop("event", {})
        alert = {
            "level": level,
            "module": "aqf_packages",
            "message": "finding text is not an attribution source",
            "event": event,
            "matched_indicator": None,
        }
        alert.update(values)
        return alert

    def write_alerts(self, alerts):
        (self.analysis / "alerts.json").write_text(json.dumps(alerts), encoding="utf-8")

    def run_prepare(self):
        return pipeline.prepare_flagged_apks(
            str(self.run_dir), self.hashes, self.alert_counts
        )

    def manifest(self):
        return json.loads((self.output / "findings.json").read_text(encoding="utf-8"))

    def test_package_hash_and_inventory_path_match_copy_once_and_trace_finding(self):
        self.write_alerts(
            [
                self.alert(event={"name": "com.example.alpha"}),
                self.alert(
                    event={
                        "files": [
                            {"sha256": self.hashes["com.example.alpha"]["sha256"]}
                        ]
                    }
                ),
                self.alert(
                    event={
                        "files": [{"path": self.hashes["com.example.beta"]["apk_path"]}]
                    }
                ),
            ]
        )
        folder, count = self.run_prepare()
        manifest = self.manifest()
        self.assertEqual(Path(folder), self.output)
        self.assertEqual(count, 2)
        self.assertEqual(
            {apk["package"] for apk in manifest["apks"]},
            set(self.hashes) - {"com.example.other"},
        )
        self.assertEqual(len(manifest["apks"]), 2)
        self.assertEqual(len(manifest["findings"]), 3)
        for apk in manifest["apks"]:
            copied = self.output / apk["filename"]
            self.assertTrue(copied.is_file())
            self.assertFalse(copied.is_symlink())
            self.assertEqual(
                hashlib.sha256(copied.read_bytes()).hexdigest(), apk["sha256"]
            )
            self.assertTrue(apk["findings"])

    def test_positive_non_apk_finding_is_reported_without_attribution(self):
        self.write_alerts([self.alert(event={"name": "com.example.not-installed"})])
        _, count = self.run_prepare()
        manifest = self.manifest()
        self.assertEqual(count, 0)
        self.assertEqual(manifest["apks"], [])
        self.assertTrue(manifest["unmatched"])

    def test_multi_block_apk_is_copied_and_verified(self):
        payload = b"APK chunk fixture" * 150000
        package = "com.example.alpha"
        (self.raw / "apks" / f"{package}.apk").write_bytes(payload)
        self.hashes[package]["sha256"] = hashlib.sha256(payload).hexdigest()
        self.write_alerts([self.alert(event={"name": package})])
        _, count = self.run_prepare()
        self.assertEqual(count, 1)
        self.assertEqual((self.output / f"{package}.apk").read_bytes(), payload)

    def test_unknown_alert_level_is_reported_without_attributing_an_apk(self):
        self.write_alerts([self.alert("UNKNOWN", event={"name": "com.example.alpha"})])
        _, count = self.run_prepare()
        self.assertEqual(count, 0)
        self.assertFalse(self.manifest()["findings"])
        self.assertTrue(self.manifest()["warnings"])

    def test_unknown_system_package_does_not_copy_unrelated_apks(self):
        self.write_alerts([self.alert(event={"name": "android.system.unknown"})])
        _, count = self.run_prepare()
        self.assertEqual(count, 0)
        self.assertEqual(self.manifest()["apks"], [])
        self.assertFalse(self.output.exists() and list(self.output.glob("*.apk")))

    def test_medium_low_and_informational_findings_are_ignored(self):
        self.write_alerts(
            [
                self.alert(level=level, event={"name": "com.example.alpha"})
                for level in ("MEDIUM", "LOW", "INFORMATIONAL")
            ]
        )
        _, count = self.run_prepare()
        self.assertEqual(count, 0)
        self.assertEqual(self.manifest()["findings"], [])

    def test_aggregate_alerts_take_precedence_over_fallback_files(self):
        self.write_alerts([self.alert(event={"name": "com.example.alpha"})])
        (self.analysis / "other_detected.json").write_text(
            json.dumps([self.alert(event={"name": "com.example.beta"})]),
            encoding="utf-8",
        )
        _, count = self.run_prepare()
        self.assertEqual(count, 1)
        self.assertEqual(
            [apk["package"] for apk in self.manifest()["apks"]], ["com.example.alpha"]
        )

    def test_fallback_detected_files_are_used_when_aggregate_is_absent(self):
        (self.analysis / "packages_detected.json").write_text(
            json.dumps([self.alert("CRITICAL", event={"name": "com.example.beta"})]),
            encoding="utf-8",
        )
        _, count = self.run_prepare()
        self.assertEqual(count, 1)
        self.assertEqual(self.manifest()["apks"][0]["package"], "com.example.beta")

    def test_missing_or_malformed_alert_data_warns_without_inventing_attribution(self):
        cases = (None, "{not json", {"unexpected": "shape"})
        for index, value in enumerate(cases):
            with self.subTest(value=value):
                if value is None:
                    (self.analysis / "alerts.json").unlink(missing_ok=True)
                else:
                    (self.analysis / "alerts.json").write_text(
                        value if isinstance(value, str) else json.dumps(value),
                        encoding="utf-8",
                    )
                folder, count = self.run_prepare()
                manifest = self.manifest()
                self.assertEqual(folder, str(self.output))
                self.assertEqual(count, 0)
                self.assertEqual(manifest["apks"], [])
                self.assertTrue(manifest["warnings"])
                if index < 2:
                    (self.analysis / "alerts.json").unlink(missing_ok=True)

    def test_hash_mismatch_is_fatal_before_any_apk_is_published(self):
        self.write_alerts([self.alert(event={"name": "com.example.alpha"})])
        source = self.raw / "apks" / "com.example.alpha.apk"
        source.write_bytes(b"changed bytes")
        with self.assertRaises(RuntimeError):
            self.run_prepare()
        self.assertEqual(source.read_bytes(), b"changed bytes")
        self.assertFalse(list(self.output.glob("*.apk")))

    def test_symlink_source_is_fatal_without_touching_target_or_publishing(self):
        self.write_alerts([self.alert(event={"name": "com.example.beta"})])
        beta_path = self.raw / "apks" / "com.example.beta.apk"
        beta_path.unlink()
        target = self.root / "outside.apk"
        target.write_bytes(b"outside secret")
        beta_path.symlink_to(target)
        with self.assertRaises(RuntimeError):
            self.run_prepare()
        self.assertTrue(beta_path.is_symlink())
        self.assertEqual(target.read_bytes(), b"outside secret")
        self.assertFalse(list(self.output.glob("*.apk")))

    def test_fifo_source_is_rejected_without_blocking_or_publishing(self):
        self.write_alerts([self.alert(event={"name": "com.example.alpha"})])
        source = self.raw / "apks" / "com.example.alpha.apk"
        source.unlink()
        os.mkfifo(source)
        real_open = os.open

        def checked_open(path, flags, *args, **kwargs):
            self.assertTrue(flags & os.O_NONBLOCK)
            return real_open(path, flags, *args, **kwargs)

        with (
            patch.object(pipeline.os, "open", side_effect=checked_open),
            self.assertRaises(RuntimeError),
        ):
            self.run_prepare()
        self.assertTrue(source.exists())
        self.assertFalse(list(self.output.glob("*.apk")))

    def test_failed_preservation_retains_prior_verified_copies_and_raw_evidence(self):
        self.write_alerts(
            [
                self.alert(event={"name": "com.example.alpha"}),
                self.alert(event={"name": "com.example.beta"}),
            ]
        )
        source = self.raw / "apks" / "com.example.beta.apk"
        source.write_bytes(b"changed bytes")
        with self.assertRaises(RuntimeError):
            self.run_prepare()
        self.assertEqual(
            (self.output / "com.example.alpha.apk").read_bytes(),
            self.payloads["com.example.alpha"],
        )
        self.assertFalse((self.output / "com.example.beta.apk").exists())
        self.assertEqual(source.read_bytes(), b"changed bytes")
        self.assertFalse(list(self.output.glob(".com.example.*")))

    def test_duplicate_known_hash_matches_all_packages(self):
        duplicate = "com.example.duplicate"
        source = self.raw / "apks" / f"{duplicate}.apk"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(self.payloads["com.example.alpha"])
        self.hashes[duplicate] = {
            "sha256": self.hashes["com.example.alpha"]["sha256"],
            "apk_path": f"/data/app/{duplicate}/base.apk",
        }
        self.write_alerts(
            [
                self.alert(
                    event={
                        "files": [
                            {"sha256": self.hashes["com.example.alpha"]["sha256"]}
                        ]
                    }
                )
            ]
        )
        _, count = self.run_prepare()
        self.assertEqual(count, 2)
        self.assertEqual(
            {apk["package"] for apk in self.manifest()["apks"]},
            {"com.example.alpha", duplicate},
        )

    def test_malicious_alert_paths_never_read_or_copy_outside_files(self):
        secret = self.root / "secret.apk"
        secret.write_bytes(b"do not copy")
        self.write_alerts(
            [
                self.alert(
                    event={
                        "files": [{"path": str(secret)}, {"path": "../../secret.apk"}]
                    }
                )
            ]
        )
        _, count = self.run_prepare()
        self.assertEqual(count, 0)
        self.assertEqual(self.manifest()["apks"], [])
        self.assertTrue(self.manifest()["unmatched"])
        self.assertEqual(secret.read_bytes(), b"do not copy")
        self.assertFalse(
            any(path.read_bytes() == b"do not copy" for path in self.output.glob("*"))
        )


if __name__ == "__main__":
    unittest.main()
