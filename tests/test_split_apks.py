"""Split APK identities survive inventory, caching, enrichment and attribution."""

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
SPEC = importlib.util.spec_from_file_location(
    "split_autorun", ROOT / "bin/mvt-autorun.py"
)
pipeline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pipeline)


class SplitApkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run = self.root / "run"
        self.raw = self.run / "raw"
        self.apks = self.raw / "apks"
        self.apks.mkdir(parents=True)
        (self.run / "analysis").mkdir()
        self.package = "org.example.app"
        self.payloads = {
            "/data/app/odd== directory/base.apk": b"base APK fixture",
            "/data/app/odd== directory/split_config.en.apk": b"different split APK fixture",
        }
        self.files = [
            {
                "path": path,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
            for path, payload in self.payloads.items()
        ]
        self.current = {
            self.package: {
                "sha256": self.files[0]["sha256"],
                "apk_path": self.files[0]["path"],
                "files": self.files,
            }
        }
        for active in (
            patch.object(pipeline, "log"),
            patch.object(pipeline, "CACHE_DIR", str(self.root / "cache")),
            patch.dict(os.environ, {"MVT_HASH_BIN": str(ROOT / "bin/mvt-hash")}),
        ):
            active.start()
            self.addCleanup(active.stop)

    def adb(self, args, **kwargs):
        self.assertEqual(args[0], "pull")
        Path(args[2]).write_bytes(self.payloads[args[1]])
        return subprocess.CompletedProcess(args, 0, "", "")

    def acquire(self, baseline="", current=None):
        with (
            patch.object(pipeline, "read_device_file", return_value=baseline),
            patch.object(pipeline, "run_adb", side_effect=self.adb),
        ):
            return pipeline.compare_and_sync_packages(
                "serial", current or self.current, str(self.apks)
            )

    def baseline(self):
        return "\n".join(
            f"{self.package}\t{item['sha256']}\t{item['path']}" for item in self.files
        )

    def flagged(self, event, matched_indicator=None):
        alerts = [
            {
                "level": "HIGH",
                "module": "aqf_packages",
                "event": event,
                "matched_indicator": matched_indicator,
            }
        ]
        (self.run / "analysis/alerts.json").write_text(json.dumps(alerts))
        _, count = pipeline.prepare_flagged_apks(
            str(self.run), self.current, {"HIGH": 1}
        )
        report = json.loads((self.run / "flagged_apks/findings.json").read_text())
        return count, report

    def test_inventory_lists_packages_and_all_paths_with_checked_hash_and_stat(self):
        rows = "\n".join(
            f"{self.package}\t{item['sha256']}\t{item['path']}\t{item['size']}"
            for item in self.files
        )
        with patch.object(
            pipeline,
            "run_adb",
            return_value=subprocess.CompletedProcess([], 0, rows, ""),
        ) as adb:
            current = pipeline.get_device_pkg_hashes("serial")
        script = adb.call_args.kwargs["input_data"]
        self.assertIn("pm list packages -3)", script)
        self.assertIn('pm path "$pkg") || exit 1', script)
        self.assertIn('sha256sum "$apk") || exit 1', script)
        self.assertIn('stat -c %s "$apk") || exit 1', script)
        self.assertEqual(current[self.package]["apk_path"], self.files[0]["path"])
        self.assertEqual(len(current[self.package]["files"]), 2)
        self.assertEqual(
            current[self.package]["files"][0]["local_name"], self.package + ".apk"
        )

    def test_malformed_or_duplicate_file_inventory_fails_closed(self):
        row = f"{self.package}\t{'a' * 64}\t/base.apk\t4"
        for rows in (
            row + "\n" + row,
            row.replace("\t4", "\t-1"),
            row.replace("\t4", "\tnot-size"),
            row.replace("/base.apk", "relative.apk"),
            row.replace("a" * 64, "bad"),
        ):
            with (
                self.subTest(rows=rows),
                patch.object(
                    pipeline,
                    "run_adb",
                    return_value=subprocess.CompletedProcess([], 0, rows, ""),
                ),
                self.assertRaises(RuntimeError),
            ):
                pipeline.get_device_pkg_hashes("serial")

    def test_nonzero_device_inventory_rejects_even_valid_partial_output(self):
        with (
            patch.object(
                pipeline,
                "run_adb",
                return_value=subprocess.CompletedProcess(
                    [], 1, f"{self.package}\t{'a' * 64}\t/base.apk\t4", "stat failed"
                ),
            ),
            self.assertRaises(RuntimeError),
        ):
            pipeline.get_device_pkg_hashes("serial")

    def test_all_files_are_independent_verified_cache_copies_and_reused(self):
        self.assertEqual(self.acquire(), (1, 0, 0))
        files = self.current[self.package]["files"]
        cache = Path(pipeline.CACHE_DIR)
        self.assertEqual(len(list(cache.glob("*.apk"))), 2)
        for item in files:
            raw = self.apks / item["local_name"]
            cached = cache / (item["local_name"][:-4] + "_" + item["sha256"] + ".apk")
            self.assertEqual(raw.read_bytes(), self.payloads[item["path"]])
            self.assertNotEqual(raw.stat().st_ino, cached.stat().st_ino)
            raw.unlink()
        with (
            patch.object(pipeline, "read_device_file", return_value=self.baseline()),
            patch.object(pipeline, "run_adb") as adb,
        ):
            self.assertEqual(
                pipeline.compare_and_sync_packages(
                    "serial", self.current, str(self.apks)
                ),
                (0, 0, 1),
            )
        adb.assert_not_called()

    def test_split_changes_additions_and_removals_mark_package_modified(self):
        baseline = self.baseline()
        self.assertEqual(self.acquire(baseline), (0, 0, 1))
        split = self.current[self.package]["files"][1]
        self.payloads[split["path"]] = b"modified split"
        split["sha256"] = hashlib.sha256(b"modified split").hexdigest()
        split["size"] = len(b"modified split")
        self.assertEqual(self.acquire(baseline), (0, 1, 0))
        self.current[self.package]["files"] = [self.current[self.package]["files"][0]]
        self.assertEqual(self.acquire(baseline), (0, 1, 0))
        self.assertEqual(
            self.acquire(
                f"{self.package}\t{self.files[0]['sha256']}\t{self.files[0]['path']}"
            ),
            (0, 0, 1),
        )
        self.current[self.package]["files"].append(split)
        self.assertEqual(
            self.acquire(
                f"{self.package}\t{self.files[0]['sha256']}\t{self.files[0]['path']}"
            ),
            (0, 1, 0),
        )

    def test_legacy_flat_inventory_and_three_column_baseline_remain_readable(self):
        current = {
            self.package: {
                "sha256": self.files[0]["sha256"],
                "apk_path": self.files[0]["path"],
            }
        }
        baseline = f"{self.package}\t{self.files[0]['sha256']}\t{self.files[0]['path']}"
        self.assertEqual(self.acquire(baseline, current), (0, 0, 1))
        self.assertEqual(len(current[self.package]["files"]), 1)
        self.assertEqual(
            (self.apks / (self.package + ".apk")).read_bytes(),
            self.payloads[self.files[0]["path"]],
        )

    def test_local_names_are_bounded_safe_deterministic_and_unique(self):
        package = "org." + "long" * 100
        info = {
            **self.current[self.package],
            "files": [dict(item) for item in self.files],
        }
        info["files"][1]["path"] = "/remote/../../unsafe name='\\" + "x" * 500 + ".apk"
        names = [item["local_name"] for item in pipeline._package_files(package, info)]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(
            names,
            [item["local_name"] for item in pipeline._package_files(package, info)],
        )
        for name in names:
            self.assertEqual(Path(name).name, name)
            self.assertLess(len(name.encode()) + 65, 255)
            self.assertNotIn("unsafe", name)

    def test_size_mismatch_does_not_publish_file_or_cache(self):
        self.current[self.package]["files"][0]["size"] += 1
        with self.assertRaises(RuntimeError):
            self.acquire()
        self.assertFalse(list(Path(pipeline.CACHE_DIR).glob("*.apk")))
        self.assertFalse(list(self.apks.glob("*.apk")))

    def test_enrichment_hashes_and_certifies_each_actual_apk_without_base_overwrite(
        self,
    ):
        self.acquire()
        entries = [{"path": item["path"]} for item in self.files] + [
            {"path": "/unknown/split.apk"}
        ]
        (self.raw / "packages.json").write_text(
            json.dumps([{"name": self.package, "files": entries}])
        )
        signer_paths = []
        real_run = subprocess.run

        def signer(cmd, **kwargs):
            if cmd[0] != "apksigner":
                return real_run(cmd, **kwargs)
            signer_paths.append(cmd[-1])
            cert = hashlib.sha256(Path(cmd[-1]).read_bytes()).hexdigest()
            return subprocess.CompletedProcess(
                cmd, 0, "Signer #1 certificate SHA-256 digest: " + cert, ""
            )

        with patch.object(pipeline.subprocess, "run", side_effect=signer):
            pipeline.enrich_packages_json(str(self.raw), self.current)
        enriched = json.loads((self.raw / "packages.json").read_text())[0]["files"]
        self.assertEqual(len(signer_paths), 2)
        for actual, expected in zip(enriched[:2], self.files):
            self.assertEqual(actual["sha256"], expected["sha256"])
            self.assertEqual(actual["certificate"]["Sha256"], expected["sha256"])
        self.assertEqual(enriched[2], {"path": "/unknown/split.apk"})
        self.assertNotEqual(enriched[0]["sha256"], enriched[1]["sha256"])

    def test_package_and_certificate_findings_collect_all_package_files(self):
        self.acquire()
        for indicator in (
            {"type": "package", "value": self.package},
            {"type": "certificate", "value": "c" * 64},
        ):
            with self.subTest(indicator=indicator):
                count, report = self.flagged(
                    {"name": self.package, "files": self.files}, indicator
                )
                self.assertEqual(count, 2)
                self.assertEqual(
                    {item["path"] for item in report["apks"]}, set(self.payloads)
                )

    def test_exact_split_hash_overrides_enclosing_package_and_full_file_list(self):
        self.acquire()
        split = self.files[1]
        count, report = self.flagged(
            {"name": self.package, "files": self.files}, {"sha256": split["sha256"]}
        )
        self.assertEqual(count, 1)
        self.assertEqual(report["apks"][0]["path"], split["path"])
        self.assertEqual(
            (self.run / "flagged_apks" / report["apks"][0]["filename"]).read_bytes(),
            self.payloads[split["path"]],
        )

    def test_exact_file_path_selects_only_split(self):
        self.acquire()
        count, report = self.flagged({"path": self.files[1]["path"]})
        self.assertEqual(count, 1)
        self.assertEqual(report["apks"][0]["sha256"], self.files[1]["sha256"])

    def test_cli_dispatch_preserves_peer_argument_contracts(self):
        for args, module, expected in (
            (["doctor", "--json"], pipeline.mvt_doctor, ["--json"]),
            (["verify", "case"], pipeline.mvt_evidence, ["verify", "case"]),
            (["prune", "--apply"], pipeline.mvt_evidence, ["prune", "--apply"]),
        ):
            with (
                self.subTest(args=args),
                patch.object(sys, "argv", ["mvt-autorun", *args]),
                patch.object(module, "main", return_value=7) as helper,
            ):
                self.assertEqual(pipeline.main(), 7)
                helper.assert_called_once_with(expected)


if __name__ == "__main__":
    unittest.main()
