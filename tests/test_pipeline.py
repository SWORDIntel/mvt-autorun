"""Offline regression tests for the transactional MVT pipeline."""

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
SPEC = importlib.util.spec_from_file_location(
    "mvt_autorun_pipeline", ROOT / "bin" / "mvt-autorun.py"
)
pipeline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pipeline)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
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
        tools = self.root / "tools"
        tools.mkdir()
        for name in ("adb", "apksigner", "androidqf", "mvt-android"):
            executable = tools / name
            executable.write_text("#!/bin/sh\nexit 0\n")
            executable.chmod(0o700)
        self.patches = [
            patch.dict(
                os.environ,
                {
                    "MVT_HASH_BIN": str(ROOT / "bin" / "mvt-hash"),
                    "PATH": str(tools) + os.pathsep + os.environ.get("PATH", ""),
                },
            ),
            patch.object(pipeline, "MVT_ROOT", str(self.root)),
            patch.object(pipeline, "INDICATORS_DIR", str(indicators)),
            patch.object(pipeline, "AQF_BIN", str(tools / "androidqf")),
            patch.object(pipeline, "MVT_BIN", str(tools / "mvt-android")),
            patch.object(pipeline, "log"),
            patch.object(pipeline, "send_toast"),
        ]
        for active in self.patches:
            active.start()
            self.addCleanup(active.stop)

    def configure_paths(self, root=None):
        root = self.root if root is None else root
        paths = {
            "OUTPUT_ROOT": root / "output",
            "RUNS_DIR": root / "output" / "runs",
            "LATEST_LINK": root / "output" / "latest",
            "LOCK_DIR": root / "locks",
            "CACHE_DIR": root / "cache",
            "INCIDENTS_DIR": root / "incidents",
            "LOG_FILE": root / "pipeline.log",
        }
        for name, value in paths.items():
            if hasattr(pipeline, name):
                active = patch.object(pipeline, name, str(value))
                active.start()
                self.addCleanup(active.stop)
        return paths

    def test_external_tool_failures_propagate_and_retain_logs(self):
        for helper, args, log_path in (
            (
                pipeline.run_androidqf,
                ("serial", str(self.root / "raw")),
                self.root / "raw" / "androidqf_run.log",
            ),
            (
                pipeline.run_mvt_analysis,
                (str(self.root / "raw"), str(self.root / "analysis")),
                self.root / "analysis" / "mvt_run.log",
            ),
        ):

            def failed_run(cmd, **kwargs):
                kwargs["stdout"].write("partial tool output")
                return subprocess.CompletedProcess(cmd, 7)

            with (
                self.subTest(helper=helper.__name__),
                patch.object(pipeline.subprocess, "run", side_effect=failed_run),
            ):
                with self.assertRaises(RuntimeError):
                    helper(*args)
                self.assertTrue(log_path.is_file())
                self.assertIn("partial tool output", log_path.read_text())

    def test_tool_timeouts_propagate_and_keep_partial_output(self):
        failure = subprocess.TimeoutExpired(
            ["tool"], 1, output=b"partial timeout output"
        )
        with (
            patch.object(pipeline.subprocess, "run", side_effect=failure),
            self.assertRaises(RuntimeError),
        ):
            pipeline.run_androidqf("serial", str(self.root / "raw"))
        self.assertIn(
            "partial timeout output",
            (self.root / "raw" / "androidqf_run.log").read_text(),
        )

    def test_mvt_summary_requires_all_five_valid_levels_and_counts_high(self):
        summaries = "MVT produced 1 INFORMATIONAL alerts.\nMVT produced 2 LOW alerts.\nMVT produced 3 MEDIUM alerts.\nMVT produced 4 HIGH alerts.\nMVT produced 5 CRITICAL alerts.\n"
        expected = {"INFORMATIONAL": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}

        def successful_run(cmd, **kwargs):
            kwargs["stdout"].write(summaries)
            return subprocess.CompletedProcess(cmd, 0)

        with patch.object(pipeline.subprocess, "run", side_effect=successful_run):
            self.assertEqual(
                pipeline.run_mvt_analysis("raw", str(self.root / "analysis")), expected
            )
        invalid = (
            summaries.replace("MVT produced 1 INFORMATIONAL alerts.\n", ""),
            summaries.replace(
                "MVT produced 1 INFORMATIONAL alerts.",
                "MVT produced many INFORMATIONAL alerts.",
            ),
            summaries.replace(
                "MVT produced 1 INFORMATIONAL alerts.",
                "MVT produced -1 INFORMATIONAL alerts.",
            ),
            summaries.replace(
                "MVT produced 1 INFORMATIONAL alerts.",
                "MVT produced 1 INFORMATIONAL alerts.\nMVT produced 1 INFORMATIONAL alerts.",
            ),
        )
        for output in invalid:

            def run_with_output(cmd, output=output, **kwargs):
                kwargs["stdout"].write(output)
                return subprocess.CompletedProcess(cmd, 0)

            with (
                self.subTest(output=output[:60]),
                patch.object(pipeline.subprocess, "run", side_effect=run_with_output),
                self.assertRaises((ValueError, RuntimeError)),
            ):
                pipeline.run_mvt_analysis("raw", str(self.root / "bad-analysis"))

    def test_malformed_device_inventory_is_rejected(self):
        for inventory in (
            "bad-row",
            "pkg\tnot-a-hash\t/device/app.apk",
            "pkg\t" + "a" * 64 + "\trelative.apk",
        ):
            with (
                self.subTest(inventory=inventory),
                patch.object(
                    pipeline,
                    "run_adb",
                    return_value=subprocess.CompletedProcess(["adb"], 0, inventory, ""),
                ),
                self.assertRaises(RuntimeError),
            ):
                pipeline.get_device_pkg_hashes("serial")

    def test_device_state_missing_token_is_distinct_from_transport_failure(self):
        missing = subprocess.CompletedProcess(
            ["adb"], 1, "", "cat: No such file or directory"
        )
        with patch.object(pipeline, "run_adb", return_value=missing):
            self.assertEqual(pipeline.read_device_file("serial", "/state"), "")
        failed = subprocess.CompletedProcess(["adb"], 1, "", "device offline")
        with (
            patch.object(pipeline, "run_adb", return_value=failed),
            self.assertRaises(RuntimeError),
        ):
            pipeline.read_device_file("serial", "/state")

    def test_write_device_file_checks_push_and_remote_rename_and_cleans_unique_temps(
        self,
    ):
        calls = []

        def successful_adb(args, **kwargs):
            calls.append((args, kwargs))
            if args[0] == "push":
                local_paths.append(args[1])
                self.assertTrue(Path(args[1]).is_file())
                return subprocess.CompletedProcess(args, 0, "", "")
            return subprocess.CompletedProcess(args, 0, "", "")

        local_paths = []
        with patch.object(pipeline, "run_adb", side_effect=successful_adb):
            pipeline.write_device_file("serial", "/state", "one")
            pipeline.write_device_file("serial", "/state", "two")
        self.assertEqual(len(set(local_paths)), 2)
        self.assertTrue(all(not Path(path).exists() for path in local_paths))
        self.assertEqual(
            [call[0][0] for call in calls], ["push", "shell", "push", "shell"]
        )
        self.assertTrue(all(call[1].get("check", True) for call in calls))

        def failed_rename(args, **kwargs):
            calls.append((args, kwargs))
            if args[0] == "shell" and args[1].startswith("mv -f"):
                raise RuntimeError("rename failed")
            return subprocess.CompletedProcess(args, 0, "", "")

        calls.clear()
        local_paths.clear()
        with (
            patch.object(pipeline, "run_adb", side_effect=failed_rename),
            self.assertRaisesRegex(RuntimeError, "rename failed"),
        ):
            pipeline.write_device_file("serial", "/state", "value")
        self.assertEqual([call[0][0] for call in calls], ["push", "shell", "shell"])
        self.assertTrue(all(not Path(path).exists() for path in local_paths))

    def test_failed_or_mismatched_pull_does_not_publish_cache(self):
        self.configure_paths()
        expected = b"expected APK"
        digest = hashlib.sha256(expected).hexdigest()
        current = {"sample": {"sha256": digest, "apk_path": "/device/sample.apk"}}
        cache = Path(pipeline.CACHE_DIR) / f"sample_{digest}.apk"
        for payload in (None, b"wrong APK"):
            raw = self.root / ("raw-" + str(payload is None))

            def adb(args, payload=payload, **kwargs):
                if args[0] == "pull":
                    if payload is None:
                        raise RuntimeError("adb pull failed (1): pull failed")
                    Path(args[2]).write_bytes(payload)
                    return subprocess.CompletedProcess(args, 0, "", "")
                return subprocess.CompletedProcess(args, 0, "", "")

            with (
                self.subTest(payload=payload),
                patch.object(pipeline, "read_device_file", return_value=""),
                patch.object(pipeline, "run_adb", side_effect=adb),
            ):
                with self.assertRaises(RuntimeError):
                    pipeline.compare_and_sync_packages("serial", current, str(raw))
                self.assertFalse(cache.exists())

    def test_cached_apk_is_reused_only_when_digest_matches(self):
        self.configure_paths()
        apk = b"small deterministic APK fixture"
        digest = hashlib.sha256(apk).hexdigest()
        current = {"sample": {"sha256": digest, "apk_path": "/device/sample.apk"}}
        cache = Path(pipeline.CACHE_DIR) / f"sample_{digest}.apk"
        cache.parent.mkdir(parents=True)
        cache.write_bytes(apk)
        raw = self.root / "raw"
        with (
            patch.object(
                pipeline, "read_device_file", return_value=f"sample\t{digest}"
            ) as read,
            patch.object(pipeline, "run_adb") as adb,
        ):
            result = pipeline.compare_and_sync_packages("serial", current, str(raw))
        self.assertEqual(result, (0, 0, 1))
        self.assertEqual((raw / "sample.apk").read_bytes(), apk)
        adb.assert_not_called()
        read.assert_called_once()

    def test_corrupt_cache_is_repulled_and_verified(self):
        self.configure_paths()
        apk = b"correct APK bytes"
        digest = hashlib.sha256(apk).hexdigest()
        current = {"sample": {"sha256": digest, "apk_path": "/device/sample.apk"}}
        cache = Path(pipeline.CACHE_DIR) / f"sample_{digest}.apk"
        cache.parent.mkdir(parents=True)
        cache.write_bytes(b"corrupt")
        raw = self.root / "raw"

        def adb(args, **kwargs):
            if args[0] == "pull":
                Path(args[2]).write_bytes(apk)
                return subprocess.CompletedProcess(args, 0, "", "")
            return subprocess.CompletedProcess(args, 0, "sample\t" + digest, "")

        with (
            patch.object(
                pipeline, "read_device_file", return_value=f"sample\t{digest}"
            ),
            patch.object(pipeline, "run_adb", side_effect=adb) as mocked,
        ):
            pipeline.compare_and_sync_packages("serial", current, str(raw))
        self.assertEqual((raw / "sample.apk").read_bytes(), apk)
        self.assertEqual(hashlib.sha256(cache.read_bytes()).hexdigest(), digest)
        self.assertTrue(
            any(call.args[0][0] == "pull" for call in mocked.call_args_list)
        )

    def test_concurrent_valid_cache_publication_is_not_deleted_on_pull_failure(self):
        self.configure_paths()
        apk = b"concurrent valid APK"
        digest = hashlib.sha256(apk).hexdigest()
        current = {"sample": {"sha256": digest, "apk_path": "/device/sample.apk"}}
        cached = Path(pipeline.CACHE_DIR) / f"sample_{digest}.apk"
        cached.parent.mkdir(parents=True)
        cached.write_bytes(b"corrupt")

        def observe_corrupt_version(path):
            self.assertEqual(Path(path), cached)
            cached.write_bytes(apk)
            return "0" * 64

        with (
            patch.object(pipeline, "read_device_file", return_value=""),
            patch.object(pipeline, "_sha256", side_effect=observe_corrupt_version),
            patch.object(pipeline, "run_adb", side_effect=RuntimeError("pull failed")),
            self.assertRaises(RuntimeError),
        ):
            pipeline.compare_and_sync_packages(
                "serial", current, str(self.root / "raw")
            )
        self.assertEqual(cached.read_bytes(), apk)

    def test_previous_run_cache_prune_keeps_current_apks_and_unknown_entries(self):
        paths = self.configure_paths()
        cache = paths["CACHE_DIR"]
        cache.mkdir(parents=True)
        current_bytes = b"current apk bytes"
        current_hash = hashlib.sha256(current_bytes).hexdigest()
        current = cache / f"sample_{current_hash}.apk"
        current.write_bytes(current_bytes)
        previous = cache / f"old_{'b' * 64}.apk"
        previous.write_bytes(b"previous cached APK")
        unrelated = cache / "notes.txt"
        unrelated.write_text("keep this")
        link = cache / "linked.apk"
        link.symlink_to(previous)
        removed, warnings = pipeline.prune_previous_apk_cache(
            {"sample": {"sha256": current_hash, "apk_path": "/device/sample.apk"}}
        )
        self.assertEqual(removed, [str(previous)])
        self.assertEqual(warnings, [])
        self.assertTrue(current.exists())
        self.assertTrue(unrelated.exists())
        self.assertTrue(link.is_symlink())

    def test_device_audit_history_retains_last_five_machine_key_names(self):
        entries = [
            {
                "machine_key_name": f"machine-{index}-mvt-signing",
                "audited_at_utc": f"2025-01-{index + 1:02d}T00:00:00Z",
                "run_id": f"run-{index}",
            }
            for index in range(5)
        ]
        class FrozenDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime(2025, 1, 6, tzinfo=timezone.utc)

        with (
            patch.object(
                pipeline,
                "read_device_file",
                return_value=json.dumps({"schema": 1, "entries": entries}),
            ),
            patch.object(pipeline, "datetime", FrozenDateTime),
        ):
            updated = pipeline.updated_audit_history(
                "serial", {"machine_key_name": "new-host-key"}, "run-current"
            )
        self.assertEqual(
            [entry["machine_key_name"] for entry in updated],
            [
                "machine-1-mvt-signing",
                "machine-2-mvt-signing",
                "machine-3-mvt-signing",
                "machine-4-mvt-signing",
                "new-host-key",
            ],
        )
        self.assertEqual(updated[-1]["run_id"], "run-current")

    def test_malformed_device_audit_history_fails_without_discarding_entries(self):
        with (
            patch.object(pipeline, "read_device_file", return_value="not-json"),
            self.assertRaisesRegex(RuntimeError, "malformed"),
        ):
            pipeline.updated_audit_history(
                "serial", {"machine_key_name": "host-key"}, "run-current"
            )

    def _run_main(
        self, failure_stage=None, alerts=None, publish_failure=False, state_failure=None
    ):
        paths = self.configure_paths(Path(tempfile.mkdtemp(dir=self.root)))
        argv = patch("sys.argv", ["mvt-autorun.py", "--serial", "serial", "--force"])
        with ExitStack() as stack:
            stack.enter_context(argv)
            for name, value in paths.items():
                if hasattr(pipeline, name):
                    stack.enter_context(patch.object(pipeline, name, str(value)))
            stack.enter_context(
                patch.object(
                    pipeline,
                    "run_adb",
                    return_value=subprocess.CompletedProcess([], 0, "device", ""),
                )
            )
            stack.enter_context(
                patch.object(pipeline, "check_rate_limit", return_value=True)
            )
            stack.enter_context(
                patch.object(pipeline, "read_device_file", return_value="")
            )
            stack.enter_context(
                patch.object(
                    pipeline,
                    "get_device_pkg_hashes",
                    side_effect=RuntimeError("acquisition failed")
                    if failure_stage == "acquisition"
                    else None,
                    return_value={"pkg": {"sha256": "a" * 64, "apk_path": "/pkg.apk"}},
                )
            )
            stack.enter_context(
                patch.object(
                    pipeline, "compare_and_sync_packages", return_value=(1, 0, 0)
                )
            )
            stack.enter_context(
                patch.object(
                    pipeline,
                    "run_androidqf",
                    side_effect=RuntimeError("acquisition failed")
                    if failure_stage == "acquisition"
                    else None,
                )
            )
            stack.enter_context(patch.object(pipeline, "enrich_packages_json"))
            stack.enter_context(
                patch.object(
                    pipeline,
                    "run_mvt_analysis",
                    side_effect=RuntimeError("analysis failed")
                    if failure_stage == "analysis"
                    else None,
                    return_value=alerts
                    or {
                        "CRITICAL": 0,
                        "HIGH": 0,
                        "MEDIUM": 0,
                        "LOW": 0,
                        "INFORMATIONAL": 0,
                    },
                )
            )
            if failure_stage in ("provenance", "manifest"):
                name = (
                    "capture_provenance"
                    if failure_stage == "provenance"
                    else "write_evidence_manifest"
                )
                stack.enter_context(
                    patch.object(
                        pipeline.mvt_evidence,
                        name,
                        side_effect=RuntimeError(name + " failed"),
                    )
                )
            state_write = stack.enter_context(
                patch.object(pipeline, "write_device_file", side_effect=state_failure)
            )
            if publish_failure:
                old_latest = paths["LATEST_LINK"]
                old_latest.parent.mkdir(parents=True, exist_ok=True)
                old_latest.symlink_to(paths["RUNS_DIR"] / "prior-run")
                stack.enter_context(
                    patch.object(
                        pipeline, "publish_latest", side_effect=OSError("disk error")
                    )
                )
            result = pipeline.main()
        return result, state_write, paths

    def test_main_acquisition_and_analysis_failures_do_not_commit_state_or_latest(self):
        for stage in ("acquisition", "analysis", "provenance", "manifest"):
            with self.subTest(stage=stage):
                result, state_write, paths = self._run_main(stage)
                self.assertEqual(result, 1)
                state_write.assert_not_called()
                self.assertFalse(paths["LATEST_LINK"].exists())
                runs = list(paths["RUNS_DIR"].glob("run-*"))
                self.assertEqual(len(runs), 1)
                self.assertEqual(
                    json.loads((runs[0] / "run.json").read_text())["status"], "failed"
                )

    def test_missing_configured_iocs_fails_without_committing(self):
        Path(pipeline.INDICATORS_DIR, "fixture.stix2").unlink()
        result, writes, paths = self._run_main()
        self.assertEqual(result, 1)
        writes.assert_not_called()
        self.assertFalse(paths["LATEST_LINK"].exists())

    def test_automatic_retention_precedes_device_lock_and_reports_errors(self):
        (self.root / "config.json").write_text(
            json.dumps({"auto_prune": True, "run_retention_days": 7})
        )

        def maintenance(root, **policy):
            self.assertEqual(root, str(self.root))
            self.assertTrue(policy["apply"])
            directory = Path(pipeline.LOCK_DIR)
            directory.mkdir(parents=True, exist_ok=True)
            device = hashlib.sha256(b"serial").hexdigest()[:24]
            with (directory / f"device-{device}.lock").open("a") as lock:
                pipeline.fcntl.flock(
                    lock, pipeline.fcntl.LOCK_EX | pipeline.fcntl.LOCK_NB
                )
            return {"deleted": [], "errors": ["cleanup warning"]}

        with patch.object(
            pipeline.mvt_evidence, "prune_storage", side_effect=maintenance
        ) as prune:
            result, writes, _ = self._run_main()
        self.assertEqual(result, 0)
        self.assertEqual(writes.call_count, 3)
        prune.assert_called_once()
        self.assertTrue(
            any("cleanup warning" in str(call) for call in pipeline.log.call_args_list)
        )

    def test_low_space_preflight_prevents_collection(self):
        (self.root / "config.json").write_text(json.dumps({"min_free_bytes": 2**63}))
        with patch.object(pipeline, "get_device_pkg_hashes") as inventory:
            result, writes, paths = self._run_main()
        self.assertEqual(result, 1)
        writes.assert_not_called()
        inventory.assert_not_called()
        self.assertFalse(paths["RUNS_DIR"].exists())

    def test_automatic_prune_requires_explicit_opt_in(self):
        real_prune = pipeline.mvt_evidence.prune_storage
        with patch.object(
            pipeline.mvt_evidence, "prune_storage", wraps=real_prune
        ) as prune:
            self.assertEqual(self._run_main()[0], 0)
            prune.assert_not_called()
            (self.root / "config.json").write_text(json.dumps({"auto_prune": True}))
            self.assertEqual(self._run_main()[0], 0)
            prune.assert_called_once_with(
                str(self.root), run_days=None, cache_days=None, apply=True
            )

    def test_incident_preservation_failure_prevents_device_state_commits(self):
        alerts = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
        with patch.object(
            pipeline.shutil, "copytree", side_effect=OSError("archive full")
        ):
            result, writes, paths = self._run_main(alerts=alerts)
        self.assertEqual(result, 1)
        writes.assert_not_called()
        self.assertFalse(paths["LATEST_LINK"].exists())

    def test_device_state_commit_failure_does_not_advance_daily_token(self):
        for failed_path in (
            "/sdcard/Documents/.mvt_pkg_hashes",
            "/sdcard/Documents/.mvt_audit_history",
            "/sdcard/Documents/.mvt_last_check",
        ):
            with self.subTest(failed_path=failed_path):
                committed = {}

                def commit(
                    serial, path, value, failed_path=failed_path, committed=committed
                ):
                    if path == failed_path:
                        raise RuntimeError("remote commit failed")
                    committed[path] = value

                result, writes, paths = self._run_main(state_failure=commit)
                self.assertEqual(result, 1)
                self.assertNotIn("/sdcard/Documents/.mvt_last_check", committed)
                self.assertEqual(
                    writes.call_count,
                    1
                    if failed_path.endswith("pkg_hashes")
                    else 2
                    if failed_path.endswith("audit_history")
                    else 3,
                )
                if failed_path.endswith(("audit_history", "last_check")):
                    self.assertIn("/sdcard/Documents/.mvt_pkg_hashes", committed)
                if failed_path.endswith("last_check"):
                    self.assertIn("/sdcard/Documents/.mvt_audit_history", committed)
                self.assertFalse(paths["LATEST_LINK"].exists())

    def test_final_metadata_failure_is_nonfatal_and_preserves_analysis_manifest(self):
        real_dump = json.dump

        def fail_final_metadata(metadata, output, **kwargs):
            if metadata.get("status") == "completed":
                output.write('{"partial":')
                raise OSError("metadata update failed during serialization")
            return real_dump(metadata, output, **kwargs)

        with (
            patch.object(pipeline.json, "dump", side_effect=fail_final_metadata),
            patch.object(pipeline, "send_toast") as toast,
        ):
            result, writes, paths = self._run_main()
        self.assertEqual(result, 0)
        self.assertEqual(writes.call_count, 3)
        self.assertIn("WARNING", toast.call_args.args[1])
        run = paths["LATEST_LINK"].resolve()
        self.assertEqual(
            json.loads((run / "run.json").read_text())["status"], "analysis_completed"
        )
        self.assertFalse(list(run.glob(".run-metadata-*.tmp")))

    def test_atomic_metadata_replacement_failure_preserves_previous_manifest(self):
        run = self.root / "run"
        run.mkdir()
        pipeline.write_run_metadata(str(run), {"status": "analysis_completed"})
        original = (run / "run.json").read_bytes()
        with (
            patch.object(pipeline.os, "replace", side_effect=OSError("rename failed")),
            self.assertRaises(OSError),
        ):
            pipeline.write_run_metadata(str(run), {"status": "completed"})
        self.assertEqual((run / "run.json").read_bytes(), original)
        self.assertFalse(list(run.glob(".run-metadata-*.tmp")))

    def test_publish_latest_failure_after_state_commit_is_nonfatal_and_names_run(self):
        with (
            patch.object(pipeline, "send_toast") as toast,
            patch.object(pipeline, "log"),
        ):
            # Keep an existing publication intact when replacement fails.
            result, state_write, paths = self._run_main(publish_failure=True)
            self.assertEqual(result, 0)
            self.assertEqual(state_write.call_count, 3)
            self.assertEqual(
                os.readlink(paths["LATEST_LINK"]), str(paths["RUNS_DIR"] / "prior-run")
            )
            run_dir = next(paths["RUNS_DIR"].glob("run-*"))
            self.assertIn(str(run_dir), toast.call_args.args[1])
            self.assertIn("WARNING", toast.call_args.args[1])

    def test_publish_latest_atomically_preserves_legacy_directory(self):
        paths = self.configure_paths()
        legacy = paths["LATEST_LINK"]
        legacy.mkdir(parents=True)
        (legacy / "legacy.txt").write_text("keep")
        run = paths["RUNS_DIR"] / "complete-run"
        run.mkdir(parents=True)
        (run / "result.txt").write_text("complete")
        pipeline.publish_latest(str(run))
        self.assertTrue(
            any(
                (paths["RUNS_DIR"] / name / "legacy.txt").read_text() == "keep"
                for name in os.listdir(paths["RUNS_DIR"])
                if name.startswith("legacy-")
            )
        )
        self.assertTrue(legacy.is_symlink())
        self.assertEqual(legacy.resolve(), run.resolve())


if __name__ == "__main__":
    unittest.main()
