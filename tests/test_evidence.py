"""Offline evidence tests use real C hashing and real temporary OpenSSL keys."""

import contextlib
import fcntl
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
import mvt_evidence as evidence


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory()
        cls.native = Path(cls.build.name) / "mvt-hash"
        subprocess.run(
            [
                "cc",
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(ROOT / "native" / "mvt-hash.c"),
                "-lcrypto",
                "-o",
                str(cls.native),
            ],
            check=True,
            capture_output=True,
            timeout=60,
        )
        cls.environment = patch.dict(os.environ, {"MVT_HASH_BIN": str(cls.native)})
        cls.environment.start()

    @classmethod
    def tearDownClass(cls):
        cls.environment.stop()
        cls.build.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run = self.root / "run"
        self.run.mkdir()
        (self.run / "raw").mkdir()
        (self.run / "raw" / "sample.apk").write_bytes(b"unaltered acquisition\x00")
        self.script = self.root / "script.py"
        self.script.write_text("# recorded source\n")

    def key(self, name="key"):
        private = self.root / f"{name}.pem"
        public = self.root / f"{name}.pub"
        subprocess.run(
            [
                shutil.which("openssl"),
                "genpkey",
                "-algorithm",
                "Ed25519",
                "-out",
                str(private),
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        private.chmod(0o600)
        subprocess.run(
            [
                shutil.which("openssl"),
                "pkey",
                "-in",
                str(private),
                "-pubout",
                "-out",
                str(public),
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        return private, public

    def indicators(self):
        source = self.root / "source-iocs"
        source.mkdir()
        content = {
            "type": "bundle",
            "id": "bundle--fixture",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--fixture",
                    "spec_version": "2.1",
                    "modified": "2026-01-01T00:00:00Z",
                    "pattern": "[domain-name:value = 'example.invalid']",
                }
            ],
        }
        (source / "fixture.stix2").write_text(json.dumps(content))
        return source

    def manifest(self, key=None):
        return evidence.write_evidence_manifest(
            self.run,
            {
                "serial": "test-device",
                "alerts": {"HIGH": 0},
                "provenance": {"source": "offline fixture"},
            },
            signing_key=key,
        )

    def test_hashes_use_real_native_batch_and_unsigned_is_not_authenticated(self):
        with patch.object(
            evidence.mvt_hash, "hash_files", wraps=evidence.mvt_hash.hash_files
        ) as batch:
            manifest = self.manifest()
            self.assertTrue(batch.called)
        digest = hashlib.sha256(
            (self.run / "raw" / "sample.apk").read_bytes()
        ).hexdigest()
        self.assertEqual(manifest["files"]["raw/sample.apk"]["sha256"], digest)
        self.assertEqual(
            (self.run / evidence.MANIFEST).read_bytes(), evidence._json_bytes(manifest)
        )
        verified = evidence.verify_evidence_manifest(self.run)
        self.assertTrue(verified["ok"], verified)
        self.assertFalse(verified["signature"]["authenticated"])
        self.assertIn("not authenticated", verified["signature"]["note"])
        self.assertFalse(
            evidence.verify_evidence_manifest(self.run, require_signature=True)["ok"]
        )

    def test_no_python_hash_fallback_if_native_missing(self):
        with (
            patch.dict(os.environ, {"MVT_HASH_BIN": str(self.root / "missing-native")}),
            self.assertRaises(RuntimeError),
        ):
            self.manifest()
        self.assertFalse((self.run / evidence.MANIFEST).exists())

    def test_added_missing_modified_files_and_nested_run_metadata_are_detected(self):
        self.manifest()
        file = self.run / "raw" / "sample.apk"
        original = file.read_bytes()
        file.write_bytes(b"tampered")
        self.assertIn(
            "Modified evidence: raw/sample.apk",
            evidence.verify_evidence_manifest(self.run)["errors"],
        )
        file.unlink()
        self.assertIn(
            "Missing evidence: raw/sample.apk",
            evidence.verify_evidence_manifest(self.run)["errors"],
        )
        file.write_bytes(original)
        (self.run / "raw" / "run.json").write_text("{}")
        self.assertIn(
            "Added evidence: raw/run.json",
            evidence.verify_evidence_manifest(self.run)["errors"],
        )

    def test_lifecycle_metadata_only_is_excluded(self):
        (self.run / "run.json").write_text('{"status":"running"}')
        self.manifest()
        (self.run / "run.json").write_text('{"status":"completed"}')
        self.assertTrue(evidence.verify_evidence_manifest(self.run)["ok"])
        (self.run / "empty-added-directory").mkdir()
        self.assertFalse(evidence.verify_evidence_manifest(self.run)["ok"])

    def test_symlinks_are_recorded_without_following_and_change_is_detected(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "secret").write_text("not evidence")
        link = self.run / "external"
        link.symlink_to(outside, target_is_directory=True)
        dangling = self.run / "dangling"
        dangling.symlink_to("not-present")
        manifest = self.manifest()
        self.assertEqual(
            manifest["files"]["external"], {"type": "symlink", "target": str(outside)}
        )
        self.assertNotIn("external/secret", manifest["files"])
        (outside / "secret").write_text("changed outside")
        self.assertTrue(evidence.verify_evidence_manifest(self.run)["ok"])
        link.unlink()
        link.symlink_to("raw")
        self.assertFalse(evidence.verify_evidence_manifest(self.run)["ok"])

    def test_path_traversal_and_manifest_exclusion_tampering_rejected(self):
        manifest = self.manifest()
        for path in (
            "../outside",
            "/etc/passwd",
            "raw/../outside",
            "raw//child",
            "raw\\child",
            "./raw",
            "run.json",
        ):
            with self.subTest(path=path):
                malicious = dict(manifest)
                malicious["files"] = {
                    path: {"type": "file", "sha256": "0" * 64, "size": 0}
                }
                (self.run / evidence.MANIFEST).write_bytes(
                    evidence._json_bytes(malicious)
                )
                checked = evidence.verify_evidence_manifest(self.run)
                self.assertFalse(checked["ok"])
                self.assertIn("Unsafe manifest path", checked["errors"][0])
        manifest["exclusions"] = [*evidence.EXCLUSIONS, "raw/sample.apk"]
        (self.run / evidence.MANIFEST).write_bytes(evidence._json_bytes(manifest))
        self.assertFalse(evidence.verify_evidence_manifest(self.run)["ok"])

    def test_manifest_duplicate_keys_and_symlink_manifest_rejected(self):
        self.manifest()
        path = self.run / evidence.MANIFEST
        path.write_text('{"schema_version":1,"schema_version":1}')
        self.assertIn(
            "Duplicate JSON key",
            evidence.verify_evidence_manifest(self.run)["errors"][0],
        )
        path.unlink()
        path.symlink_to(self.script)
        self.assertFalse(evidence.verify_evidence_manifest(self.run)["ok"])

    def test_real_ed25519_sign_verify_wrong_untrusted_and_corrupted_signature(self):
        private, public = self.key()
        self.manifest(private)
        self.assertFalse(evidence.verify_evidence_manifest(self.run)["ok"])
        self.assertEqual(
            evidence.verify_evidence_manifest(self.run)["signature"]["status"],
            "untrusted",
        )
        verified = evidence.verify_evidence_manifest(self.run, public, True)
        self.assertTrue(verified["ok"], verified)
        self.assertTrue(verified["signature"]["authenticated"])
        _, wrong_public = self.key("wrong")
        self.assertFalse(
            evidence.verify_evidence_manifest(self.run, wrong_public)["ok"]
        )
        signature = self.run / evidence.SIGNATURE
        data = bytearray(signature.read_bytes())
        data[0] ^= 1
        signature.write_bytes(data)
        self.assertFalse(evidence.verify_evidence_manifest(self.run, public)["ok"])

    def test_signed_manifest_metadata_tampering_and_artifact_modification(self):
        private, public = self.key()
        manifest = self.manifest(private)
        manifest["metadata"]["serial"] = "forged"
        (self.run / evidence.MANIFEST).write_bytes(evidence._json_bytes(manifest))
        self.assertFalse(evidence.verify_evidence_manifest(self.run, public)["ok"])
        self.manifest(private)
        (self.run / "raw" / "sample.apk").write_text("changed after signing")
        self.assertFalse(evidence.verify_evidence_manifest(self.run, public)["ok"])

    def test_invalid_key_permissions_symlinks_and_signing_failure_are_fatal(self):
        private, _ = self.key()
        private.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "0600"):
            self.manifest(private)
        private.chmod(0o600)
        link = self.root / "linked-key.pem"
        link.symlink_to(private)
        with self.assertRaises(ValueError):
            self.manifest(link)
        private.write_text("not a key")
        with self.assertRaises(RuntimeError):
            self.manifest(private)
        self.assertFalse((self.run / evidence.MANIFEST).exists())
        self.assertFalse((self.run / evidence.SIGNATURE).exists())

    def test_non_ed25519_key_rejected(self):
        private = self.root / "ec.pem"
        subprocess.run(
            [
                shutil.which("openssl"),
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                str(private),
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        private.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "Ed25519"):
            self.manifest(private)

    def test_provenance_snapshots_independent_actual_tool_and_native_hashes(self):
        source = self.indicators()
        tool = self.root / "tool"
        tool.write_text("#!/bin/sh\necho MUST-NOT-EXECUTE >&2\nexit 12\n")
        tool.chmod(0o700)
        record = evidence.capture_provenance(
            self.root, self.run, {"fixture-tool": str(tool)}, source, self.script
        )
        self.assertEqual(record["tools"]["fixture-tool"]["version"], "unknown")
        self.assertTrue(record["warnings"])
        self.assertEqual(
            record["runtime"]["native_hash"]["resolved_path"], str(self.native)
        )
        self.assertEqual(
            record["ioc_files"][0]["object_versions"][0]["spec_version"], "2.1"
        )
        snap = Path(record["indicators"][0])
        self.assertNotEqual(
            snap.stat().st_ino, (source / "fixture.stix2").stat().st_ino
        )
        saved = snap.read_bytes()
        (source / "fixture.stix2").write_text("changed source")
        self.assertEqual(snap.read_bytes(), saved)
        self.assertEqual(record["environment"]["MVT_STIX2"], "")
        self.assertEqual(
            list(Path(record["environment"]["XDG_DATA_HOME"]).iterdir()), []
        )
        manifest = evidence.write_evidence_manifest(self.run, {"provenance": record})
        self.assertIn("indicators/fixture.stix2", manifest["files"])

    def test_only_matching_install_metadata_can_assert_version(self):
        source = self.indicators()
        tool = self.root / "tool"
        tool.write_text("#!/bin/sh\nexit 12\n")
        tool.chmod(0o700)
        installed = {
            "tools": {
                "tool": {
                    "path": str(tool),
                    "sha256": evidence.mvt_hash.hash_file(tool),
                    "version": "3.4.5",
                }
            }
        }
        (self.root / "installed-tools.json").write_text(json.dumps(installed))
        record = evidence.capture_provenance(
            self.root, self.run, {"tool": str(tool)}, source, self.script
        )
        self.assertEqual(record["tools"]["tool"]["version"], "3.4.5")
        self.assertEqual(record["installed_tools"]["contents"], installed)
        other = self.root / "run2"
        other.mkdir()
        tool.write_text("#!/bin/sh\nexit 99\n")
        changed = evidence.capture_provenance(
            self.root, other, {"tool": str(tool)}, source, self.script
        )
        self.assertEqual(changed["tools"]["tool"]["version"], "unknown")

    def test_missing_empty_invalid_iocs_and_symlink_escape_rejected(self):
        with self.assertRaises(ValueError):
            evidence.capture_provenance(
                self.root, self.run, {}, self.root / "missing", self.script
            )
        source = self.root / "indicators"
        source.mkdir()
        with self.assertRaisesRegex(RuntimeError, "No configured STIX2"):
            evidence.capture_provenance(self.root, self.run, {}, source, self.script)
        (source / "escape.stix2").symlink_to(self.script)
        with self.assertRaisesRegex(ValueError, "escape"):
            evidence.capture_provenance(self.root, self.run, {}, source, self.script)
        (source / "escape.stix2").unlink()
        (source / "invalid.stix2").write_text("{}")
        with self.assertRaisesRegex(ValueError, "STIX2 bundle"):
            evidence.capture_provenance(self.root, self.run, {}, source, self.script)
        self.assertFalse((self.run / "indicators").exists())

    def test_config_defaults_and_invalid_values_never_rewrite_config(self):
        self.assertEqual(evidence.load_config(self.root), evidence.DEFAULTS)
        config = self.root / "config.json"
        self.assertFalse(config.exists())
        invalid = [
            {"min_free_bytes": True},
            {"min_free_bytes": -1},
            {"run_retention_days": 1.5},
            {"cache_retention_days": -2},
            {"auto_prune": "yes"},
            {"signing_key": 42},
            {"signing_key": "relative/key"},
            {"signing_key": str(self.root / "missing")},
            {"typo": 1},
            [],
        ]
        for value in invalid:
            original = json.dumps(value)
            config.write_text(original)
            with self.subTest(value=value), self.assertRaises(ValueError):
                evidence.load_config(self.root)
            self.assertEqual(config.read_text(), original)
        private, _ = self.key()
        config.write_text(
            json.dumps(
                {
                    "signing_key": str(private),
                    "auto_prune": True,
                    "run_retention_days": 7,
                }
            )
        )
        self.assertEqual(evidence.load_config(self.root)["run_retention_days"], 7)

    def test_low_space_existing_ancestor_reserve_plus_estimate(self):
        target = self.root / "never" / "create"
        free = shutil.disk_usage(self.root).free
        result = evidence.check_free_space(
            target, min_free_bytes=free - 5, required_bytes=5
        )
        self.assertEqual(result["path"], str(self.root))
        with self.assertRaisesRegex(RuntimeError, "Insufficient free space"):
            evidence.check_free_space(target, min_free_bytes=free, required_bytes=1)
        self.assertFalse(target.parent.exists())
        for value in (-1, True, "4"):
            with self.assertRaises(ValueError):
                evidence.check_free_space(target, value)

    def storage_run(self, name, status="completed", high=0, serial=None):
        run = self.root / "output" / "runs" / name
        run.mkdir(parents=True)
        metadata = {
            "serial": serial or name,
            "status": status,
            "completed_at": evidence._utc(time.time() - 20 * 86400),
            "alerts": dict.fromkeys(evidence.LEVELS, 0),
        }
        metadata["alerts"]["HIGH"] = high
        (run / "run.json").write_text(json.dumps(metadata))
        (run / "artifact").write_bytes(b"independent evidence")
        evidence.write_evidence_manifest(run, metadata)
        return run

    def cache_file(self, content=b"cache", name=None):
        digest = hashlib.sha256(content).hexdigest()
        cache = self.root / "cache" / "apks"
        cache.mkdir(parents=True, exist_ok=True)
        path = cache / (name or f"org.example_{digest}.apk")
        path.write_bytes(content)
        return path

    def test_retention_disabled_has_no_side_effect_and_rejects_bad_policy(self):
        self.assertEqual(
            evidence.prune_storage(self.root),
            {"candidates": [], "deleted": [], "protected": [], "errors": []},
        )
        self.assertFalse((self.root / "state").exists())
        for kwargs in ({"run_days": -1}, {"cache_days": True}, {"apply": "yes"}):
            with self.assertRaises(ValueError):
                evidence.prune_storage(self.root, **kwargs)

    def test_retention_dryrun_apply_latest_incident_positive_failure_active_legacy(
        self,
    ):
        ordinary = self.storage_run("ordinary")
        second = self.storage_run("ordinary2", serial="ordinary")
        latest = self.storage_run("latest")
        positive = self.storage_run("positive", high=1)
        failure = self.storage_run("failure", status="failed")
        active = self.storage_run("active", status="running")
        legacy = self.root / "output" / "runs" / "legacy"
        legacy.mkdir()
        (self.root / "output" / "latest").symlink_to(latest)
        incidents = self.root / "output" / "incidents"
        incidents.mkdir()
        incident = incidents / "incident-file.tar.gz"
        incident.write_text("incident archive")
        external = self.root / "external"
        external.mkdir()
        (self.root / "output" / "runs" / "symlink").symlink_to(external)
        now = time.time() + 30 * 86400
        planned = evidence.prune_storage(self.root, run_days=7, now=now)
        self.assertEqual(planned["errors"], [])
        self.assertEqual(
            {item["path"] for item in planned["candidates"]},
            {str(ordinary), str(second)},
        )
        self.assertEqual(planned["deleted"], [])
        self.assertTrue(ordinary.exists())
        applied = evidence.prune_storage(self.root, run_days=7, apply=True, now=now)
        self.assertEqual(set(applied["deleted"]), {str(ordinary), str(second)})
        for path in (latest, positive, failure, active, legacy, external, incident):
            self.assertTrue(path.exists(), path)

    def test_retention_honors_live_perdevice_lock(self):
        run = self.storage_run("locked-device", serial="serial")
        locks = self.root / "state" / "locks"
        locks.mkdir(parents=True)
        device = hashlib.sha256(b"serial").hexdigest()[:24]
        with (locks / f"device-{device}.lock").open("a") as locked:
            fcntl.flock(locked, fcntl.LOCK_EX)
            result = evidence.prune_storage(
                self.root, run_days=0, apply=True, now=time.time() + 86400
            )
        self.assertEqual(result["deleted"], [])
        self.assertTrue(run.exists())

    def test_cache_lru_reference_protection_and_unknown_independent_evidence(self):
        kept = self.storage_run("latest")
        (self.root / "output" / "latest").symlink_to(kept)
        referenced = self.cache_file(b"independent evidence")
        unused = self.cache_file(b"unused cache")
        fresh = self.cache_file(b"future cache")
        os.utime(fresh, (time.time() + 20 * 86400,) * 2)
        now = time.time() + 10 * 86400
        result = evidence.prune_storage(self.root, cache_days=7, apply=True, now=now)
        self.assertEqual(result["deleted"], [str(unused)])
        self.assertTrue(referenced.exists())
        self.assertTrue(fresh.exists())
        unknown = self.root / "output" / "runs" / "unknown"
        unknown.mkdir()
        unused = self.cache_file(b"unreferenced but unknown consumers")
        result = evidence.prune_storage(self.root, cache_days=0, apply=True, now=now)
        self.assertIn(str(unused), result["deleted"])
        self.assertFalse(unused.exists())
        self.assertTrue(unknown.exists())

    def test_unsealed_evidence_cache_links_are_protected_without_blocking_unused_cache(
        self,
    ):
        unknown = self.root / "output" / "runs" / "failed-unsealed"
        unknown.mkdir(parents=True)
        linked = self.cache_file(b"linked evidence")
        unused = self.cache_file(b"unreferenced cache")
        (unknown / "collected.apk").symlink_to(linked)
        result = evidence.prune_storage(
            self.root, cache_days=0, apply=True, now=time.time() + 86400
        )
        self.assertEqual(result["deleted"], [str(unused)])
        self.assertEqual((unknown / "collected.apk").read_bytes(), b"linked evidence")
        self.assertTrue(linked.exists())

    def test_unsealed_directory_link_or_unreadable_evidence_blocks_cache_reclaim(self):
        unknown = self.root / "output" / "runs" / "unsealed"
        unknown.mkdir(parents=True)
        cached = self.cache_file()
        link = unknown / "cache-tree"
        link.symlink_to(cached.parent, target_is_directory=True)
        result = evidence.prune_storage(
            self.root, cache_days=0, apply=True, now=time.time() + 86400
        )
        self.assertFalse(result["deleted"])
        link.unlink()
        with patch.object(
            evidence.os, "walk", side_effect=PermissionError("cannot inspect evidence")
        ):
            result = evidence.prune_storage(
                self.root, cache_days=0, apply=True, now=time.time() + 86400
            )
        self.assertFalse(result["deleted"])
        self.assertTrue(cached.exists())

    def test_cache_maintenance_and_publication_locks_prevent_races(self):
        cached = self.cache_file()
        locks = self.root / "state" / "locks"
        locks.mkdir(parents=True)
        for name in ("maintenance.lock", "publication.lock"):
            with self.subTest(lock=name), (locks / name).open("a") as locked:
                fcntl.flock(locked, fcntl.LOCK_SH)
                result = evidence.prune_storage(
                    self.root, cache_days=0, apply=True, now=time.time() + 86400
                )
                self.assertTrue(result["errors"])
                self.assertEqual(result["deleted"], [])
                self.assertTrue(cached.exists())

    def test_cache_symlinks_hardlinks_escape_and_unsafe_layout_never_deleted(self):
        cached = self.cache_file()
        external = self.root / "external.apk"
        external.write_text("outside cache")
        (cached.parent / ("a" * 64 + ".apk")).symlink_to(external)
        hard = cached.parent / ("b" * 64 + ".apk")
        os.link(cached, hard)
        result = evidence.prune_storage(
            self.root, cache_days=0, apply=True, now=time.time() + 86400
        )
        self.assertEqual(result["deleted"], [])
        self.assertTrue(external.exists())
        (self.root / "output").symlink_to(self.run)
        result = evidence.prune_storage(
            self.root, run_days=0, apply=True, now=time.time() + 86400
        )
        self.assertTrue(result["errors"])
        self.assertTrue((self.run / "raw" / "sample.apk").exists())

    def test_retention_rejects_mutated_positive_metadata_and_unsealed_legacy(self):
        positive = self.storage_run("positive-source", high=1)
        metadata = json.loads((positive / "run.json").read_text())
        metadata["alerts"]["HIGH"] = 0
        (positive / "run.json").write_text(json.dumps(metadata))
        legacy = self.storage_run("unsealed")
        (legacy / evidence.MANIFEST).unlink()
        result = evidence.prune_storage(
            self.root, run_days=0, apply=True, now=time.time() + 86400
        )
        self.assertEqual(result["deleted"], [])
        self.assertTrue(positive.exists())
        self.assertTrue(legacy.exists())

    def test_cache_incident_references_corruption_and_unsupported_entries_protected(
        self,
    ):
        incident = self.root / "output" / "incidents" / "preserved"
        incident.mkdir(parents=True)
        (incident / "sample.apk").write_bytes(b"incident content")
        evidence.write_evidence_manifest(incident, {"alerts": {"HIGH": 1}})
        referenced = self.cache_file(b"incident content")
        ordinary = self.cache_file(b"ordinary unreferenced cache")
        corrupt = self.cache_file(b"wrong content", "0" * 64 + ".apk")
        unknown = self.cache_file(b"unknown cache format", "unknown.tmp")
        result = evidence.prune_storage(
            self.root, cache_days=0, apply=True, now=time.time() + 86400
        )
        self.assertEqual(result["deleted"], [str(ordinary)])
        for path in (referenced, corrupt, unknown, incident / "sample.apk"):
            self.assertTrue(path.exists())

    def test_snapshot_source_mutation_fails_without_publishing_partial_snapshot(self):
        source = self.indicators()
        real_copy = shutil.copyfileobj

        def changed(reader, writer):
            real_copy(reader, writer)
            (source / "fixture.stix2").write_text('{"type":"bundle","objects":[]}')

        with (
            patch.object(evidence.shutil, "copyfileobj", side_effect=changed),
            self.assertRaisesRegex(RuntimeError, "changed during snapshot"),
        ):
            evidence.capture_provenance(self.root, self.run, {}, source, self.script)
        self.assertFalse((self.run / "indicators").exists())
        self.assertEqual(list(self.run.glob(".indicators-*")), [])

    def test_manifest_reserved_directory_and_special_files_rejected(self):
        (self.run / "run.json").mkdir()
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.manifest()
        (self.run / "run.json").rmdir()
        os.mkfifo(self.run / "raw" / "pipe")
        with self.assertRaisesRegex(ValueError, "special evidence"):
            self.manifest()

    def test_signed_missing_signature_and_unsigned_cli_require_signature_fail(self):
        private, public = self.key()
        self.manifest(private)
        (self.run / evidence.SIGNATURE).unlink()
        self.assertFalse(evidence.verify_evidence_manifest(self.run, public)["ok"])
        self.manifest()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                evidence.main(["verify", str(self.run), "--require-signature"]), 1
            )

    def test_new_file_during_native_batch_prevents_manifest_publication(self):
        real_hash = evidence.mvt_hash.hash_files

        def add_during_hash(paths):
            result = real_hash(paths)
            (self.run / "raw" / "late-arrival").write_text(
                "must not be silently omitted"
            )
            return result

        with (
            patch.object(evidence.mvt_hash, "hash_files", side_effect=add_during_hash),
            self.assertRaisesRegex(RuntimeError, "changed while hashing"),
        ):
            self.manifest()
        self.assertFalse((self.run / evidence.MANIFEST).exists())

    def test_invalid_now_is_never_a_deletion_policy(self):
        cached = self.cache_file()
        for value in (float("nan"), float("inf"), -float("inf")):
            with self.assertRaisesRegex(ValueError, "finite timestamp"):
                evidence.prune_storage(self.root, cache_days=0, apply=True, now=value)
        self.assertTrue(cached.exists())

    def test_cli_verify_and_prune_default_dry_run(self):
        self.manifest()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(evidence.main(["verify", str(self.run)]), 0)
        self.assertTrue(json.loads(output.getvalue())["ok"])
        cached = self.cache_file()
        os.utime(cached, (time.time() - 5,) * 2)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(
                evidence.main(["prune", "--root", str(self.root), "--cache-days", "0"]),
                0,
            )
        self.assertEqual(json.loads(output.getvalue())["deleted"], [])
        self.assertTrue(cached.exists())


if __name__ == "__main__":
    unittest.main()
