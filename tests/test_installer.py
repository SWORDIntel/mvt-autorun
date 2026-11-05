"""Installer checks use only temporary directories; never execute install.sh."""

import contextlib
import copy
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "install_dependencies", ROOT / "tools/install_dependencies.py"
)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class InstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native_dir = tempfile.TemporaryDirectory(
            prefix="mvt-installer-native-test-"
        )
        cls.hash_bin = Path(cls.native_dir.name) / "mvt-hash"
        flags = subprocess.run(
            ["pkg-config", "--cflags", "--libs", "libcrypto"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.split()
        subprocess.run(
            [
                "cc",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(ROOT / "native/mvt-hash.c"),
                "-o",
                str(cls.hash_bin),
                *flags,
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        subprocess.run(
            [str(cls.hash_bin), "--self-test"],
            check=True,
            capture_output=True,
            timeout=10,
        )

    @classmethod
    def tearDownClass(cls):
        cls.native_dir.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mvt-installer-test-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.source = self.work / "source"
        self.source.mkdir()
        (self.source / "bin").mkdir()
        (self.source / "udev").mkdir()
        self.root = self.work / "installed"
        (self.root / "bin").mkdir(parents=True)
        self.rules = self.work / "rules.d"
        self.rules.mkdir()
        for name in [
            "dependencies.json",
            "requirements-pinned.txt",
            "udev/70-mvt-android.rules",
        ]:
            shutil.copyfile(ROOT / name, self.source / name)
        self.lock = installer.load_lock(self.source)
        self.binary = b"pinned test AndroidQF bytes\n"
        fixture = self.work / "fixture"
        fixture.write_bytes(self.binary)
        self.digest = installer.native_sha256(fixture, self.hash_bin)
        self.lock["androidqf"]["assets"]["linux-amd64"]["sha256"] = self.digest
        self.destination = self.root / "bin/androidqf"

    def install_aqf(self, **kwargs):
        installer.install_androidqf(
            self.lock, self.source, self.root, self.hash_bin, machine="x86_64", **kwargs
        )

    def test_install_creates_and_reuses_machine_named_signing_identity_and_preserves_config(
        self,
    ):
        import getpass

        home = self.work / "target-home"
        home.mkdir()
        config = {"min_free_bytes": 4096, "run_retention_days": 14, "auto_prune": False}
        (self.root / "config.json").write_text(json.dumps(config))
        identity = installer.install_signing_identity(
            self.root, home, getpass.getuser(), "phone-lab/worker 7"
        )
        ssh = home / ".ssh"
        private = Path(identity["private_key"])
        public = Path(identity["public_key"])
        self.assertEqual(identity["machine_key_name"], "phone-lab-worker-7-mvt-signing")
        self.assertEqual(ssh.stat().st_mode & 0o777, 0o700)
        self.assertEqual(private.stat().st_mode & 0o777, 0o600)
        self.assertTrue(public.is_file())
        stored = json.loads((self.root / "config.json").read_text())
        self.assertEqual(stored["signing_key"], str(private))
        self.assertEqual(stored["machine_key_name"], identity["machine_key_name"])
        self.assertEqual(stored["run_retention_days"], 14)
        self.assertFalse(stored["auto_prune"])
        private_bytes = private.read_bytes()
        reused = installer.install_signing_identity(
            self.root, home, getpass.getuser(), "phone-lab/worker 7"
        )
        self.assertEqual(reused, identity)
        self.assertEqual(private.read_bytes(), private_bytes)

    def test_signing_identity_refuses_symlinked_ssh_and_invalid_existing_key(self):
        import getpass

        home = self.work / "symlink-home"
        home.mkdir()
        external = self.work / "external"
        external.mkdir()
        (home / ".ssh").symlink_to(external, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlinked"):
            installer.install_signing_identity(
                self.root, home, getpass.getuser(), "host"
            )
        (home / ".ssh").unlink()
        (home / ".ssh").mkdir(mode=0o700)
        invalid = home / ".ssh" / "host-mvt-signing.pem"
        invalid.write_text("not a private key")
        invalid.chmod(0o600)
        with self.assertRaises(subprocess.CalledProcessError):
            installer.install_signing_identity(
                self.root, home, getpass.getuser(), "host"
            )
        self.assertEqual(invalid.read_text(), "not a private key")

    def test_shell_syntax_without_execution(self):
        subprocess.run(
            ["bash", "-n", str(ROOT / "install.sh")],
            check=True,
            capture_output=True,
            timeout=10,
        )

    def test_architecture_is_explicit(self):
        for machine, key in [
            ("x86_64", "linux-amd64"),
            ("arm64", "linux-arm64"),
            ("aarch64", "linux-arm64"),
        ]:
            self.assertEqual(installer.target_key(machine), key)
        for machine in ["i686", "armv7l", "riscv64", "", "AMD64"]:
            with self.assertRaisesRegex(ValueError, "Unsupported CPU"):
                installer.target_key(machine)

    def test_unsupported_arch_never_downloads(self):
        with (
            mock.patch.object(installer, "download") as download,
            self.assertRaises(ValueError),
        ):
            installer.install_androidqf(
                self.lock, self.source, self.root, self.hash_bin, machine="armv7l"
            )
        download.assert_not_called()
        self.assertFalse(self.destination.exists())

    def test_checksum_rejection_preserves_old_binary_and_mode(self):
        self.destination.write_bytes(b"old binary")
        self.destination.chmod(0o750)
        with (
            mock.patch.object(
                installer,
                "download",
                side_effect=lambda url, output: output.write(b"corrupt"),
            ),
            self.assertRaisesRegex(ValueError, "SHA256 mismatch"),
        ):
            self.install_aqf()
        self.assertEqual(self.destination.read_bytes(), b"old binary")
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o750)
        self.assertEqual(list(self.destination.parent.glob(".androidqf-*")), [])

    def test_download_failure_preserves_old_binary(self):
        self.destination.write_bytes(b"old")
        with (
            mock.patch.object(
                installer, "download", side_effect=TimeoutError("bounded")
            ),
            self.assertRaises(TimeoutError),
        ):
            self.install_aqf()
        self.assertEqual(self.destination.read_bytes(), b"old")
        self.assertEqual(list(self.destination.parent.glob(".androidqf-*")), [])

    def test_verified_download_is_atomic_and_never_executable_while_staged(self):
        self.destination.write_bytes(b"old")

        def download(url, output):
            self.assertEqual(self.destination.read_bytes(), b"old")
            self.assertEqual(os.fstat(output.fileno()).st_mode & 0o777, 0o600)
            output.write(self.binary)

        original_hash = installer.native_sha256

        def inspect_hash(path, hash_bin):
            if path.name.startswith(".androidqf-"):
                self.assertEqual(path.stat().st_mode & 0o111, 0)
                self.assertEqual(self.destination.read_bytes(), b"old")
            return original_hash(path, hash_bin)

        with (
            mock.patch.object(installer, "download", side_effect=download),
            mock.patch.object(installer, "native_sha256", side_effect=inspect_hash),
        ):
            self.install_aqf()
        self.assertEqual(self.destination.read_bytes(), self.binary)
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o755)

    def test_matching_installed_binary_only_is_reused(self):
        self.destination.write_bytes(self.binary)
        with mock.patch.object(installer, "download") as download:
            self.install_aqf()
        download.assert_not_called()

    def test_matching_bundle_is_verified_and_copied(self):
        bundled = self.source / "bin/androidqf"
        bundled.write_bytes(self.binary)
        with mock.patch.object(installer, "download") as download:
            self.install_aqf()
        download.assert_not_called()
        self.assertEqual(self.destination.read_bytes(), self.binary)
        self.assertNotEqual(self.destination.stat().st_ino, bundled.stat().st_ino)

    def test_wrong_architecture_bundle_is_not_reused(self):
        (self.source / "bin/androidqf").write_bytes(b"some other architecture")
        with mock.patch.object(
            installer,
            "download",
            side_effect=lambda url, output: output.write(self.binary),
        ) as download:
            self.install_aqf()
        download.assert_called_once()
        self.assertEqual(self.destination.read_bytes(), self.binary)

    def test_destination_symlink_is_replaced_not_followed(self):
        other = self.work / "unrelated"
        other.write_bytes(b"unrelated")
        self.destination.symlink_to(other)
        with mock.patch.object(
            installer,
            "download",
            side_effect=lambda url, output: output.write(self.binary),
        ):
            self.install_aqf()
        self.assertFalse(self.destination.is_symlink())
        self.assertEqual(other.read_bytes(), b"unrelated")

    def test_native_hash_known_vector(self):
        path = self.work / "abc"
        path.write_bytes(b"abc")
        self.assertEqual(
            installer.native_sha256(path, self.hash_bin),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        with (
            mock.patch.object(
                installer.subprocess,
                "run",
                return_value=mock.Mock(returncode=0, stdout=b"fake"),
            ),
            self.assertRaisesRegex(RuntimeError, "Native hasher"),
        ):
            installer.native_sha256(path, self.hash_bin)

    def test_custom_udev_rule_preserved_and_wide_mode_warns(self):
        legacy = self.rules / "51-android.rules"
        content = b'# local administrator\nSUBSYSTEM=="usb", MODE="0666"\n'
        legacy.write_bytes(content)
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            installer.install_udev(self.source, self.rules)
        self.assertEqual(legacy.read_bytes(), content)
        self.assertIn("world-writable", errors.getvalue())
        self.assertEqual(list(self.rules.glob("*.mvt-backup-*")), [])
        self.assertTrue((self.rules / "70-mvt-android.rules").is_file())

    def test_exact_legacy_rule_is_backed_up_then_removed(self):
        legacy = self.rules / "51-android.rules"
        legacy.write_bytes(installer.LEGACY_RULES)
        installer.install_udev(self.source, self.rules)
        self.assertFalse(legacy.exists())
        backups = list(self.rules.glob("51-android.rules.mvt-backup-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), installer.LEGACY_RULES)
        installer.install_udev(self.source, self.rules)
        self.assertEqual(len(list(self.rules.glob("51-android.rules.mvt-backup-*"))), 1)

    def test_near_legacy_or_custom_symlink_is_never_removed(self):
        legacy = self.rules / "51-android.rules"
        content = installer.LEGACY_RULES + b"# administrator addition\n"
        legacy.write_bytes(content)
        installer.install_udev(self.source, self.rules)
        self.assertEqual(legacy.read_bytes(), content)
        legacy.unlink()
        target = self.work / "admin.rules"
        target.write_bytes(installer.LEGACY_RULES)
        legacy.symlink_to(target)
        installer.install_udev(self.source, self.rules)
        self.assertTrue(legacy.is_symlink())
        self.assertEqual(target.read_bytes(), installer.LEGACY_RULES)

    def test_only_interface_specific_non_world_writable_rules_are_installed(self):
        installer.install_udev(self.source, self.rules)
        text = (self.rules / "70-mvt-android.rules").read_text()
        for line in text.splitlines():
            if line.startswith("#") or "MODE" not in line:
                continue
            self.assertIn("ff4201", line)
            self.assertIn('GROUP="adbusers"', line)
            self.assertIn('MODE="0660"', line)
        self.assertNotIn('MODE="0666"', text)
        self.assertEqual(
            {p.name for p in self.rules.iterdir()}, {"70-mvt-android.rules"}
        )

    def test_lock_completeness_and_fixed_urls(self):
        expected = {
            "annotated-types",
            "appdirs",
            "betterproto2",
            "certifi",
            "cffi",
            "charset-normalizer",
            "click",
            "cryptography",
            "idna",
            "iphone-backup-decrypt",
            "markdown-it-py",
            "mdurl",
            "mvt",
            "nskeyedunarchiver",
            "packaging",
            "pip",
            "pyahocorasick",
            "pycparser",
            "pycryptodome",
            "pydantic",
            "pydantic-core",
            "pydantic-settings",
            "pygments",
            "python-dateutil",
            "python-dotenv",
            "pyyaml",
            "requests",
            "rich",
            "setuptools",
            "simplejson",
            "six",
            "tld",
            "typing-extensions",
            "typing-inspection",
            "tzdata",
            "urllib3",
            "wheel",
        }
        packages = installer.locked_requirements(ROOT / "requirements-pinned.txt")
        self.assertEqual(set(packages), expected)
        self.assertEqual(packages["mvt"], self.lock["mvt"]["version"])
        for key, asset in self.lock["androidqf"]["assets"].items():
            self.assertRegex(asset["sha256"], r"^[a-f0-9]{64}$")
            self.assertNotIn("latest", asset["url"])
            self.assertIn(key.removeprefix("linux-"), asset["url"])
        install_text = (ROOT / "install.sh").read_text()
        self.assertIn("--require-hashes", install_text)
        self.assertIn("--only-binary=:all:", install_text)
        self.assertNotIn("/releases/latest", install_text)
        self.assertNotIn("platform-tools-latest", install_text)
        self.assertNotIn("pip install --upgrade", install_text)
        self.assertIn("python -m pip --isolated check", install_text)

    def test_unhashed_or_missing_bootstrap_requirement_is_rejected(self):
        path = self.work / "requirements"
        for text in ["mvt>=2", "mvt==2", "mvt==2 --hash=sha256:" + "a" * 64]:
            path.write_text(text)
            with self.assertRaises(ValueError):
                installer.locked_requirements(path)

    def test_dependency_manifest_version_or_arch_omissions_fail(self):
        for modify in [
            lambda data: data["mvt"].update(version="0"),
            lambda data: data["androidqf"]["assets"].pop("linux-arm64"),
            lambda data: data.update(platform_tools={"url": "unverified"}),
        ]:
            data = copy.deepcopy(self.lock)
            modify(data)
            (self.source / "dependencies.json").write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                installer.load_lock(self.source)

    def test_download_rejects_non_https_and_oversize(self):
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            installer.download("http://example.invalid/a", io.BytesIO())
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.url = "https://example.invalid/a"
        response.headers = {"Content-Length": str(installer.MAX_DOWNLOAD + 1)}
        with (
            mock.patch.object(
                installer.urllib.request, "urlopen", return_value=response
            ) as request,
            self.assertRaisesRegex(ValueError, "size limit"),
        ):
            installer.download(response.url, io.BytesIO())
        self.assertEqual(request.call_args.kwargs["timeout"], 30)

    def test_os_package_versions_are_real_parsed_records(self):
        with (
            mock.patch.object(
                installer.shutil, "which", side_effect=lambda name: name == "dpkg-query"
            ),
            mock.patch.object(
                installer, "run", return_value="ii \tadb\t1.0\nrc \tremoved\t0\n"
            ),
        ):
            self.assertEqual(
                installer.os_packages(), {"manager": "dpkg", "versions": {"adb": "1.0"}}
            )

    def test_provenance_records_verified_files_versions_and_lock_copies(self):
        (self.root / "venv/bin").mkdir(parents=True)
        for name in ["python", "mvt-android"]:
            (self.root / "venv/bin" / name).write_bytes(b"fixture " + name.encode())
        (self.root / "bin/adb").write_bytes(b"fixture adb")
        self.destination.write_bytes(self.binary)
        for name in ["dependencies.json", "requirements-pinned.txt"]:
            shutil.copyfile(self.source / name, self.root / name)
        packages = installer.locked_requirements(
            self.source / "requirements-pinned.txt"
        )
        real_run = installer.run

        def probe(argv, timeout=60):
            if "-c" in argv:
                return json.dumps(packages)
            if argv[0] == str(self.hash_bin):
                return real_run(argv, timeout=timeout)
            if argv[-1] == "--version":
                return "Python fixture version"
            return "Android Debug Bridge fixture version"

        with (
            mock.patch.object(installer, "run", side_effect=probe),
            mock.patch.object(
                installer, "package_owner", return_value="fixture-os-package: /adb"
            ),
            mock.patch.object(
                installer,
                "os_packages",
                return_value={"manager": "fixture", "versions": {"adb": "1"}},
            ),
            mock.patch.object(installer, "target_key", return_value="linux-amd64"),
        ):
            installer.record_install(self.lock, self.source, self.root, self.hash_bin)
            record = json.loads((self.root / "installed-tools.json").read_text())
            self.assertEqual(record["tools"]["androidqf"]["sha256"], self.digest)
            self.assertEqual(record["tools"]["mvt"]["version"], packages["mvt"])
            self.assertEqual(record["tools"]["adb"]["source"], "os-package")
            for name in ["dependencies.json", "requirements-pinned.txt"]:
                self.assertEqual(
                    record["locks"][name],
                    installer.native_sha256(self.root / name, self.hash_bin),
                )
            old_manifest = (self.root / "installed-tools.json").read_bytes()
            (self.root / "requirements-pinned.txt").write_text("tampered")
            with self.assertRaisesRegex(ValueError, "Installed lock copy differs"):
                installer.record_install(
                    self.lock, self.source, self.root, self.hash_bin
                )
            self.assertEqual(
                (self.root / "installed-tools.json").read_bytes(), old_manifest
            )

    def test_provenance_rejects_installed_mvt_version_drift(self):
        packages = installer.locked_requirements(
            self.source / "requirements-pinned.txt"
        )
        packages["mvt"] = "2.0.0"
        with (
            mock.patch.object(installer, "run", return_value=json.dumps(packages)),
            self.assertRaisesRegex(
                ValueError, "Installed Python version does not match"
            ),
        ):
            installer.record_install(self.lock, self.source, self.root, self.hash_bin)
        self.assertFalse((self.root / "installed-tools.json").exists())

    def test_stream_size_and_deadline_bounds(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.url = "https://example.invalid/a"
        response.headers = {}
        response.read1.return_value = b"12345"
        with (
            mock.patch.object(
                installer.urllib.request, "urlopen", return_value=response
            ),
            mock.patch.object(installer, "MAX_DOWNLOAD", 4),
            self.assertRaisesRegex(ValueError, "size limit"),
        ):
            installer.download(response.url, io.BytesIO())
        with (
            mock.patch.object(
                installer.urllib.request, "urlopen", return_value=response
            ),
            mock.patch.object(
                installer.time,
                "monotonic",
                side_effect=[0, installer.DOWNLOAD_SECONDS + 1],
            ),
            self.assertRaisesRegex(TimeoutError, "wall-clock"),
        ):
            installer.download(response.url, io.BytesIO())

    def test_atomic_publish_failure_cleans_stage_and_preserves_old_bytes(self):
        self.destination.write_bytes(b"old binary")
        with (
            mock.patch.object(
                installer,
                "download",
                side_effect=lambda url, output: output.write(self.binary),
            ),
            mock.patch.object(
                installer.os, "replace", side_effect=OSError("failed replace")
            ),
            self.assertRaises(OSError),
        ):
            self.install_aqf()
        self.assertEqual(self.destination.read_bytes(), b"old binary")
        self.assertEqual(list(self.destination.parent.glob(".androidqf-*")), [])

    def test_literal_license_block_and_modules_preserved(self):
        script = (ROOT / "install.sh").read_text()
        block = script.split("# Preserve the licence", 1)[1].split(
            "# Set ownership", 1
        )[0]
        self.assertIn('install -m 644 "$SCRIPT_DIR/LICENSE" /opt/mvt/LICENSE', block)
        self.assertIn(
            'install -m 644 "$SCRIPT_DIR/LICENSES/"*.txt /opt/mvt/LICENSES/', block
        )
        for name in ["mvt-hash", "mvt_hash.py", "mvt_doctor.py", "mvt_evidence.py"]:
            self.assertIn(name, script)
        self.assertLess(
            script.index('make -C "$SCRIPT_DIR" native'),
            script.index('install_dependencies.py" androidqf'),
        )
        self.assertIsNotNone(re.search(r"libssl-dev.*pkg-config", script, re.DOTALL))


if __name__ == "__main__":
    unittest.main()
