"""Real OpenSSL native-hasher tests; hashlib is only an independent test oracle."""

import hashlib
import importlib.util
import os
import resource
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "bin" / "mvt-hash"
SPEC = importlib.util.spec_from_file_location(
    "native_hash_under_test", ROOT / "bin" / "mvt_hash.py"
)
hasher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hasher)


class NativeHashTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build = subprocess.run(
            ["make", "native"], cwd=ROOT, capture_output=True, timeout=60, check=False
        )
        if build.returncode:
            raise RuntimeError(
                f"Native build failed: {build.stdout!r} {build.stderr!r}"
            )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def file(self, name="sample", data=b"abc"):
        path = self.directory / name
        path.write_bytes(data)
        return path

    def native(self, *args, data=None, cwd=None):
        return subprocess.run(
            [str(BINARY), *args],
            input=data,
            capture_output=True,
            timeout=10,
            check=False,
            cwd=cwd,
        )

    def machine(self, data):
        return self.native("--files0-from", "-", "--zero", data=data)

    def fake_binary(self, body):
        path = self.directory / "fake hasher"
        path.write_text(f"#!{sys.executable}\n{body}\n", encoding="utf-8")
        path.chmod(0o700)
        return path

    def test_version(self):
        result = self.native("--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"mvt-hash", result.stdout)
        self.assertIn(b"OpenSSL", result.stdout)

    def test_self_test_without_files_or_writes(self):
        result = self.native("--self-test", cwd=self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"self-test OK", result.stdout)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_known_vectors(self):
        vectors = [
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (
                b"abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
        ]
        for i, (data, expected) in enumerate(vectors):
            with self.subTest(data=data):
                path = self.file(str(i), data)
                self.assertEqual(hasher.hash_file(path, binary=BINARY), expected)
                proc = self.native("--", str(path))
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(
                    proc.stdout, expected.encode() + b"  " + os.fsencode(path) + b"\n"
                )

    def test_random_and_multimegabyte_files(self):
        for size in [1, 65535, 65536, 65537, 4 * 1024 * 1024 + 113]:
            with self.subTest(size=size):
                data = os.urandom(size)
                path = self.file(str(size), data)
                self.assertEqual(
                    hasher.hash_file(path, binary=BINARY),
                    hashlib.sha256(data).hexdigest(),
                )

    def test_batch_path_encoding_and_order(self):
        names = [
            "with spaces",
            "with\nnewline",
            "évidence-证据",
            "-dash",
            "back\\slash",
        ]
        paths = [self.file(name, os.fsencode(name)) for name in names]
        expected = {
            str(path): hashlib.sha256(os.fsencode(path.name)).hexdigest()
            for path in paths
        }
        self.assertEqual(hasher.hash_files(iter(paths), binary=BINARY), expected)
        result = self.machine(b"\0".join(os.fsencode(path) for path in paths) + b"\0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            b"".join(value.encode() + b"\0" for value in expected.values()),
        )
        self.assertEqual(result.stderr, b"")

    def test_relative_dash_name_is_not_an_option(self):
        path = self.file("--self-test")
        result = self.native("--", path.name, cwd=self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            hashlib.sha256(b"abc").hexdigest().encode() + b"  --self-test\n",
        )
        result = self.native(
            "--files0-from", "-", "--zero", data=b"--self-test\0", cwd=self.directory
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout, hashlib.sha256(b"abc").hexdigest().encode() + b"\0"
        )

    def test_undecodable_filename_roundtrip(self):
        path = self.file(os.fsdecode(b"invalid-\xff"), b"opaque filename")
        expected = hashlib.sha256(b"opaque filename").hexdigest()
        self.assertEqual(
            hasher.hash_files([path], binary=BINARY), {str(path): expected}
        )

    def test_large_batch_chunk_boundaries_and_descriptor_cleanup(self):
        path = self.file("a" * 180)
        count = 1500
        payload = (os.fsencode(path) + b"\0") * count
        self.assertGreater(len(payload), 65536)

        def limit_descriptors():
            resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))

        result = subprocess.run(
            [str(BINARY), "--files0-from", "-", "--zero"],
            input=payload,
            capture_output=True,
            timeout=20,
            check=False,
            preexec_fn=limit_descriptors,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout, (hashlib.sha256(b"abc").hexdigest().encode() + b"\0") * count
        )
        self.assertEqual(
            hasher.hash_files([path, path], binary=BINARY),
            {str(path): hashlib.sha256(b"abc").hexdigest()},
        )

    def test_empty_batch_does_not_execute(self):
        self.assertEqual(hasher.hash_files([], binary="/does/not/exist"), {})
        result = self.machine(b"")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_rejects_malformed_machine_input(self):
        path = self.file()
        for data in [
            b"\0",
            os.fsencode(path),
            os.fsencode(path) + b"\0\0",
            b"x" * 4096 + b"\0",
        ]:
            with self.subTest(data=data[:60]):
                result = self.machine(data)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(result.stderr)

    def test_rejects_missing_directory_symlink_and_fifo(self):
        regular = self.file()
        link = self.directory / "link"
        link.symlink_to(regular)
        fifo = self.directory / "fifo"
        os.mkfifo(fifo)
        for path in [self.directory / "missing", self.directory, link, fifo]:
            with self.subTest(path=path):
                result = self.machine(os.fsencode(path) + b"\0")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
                self.assertTrue(result.stderr)
                with self.assertRaises(hasher.HashError):
                    hasher.hash_file(path, binary=BINARY)

    def test_partial_success_is_not_returned(self):
        path = self.file()
        missing = self.directory / "missing"
        result = self.machine(os.fsencode(path) + b"\0" + os.fsencode(missing) + b"\0")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            result.stdout, hashlib.sha256(b"abc").hexdigest().encode() + b"\0"
        )
        with self.assertRaisesRegex(hasher.HashError, "Native hasher failed"):
            hasher.hash_files([path, missing], binary=BINARY)

    def test_human_mode_reports_failed_paths(self):
        path = self.file()
        result = self.native("--", str(self.directory / "missing"), str(path))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(hashlib.sha256(b"abc").hexdigest().encode(), result.stdout)

    def test_invalid_cli_forms(self):
        for args in [
            ("--",),
            ("--zero",),
            ("--files0-from", "file", "--zero"),
            ("--files0-from", "-", "--zero", "extra"),
            ("--self-test", "extra"),
        ]:
            with self.subTest(args=args):
                result = self.native(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")

    def test_unified_human_stdin_and_hash_subcommand_are_preserved(self):
        result = self.native(data=b"abc")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout, hashlib.sha256(b"abc").hexdigest().encode() + b"  -\n"
        )
        executable = self.directory / "mvt-tools"
        executable.symlink_to(BINARY)
        path = self.file()
        result = subprocess.run(
            [str(executable), "hash", "--files0-from", "-", "--zero"],
            input=os.fsencode(path) + b"\0",
            capture_output=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout, hashlib.sha256(b"abc").hexdigest().encode() + b"\0"
        )

    def test_adapter_default_env_and_explicit_override(self):
        path = self.file()
        digest = hashlib.sha256(b"abc").hexdigest()
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(hasher.hash_file(path), digest)
        with mock.patch.dict(os.environ, {"MVT_HASH_BIN": str(BINARY)}):
            self.assertEqual(hasher.hash_file(path), digest)
        with mock.patch.dict(os.environ, {"MVT_HASH_BIN": "/does/not/exist"}):
            self.assertEqual(hasher.hash_file(path, binary=BINARY), digest)
            with self.assertRaisesRegex(
                hasher.HashError, "Cannot execute native hasher"
            ):
                hasher.hash_file(path)

    def test_adapter_rejects_invalid_names_before_execution(self):
        for name in ["", "nul\0name", None, 123]:
            with (
                self.subTest(name=name),
                mock.patch.object(hasher.subprocess, "run") as run,
            ):
                with self.assertRaises(hasher.HashError):
                    hasher.hash_file(name, binary=BINARY)
                run.assert_not_called()

    def test_adapter_missing_and_nonexecutable_binary(self):
        for binary in [self.directory / "absent", self.file("not executable", b"data")]:
            with (
                self.subTest(binary=binary),
                self.assertRaisesRegex(hasher.HashError, "Cannot execute"),
            ):
                hasher.hash_file(self.file(), binary=binary)

    def test_adapter_uses_binary_protocol_and_bounded_timeout(self):
        path = self.file("line\nname")
        digest = hashlib.sha256(b"abc").hexdigest()
        response = subprocess.CompletedProcess([], 0, digest.encode() + b"\0", b"")
        with mock.patch.object(hasher.subprocess, "run", return_value=response) as run:
            self.assertEqual(hasher.hash_file(path, binary=BINARY), digest)
        args, kwargs = run.call_args
        self.assertEqual(args[0], [str(BINARY), "--files0-from", "-", "--zero"])
        self.assertEqual(kwargs["input"], os.fsencode(path) + b"\0")
        self.assertEqual(kwargs["timeout"], 300)
        self.assertNotIn("shell", kwargs)
        self.assertNotIn("text", kwargs)

    def test_adapter_rejects_malformed_success_output(self):
        valid = hashlib.sha256(b"abc").hexdigest().encode()
        outputs = [
            b"",
            valid,
            valid + b"\n",
            valid.upper() + b"\0",
            b"g" * 64 + b"\0",
            valid + b"\0extra",
            (valid + b"\0") * 2,
            b"\xff" * 64 + b"\0",
            b"\0" + valid,
            valid[:32] + b"\0" + valid[32:],
        ]
        for output in outputs:
            with self.subTest(output=output):
                binary = self.fake_binary(
                    f"import sys\nsys.stdout.buffer.write({output!r})"
                )
                with self.assertRaisesRegex(hasher.HashError, "malformed|incomplete"):
                    hasher.hash_file(self.file(), binary=binary)

    def test_adapter_rejects_partial_batch_output(self):
        valid = hashlib.sha256(b"abc").hexdigest().encode() + b"\0"
        binary = self.fake_binary(f"import sys\nsys.stdout.buffer.write({valid!r})")
        with self.assertRaisesRegex(hasher.HashError, "incomplete"):
            hasher.hash_files([self.file("one"), self.file("two")], binary=binary)

    def test_adapter_reports_nonzero_with_output_and_invalid_utf8_error(self):
        binary = self.fake_binary(
            "import sys\nsys.stdout.buffer.write(b'a' * 64 + b'\\0')\n"
            "sys.stderr.buffer.write(b'failure \\xff')\nsys.exit(7)"
        )
        with self.assertRaisesRegex(hasher.HashError, "exit 7.*failure"):
            hasher.hash_file(self.file(), binary=binary)

    def test_adapter_real_subprocess_timeout(self):
        binary = self.fake_binary("import time\ntime.sleep(60)")
        with (
            mock.patch.object(hasher, "HASH_TIMEOUT", 0.05),
            self.assertRaisesRegex(hasher.HashError, "timed out"),
        ):
            hasher.hash_file(self.file(), binary=binary)


if __name__ == "__main__":
    unittest.main()
