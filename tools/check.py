"""
tools/check.py: Repository verification tool.
Python >= 3.10 stdlib-only.
Checks:
- Compiles Python files without creating __pycache__ or .pyc
- bash -n syntax checks on shell scripts
- Bounded --help smoke tests for scan, doctor, evidence and speedup commands
- Unittest discovery disabling bytecode (-B)
"""

import os
import subprocess
import sys
import unittest

MIN_PYTHON = (3, 10)


def log(msg: str):
    print(f"[check.py] {msg}", flush=True)


def check_python_version():
    log(f"Checking Python version: {sys.version.split()[0]}")
    if sys.version_info < MIN_PYTHON:
        print(
            f"Error: Python >= 3.10 required, current: {sys.version}", file=sys.stderr
        )
        return False
    return True


def check_python_compile(root_dir: str):
    log("Compiling Python files (stdlib compile without bytecode output)...")
    success = True
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [
            name
            for name in dirnames
            if name
            not in {".git", ".venv", "venv", "__pycache__", "output", "cache", "state"}
        ]
        for f in filenames:
            if f.endswith(".py"):
                path = os.path.join(dirpath, f)
                try:
                    with open(path, "rb") as source_file:
                        source_bytes = source_file.read()
                    compile(source_bytes, path, "exec", dont_inherit=True)
                except (OSError, SyntaxError) as e:
                    print(f"Compile error in {path}: {e}", file=sys.stderr)
                    success = False
    return success


def check_bash_scripts(root_dir: str):
    log("Running bash -n on shell scripts...")
    success = True
    scripts = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [
            name
            for name in dirnames
            if name
            not in {".git", ".venv", "venv", "__pycache__", "output", "cache", "state"}
        ]
        for f in filenames:
            path = os.path.join(dirpath, f)
            if f.endswith(".sh"):
                scripts.append(path)
            elif (
                not os.path.islink(path)
                and os.path.isfile(path)
                and os.access(path, os.X_OK)
            ):
                try:
                    with open(path, "rb") as sf:
                        head = sf.read(64)
                    if (
                        head.startswith(b"#!")
                        and b"bash" in head.split(b"\n")[0]
                        and path not in scripts
                    ):
                        scripts.append(path)
                except OSError:
                    pass

    for s in sorted(scripts):
        proc = subprocess.run(
            ["bash", "-n", s], capture_output=True, text=True, timeout=10, check=False
        )
        if proc.returncode != 0:
            print(f"bash -n failed for {s}:\n{proc.stderr}", file=sys.stderr)
            success = False
    return success


def check_help_smoke(root_dir: str):
    log("Running bounded --help smoke test for bin scripts...")
    runtime = os.path.join(root_dir, "bin", "mvt-autorun.py")
    targets = [
        (runtime, ["--help"]),
        (os.path.join(root_dir, "bin", "system_speedup.py"), ["--help"]),
        (runtime, ["doctor", "--help"]),
        (runtime, ["verify", "--help"]),
        (runtime, ["prune", "--help"]),
    ]
    success = True
    for t, args in targets:
        if not os.path.exists(t):
            print(f"Help smoke target not found: {t}", file=sys.stderr)
            success = False
            continue
        try:
            proc = subprocess.run(
                [sys.executable, "-B", t, *args],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode != 0:
                print(
                    f"Help smoke failed for {t} (code {proc.returncode}):\n{proc.stderr}",
                    file=sys.stderr,
                )
                success = False
            elif (
                "--help" not in proc.stdout
                and "usage:" not in proc.stdout.lower()
                and "options:" not in proc.stdout.lower()
            ):
                print(
                    f"Help smoke output unexpected for {t}:\n{proc.stdout}",
                    file=sys.stderr,
                )
                success = False
        except subprocess.TimeoutExpired:
            print(f"Help smoke timed out for {t}", file=sys.stderr)
            success = False
        except (OSError, UnicodeError) as e:
            print(f"Help smoke exception for {t}: {e}", file=sys.stderr)
            success = False
    return success


def run_unit_tests(root_dir: str):
    log("Running unittest discovery (-B / sys.dont_write_bytecode)...")
    sys.dont_write_bytecode = True
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    sys.path.insert(0, os.path.join(root_dir, "bin"))

    loader = unittest.defaultTestLoader
    tests_dir = os.path.join(root_dir, "tests")
    if not os.path.exists(tests_dir):
        print(f"Tests directory not found: {tests_dir}", file=sys.stderr)
        return False

    suite = loader.discover(start_dir=tests_dir, pattern="test_*.py")
    if not suite.countTestCases():
        print("No unit tests discovered", file=sys.stderr)
        return False
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


def main():
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    checks = [
        check_python_version,
        lambda: check_python_compile(root_dir),
        lambda: check_bash_scripts(root_dir),
        lambda: check_help_smoke(root_dir),
        lambda: run_unit_tests(root_dir),
    ]

    for c in checks:
        if not c():
            log("FAILED verification check.")
            sys.exit(1)

    log("ALL verification checks passed.")
    sys.exit(0)


if __name__ == "__main__":
    main()
