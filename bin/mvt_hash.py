"""SHA256 file hashing through the required native OpenSSL utility (Python 3.10+)."""

import os
import re
import subprocess
from collections.abc import Iterable
from pathlib import Path


class HashError(RuntimeError):
    """The native hasher failed or returned an invalid response."""


HASH_TIMEOUT = 300
_DIGEST = re.compile(rb"[0-9a-f]{64}\Z")


def hash_files(
    paths: Iterable[str | os.PathLike[str]],
    binary: str | os.PathLike[str] | None = None,
) -> dict[str, str]:
    """Hash regular, non-symlink files in one native invocation; fail atomically."""
    names = []
    encoded = []
    try:
        for path in paths:
            name = os.fsdecode(os.fspath(path))
            raw = os.fsencode(name)
            if not raw or b"\0" in raw:
                raise HashError(
                    "Native hashing requires nonempty filenames without NUL bytes"
                )
            names.append(name)
            encoded.append(raw)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise HashError(f"Invalid filename for native hashing: {exc}") from exc
    if not names:
        return {}

    executable = (
        binary
        if binary is not None
        else os.environ.get(
            "MVT_HASH_BIN", str(Path(__file__).resolve().with_name("mvt-hash"))
        )
    )
    try:
        proc = subprocess.run(
            [os.fspath(executable), "--files0-from", "-", "--zero"],
            input=b"\0".join(encoded) + b"\0",
            capture_output=True,
            timeout=HASH_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise HashError(
            f"Native hashing timed out after {HASH_TIMEOUT} seconds"
        ) from exc
    except (OSError, TypeError, ValueError) as exc:
        raise HashError(f"Cannot execute native hasher {executable!r}: {exc}") from exc
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", errors="replace").strip()
        raise HashError(
            f"Native hasher failed (exit {proc.returncode}): {detail or 'no diagnostic'}"
        )
    if len(proc.stdout) != len(names) * 65:
        raise HashError("Native hasher returned incomplete or malformed output")
    digests = proc.stdout.split(b"\0")
    if digests[-1] != b"" or any(
        _DIGEST.fullmatch(digest) is None for digest in digests[:-1]
    ):
        raise HashError("Native hasher returned malformed SHA256 output")
    return dict(zip(names, (digest.decode("ascii") for digest in digests[:-1])))


def hash_file(
    path: str | os.PathLike[str],
    binary: str | os.PathLike[str] | None = None,
) -> str:
    """Return the native SHA256 digest for one regular, non-symlink file."""
    return next(iter(hash_files([path], binary=binary).values()))
