import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class RepositoryTests(unittest.TestCase):
    def test_current_license_matches_archived_version(self):
        current = (ROOT / "LICENSE").read_bytes()
        archived = (ROOT / "LICENSES" / "LicenseRef-SRSL-1.1.txt").read_bytes()
        self.assertEqual(current, archived)
        self.assertTrue(
            current.startswith(b"SWORD RESTRICTED SOURCE LICENCE (SRSL-1.1)")
        )

    def test_older_license_archive_exists(self):
        self.assertTrue((ROOT / "LICENSES" / "SRSL-1.0.txt").is_file())

    def test_installer_preserves_license_notice_and_commands_work_in_temp_tree(self):
        installer = (ROOT / "install.sh").read_text()
        start_marker = (
            "# Preserve the licence and version archive with installed copies."
        )
        end_marker = "# Set ownership"
        self.assertIn(start_marker, installer)
        self.assertIn(end_marker, installer)
        block = installer.split(start_marker, 1)[1].split(end_marker, 1)[0]
        expected = [
            'install -m 644 "$SCRIPT_DIR/LICENSE" /opt/mvt/LICENSE',
            "mkdir -p /opt/mvt/LICENSES",
            'install -m 644 "$SCRIPT_DIR/LICENSES/"*.txt /opt/mvt/LICENSES/',
        ]
        for command in expected:
            self.assertIn(command, block)

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            (source / "LICENSE").write_bytes((ROOT / "LICENSE").read_bytes())
            (source / "LICENSES").mkdir()
            for archive in (ROOT / "LICENSES").glob("*.txt"):
                (source / "LICENSES" / archive.name).write_bytes(archive.read_bytes())
            destination = root / "opt" / "mvt"
            destination.mkdir(parents=True)
            script = (
                "#!/usr/bin/env bash\nset -euo pipefail\nSCRIPT_DIR="
                + repr(str(source))
                + "\n"
                + start_marker
                + block.replace("/opt/mvt", str(destination))
            )
            subprocess.run(["bash", "-c", script], check=True, timeout=10)
            self.assertEqual(
                (destination / "LICENSE").read_bytes(),
                (source / "LICENSE").read_bytes(),
            )
            self.assertEqual(
                {p.name for p in (destination / "LICENSES").glob("*.txt")},
                {p.name for p in (source / "LICENSES").glob("*.txt")},
            )
            for archive in (source / "LICENSES").glob("*.txt"):
                self.assertEqual(
                    (destination / "LICENSES" / archive.name).read_bytes(),
                    archive.read_bytes(),
                )


if __name__ == "__main__":
    unittest.main()
