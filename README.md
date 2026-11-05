# MVT Android Auto-Runner & Forensics Pipeline

Android acquisition and indicator analysis using Amnesty International’s Mobile Verification Toolkit (MVT) and Android Quick Forensics (`androidqf`). A systemd watcher starts the pipeline when an authorized Android device connects.

This is **not a write-blocked acquisition workflow**: it writes scan state to the phone and stores evidence on the host. A negative result is not proof that a device is clean.

## Contents

- [Installation](#installation)
- [Scanning and notifications](#scanning-and-notifications)
- [Diagnostics](#diagnostics)
- [Evidence and positive results](#evidence-and-positive-results)
- [Signatures and verification](#signatures-and-verification)
- [Storage policy](#storage-policy)
- [Native hashing and development](#native-hashing-and-development)
- [Optional speedup utility](#optional-speedup-utility)
- [Uninstallation](#uninstallation)
- [License](#license)

## Installation

Requirements: Linux, systemd/udev, Python 3.10+, an authorized USB-debugging connection, and network access for installation and indicator updates. A graphical session is optional; notifications and automatic folder opening require the installation user’s desktop session.

```bash
git clone https://github.com/SWORDIntel/mvt-autorun.git
cd mvt-autorun
./setup.sh
```

`setup.sh` delegates to the root-elevating `install.sh`. The installer supports apt, dnf, and pacman branches; that is not a claim that every distro/package combination has been tested. It installs the compiler/OpenSSL dependencies, builds the native hash helper, installs the application tools, downloads indicators, retains the licence files, and enables the watcher.

Application download versions and SHA-256 values are recorded in [`dependencies.json`](dependencies.json). Python dependencies are pinned and hash-checked through [`requirements-pinned.txt`](requirements-pinned.txt). Downloads are verified before installation; existing binaries are not trusted merely because they are present. `installed-tools.json` records the installed selection and provenance. During install, a machine-named Ed25519 signing key is created or safely reused under the target user's `~/.ssh/`; it is not an SSH login key. Its private half is mode 0600, configured for manifest signing, and its public half is retained for trust distribution. Reinstall does not replace the named key. Back up the private key securely; losing it prevents future signatures from that identity, and changing it changes the machine audit label. Distribution packages, the OS, and the compiler remain platform dependencies rather than a bit-for-bit reproducible OS image.

The managed Android USB rule grants group-controlled access to USB devices advertising an Android debugging interface, not world-writable access to every USB device. An exact legacy rule installed by older versions can be backed up and migrated; administrator-written rules are preserved. Other rules can still grant broader access, which must be reviewed separately. Log out and back in for new group membership to apply.

The installer’s desktop dependencies include `gdbus` (`libglib2.0-bin` on Debian, `glib2` on Fedora/Arch). Automatic folder opening uses the standard `org.freedesktop.FileManager1` interface and does not change global desktop notification preferences.

## Scanning and notifications

The watcher monitors `adb track-devices`. Unlock the phone and approve its USB-debugging authorization prompt before scanning.

The first scan notice shows the last recorded successful scan and the next due time in **GMT**. Scheduling uses GMT/UTC calendar days, not rolling 24-hour intervals. New tokens contain ISO 8601 UTC timestamps; older timezone-less tokens are interpreted in the host’s local timezone. A not-due device receives a schedule notice and is skipped. `--force` overrides the due-time check while still showing the recorded schedule.

Due scans report these stages:

| Progress | Stage |
| --- | --- |
| 0% | Schedule checked; scan starting |
| 25% | APK inventory and verified cache synchronization complete |
| 50% | AndroidQF acquisition and per-file metadata enrichment complete |
| 75% | MVT analysis complete |
| 100% | Required evidence preservation and device-state commits complete |

All popups request normal urgency and a 3-second expiry without a resident hint. The desktop notification daemon ultimately controls display timing.

The pipeline inventories **base and split APKs for third-party packages**. Every APK is hashed independently on the device and verified after download or cache reuse. Each run receives independent copies rather than mutable links to the cache. Hashes and signing-certificate metadata are assigned to their matching APK paths, not copied from the base APK to every split. This is still not a full acquisition of all system APKs or all device data.

Run manually as the installation user, replacing `SERIAL` with a value from `adb devices`:

```bash
/opt/mvt/bin/mvt-autorun.sh --serial SERIAL
/opt/mvt/bin/mvt-autorun.sh --serial SERIAL --force
```

Without `--serial`, the first authorized device is selected. A per-device lock prevents overlapping scans of the same phone; different devices have independent run directories.

Phone state is stored in `/sdcard/Documents/.mvt_pkg_hashes`, `.mvt_audit_history` (last five successful machine/key-label audit entries), and `.mvt_last_check`. The package baseline and the last-five-machine audit history are committed before the daily token, only after required collection, analysis, manifest generation, and incident preservation succeed. History entries contain the configured machine key name, UTC audit time and run identifier. Each phone-state file is staged and renamed, but the files are not a cross-file transaction. A failure may leave earlier files advanced; the daily token is written last. Use `--force` to retry if an earlier same-day token exists.

## Diagnostics

`doctor` checks readiness without acquiring a phone, starting a scan, opening a folder, or changing settings:

```bash
/opt/mvt/bin/mvt-autorun.sh doctor
/opt/mvt/bin/mvt-autorun.sh doctor --source /path/to/mvt-autorun --json
```

Checks cover installed-versus-source files, installed tool metadata, service health, ADB authorization, indicator availability/age, storage, desktop integration, and native hashing readiness. Unavailable or incomplete checks are reported rather than silently treated as successful. Indicator age is an operational signal, not a guarantee of detection coverage.

For source-checkout diagnostics:

```bash
make native
python3 bin/mvt-autorun.py doctor --root /opt/mvt --source . --json
```

Useful service commands:

```bash
systemctl status mvt-watcher.service
journalctl -u mvt-watcher.service -f
tail -f /opt/mvt/logs/mvt-autorun.log
```

## Evidence and positive results

The installation uses this layout:

```text
bin/                         Runtime scripts, helpers and mvt-hash
installed-tools.json         Installed application provenance
config.json                  Optional storage/signing policy
indicators/                  Host indicator collection
cache/apks/                  Verified APK cache
state/locks/                 Device, publication and cache locks
output/runs/<id>/            Independent evidence for each run
output/latest                Link to the most recent completed run
output/incidents/<id>/       Preserved positive-result snapshots
```

Each run contains `raw/`, `analysis/`, a run-specific indicator snapshot, lifecycle metadata (`run.json`), and an evidence manifest. Acquisition and analysis logs are `raw/androidqf_run.log` and `analysis/mvt_run.log`. Provenance records the tool selection/fingerprints, timestamps and the indicator data used for the run. Analysis uses the captured indicator set rather than silently loading unrelated host defaults.

A successful **HIGH** or **CRITICAL** result preserves `flagged_apks/` with independently verified APK copies and `findings.json`. Selection follows structured MVT package, hash and path evidence. Package-level findings can identify an application’s APK set; file-specific findings retain the matching artifacts. Unrelated APKs are not labelled malicious. Unmatched findings, including unavailable system APKs and non-APK indicators, remain report-only. MEDIUM results are suspicious but do not meet this automatic preservation/opening threshold.

After a positive scan completes, the preserved incident’s `flagged_apks/` directory is opened in the installation user’s file manager. The installer prints the exact incident location and reminds the operator to inspect and manually delete unwanted suspicious APKs/cases; automatic cleanup never removes incident folders. APKs themselves are **never opened, executed or installed**. A missing desktop/file manager, headless session or D-Bus error produces a warning and the folder path without invalidating the completed scan.

Nonzero tool exits, timeouts, incomplete MVT summaries or required evidence-preservation failures fail the run closed. Failed runs remain available and never become `latest`. Existing legacy `latest` directories are moved to a unique retained legacy run rather than deleted. Completion notices point to the specific run, not a moving link. Updating the convenience `latest` link or final lifecycle metadata can warn after an otherwise successful scan; neither warning turns completed acquisition into a failed scan.

Artifacts and incident copies are not immutable. Keep independent backups and protect access to the host, signing keys and trusted verification material. Detection quality depends on indicators, acquisition coverage and the upstream tools; inspect the evidence, not just the final toast.

## Signatures and verification

The evidence manifest fingerprints stable collected artifacts and records provenance. Mutable top-level `run.json` lifecycle metadata is explicitly excluded, and runtime locks live outside the evidence tree. Final status changes therefore do not invalidate the captured evidence. Verification checks for changed, missing and unexpected artifacts without following paths outside the case.

```bash
/opt/mvt/bin/mvt-autorun.sh verify /opt/mvt/output/runs/RUN_ID
```

Unsigned hash verification detects inconsistency but does **not** authenticate a manifest against an attacker who can replace both the data and manifest.

Optional Ed25519 signing uses an operator-provided private key; the program does not generate one automatically. For example, create a private directory and key outside the evidence tree:

```bash
umask 077
mkdir -p "$HOME/.local/share/mvt-signing"
openssl genpkey -algorithm ED25519 -out "$HOME/.local/share/mvt-signing/private.pem"
openssl pkey -in "$HOME/.local/share/mvt-signing/private.pem" -pubout \
  -out "$HOME/.local/share/mvt-signing/trusted-public.pem"
```

Set `signing_key` in `/opt/mvt/config.json` to the private-key path. Keep private keys access-restricted and preserve the trusted public key independently. Signing errors do not silently fall back to unsigned evidence.

```bash
/opt/mvt/bin/mvt-autorun.sh verify /opt/mvt/output/incidents/INCIDENT_ID \
  --public-key "$HOME/.local/share/mvt-signing/trusted-public.pem" --require-signature
```

A public key stored alongside evidence is not, by itself, a trust anchor. Authenticated verification requires a trusted key supplied independently.

## Storage policy

Collection checks free space before consuming storage, including configured reserve and estimated APK-copy requirements. Insufficient space is a scan failure, not a reason to discard old incidents.

Retention is **disabled by default**. A policy example for `/opt/mvt/config.json` is:

```json
{
  "min_free_bytes": 1073741824,
  "run_retention_days": 30,
  "cache_retention_days": 90,
  "auto_prune": false,
  "signing_key": null
}
```

Preview candidates before explicitly applying a policy:

```bash
/opt/mvt/bin/mvt-autorun.sh prune --run-days 30 --cache-days 90
/opt/mvt/bin/mvt-autorun.sh prune --run-days 30 --cache-days 90 --apply
```

Setting `auto_prune` to `true` opts into automatic cleanup using the configured ages. Incidents, positive results, the latest completed run, active scans and unrecognized legacy data are protected; failed evidence is retained for investigation. Cache cleanup coordinates with active cache users. In addition, after each successful scan the cache drops APK blobs not used by that scan; independent run evidence and suspicious incident copies remain intact. This per-run cache pruning does not delete previously collected run evidence. Logs and protected evidence still require an operator-managed retention/backup policy.

## Native hashing and development

Host file SHA-256 verification uses the compiled `mvt-hash` C binary backed by OpenSSL EVP. There is no silent Python file-hashing fallback. Device-side inventory uses Android’s `sha256sum`; the host helper is not an Android executable.

On Debian, development prerequisites include Python 3.10+, Bash, Make, a C11 compiler, `libssl-dev`, `pkg-config`, and OpenSSL. Equivalent development packages are needed elsewhere.

```bash
make native
bin/mvt-hash --self-test
bin/mvt-hash -- path/to/file.apk
make check
```

The Python adapter supports batched, NUL-delimited filenames so spaces and newlines are not misparsed. Machine-protocol file inputs must be regular files: the native tool rejects symlinks and FIFOs. Human-readable hashing also supports standard input, while NUL-delimited machine inputs always identify literal filenames.

Checks build the real C utility, validate Python/shell syntax, exercise CLI help and run unit plus offline fake-tool integration tests. Crypto tests use temporary keys and real OpenSSL operations. Tests do not require a phone, root, desktop popups or network access. They do not establish actual-device acquisition completeness or live desktop compatibility. CI runs the suite on Python 3.10 and 3.13.

## Optional speedup utility

`system_speedup.py` is a separate device-changing convenience utility, **not** a forensic step. It can change Android settings, permissions and compilation state.

```bash
/opt/mvt/bin/system_speedup.py --serial SERIAL --defaults
/opt/mvt/bin/system_speedup.py --serial SERIAL --apps com.example.app --anim 0
```

## Uninstallation

```bash
sudo ./uninstall.sh
```

Back up evidence and the signing private key first: uninstallation removes `/opt/mvt`, including output, cache, configuration, logs and the virtual environment, but leaves the per-machine signing key and public key in the installation user's `~/.ssh/`. It does not remove installed system packages, groups, USB rules or the `/usr/local/bin/` speedup symlink.

## License

This repository is distributed under the **SWORD Restricted Source Licence (SRSL-1.1)** in [`LICENSE`](LICENSE). It is source-available, not OSI open source. Eligible non-commercial use is permitted subject to the full licence; commercial exploitation requires a separately executed written agreement.

The current text is also available as [`LICENSES/LicenseRef-SRSL-1.1.txt`](LICENSES/LicenseRef-SRSL-1.1.txt). [`LICENSES/SRSL-1.0.txt`](LICENSES/SRSL-1.0.txt) is a historical archive, not an alternative licence choice. The supplied 1.1 text contains internal references to 1.0 and has been copied verbatim; this summary does not amend its terms.

Third-party tools and libraries, including [MVT](https://github.com/mvt-project/mvt), [androidqf](https://github.com/mvt-project/androidqf) and [OpenSSL](https://www.openssl.org/), retain their own licences. This licence does not override them.
