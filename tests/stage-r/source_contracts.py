#!/usr/bin/env python3
"""Unprivileged Stage R source/package contracts.

These checks intentionally inspect source artifacts only.  They do not start
systemd units, install a package, contact Docker, or claim boot/network proof.
The corresponding runtime assertions remain Stage R2 gates.
"""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    path = ROOT / relative
    if not path.is_file():
        raise AssertionError(f"required source artifact is missing: {relative}")
    return path.read_text(encoding="utf-8")


def logical_lines(text: str) -> list[str]:
    """Join backslash continuations without interpreting shell syntax."""
    result: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        result.append(pending + line)
        pending = ""
    if pending:
        result.append(pending)
    return result


def parse_unit(relative: str) -> dict[str, dict[str, list[str]]]:
    """Parse the small systemd subset needed by these static contracts."""
    sections: dict[str, dict[str, list[str]]] = defaultdict(
        lambda: defaultdict(list)
    )
    section = ""
    for number, raw in enumerate(logical_lines(read(relative)), start=1):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if not section or "=" not in line:
            raise AssertionError(
                f"{relative}:{number}: malformed unit line for contract parser: {raw!r}"
            )
        key, value = line.split("=", 1)
        sections[section][key].append(value.strip())
    return sections


def values(unit: dict[str, dict[str, list[str]]], section: str, key: str) -> list[str]:
    return list(unit.get(section, {}).get(key, []))


def words(unit: dict[str, dict[str, list[str]]], section: str, key: str) -> set[str]:
    result: set[str] = set()
    for value in values(unit, section, key):
        try:
            result.update(shlex.split(value, posix=True))
        except ValueError as exc:
            raise AssertionError(f"invalid {section}.{key} value {value!r}: {exc}") from exc
    return result


def one(unit: dict[str, dict[str, list[str]]], section: str, key: str) -> str:
    found = values(unit, section, key)
    if len(found) != 1:
        raise AssertionError(
            f"expected exactly one {section}.{key}, found {len(found)}: {found!r}"
        )
    return found[0]


class InstallerLifecycleContracts(unittest.TestCase):
    INSTALLERS = (
        "scripts/install.sh",
        "packaging/deb/preinst",
        "packaging/deb/postinst",
        "packaging/deb/prerm",
        "packaging/deb/postrm",
    )

    # daemon-reload and read-only status queries are deliberately absent from
    # this list.  Package/runtime execution is still proved only in Stage R2.
    FORBIDDEN_ALL = (
        "enable",
        "reenable",
        "preset",
        "preset-all",
        "start",
        "restart",
        "try-restart",
        "reload",
        "reload-or-restart",
    )

    def test_installers_never_activate_or_restart_units(self) -> None:
        failures: list[str] = []
        forbidden = "|".join(re.escape(item) for item in self.FORBIDDEN_ALL)
        command = re.compile(
            rf"\bsystemctl\b[^\n;|&]*?(?:^|[\s])({forbidden})(?=$|[\s])",
            re.MULTILINE,
        )
        alternate_frontend = re.compile(
            r"\b(?:deb-systemd-invoke|invoke-rc\.d|service)\b[^\n;|&]*"
            r"\b(?:start|restart|try-restart|force-reload)\b|"
            r"\bupdate-rc\.d\b[^\n;|&]*\b(?:defaults|enable)\b"
        )
        for relative in self.INSTALLERS:
            joined = "\n".join(logical_lines(read(relative)))
            for match in command.finditer(joined):
                failures.append(
                    f"{relative}: forbidden systemctl lifecycle verb {match.group(1)!r}"
                )
            if alternate_frontend.search(joined):
                failures.append(
                    f"{relative}: alternate service frontend can enable/activate/restart a unit"
                )
        self.assertFalse(
            failures,
            "install/package scripts must leave every NFTFW unit inactive; "
            "daemon-reload and read-only queries are allowed:\n- " + "\n- ".join(failures),
        )

    def test_portable_installer_does_not_stop_or_disable_existing_units(self) -> None:
        source = "\n".join(logical_lines(read("scripts/install.sh")))
        mutation = re.search(
            r"\bsystemctl\b[^\n;|&]*?(?:^|[\s])"
            r"(stop|disable|mask|unmask|reset-failed|set-property|add-wants|add-requires)"
            r"(?=$|[\s])",
            source,
            re.MULTILINE,
        )
        self.assertIsNone(
            mutation,
            "scripts/install.sh may run daemon-reload and inspect state, but must not "
            f"mutate service lifecycle state (found {mutation.group(1)!r})"
            if mutation
            else "",
        )

    def test_upgrade_prerm_has_no_service_mutation(self) -> None:
        source = "\n".join(logical_lines(read("packaging/deb/prerm")))
        upgrade = re.search(r"\bupgrade\)(.*?)(?:;;|\besac\b)", source, re.DOTALL)
        if upgrade is None:
            return
        self.assertNotRegex(
            upgrade.group(1),
            r"\b(?:systemctl|deb-systemd-invoke|invoke-rc\.d|service)\b",
            "the corrected-package upgrade path must preserve active/inactive state; "
            "the upgrade case may not invoke a service manager",
        )

    def test_deb_preinst_rejects_retained_legacy_state_on_fresh_install(self) -> None:
        source = read("packaging/deb/preinst")
        refusal = source.find('if [ -e "$state_dir/state.db" ]')
        fresh_install_exit = source.find('if [ -z "$old_version" ]')
        self.assertGreaterEqual(refusal, 0, "preinst is missing the legacy-state refusal")
        self.assertGreater(
            fresh_install_exit,
            refusal,
            "legacy state retained after package removal must be rejected before the "
            "fresh-install fast path can exit",
        )

    def test_fresh_install_does_not_adopt_unversioned_canonical_state(self) -> None:
        package = read("packaging/deb/preinst")
        portable = read("scripts/install.sh")
        self.assertIn(
            "Refusing retained or shadowing NFTFW state on a fresh install",
            package,
            "dpkg install without an old version must not adopt state retained from an "
            "unknown or newer removed package",
        )
        unknown_portable_upgrade = portable.split('elif [[ -e "$DATABASE"', 1)
        self.assertEqual(len(unknown_portable_upgrade), 2)
        self.assertIn(
            '-e "$DATABASE"',
            'elif [[ -e "$DATABASE"' + unknown_portable_upgrade[1].split("]]", 1)[0],
            "the source installer must refuse canonical state when no installed binary "
            "can establish its version",
        )
        for marker in ("enforcement-enabled", "provenance-ledger.db"):
            self.assertIn(
                marker,
                package,
                f"dpkg fresh install must refuse retained {marker} evidence",
            )
            self.assertIn(
                marker,
                portable,
                f"source fresh install must refuse retained {marker} evidence",
            )
        for shadow in (
            "/etc/systemd/system/nftfwd.service",
            "/run/systemd/system/nftfwd.service",
            "/usr/local/lib/systemd/system/nftfwd.service",
        ):
            root = shadow.rsplit("/", 1)[0]
            self.assertIn(
                root,
                package,
                f"package install/upgrade must fail closed on shadowing unit root {root}",
            )
        for unit in (
            "nftfw-early.service",
            "nftfw-enforcement-ready.service",
            "nftfw-rollback.service",
            "nftfw-rollback.timer",
            "nftfw-setup-rollback.service",
            "nftfw-setup-rollback.timer",
            "nftfw-setup-boot-hold.service",
            "nftfw-setup-docker-hold.service",
            "nftfw-managed-rollback.service",
            "nftfw-managed-rollback.timer",
            "nftfw-vpn.service",
            "nftfw-web.service",
            "nftfwd.service",
        ):
            self.assertIn(unit, package)

    def test_deb_preinst_refuses_a_newer_installed_version(self) -> None:
        preinst = read("packaging/deb/preinst")
        builder = read("scripts/build-deb.sh")
        self.assertIn("package_version='@VERSION@'", preinst)
        self.assertIn("package_commit='@COMMIT@'", preinst)
        self.assertIn(
            'dpkg --compare-versions "$old_version" gt "$package_version"',
            preinst,
            "a 2.0.3 package must not open state from a future/newer package",
        )
        self.assertIn(
            '-e "s/@VERSION@/$version/g" -e "s/@COMMIT@/$candidate_commit/g"',
            builder,
            "the package builder must bind version and commit guards to protected "
            "candidate metadata",
        )
        self.assertIn(
            '"$installed_identity_commit" != "$package_commit"',
            preinst,
            "a same-version package reinstall must refuse a different commit",
        )
        self.assertIn(
            '"$identity_version" == "$version"',
            builder,
            "the package version must match the binary identity used for commit binding",
        )
        portable = read("scripts/install.sh")
        self.assertIn(
            "read -r candidate_version candidate_commit",
            portable,
            "the source installer must extract both candidate identity fields",
        )
        self.assertIn(
            'dpkg --compare-versions "$installed_version" gt "$candidate_version"',
            portable,
            "portable upgrade ordering must use Debian version semantics",
        )
        self.assertIn(
            'dpkg --validate-version "$installed_version"',
            portable,
            "portable upgrades must reject an ambiguous version before comparing it",
        )
        self.assertLess(
            portable.index(
                'dpkg --compare-versions "$installed_version" gt "$candidate_version"'
            ),
            portable.index("case \"$installed_version\" in"),
            "the source installer must reach the newer-version refusal before its "
            "2.0.2/2.0.3 compatibility-family gate",
        )
        self.assertIn(
            '"$installed_commit" != "$candidate_commit"',
            portable,
            "a same-version source install must refuse different commit identity",
        )
        self.assertIn(
            '[[ "$commit" =~ ^[0-9a-f]{40}$ ]]',
            portable,
            "candidate and installed identities must refuse unknown/short commits",
        )

    def test_deb_preinst_version_substitution_preserves_only_the_guard_value(self) -> None:
        source = read("packaging/deb/preinst")
        staged = source.replace("@VERSION@", "2.0.3~rc1").replace(
            "@COMMIT@", "a" * 40
        ).replace("@BUILD_DISPOSITION@", "release")
        self.assertNotIn("@VERSION@", staged)
        self.assertNotIn("@COMMIT@", staged)
        self.assertNotIn("@BUILD_DISPOSITION@", staged)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", prefix="nftfw-preinst-", delete=True
        ) as script:
            script.write(staged)
            script.flush()
            result = subprocess.run(
                ["dash", script.name, "abort-upgrade", "2.0.3~rc0"],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("was not substituted safely", result.stderr)

    def test_deb_preinst_intrinsically_refuses_non_release_payloads(self) -> None:
        staged = (
            read("packaging/deb/preinst")
            .replace("@VERSION@", "2.0.3~stage.r.aaaaaaaaaaaa")
            .replace("@COMMIT@", "a" * 40)
            .replace("@BUILD_DISPOSITION@", "stage-r-candidate-only")
        )
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", prefix="nftfw-candidate-preinst-", delete=True
        ) as script:
            script.write(staged)
            script.flush()
            result = subprocess.run(
                ["dash", script.name, "install", "2.0.3~stage.r.old"],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Stage R candidate package", result.stderr)

        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", prefix="nftfw-candidate-abort-", delete=True
        ) as script:
            script.write(staged)
            script.flush()
            recovery = subprocess.run(
                ["dash", script.name, "abort-upgrade", "2.0.3~stage.r.old"],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(recovery.returncode, 0, recovery.stderr)

    @unittest.skipUnless(shutil.which("dpkg"), "dpkg is required by installers")
    def test_debian_version_ordering_allows_rc_to_final_but_refuses_downgrade(self) -> None:
        def compare(left: str, operator: str, right: str) -> bool:
            return subprocess.run(
                ["dpkg", "--compare-versions", left, operator, right],
                check=False,
            ).returncode == 0

        self.assertTrue(compare("2.0.3~rc1", "lt", "2.0.3"))
        self.assertTrue(compare("2.0.3+ci", "gt", "2.0.3"))
        self.assertTrue(compare("2.0.3", "gt", "2.0.2"))

    def test_portable_binary_identity_parser_rejects_ambiguous_builds(self) -> None:
        source = read("scripts/install.sh")
        match = re.search(r"(?ms)^binary_identity\(\) \{\n.*?^\}\n", source)
        self.assertIsNotNone(match, "portable identity parser is missing")
        function = match.group(0) if match else ""

        def identify(output: str) -> subprocess.CompletedProcess[str]:
            with tempfile.TemporaryDirectory(prefix="nftfw-identity-contract-") as temp:
                fake = Path(temp) / "nftfw"
                fake.write_text(
                    "#!/bin/sh\nprintf '%s\\n' " + shlex.quote(output) + "\n",
                    encoding="utf-8",
                )
                fake.chmod(0o755)
                return subprocess.run(
                    ["bash", "-c", function + '\nbinary_identity "$1"', "contract", str(fake)],
                    check=False,
                    capture_output=True,
                    text=True,
                )

        commit = "a" * 40
        accepted = identify(
            '{"version":"2.0.3~rc1","commit":"'
            + commit
            + '","build_date":"2026-08-24T00:00:00Z",'
            '"build_disposition":"release",'
            '"artifact_identity":"2.0.3~rc1|'
            + commit
            + '|2026-08-24T00:00:00Z|release"}'
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual(accepted.stdout, f"2.0.3~rc1 {commit} release\n")
        self.assertNotEqual(
            identify(
                '{"version":"2.0.3","commit":"unknown",'
                '"build_date":"unknown","build_disposition":"release",'
                '"artifact_identity":"2.0.3|unknown|unknown|release"}'
            ).returncode,
            0,
        )
        self.assertNotEqual(
            identify(
                '{"version":"2.0.3","commit":"'
                + commit
                + '","build_date":"now","build_disposition":"release",'
                '"artifact_identity":"2.0.3|'
                + commit
                + '|now|release"}'
            ).returncode,
            0,
        )
        self.assertEqual(
            identify(
                '{"version":"2.0.3","commit":"'
                + commit
                + '","build_date":"2026-08-24T00:00:00Z",'
                '"build_disposition":"stage-r-candidate-only",'
                '"artifact_identity":"2.0.3|'
                + commit
                + '|2026-08-24T00:00:00Z|stage-r-candidate-only"}'
            ).returncode,
            0,
            "the parser recognizes candidate identity so the installer can issue its "
            "explicit non-release refusal",
        )

    def test_existing_canonical_state_must_be_exact_schema_six(self) -> None:
        package = read("packaging/deb/preinst")
        portable = read("scripts/install.sh")
        for relative, source in (
            ("packaging/deb/preinst", package),
            ("scripts/install.sh", portable),
        ):
            self.assertIn(
                "1,2,3,4,5,6",
                source,
                f"{relative} must bind compatible state to exact schema 6 history",
            )
            self.assertIn(
                "mode=ro&immutable=1",
                source,
                f"{relative} schema inspection must not create or alter SQLite sidecars",
            )
            self.assertIn(
                "SELECT group_concat(version, ',')",
                source,
                f"{relative} must reject missing, extra, or noncontiguous migrations",
            )
        self.assertIn("sqlite3", read("packaging/deb/control"))
        self.assertLess(
            portable.index("existing_canonical_state=false"),
            portable.index('install -d -o root -g root -m 0755 "$BIN_DIR"'),
            "the source installer must reject an incompatible schema before durable "
            "installation-directory or account changes",
        )

    def test_offline_legacy_migration_is_explicit_locked_and_non_overwriting(self) -> None:
        command = read("cmd/nftfw/main.go")
        migration = read("internal/state/offline_migration.go")
        acceptance = read("tests/acceptance/database.sh")
        self.assertIn('args[0] != "migrate"', command)
        self.assertIn("state.MigrateOffline(", command)
        self.assertIn("state.WithMutationLock(", command)
        self.assertIn("--backup", command)
        for contract in (
            "MutationLockHeld(ctx)",
            "schema 1..%d",
            "validateLegacyObjects",
            "copyRegularFileExclusive",
            "legacy database changed while its protected backup was created",
            "OpenReadOnly(ctx, work)",
            "os.Link(work, destination)",
            "legacy source changed during offline migration",
        ):
            self.assertIn(contract, migration)
        self.assertNotIn("os.Rename(work, destination)", migration)
        self.assertIn("state migrate", acceptance)
        self.assertIn("1,2,3,4,5,6", acceptance)
        self.assertIn("V1-TO-V6", acceptance)

    def test_upgrade_backups_are_unique_and_never_overwritten(self) -> None:
        package = read("packaging/deb/preinst")
        portable = read("scripts/install.sh")
        self.assertIn("state-before-package-upgrade-$stamp-$$.db", package)
        self.assertIn('if [ -e "$backup" ] || [ -L "$backup" ]', package)
        self.assertIn("state-before-install-$(date -u +%Y%m%dT%H%M%SZ)-$$.db", portable)
        self.assertIn('[[ ! -e "$backup" && ! -L "$backup" ]]', portable)
        for relative, source in (
            ("packaging/deb/preinst", package),
            ("scripts/install.sh", portable),
        ):
            self.assertNotIn(
                'rm -f "$backup"',
                source,
                f"{relative} must preserve a failed or ambiguous backup for diagnosis",
            )

    def test_existing_state_backup_uses_canonical_lock_without_service_activation(self) -> None:
        for relative in ("packaging/deb/preinst", "scripts/install.sh"):
            source = "\n".join(logical_lines(read(relative)))
            self.assertIn(
                'install -d -o root -g nftfw-web -m 0750 "$runtime_dir"'
                if relative.endswith("preinst")
                else 'install -d -o root -g nftfw-web -m 0750 "$RUNTIME_DIR"',
                source,
                f"{relative} must establish the canonical lock directory even when all "
                "RuntimeDirectory-owning units are stopped",
            )
            self.assertIn(
                'NFTFW_RUNTIME_DIR="$runtime_dir"'
                if relative.endswith("preinst")
                else 'NFTFW_RUNTIME_DIR="$RUNTIME_DIR"',
                source,
                f"{relative} must bind backup to /run/nftfw/mutation.lock",
            )
            self.assertIn(
                "no unlocked fallback was attempted",
                source,
                f"{relative} must fail closed when lock acquisition or backup fails",
            )
            self.assertRegex(
                source,
                r'(?:nftfw|installed_binary)"? state verify --database "\$backup"',
                f"{relative} must verify the published backup with the nonmutating CLI",
            )
            self.assertNotRegex(
                source,
                r'(?m)^\s*sqlite3\s+"\$DATABASE|^\s*sqlite3\s+"\$database',
                f"{relative} must not bypass a failed common lock with direct sqlite3",
            )

    def test_fresh_install_creates_only_the_inactive_canonical_lock_directory(self) -> None:
        package = "\n".join(logical_lines(read("packaging/deb/postinst")))
        portable = "\n".join(logical_lines(read("scripts/install.sh")))
        for relative, source, path_word in (
            ("packaging/deb/postinst", package, "/run/nftfw"),
            ("scripts/install.sh", portable, '"$RUNTIME_DIR"'),
        ):
            self.assertIn(
                f"install -d -o root -g nftfw-web -m 0750 {path_word}",
                source,
                f"{relative} must make nftfw plan usable while all units remain inactive",
            )
            self.assertRegex(
                source,
                r'\[ -L "?\$?(?:directory|RUNTIME_DIR)|! -L "\$directory"',
                f"{relative} must refuse a symlinked/non-directory /run/nftfw target",
            )

    def test_package_and_portable_installer_ship_all_units_and_inert_templates(self) -> None:
        units = {
            "nftfw-early.service",
            "nftfw-enforcement-ready.service",
            "nftfw-rollback.service",
            "nftfw-rollback.timer",
            "nftfw-setup-rollback.service",
            "nftfw-setup-rollback.timer",
            "nftfw-setup-boot-hold.service",
            "nftfw-setup-docker-hold.service",
            "nftfw-managed-rollback.service",
            "nftfw-managed-rollback.timer",
            "nftfw-vpn.service",
            "nftfw-web.service",
            "nftfwd.service",
        }
        examples = {
            "nftfwd-docker-access.conf.example",
            "nftfwd-final-early.conf.example",
            "nftfw-rollback-final-early.conf.example",
            "nftfw-consumer-final-ready.conf.example",
        }
        for name in units | examples:
            self.assertTrue(
                (ROOT / "packaging/systemd" / name).is_file(),
                f"packaging source is missing {name}",
            )
        inert_destinations = {
            "scripts/build-deb.sh": (
                '"$stage/usr/share/doc/nft-firewall-v2/examples/$example"'
            ),
            "scripts/install.sh": '"$DOC_EXAMPLE_DIR/$example"',
        }
        for relative, inert_destination in inert_destinations.items():
            source = read(relative)
            for name in units | examples:
                if name not in source:
                    self.fail(f"{relative} does not explicitly ship required artifact {name}")
            if inert_destination not in source:
                self.fail(
                    f"{relative} must install final drop-in examples only under its "
                    f"documentation examples directory (missing {inert_destination})"
                )
            for line in logical_lines(source):
                if "$example" in line and re.search(
                    r"/(?:etc|usr/lib)/systemd/system(?:/|\b)|\.wants/|\.requires/",
                    line,
                ):
                    self.fail(
                        f"{relative} activates an example drop-in instead of leaving it "
                        f"inert: {line.strip()}"
                    )


class SystemdGraphContracts(unittest.TestCase):
    def test_managed_setup_rollback_can_restore_exact_owned_state(self) -> None:
        unit = parse_unit("packaging/systemd/nftfw-setup-rollback.service")
        self.assertEqual(one(unit, "Service", "ProtectKernelTunables"), "no")
        capabilities = set(one(unit, "Service", "CapabilityBoundingSet").split())
        self.assertIn("CAP_NET_ADMIN", capabilities)
        self.assertIn("CAP_CHOWN", capabilities)
        writable = words(unit, "Service", "ReadWritePaths")
        self.assertEqual(
            writable,
            {
                "/boot",
                "-/var/lib/initramfs-tools",
                "/etc/nftfw",
                "-/etc/default/grub.d",
                "-/etc/initramfs-tools/scripts/init-top",
                "-/etc/wireguard",
                "-/etc/docker",
                "/etc/sysctl.d",
                "/etc/systemd/system",
                "/var/lib/nftfw",
                "/run/nftfw",
                "-/run/resolvconf",
                "-/run/systemd/resolve",
            },
            "setup rollback must retain its exact reviewed write surface; the "
            "initramfs-tools transaction path is writable when present but must not "
            "prevent clean-host activation when absent",
        )
        self.assertNotIn(
            "/var/lib/initramfs-tools",
            writable,
            "systemd treats an absent mandatory ReadWritePaths entry as a namespace "
            "failure before the rollback command can execute",
        )

    def test_all_shipped_unit_path_directives_match_the_clean_host_audit(self) -> None:
        expected = {
            "nftfw-early.service": {
                "ReadWritePaths": {"/var/lib/nftfw/generation-state"},
                "ReadOnlyPaths": self.EARLY_RO,
            },
            "nftfw-enforcement-ready.service": {
                "ReadWritePaths": {"/run/nftfw"},
                "ReadOnlyPaths": {"/var/lib/nftfw"},
            },
            "nftfw-managed-rollback.service": {
                "ReadWritePaths": {"/etc/nftfw", "/var/lib/nftfw", "/run/nftfw"},
            },
            "nftfw-rollback.service": {
                "ReadWritePaths": {"/var/lib/nftfw/generation-state", "/run/nftfw"},
                "ReadOnlyPaths": {
                    "/etc/nftfw",
                    "/var/lib/nftfw/provenance-ledger.db",
                    "-/var/lib/nftfw/provenance-ledger.db-journal",
                    "-/var/lib/nftfw/provenance-ledger.db-wal",
                    "-/var/lib/nftfw/provenance-ledger.db-shm",
                    "/var/lib/nftfw/generations",
                    "/var/lib/nftfw/backups",
                    "-/var/lib/nftfw/active.snapshot.json",
                    "-/var/lib/nftfw/enforcement-enabled",
                },
            },
            "nftfw-setup-rollback.service": {
                "ReadWritePaths": {
                    "/boot",
                    "-/var/lib/initramfs-tools",
                    "/etc/nftfw",
                    "-/etc/default/grub.d",
                    "-/etc/initramfs-tools/scripts/init-top",
                    "-/etc/wireguard",
                    "-/etc/docker",
                    "/etc/sysctl.d",
                    "/etc/systemd/system",
                    "/var/lib/nftfw",
                    "/run/nftfw",
                    "-/run/resolvconf",
                    "-/run/systemd/resolve",
                },
            },
            "nftfw-setup-boot-hold.service": {
                "ReadWritePaths": {"/run/nftfw"},
                "ReadOnlyPaths": {
                    "/boot",
                    "/etc/nftfw",
                    "/etc/default/grub.d",
                    "/etc/initramfs-tools/scripts/init-top",
                    "/usr/lib/nftfw/initramfs",
                    "/var/lib/nftfw",
                    "/proc",
                    "/sys",
                },
            },
            "nftfw-setup-docker-hold.service": {
                "ReadWritePaths": {"/run/nftfw"},
                "ReadOnlyPaths": {"/etc/nftfw"},
            },
            "nftfw-vpn.service": {
                "ReadOnlyPaths": {
                    "/etc/nftfw/intent.toml",
                    "/etc/wireguard/nftfw0.conf",
                },
                "ReadWritePaths": {
                    "/run/nftfw",
                    "-/run/resolvconf",
                    "-/run/systemd/resolve",
                },
            },
            "nftfwd.service": {
                "ReadWritePaths": {"/var/lib/nftfw", "/run/nftfw"},
                "InaccessiblePaths": {"-/run/docker.sock", "-/var/run/docker.sock"},
            },
        }
        directives = (
            "ReadWritePaths",
            "ReadOnlyPaths",
            "InaccessiblePaths",
            "BindPaths",
            "BindReadOnlyPaths",
        )
        for path in sorted((ROOT / "packaging/systemd").glob("*.service")):
            unit = parse_unit(str(path.relative_to(ROOT)))
            actual = {
                directive: words(unit, "Service", directive)
                for directive in directives
                if values(unit, "Service", directive)
            }
            self.assertEqual(
                actual,
                expected.get(path.name, {}),
                f"{path.name} path sandbox differs from the reviewed Debian 13 "
                "clean-host contract",
            )

    def test_managed_policy_rollback_is_narrow_and_generation_scoped(self) -> None:
        service = parse_unit("packaging/systemd/nftfw-managed-rollback.service")
        timer = parse_unit("packaging/systemd/nftfw-managed-rollback.timer")
        self.assertEqual(
            one(service, "Service", "ExecStart"),
            "/usr/lib/nftfw/nftfw managed-recover --expired",
        )
        self.assertEqual(
            words(service, "Service", "RestrictAddressFamilies"),
            {"AF_UNIX"},
        )
        self.assertEqual(
            words(service, "Service", "ReadWritePaths"),
            {"/etc/nftfw", "/var/lib/nftfw", "/run/nftfw"},
        )
        self.assertEqual(one(service, "Service", "CapabilityBoundingSet"), "")
        self.assertEqual(one(service, "Service", "AmbientCapabilities"), "")
        self.assertEqual(
            one(timer, "Timer", "Unit"),
            "nftfw-managed-rollback.service",
        )
        self.assertEqual(one(timer, "Timer", "OnUnitActiveSec"), "15s")
        recovery = read("cmd/nftfw/managed_recovery.go")
        runtime = read("internal/app/runtime.go")
        self.assertIn("nftfw.managed-change-journal.v1", recovery)
        self.assertIn('Op: "generation", Generation: record.Generation', recovery)
        self.assertIn('case "generation":', runtime)

    ACTIVATING_KEYS = ("Requires", "Wants", "BindsTo", "Upholds")
    EARLY_RO = {
        "/etc/nftfw",
        "/var/lib/nftfw/provenance-ledger.db",
        "-/var/lib/nftfw/provenance-ledger.db-journal",
        "-/var/lib/nftfw/provenance-ledger.db-wal",
        "-/var/lib/nftfw/provenance-ledger.db-shm",
        "/var/lib/nftfw/generations",
        "/var/lib/nftfw/backups",
        "-/var/lib/nftfw/active.snapshot.json",
        "/var/lib/nftfw/enforcement-enabled",
    }

    def test_base_daemon_is_independent_of_early_restore(self) -> None:
        source = read("packaging/systemd/nftfwd.service")
        self.assertNotIn(
            "nftfw-early.service",
            source,
            "base nftfwd.service must not order on, require, want, or activate early "
            "restore before the first committed generation",
        )

    def test_rollback_timer_and_service_are_daemon_independent(self) -> None:
        for relative in (
            "packaging/systemd/nftfw-rollback.timer",
            "packaging/systemd/nftfw-rollback.service",
        ):
            unit = parse_unit(relative)
            references = words(unit, "Unit", "After") | words(unit, "Unit", "Before")
            for key in self.ACTIVATING_KEYS + ("Requisite", "PartOf", "Conflicts"):
                references |= words(unit, "Unit", key)
            self.assertNotIn(
                "nftfwd.service",
                references,
                f"{relative} must invoke the static rollback binary without a daemon "
                "ordering/dependency edge",
            )
        rollback = parse_unit("packaging/systemd/nftfw-rollback.service")
        rollback_ro = words(rollback, "Service", "ReadOnlyPaths")
        self.assertIn(
            "-/var/lib/nftfw/enforcement-enabled",
            rollback_ro,
            "the independent timer must run before first commit, when no enforcement "
            "pointer exists",
        )
        self.assertIn(
            "-/var/lib/nftfw/active.snapshot.json",
            rollback_ro,
            "2.0.3 never publishes the legacy active snapshot, so its absence must not "
            "fail the static service sandbox",
        )
        self.assertIn(
            "-/var/lib/nftfw/provenance-ledger.db-journal",
            rollback_ro,
            "the read-only ledger sandbox must admit its optional DELETE-journal "
            "crash sidecar without making it writable",
        )

    def test_shared_runtime_directory_has_one_owner_and_survives_oneshots(self) -> None:
        users_and_groups: set[tuple[str, str]] = set()
        for relative in (
            "packaging/systemd/nftfw-early.service",
            "packaging/systemd/nftfw-rollback.service",
            "packaging/systemd/nftfw-setup-boot-hold.service",
            "packaging/systemd/nftfw-setup-docker-hold.service",
            "packaging/systemd/nftfwd.service",
        ):
            unit = parse_unit(relative)
            self.assertEqual(
                words(unit, "Service", "RuntimeDirectory"),
                {"nftfw"},
                f"{relative} must use the one shared directory containing sockets and "
                "the cross-process mutation lock",
            )
            self.assertEqual(one(unit, "Service", "RuntimeDirectoryMode"), "0750")
            self.assertEqual(
                one(unit, "Service", "RuntimeDirectoryPreserve"),
                "yes",
                f"stopping {relative} must not remove another NFTFW process's "
                "sockets or mutation lock",
            )
            users_and_groups.add(
                (
                    one(unit, "Service", "User"),
                    one(unit, "Service", "Group"),
                )
            )
        self.assertEqual(
            users_and_groups,
            {("root", "nftfw-web")},
            "every unit sharing /run/nftfw must use identical ownership so a timer "
            "start cannot chown-break dashboard traversal",
        )

    def test_early_unit_remains_active_and_has_exact_storage_shape(self) -> None:
        relative = "packaging/systemd/nftfw-early.service"
        unit = parse_unit(relative)
        self.assertEqual(one(unit, "Service", "Type"), "oneshot")
        self.assertEqual(
            one(unit, "Service", "RemainAfterExit"),
            "yes",
            "successful early restore must remain active as a non-activating requisite",
        )
        self.assertEqual(
            one(unit, "Service", "ExecStart"),
            "/usr/lib/nftfw/nftfwd --restore-active --recover-commit-publication "
            "--resolve-stale-pending --state-dir /var/lib/nftfw",
            "early restore must use the complete 2.0.3 recovery operation",
        )
        self.assertFalse(
            values(unit, "Service", "ExecStop"),
            "early enforcement must not be removed by service stop/shutdown",
        )
        self.assertEqual(
            words(unit, "Service", "ReadWritePaths"),
            {"/var/lib/nftfw/generation-state"},
            "early restore may write only the generation database subtree",
        )
        self.assertEqual(
            words(unit, "Service", "ReadOnlyPaths"),
            self.EARLY_RO,
            "ledger, configs, immutable generations, snapshots, and pointer must be "
            "read-only to early restore",
        )
        self.assertEqual(
            one(unit, "Unit", "ConditionPathExists"),
            "/var/lib/nftfw/enforcement-enabled",
        )
        self.assertTrue(
            {
                "network-pre.target",
                "nftfwd.service",
                "nftfw-enforcement-ready.service",
            }.issubset(words(unit, "Unit", "Before")),
            "early restore must precede networking, the daemon, and readiness",
        )

    def test_ready_unit_is_independently_scheduled_and_read_only(self) -> None:
        relative = "packaging/systemd/nftfw-enforcement-ready.service"
        unit = parse_unit(relative)
        self.assertFalse(
            values(unit, "Unit", "Requisite"),
            "readiness must not reject the boot transaction before the independently "
            "scheduled early restore can become active",
        )
        for key in self.ACTIVATING_KEYS:
            self.assertNotIn(
                "nftfw-early.service",
                words(unit, "Unit", key),
                f"readiness may order after early but must not activate it with {key}=",
            )
        self.assertEqual(one(unit, "Unit", "DefaultDependencies"), "no")
        self.assertEqual(
            words(unit, "Unit", "After"),
            {"local-fs.target", "nftfw-early.service"},
        )
        self.assertEqual(words(unit, "Unit", "Before"), {"network-pre.target"})
        self.assertEqual(one(unit, "Service", "Type"), "oneshot")
        self.assertEqual(one(unit, "Service", "RemainAfterExit"), "yes")
        self.assertEqual(
            one(unit, "Service", "ExecStart"),
            "/usr/lib/nftfw/nftfwd --verify-enforcement --state-dir /var/lib/nftfw",
        )
        self.assertEqual(
            words(unit, "Service", "ReadOnlyPaths"), {"/var/lib/nftfw"}
        )
        self.assertEqual(
            words(unit, "Service", "ReadWritePaths"),
            {"/run/nftfw"},
            "the readiness verifier may write only the common volatile flock path, "
            "never durable state",
        )
        self.assertFalse(
            values(unit, "Service", "RuntimeDirectory"),
            "readiness must use the directory retained by early and must not become "
            "another lifecycle owner that can remove shared sockets or the lock",
        )
        self.assertEqual(
            words(unit, "Install", "RequiredBy"), {"network-pre.target"}
        )
        self.assertFalse(
            values(unit, "Install", "WantedBy"),
            "readiness is required by network-pre only after explicit enablement",
        )

    def _requisite_templates(self, target: str) -> list[Path]:
        result: list[Path] = []
        needle = f"Requisite={target}"
        for path in sorted((ROOT / "packaging/systemd").rglob("*.conf.example")):
            if needle in path.read_text(encoding="utf-8"):
                result.append(path)
        return result

    def test_final_dependency_templates_are_inert_and_requisite_only(self) -> None:
        required_template_paths = {
            ROOT / "packaging/systemd/nftfwd-final-early.conf.example",
            ROOT / "packaging/systemd/nftfw-rollback-final-early.conf.example",
            ROOT / "packaging/systemd/nftfw-consumer-final-ready.conf.example",
        }
        self.assertTrue(
            all(path.is_file() for path in required_template_paths),
            "the daemon, rollback, and consumer final dependency templates must all exist",
        )
        expected_counts = {
            # The daemon and static rollback service receive separate inactive
            # copies of this final post-commit edge.
            "nftfw-early.service": 2,
            # One reusable template is installed explicitly for each audited
            # network consumer during the later host handoff.
            "nftfw-enforcement-ready.service": 1,
        }
        for target, expected_count in expected_counts.items():
            templates = self._requisite_templates(target)
            self.assertEqual(
                len(templates),
                expected_count,
                f"expected {expected_count} inactive *.conf.example template(s) for {target}; "
                f"found {[str(path.relative_to(ROOT)) for path in templates]}",
            )
            for path in templates:
                relative = str(path.relative_to(ROOT))
                unit = parse_unit(relative)
                self.assertEqual(words(unit, "Unit", "Requisite"), {target})
                self.assertEqual(words(unit, "Unit", "After"), {target})
                for key in self.ACTIVATING_KEYS:
                    self.assertFalse(
                        values(unit, "Unit", key),
                        f"{relative} must not contain activating {key}= edges",
                    )
                self.assertEqual(
                    set(unit),
                    {"Unit"},
                    f"{relative} must be an inert dependency fragment, not an installable unit",
                )

        active_links = [
            path
            for path in (ROOT / "packaging/systemd").rglob("*")
            if path.is_symlink()
            or any(part.endswith((".wants", ".requires")) for part in path.parts)
        ]
        self.assertFalse(
            active_links,
            "final dependency templates must not be pre-enabled in the source package: "
            + ", ".join(str(path.relative_to(ROOT)) for path in active_links),
        )


class NftfwdCLIContracts(unittest.TestCase):
    """Keep packaged ExecStart commands aligned with the shipped binary.

    These source checks prove only that the CLI modes and canonical path are
    wired.  Recovery atomicity, read-only verification, boot ordering, and
    nftables behavior remain unit and Stage R2 runtime gates.
    """

    def test_packaged_lifecycle_modes_are_declared_by_nftfwd(self) -> None:
        source = read("cmd/nftfwd/main.go")
        required_boolean_flags = {
            "rollback-expired",
            "restore-active",
            "recover-commit-publication",
            "resolve-stale-pending",
            "verify-enforcement",
        }
        for name in sorted(required_boolean_flags):
            if f'flag.Bool("{name}"' not in source:
                self.fail(f"packaged systemd units require nftfwd --{name}")
        if 'flag.String("state-dir"' not in source:
            self.fail("every static lifecycle mode must resolve state from --state-dir")

    def test_static_modes_use_the_canonical_generation_database(self) -> None:
        source = read("cmd/nftfwd/main.go")
        if '"/var/lib/nftfw/state.db"' in source:
            self.fail(
                "2.0.3 static recovery must not silently fall back to the legacy database"
            )
        canonical_database = (
            r'filepath\.Join\([^\n]*"generation-state"[^\n]*"state\.db"'
        )
        if re.search(canonical_database, source) is None:
            self.fail(
                "static lifecycle modes must derive generation-state/state.db from "
                "the canonical state root"
            )

    def test_verifier_has_a_strict_read_only_state_open(self) -> None:
        source = read("cmd/nftfwd/main.go")
        if "state.OpenReadOnly(" not in source:
            self.fail(
                "--verify-enforcement must not call the migrating/read-write state open"
            )

    def test_static_rollback_uses_the_global_runtime_lock_and_state_root(self) -> None:
        source = read("cmd/nftfwd/main.go")
        lock_uses = source.count("state.DefaultMutationLockDir, nft.New(nil)")
        if lock_uses != 3:
            self.fail(
                "early recovery, static rollback, and verification must each receive "
                f"the canonical mutation lock directory (found {lock_uses}/3)"
            )
        if "state.AcquireMutationLock(ctx, lockDirectory)" not in source:
            self.fail("static lifecycle helpers must acquire their supplied global lock")
        lock_source = read("internal/state/claim_lock.go")
        if 'DefaultMutationLockDir = "/run/nftfw"' not in lock_source:
            self.fail("the canonical mutation lock directory must be exactly /run/nftfw")
        if "restoreRollbackFallback(ctx, filepath.Dir(databasePath)" in source:
            self.fail(
                "generation-state is the database subtree, not the canonical state root; "
                "fallback snapshots and the enforcement pointer live one level above it"
            )

    def test_static_rollback_does_not_open_the_full_daemon_runtime(self) -> None:
        source = read("cmd/nftfwd/main.go")
        rollback_branch = source.split("if *expired {", 1)
        self.assertEqual(
            len(rollback_branch),
            2,
            "nftfwd must retain an explicit --rollback-expired branch",
        )
        rollback_branch = rollback_branch[1].split("rt, err := app.Open(ctx", 1)[0]
        if "app.OpenQuiet(" in rollback_branch:
            self.fail(
                "the sandboxed static rollback service must not open/migrate the full "
                "daemon runtime or writable provenance ledger"
            )

    def test_safe_apply_guard_matches_packaged_state_dir_contract(self) -> None:
        unit = parse_unit("packaging/systemd/nftfw-rollback.service")
        self.assertEqual(
            one(unit, "Service", "ExecStart"),
            "/usr/lib/nftfw/nftfwd --rollback-expired --state-dir /var/lib/nftfw",
        )
        guard = read("internal/recovery/recovery.go")
        self.assertIn('"--state-dir"', guard)
        self.assertIn("execStartUsesStateDir", guard)
        self.assertNotIn(
            "StateDB",
            guard,
            "safe-apply preflight must compare the canonical state root used by the "
            "packaged static rollback command, not the obsolete database flag",
        )
        self.assertIn(
            "recovery.SystemdGuard{StateDir: c.State.Directory}",
            read("cmd/nftfw/main.go"),
        )
        self.assertIn(
            "recovery.SystemdGuard{StateDir: st.Dir}",
            read("internal/app/runtime.go"),
        )


class ManagedDockerContracts(unittest.TestCase):
    def test_managed_setup_owns_forwarding_without_restoring_docker_mutation(self) -> None:
        managed = read("internal/containers/managed.go")
        setup = read("internal/setup/system.go")
        self.assertIn(
            '"iptables", "ip6tables", "ip-forward", "ip-masq", "userland-proxy"',
            managed,
        )
        self.assertIn('value[option] = false', managed)
        self.assertIn('builder.WriteString("net.ipv4.ip_forward = 1\\n")', setup)
        self.assertIn('settings["net.ipv4.ip_forward"] = "1"', setup)
        self.assertIn(
            '"nft", "--check", "--file", candidatePath',
            setup,
            "the generated policy must pass nft --check before Docker restart",
        )
        self.assertIn("SETUP_DOCKER_CONFIG_CHANGED_AFTER_PLAN", setup)

    def test_docker_observation_is_local_strict_and_stable(self) -> None:
        docker = read("internal/containers/docker.go")
        managed = read("internal/containers/managed.go")
        discovery = read("internal/discovery/discovery.go")
        intent = read("internal/intent/intent.go")
        setup = read("internal/setup/system.go")
        self.assertIn(
            'localDockerHost = "unix:///var/run/docker.sock"',
            docker,
        )
        self.assertIn("duplicate object key", managed)
        self.assertIn("DOCKER_DAEMON_CONFIG_CHANGED_DURING_READ", managed)
        self.assertIn("DOCKER_NETWORK_CHANGED_DURING_READ", managed)
        self.assertIn("INTENT_DOCKER_SUBNET_OVERLAPS_LAN", intent)
        self.assertIn("INTENT_DOCKER_SUBNET_OVERLAPS_VPN", intent)
        self.assertIn("INTENT_DOCKER_SUBNET_OVERLAPS_BOOTSTRAP", intent)
        self.assertIn("INTENT_DOCKER_SUBNET_OVERLAPS_RESERVED", intent)
        self.assertIn("observeDockerWorkloads", discovery)
        self.assertIn('"ps", "-q", "--no-trunc"', discovery)
        self.assertIn('"ps", "-aq", "--no-trunc"', discovery)
        self.assertIn("DISCOVERY_DOCKER_WORKLOADS_REQUIRE_ADOPT", discovery)
        self.assertIn("DISCOVERY_DOCKER_STATE_CHANGED", discovery)
        self.assertNotIn('"filter", "type=custom"', discovery)
        self.assertIn("SETUP_DOCKER_STATE_CHANGED_AFTER_PLAN", setup)

    def test_clean_host_route_inspection_uses_numeric_all_table_json(self) -> None:
        routing = re.sub(r"\s+", " ", read("internal/routing/manager.go"))
        tests = read("internal/routing/manager_test.go")
        self.assertIn(
            '"ip", "-j", "-N", "-4", "route", "show", "table", "all"',
            routing,
        )
        self.assertNotIn(
            '"route", "show", "table", strconv.Itoa(config.Table)',
            routing,
        )
        self.assertIn("decodeManagedRoutes", routing)
        self.assertIn("numericRouteTable", routing)
        for regression in (
            "TestPreflightCleanTreatsAbsentManagedTableAsClean",
            "TestDecodeManagedRoutesRejectsAmbiguousOrMalformedOutput",
            "TestManagedRouteInspectionRejectsCommandFailureClasses",
            "FuzzDecodeManagedRoutes",
        ):
            self.assertIn(regression, tests)

    def test_bridge_rebind_and_uninstall_handoff_are_transactional(self) -> None:
        runtime = read("internal/app/runtime.go")
        helper = read("scripts/docker-handoff.sh")
        builder = read("scripts/build-deb.sh")
        prerm = read("packaging/deb/prerm")
        self.assertIn("dockerBridgeBindingsChanged", runtime)
        self.assertIn("rebindDockerBridgesLocked", runtime)
        self.assertIn("r.Manager.Apply(ctx, artifact, false)", runtime)
        self.assertIn("managedsetup.WriteAtomicFile(projected.ConfigPath", runtime)
        self.assertIn("docker_bridge_rebound", runtime)
        self.assertIn("nftfw.docker-uninstall-handoff.v1", helper)
        self.assertIn("cmp -s -", helper)
        self.assertIn("scripts/docker-handoff.sh", builder)
        self.assertIn("nftfw_remove_managed_docker_dropin", prerm)


class SetupGuardContracts(unittest.TestCase):
    def test_prefix_sets_are_interval_sets_and_endpoints_remain_hosts(self) -> None:
        guard = read("internal/setup/guard.go")
        self.assertIn(
            "set endpoints_v4 { type ipv4_addr; flags interval;",
            guard,
        )
        self.assertIn(
            "set lan_v4 { type ipv4_addr; flags interval;",
            guard,
        )
        self.assertIn("prefix.Bits() != 32", guard)
        self.assertNotIn("flush ruleset", guard)


class AdoptionPlannerContracts(unittest.TestCase):
    def test_setup_adopt_is_explicit_and_dry_run_only(self) -> None:
        cli = read("cmd/nftfw/managed.go")
        self.assertIn('args[0] == "adopt"', cli)
        self.assertIn("return setupAdoptCommand(args[1:])", cli)
        self.assertIn('flag.NewFlagSet("setup adopt"', cli)
        self.assertIn('dryRun := fs.Bool("dry-run"', cli)
        self.assertIn("fs.SetOutput(io.Discard)", cli)
        self.assertIn("ADOPTION_EXECUTION_REQUIRES_SEPARATE_LIVE_PLAN", cli)
        self.assertIn("adoption.OperatorError(err)", cli)
        self.assertNotIn("acquireSetupLock()", cli.split("func setupAdoptCommand", 1)[1].split("\n}", 1)[0])

    def test_planner_has_no_mutation_surface(self) -> None:
        planner = read("internal/adoption/adoption.go")
        system = read("internal/adoption/system.go")
        combined = planner + system
        for forbidden in (
            "os.WriteFile(",
            "os.OpenFile(",
            "os.Mkdir",
            "os.Remove(",
            "exec.Command",
            "state.Open(ctx",
            "provenance.Open(ctx",
            '"systemctl", "start"',
            '"systemctl", "restart"',
            '"systemctl", "enable"',
            '"nft", "--file"',
            '"ip", "route", "add"',
            '"sysctl", "-w"',
        ):
            self.assertNotIn(forbidden, combined)
        self.assertIn("state.OpenReadOnly(ctx", system)
        self.assertIn("provenance.OpenReadOnly(ctx", system)
        self.assertIn("state.LoadVerifiedGenerationSnapshot", system)
        self.assertIn("wgconfig.Read(vpnPath)", system)
        self.assertIn("containers.ValidateManagedDaemonConfig", system)
        self.assertIn("containers.ManagedDaemonConfigFingerprint", system)
        self.assertIn("nft.CanonicalOwnedTableJSON", system)
        self.assertIn('runner.Run(ctx, "nft", "-j", "list", "table"', system)
        self.assertNotIn("nft.New(", system)
        self.assertIn("first.Fingerprint != second.Fingerprint", system)

    def test_planner_output_and_errors_are_redacted(self) -> None:
        planner = read("internal/adoption/adoption.go")
        tests = read("internal/adoption/adoption_test.go")
        self.assertIn('return "ADOPTION_INSPECTION_FAILED"', planner)
        self.assertIn("live state changed: NO", planner)
        self.assertIn("rollback required: NO", planner)
        self.assertIn("the planner writes no log", planner)
        for forbidden_field in (
            'json:"private_key"',
            'json:"endpoint"',
            'json:"public_ip"',
            'json:"container_id"',
            'json:"image"',
            'json:"volume"',
            'json:"docker_network_name"',
        ):
            self.assertNotIn(forbidden_field, planner)
        self.assertIn("FuzzAdoptionErrorRedaction", tests)
        self.assertIn("TestPlannerBuildsDeterministicRedactedWorksheet", tests)
        self.assertIn('json:"restart_required"', planner)

    def test_exact_schema6_fixture_proves_no_filesystem_change(self) -> None:
        tests = read("internal/adoption/system_test.go")
        self.assertIn("TestSystemInspectorExactSchema6FixtureIsNonMutating", tests)
        self.assertIn("before := treeSignature(t, root)", tests)
        self.assertIn("after := treeSignature(t, root)", tests)
        self.assertIn("state.Open(ctx, database)", tests)
        self.assertIn("store.Commit(ctx, 1)", tests)
        self.assertIn("mutatingCommand(command)", tests)

    def test_operator_documents_keep_planning_separate_from_execution(self) -> None:
        for relative in (
            "README.md",
            "QUICKSTART.md",
            "INSTALL.md",
            "SUPPORTED-PLATFORMS.md",
            "docs/CLI.md",
            "docs/UPGRADING.md",
            "docs/RECOVERY.md",
            "docs/TROUBLESHOOTING.md",
            "docs/ARCHITECTURE.md",
            "docs/TESTING.md",
            "SECURITY.md",
        ):
            source = read(relative)
            self.assertIn(
                "adopt",
                source.lower(),
                f"{relative} does not explain the adoption boundary",
            )
        cli = read("docs/CLI.md")
        upgrade = read("docs/UPGRADING.md")
        recovery = read("docs/RECOVERY.md")
        architecture = read("docs/ARCHITECTURE.md")
        self.assertIn("nftfw setup adopt --vpn PATH --dry-run", cli)
        self.assertIn("ADOPTION_EXECUTION_REQUIRES_SEPARATE_LIVE_PLAN", upgrade)
        self.assertIn("requires no rollback", recovery)
        self.assertIn("no writer", architecture)


class AmendmentMContracts(unittest.TestCase):
    def test_exact_203_absence_uses_one_strict_systemd_snapshot(self) -> None:
        system = read("internal/adoption/system.go")
        tests = read("internal/adoption/system_test.go")
        self.assertIn(
            '"--property=Id,Names,LoadState,ActiveState,UnitFileState,FragmentPath"',
            system,
        )
        self.assertIn('"nftfw-managed-rollback.timer": true', system)
        self.assertIn('"nftfw-setup-rollback.timer":   true', system)
        self.assertIn('"nftfw-vpn.service":            true', system)
        self.assertIn('observed.LoadState == "not-found"', system)
        self.assertIn('observed.ActiveState == "inactive"', system)
        self.assertIn('observed.UnitFileState == ""', system)
        self.assertIn('observed.FragmentPath == ""', system)
        self.assertNotIn('"--property=ActiveState", "--value"', system)
        self.assertNotIn('"--property=UnitFileState", "--value"', system)
        self.assertIn("TestExact203CanonicalAbsentUnits", tests)
        self.assertIn("TestCanonicalUnitAbsenceRejectsAmbiguity", tests)

    def test_first_setup_publishes_final_edges_only_after_commit(self) -> None:
        engine = read("internal/setup/engine.go")
        system = read("internal/setup/system.go")
        tests = read("internal/setup/system_test.go")
        self.assertLess(engine.index("PhaseRuntime"), engine.index("PhaseCommit"))
        self.assertLess(engine.index("PhaseCommit"), engine.index("PhaseHandoff"))
        self.assertLess(engine.index("PhaseHandoff"), engine.index('PhaseBoot     Phase = "boot"'))
        install_body = system.split("func (s *System) Install", 1)[1].split(
            "func sameDockerNetworks", 1
        )[0]
        self.assertNotIn("50-nftfw-final-early.conf", install_body)
        runtime_body = system.split("func (s *System) StartRuntime", 1)[1].split(
            "func (s *System) ApplySafe", 1
        )[0]
        self.assertIn('"systemctl", "start", "nftfwd.service"', runtime_body)
        self.assertNotIn("50-nftfw-final-early.conf", runtime_body)
        handoff = system.split("func (s *System) PublishFinalDependencies", 1)[1].split(
            "func (s *System) EnableBoot", 1
        )[0]
        self.assertIn('"nftfw-early.service", "nftfw-enforcement-ready.service"', handoff)
        self.assertIn('"rebuild-enabled"', handoff)
        self.assertIn("50-nftfw-final-early.conf", handoff)
        self.assertIn("TestInstallDefersFinalDependenciesUntilCommittedHandoff", tests)
        self.assertIn(
            "TestFinalDependencyPublicationFailureRecoversForward",
            read("internal/setup/engine_test.go"),
        )

    def test_initramfs_guard_is_inert_packaged_and_strictly_handed_off(self) -> None:
        hook = read("packaging/initramfs/nftfw-early-guard-hook")
        gate = read("packaging/initramfs/nftfw-udev-gate")
        loader = read("packaging/initramfs/nftfw-ipv6-early")
        manager = read("packaging/initramfs/nftfw-initramfs-manage")
        rules = read("packaging/initramfs/nftfw-initramfs-guard.nft")
        builder = read("scripts/build-deb.sh")
        service = parse_unit("packaging/systemd/nftfw-enforcement-ready.service")
        prerm = read("packaging/deb/prerm")
        self.assertIn("test -e \"$marker\" || exit 0", hook)
        self.assertIn("PREREQ=nftfw-ipv6-early", gate)
        self.assertIn('exec "$vendor" "$@"', gate)
        self.assertIn("/proc/cmdline", loader)
        self.assertIn("/sys/module/ipv6/parameters/disable", loader)
        self.assertIn('test "$managed_ipv6_disable" -eq 1', loader)
        self.assertNotIn("conf/lo/disable_ipv6", loader)
        self.assertIn("nft --check --file", loader)
        self.assertIn('comment "nftfw:initramfs-guard:v1"', rules)
        self.assertEqual(rules.count("policy drop;"), 3)
        self.assertIn("listing=$(lsinitramfs", manager)
        self.assertIn('listing=$(lsinitramfs "$image") || return 1', manager)
        for artifact in (
            "nftfw-ipv6-early",
            "nftfw-udev-gate",
            "nftfw-initramfs-guard.nft",
            "nftfw-initramfs-manage",
            "nftfw-early-guard-hook",
        ):
            self.assertIn(artifact, builder)
        self.assertIn(
            "/usr/lib/nftfw/nftfwd --handoff-initramfs-guard --state-dir /var/lib/nftfw",
            values(service, "Service", "ExecStartPost"),
        )
        self.assertLess(prerm.index("boot-handoff --package-remove"), prerm.index("if [ -d /run/systemd/system ]"))
        self.assertIn("tests/initramfs-guard-namespace.sh", read("docs/TESTING.md"))

    def test_exact_203_rollback_bridge_is_prepared_and_fail_closed(self) -> None:
        helper = read("scripts/package-rollback.sh")
        builder = read("scripts/build-deb.sh")
        test = read("tests/package-rollback-bundle.sh")
        disposable = read("tests/package-rollback-disposable.sh")
        self.assertIn("nftfw.package-rollback.v1", helper)
        self.assertIn('bridge_version="$old_version~nftfwrollback1.', helper)
        self.assertIn('dpkg --force-downgrade --install "$bundle/bridge.deb"', helper)
        self.assertIn('install_exact_old_package "$bundle/old.deb"', helper)
        self.assertIn('exec dpkg --install "$package_path"', helper)
        self.assertIn("unshare --mount --propagation private", helper)
        self.assertIn('mount --bind "$private_lock" "$canonical_lock"', helper)
        self.assertIn("private maintainer-script lock aliases the canonical lock", helper)
        self.assertNotIn("flock -u", helper)
        self.assertNotIn("/var/lib/dpkg/status", helper)
        self.assertNotIn("--force-script-chrootless", helper)
        self.assertIn("protected_directory_chain \"${path%/*}\"", helper)
        self.assertIn("old_payload_sha256", helper)
        self.assertIn("transition_sha256", helper)
        self.assertIn("X-NFTFW-Rollback-Transition", helper)
        self.assertIn('[ "\\$#" -eq 3 ]', helper)
        self.assertIn('[ "\\$3" = "\\$bridge_version" ]', helper)
        self.assertIn('= "iHR \\$new_version" ]', helper)
        self.assertIn('state_gid=\\$(id -g nftfw-web)', helper)
        self.assertIn("'0:0:600:1'|\"0:\\$state_gid:600:1\")", helper)
        self.assertIn("'unrecognized database group'", test)
        self.assertIn("validate_exact_old_configuration", helper)
        execute = helper.split("execute_bundle()", 1)[1]
        self.assertLess(
            execute.index('validate_exact_old_configuration "$bundle"'),
            execute.index("setup boot-handoff --package-downgrade"),
        )
        self.assertIn("chown root:root /run/nftfw/mutation.lock", helper)
        self.assertNotIn('= "ii  $new_version" ]', helper)
        self.assertIn("stat -c '%u:%g:%a:%h'", helper)
        self.assertIn("installed package is outside the resumable rollback states", helper)
        self.assertIn("scripts/package-rollback.sh", builder)
        self.assertIn("unsafe parent", test.lower())
        self.assertIn("hard-linked package input", test)
        self.assertIn("configured package state", test)
        self.assertIn("ambiguous multi-line package state", test)
        self.assertIn("transition identity mismatch", test)
        self.assertIn("PACKAGE_ROLLBACK_BUNDLE_PASS", test)
        self.assertIn("/run/nftfw-disposable-test-guest", disposable)
        self.assertIn("complete two-step rollback", disposable)
        self.assertIn("rollback bridge did not configure", disposable)
        self.assertIn("CANONICAL_LOCK_BLOCKED", disposable)
        self.assertIn("private maintainer-script lock residue remains", disposable)
        self.assertIn("idempotent rollback changed protected state", disposable)
        self.assertIn("PACKAGE_ROLLBACK_DISPOSABLE_COMPLETE_PASS", disposable)


class AmendmentPContracts(unittest.TestCase):
    def test_expired_setup_watchdog_reads_before_lock_and_revalidates(self) -> None:
        source = read("cmd/nftfw/managed.go")
        body = source.split("func setupRollbackCommand", 1)[1].split(
            "func setupJournalNeedsRecovery", 1
        )[0]
        first_read = body.index("journal, err := store.Read()")
        acquire = body.index("release, err := setupRollbackAcquire()")
        second_read = body.index("journal, err := store.Read()", first_read + 1)
        self.assertLess(first_read, acquire)
        self.assertLess(acquire, second_read)
        self.assertIn("validateSetupWatchdogJournal(journal)", body)
        self.assertIn('errors.New("SETUP_JOURNAL_CHANGED")', body)
        tests = read("cmd/nftfw/managed_test.go")
        for expected in (
            "TestExpiredSetupWatchdogDoesNotContendWithLiveTransaction",
            "TestExpiredSetupWatchdogRevalidatesJournalAfterLock",
            "TestExpiredSetupWatchdogRechecksDeadlineUnderLock",
            "TestSetupLockIsReleasedWhenOwnerProcessDies",
            "TestSetupWatchdogRejectsMalformedRecoveryStateBeforeLock",
        ):
            self.assertIn(expected, tests)

    def test_runtime_readiness_proves_process_sockets_and_both_apis(self) -> None:
        source = read("internal/setup/system.go")
        body = source.split("func (s *System) StartRuntime", 1)[1].split(
            "func (s *System) ApplySafe", 1
        )[0]
        for expected in (
            "s.runtimeProcessReady",
            "s.runtimeSocketContracts(s.expectedRuntimeUID())",
            "s.status(ctx)",
            's.control(ctx, api.Request{Op: "status"})',
            '"/usr/lib/nftfw/nftfwd"',
            '"/usr/lib/systemd/systemd-executor"',
            'errors.New("SETUP_DAEMON_READINESS_TIMEOUT")',
            'errors.New("SETUP_DAEMON_READINESS_CANCELED")',
            'errors.New("SETUP_DAEMON_DEGRADED")',
        ):
            self.assertIn(expected, body)
        uid_default = body.split("func (s *System) expectedRuntimeUID", 1)[1].split(
            "func validateRuntimeExecutable", 1
        )[0]
        self.assertIn("return 0", uid_default)
        self.assertIn("context.AfterFunc(ctx", read("internal/api/unix.go"))
        tests = read("internal/setup/system_test.go")
        for expected in (
            "TestStartRuntimeWaitsForDaemonReadiness",
            "TestStartRuntimeReadinessFailuresAreBounded",
            "TestRuntimeSocketContracts",
            "TestRuntimeExecutableAllowsOnlySystemdExecTransition",
            "TestRuntimeAPIReadinessUsesStatusAndAuthenticatedControl",
            "TestRuntimeSnapshotRejectsEstablishedDegradation",
            "TestRuntimeReadinessRequiresBothAPIsAndExactProcess",
            "TestRuntimeReadinessStopsBeforeUnsafeDependencies",
        ):
            self.assertIn(expected, tests)

    def test_docker_restore_resets_only_backed_up_active_docker(self) -> None:
        source = read("internal/setup/backup.go")
        restore = source.split("func restoreBackup", 1)[1].split(
            "func restoreUnitOrder", 1
        )[0]
        self.assertIn('resetUnits := []string{"reset-failed", "docker.service"}', restore)
        self.assertIn('manifest.Units["docker.socket"]', restore)
        self.assertIn('if state.Active {', restore)
        self.assertNotIn("reset-failed nftfw", restore)
        system = read("internal/setup/system.go")
        self.assertIn('service["ActiveState"] != "active"', system)
        self.assertIn("ActiveState=failed", read("internal/setup/system_test.go"))
        tests = read("internal/setup/backup_test.go")
        self.assertIn("TestDockerRestoreClearsOnlyBackedUpActiveUnits", tests)
        self.assertIn("TestDockerRestoreReportsResetAndRestartFailures", tests)

    def test_real_systemd_fixture_covers_optional_path_and_lock_contention(self) -> None:
        source = read("tests/packaging/setup_rollback_systemd.sh")
        self.assertIn("flock -n \"$lock_fd\"", source)
        self.assertIn("expired watchdog bypassed the live foreground lock", source)
        self.assertIn("optional systemd path declaration created", source)
        self.assertIn("lock-contended expiry changed the setup journal", source)


class AmendmentRContracts(unittest.TestCase):
    def test_native_initramfs_sources_are_explicitly_owned_and_ordered(self) -> None:
        manager = read("packaging/initramfs/nftfw-initramfs-manage")
        hook = read("packaging/initramfs/nftfw-early-guard-hook")
        gate = read("packaging/initramfs/nftfw-udev-gate")
        build = read("scripts/build-deb.sh")
        system = read("internal/setup/system.go")
        for path in (
            "/etc/nftfw/initramfs-source-owner-v1",
            "source_root=/etc/initramfs-tools/scripts/init-top",
            "source_loader=$source_root/nftfw-ipv6-early",
            "source_gate=$source_root/udev",
            "/usr/share/initramfs-tools/scripts/init-top/udev",
        ):
            self.assertIn(path, manager)
        for expected in (
            "managed initramfs source state is partial or ambiguous",
            "managed initramfs target changed during publication",
            "another initramfs ownership transaction is running",
            "rollback_fresh_enable",
            "restore_disabled_backup",
            "verify_image_enabled",
            "verify_image_disabled",
            "vendor_mentions == 0",
            "gate_line == guard_line + 2",
        ):
            self.assertIn(expected, manager)
        self.assertIn('copy_file script "$vendor_udev"', hook)
        self.assertNotIn("scripts/init-top/ORDER", hook)
        self.assertIn("PREREQ=nftfw-ipv6-early", gate)
        self.assertIn("nftfw-udev-gate", build)
        handoff = system.split("func (s *System) PublishFinalDependencies", 1)[1].split(
            "func (s *System) EnableBoot", 1
        )[0]
        self.assertIn('managerAction := "rebuild-enabled"', handoff)
        self.assertIn('managerAction = "verify-enabled"', handoff)
        self.assertNotIn("ensureManagedInitramfsMarker", system)
        touched = system.split("func (s *System) touchedFiles", 1)[1].split(
            "func privatePlan", 1
        )[0]
        for expected in (
            "s.Paths.InitramfsMarker",
            "s.Paths.InitramfsOwner",
            "s.Paths.InitramfsLoader",
            "s.Paths.InitramfsGate",
        ):
            self.assertIn(expected, touched)

    def test_remove_paths_refuse_without_the_ownership_transaction(self) -> None:
        for relative in ("scripts/uninstall.sh", "packaging/deb/prerm"):
            source = read(relative)
            self.assertIn("initramfs-source-owner-v1", source)
            self.assertIn("scripts/init-top/nftfw-ipv6-early", source)
            self.assertIn("scripts/init-top/udev", source)
            self.assertIn("nftfw-initramfs-manage", source)


class AmendmentTContracts(unittest.TestCase):
    def test_initramfs_verifier_propagates_every_security_result(self) -> None:
        source = read("packaging/initramfs/nftfw-initramfs-manage")
        enabled = source.split("verify_image_enabled()", 1)[1].split(
            "verify_image_disabled()", 1
        )[0]
        disabled = source.split("verify_image_disabled()", 1)[1].split(
            "verify_all()", 1
        )[0]
        aggregate = source.split("verify_all()", 1)[1].split(
            "rollback_fresh_enable()", 1
        )[0]
        for expected in (
            "require_extracted_regular",
            'loader_digest=$(digest "$loader") || return 1',
            'gate_digest=$(digest "$gate") || return 1',
            'vendor_digest=$(digest "$vendor") || return 1',
            'rules_digest=$(digest "$rules") || return 1',
            'prerequisite=$("$gate" prereqs) || return 1',
            'verify_enabled_order "$order" || return 1',
        ):
            self.assertIn(expected, enabled)
        for expected in (
            'listing=$(lsinitramfs "$image") || return 1',
            'gate_digest=$(digest "$gate") || return 1',
            'prerequisite=$("$gate" prereqs) || return 1',
            '[[ $prerequisite != *nftfw* ]] || return 1',
            '! grep -F nftfw "$order" >/dev/null || return 1',
        ):
            self.assertIn(expected, disabled)
        self.assertIn("cannot enumerate installed initramfs images", aggregate)
        self.assertIn("cannot remove initramfs verification directory", aggregate)
        self.assertIn("verification_list=", source)
        self.assertIn("verification_directory=", source)

    def test_conditional_corruption_and_publication_matrix_is_required(self) -> None:
        source = read("tests/packaging/initramfs_native_sources.sh")
        for expected in (
            "marker-mktemp loader-install gate-move owner-post-sync",
            "loader gate vendor rules marker checksum order mode owner missing symlink duplicate",
            "gate order artifact mode owner missing duplicate listing",
            "wrong gate prerequisite",
            "NFTFW disabled prerequisite",
            "exact verifier failure bypassed enable rollback",
            "aggregate verifier masked a later invalid image",
            "aggregate verifier masked cleanup failure",
        ):
            self.assertIn(expected, source)
        manager = read("packaging/initramfs/nftfw-initramfs-manage")
        self.assertIn("fail_enable_with_rollback", manager)
        self.assertIn("marker publication failed", manager)
        self.assertIn("ownership record publication failed", manager)


class AmendmentUContracts(unittest.TestCase):
    def test_out_of_process_commit_inspector_initializes_defaults(self) -> None:
        system = read("internal/setup/system.go")
        body = system.split("func (s *System) GenerationCommitted", 1)[1].split(
            "// PublishFinalDependencies", 1
        )[0]
        self.assertLess(body.index("s.defaults()"), body.index("s.status(ctx)"))
        self.assertIn('errors.New("SETUP_COMMIT_STATE_UNKNOWN")', body)

        managed = read("cmd/nftfw/managed.go")
        rollback = managed.split("func setupRollbackCommand", 1)[1].split(
            "func setupJournalNeedsRecovery", 1
        )[0]
        self.assertIn("system := setupRecoverySystem()", rollback)
        self.assertIn("system.GenerationCommitted", rollback)
        self.assertIn("system.Rollback", rollback)
        self.assertIn("system.RecoverCommitted", rollback)

    def test_commit_inspection_and_process_death_regressions_are_present(self) -> None:
        system_tests = read("internal/setup/system_test.go")
        for expected in (
            "TestGenerationCommittedInitializesDefaultsAndPreservesInjections",
            "TestGenerationCommittedFailsClosedOnUnavailableOrMalformedStatus",
        ):
            self.assertIn(expected, system_tests)

        command_tests = read("cmd/nftfw/managed_test.go")
        for expected in (
            "TestOutOfProcessSetupRollbackClassifiesEveryPostApplyPrecommitPhase",
            "TestOutOfProcessSetupRollbackRecoversCommitJournalGapForward",
            "managedsetup.PhaseApply",
            "managedsetup.PhaseTunnel",
            "managedsetup.PhaseValidate",
            "managedsetup.PhaseCommit",
        ):
            self.assertIn(expected, command_tests)


class AmendmentVContracts(unittest.TestCase):
    def test_rollback_uses_only_canonical_managed_routing_identity(self) -> None:
        source = read("internal/setup/system.go")
        route = source.split("func managedRollbackRoute", 1)[1].split(
            "func phaseMayHaveTunnel", 1
        )[0]
        for expected in (
            "summary.VPNInterface != intent.VPNInterface",
            "Interface: intent.VPNInterface",
            "Fwmark: intent.VPNFwmark",
            "Table: routing.DefaultTable",
            'errors.New("SETUP_ROLLBACK_PLAN_INVALID")',
        ):
            self.assertIn(expected, route)

    def test_recovery_transitions_are_durable_and_keep_origin_phase(self) -> None:
        engine = read("internal/setup/engine.go")
        failure = engine.split("func (e Engine) fail", 1)[1].split(
            "func journalNeedsRecovery", 1
        )[0]
        self.assertNotIn("journal.Phase, journal.Status = PhaseRollback", failure)
        self.assertIn('journal.Status = "rolling_back"', failure)
        self.assertIn('journal.Status = "recovering_committed"', failure)
        self.assertIn('errors.New("SETUP_RECOVERY_TRANSITION_WRITE_FAILED")', failure)
        self.assertIn('errors.New("SETUP_RECOVERY_RESULT_WRITE_FAILED")', failure)
        self.assertLess(
            failure.index('journal.Status = "rolling_back"'),
            failure.index("e.Executor.Rollback"),
        )
        self.assertLess(
            failure.index('journal.Status = "recovering_committed"'),
            failure.index("e.Executor.RecoverCommitted"),
        )
        interface = engine.split("type Executor interface", 1)[1].split(
            "type JournalStore interface", 1
        )[0]
        self.assertIn("GenerationCommitted(context.Context, uint64)", interface)

        command = read("cmd/nftfw/managed.go")
        rollback = command.split("func setupRollbackCommand", 1)[1].split(
            "func setupJournalNeedsRecovery", 1
        )[0]
        for expected in (
            'journal.Status = "rolling_back"',
            'journal.Status = "recovering_committed"',
            'journal.Status = "rollback_failed"',
            'journal.Status = "committed_recovery_failed"',
            "setupRecoveryErrorCode",
            "context.WithTimeout",
        ):
            self.assertIn(expected, rollback)

    def test_recovery_transaction_regression_matrix_is_present(self) -> None:
        engine_tests = read("internal/setup/engine_test.go")
        for expected in (
            "TestEveryMutationPhaseFailureRollsBack",
            "TestRecoveryTransitionWriteFailurePrecedesMutation",
            "TestRecoveryResultWriteFailureRemainsSafelyRetryable",
            "TestRecoveryTransitionsResumeAfterSecondProcessDeath",
        ):
            self.assertIn(expected, engine_tests)
        system_tests = read("internal/setup/system_test.go")
        for expected in (
            "TestManagedRollbackUsesCanonicalRoutingIdentityAndOriginPhase",
            "TestManagedRollbackRouteRejectsNoncanonicalRecoveryIdentity",
        ):
            self.assertIn(expected, system_tests)
        command_tests = read("cmd/nftfw/managed_test.go")
        for expected in (
            "TestOutOfProcessRecoveryPublishesTransitionsBeforeMutation",
            "TestOutOfProcessRecoveryTransitionWriteFailureDoesNotMutate",
            "TestOutOfProcessRecoveryFailureIsRedactedAndRetryable",
            "TestOutOfProcessCommittedRecoveryFailureIsRetryable",
            "TestSetupRecoveryJournalTransitionValidation",
        ):
            self.assertIn(expected, command_tests)


class AmendmentWContracts(unittest.TestCase):
    def test_terminal_retry_classification_is_strict_and_read_only(self) -> None:
        source = read("internal/setup/retry.go")
        prepare = read("internal/setup/system.go").split(
            "func (s *System) Prepare", 1
        )[1].split("func (s *System) Backup", 1)[0]
        for expected in (
            "terminalRolledBackJournal(current)",
            "verifyRestoredBackup(ctx, runner, journal.BackupDir)",
            "state.OpenReadOnly(ctx, database)",
            "state.LoadVerifiedGenerationSnapshot(paths.StateDir, id)",
            "provenance.OpenReadOnly(ctx, ledgerPath)",
            "wireguard.ValidateRetainedCache(cache)",
            'generation.Status != "rolled_back"',
            'filepath.Join(paths.StateDir, "enforcement-enabled")',
            "id != uint64(index+1)",
            "current.Generation != generationIDs[len(generationIDs)-1]",
            "verifyRetiredGenerationInventory(paths.StateDir, generationIDs)",
            "generation.ScriptPath != expectedScript",
            "backupPaths[journal.BackupDir]",
        ):
            self.assertIn(expected, source)
        self.assertNotIn("os.Remove(", source)
        self.assertNotIn("os.Rename(", source)
        endpoint = read("internal/wireguard/endpoint.go")
        self.assertIn('json.MarshalIndent(cache, "", "  ")', endpoint)
        self.assertIn("bytes.Equal(raw, append(canonical, '\\n'))", endpoint)
        self.assertIn("inspector.Inspect", prepare)
        self.assertIn("cleanSnapshot.ValidateCleanHost()", prepare)
        self.assertIn("inspectRetiredFirstSetup", prepare)
        self.assertIn("plan.PriorJournalSHA256", prepare)

    def test_terminal_journal_lineage_is_checksum_bound_and_durable(self) -> None:
        source = read("internal/setup/journal.go")
        engine = read("internal/setup/engine.go")
        for expected in (
            "func (f FileJournal) Begin",
            "priorSHA256",
            "readJournalFile(f.Path)",
            "archiveTerminalJournal",
            "unix.Renameat2",
            "unix.RENAME_NOREPLACE",
            'os.CreateTemp(parent, ".journal-history-*.tmp")',
            "syncRegularSetupFile(destination)",
            "syncSetupDirectory(history)",
            "syncSetupDirectory(parent)",
            "secureSetupDirectory(parent)",
            "SETUP_JOURNAL_HISTORY_COLLISION",
        ):
            self.assertIn(expected, source)
        self.assertIn("Begin(Journal, string) error", engine)
        self.assertIn("e.Journal.Begin(journal, plan.PriorJournalSHA256)", engine)

    def test_retry_lineage_security_matrix_and_operator_docs_are_present(self) -> None:
        retry_tests = read("internal/setup/retry_test.go")
        journal_tests = read("internal/setup/journal_lineage_test.go")
        backup_tests = read("internal/setup/backup_test.go")
        for expected in (
            "TestRetiredFirstSetupRetryPreservesMonotonicState",
            "TestRetiredFirstSetupRepeatedTerminalLineage",
            "TestRetiredFirstSetupPredicatesFailClosed",
            "TestPreMutationTerminalWithoutRetainedGenerationCanRetry",
            '"current-journal-not-latest"',
            '"duplicate-backup-lineage"',
            '"generation-id-gap"',
            '"generation-inventory-extra"',
        ):
            self.assertIn(expected, retry_tests)
        for expected in (
            "TestFileJournalBeginArchivesExactTerminalLineage",
            "TestFileJournalBeginRetriesExistingExactArchive",
            "TestFileJournalBeginIgnoresPreRenameCrashResidueOutsideHistory",
            "TestFileJournalBeginRefusesChangedOrAmbiguousLineage",
            "TestFileJournalBeginRefusesHistoryCollisionAndUnsafeMode",
        ):
            self.assertIn(expected, journal_tests)
        self.assertIn(
            "TestVerifyRestoredBackupFailsClosedOnEveryEvidenceClass", backup_tests
        )
        for relative in (
            "tests/packaging/managed_retry_controller.sh",
            "tests/packaging/managed_retry_disposable.sh",
        ):
            self.assertTrue((ROOT / relative).is_file(), f"missing {relative}")
        for relative in (
            "README.md",
            "QUICKSTART.md",
            "docs/ARCHITECTURE.md",
            "docs/RECOVERY.md",
            "docs/TROUBLESHOOTING.md",
            "docs/TESTING.md",
        ):
            self.assertIn(
                "terminal retry",
                read(relative).lower(),
                f"{relative} does not document terminal retry behavior",
            )


class ReleaseCandidateMetadataContracts(unittest.TestCase):
    def test_build_defaults_and_ci_identify_2_1_0(self) -> None:
        makefile = read("Makefile")
        if not (
            re.search(r"(?m)^TARGET_VERSION := .*RELEASE_VERSION", makefile)
            and "VERSION ?= $(TARGET_VERSION)" in makefile
        ):
            self.fail("Makefile must source its default VERSION from RELEASE_VERSION")
        if read("RELEASE_VERSION").strip() != "2.1.0":
            self.fail("tracked RELEASE_VERSION must identify the 2.1.0 source line")
        build_deb = read("scripts/build-deb.sh")
        if 'version=${1:-}' not in build_deb or "Usage: build-deb.sh <version>" not in build_deb:
            self.fail("build-deb.sh must require an explicit version argument")
        if re.search(r"version=\$\{1:-2\.0\.1\}", build_deb):
            self.fail("build-deb.sh retains the obsolete 2.0.1 default")
        if "make deb VERSION=2.1.0+ci" not in read(".github/workflows/ci.yml"):
            self.fail("CI package build must use the clearly non-final 2.1.0+ci version")
        if "nft-firewall-v2_2.0.1_" in read("INSTALL.md"):
            self.fail("INSTALL.md still names a 2.0.1 package as the current install input")

    def test_candidate_payload_is_intrinsically_quarantined(self) -> None:
        makefile = read("Makefile")
        version_source = read("internal/version/version.go")
        cli = read("cmd/nftfw/main.go")
        daemon = read("cmd/nftfwd/main.go")
        web = read("cmd/nftfw-web/main.go")
        builder = read("scripts/build-deb.sh")
        control = read("packaging/deb/control")
        preinst = read("packaging/deb/preinst")
        installer = read("scripts/install.sh")
        ci = read(".github/workflows/ci.yml")

        self.assertRegex(
            makefile,
            r"(?m)^COMMIT \?= .*git rev-parse --verify 'HEAD\^\{commit\}'",
        )
        self.assertIn("full 40-hex Git commit", makefile)
        self.assertIn("NFTFW_BUILD_DISPOSITION ?= $(DISPOSITION)", makefile)
        self.assertIn("BuildDisposition=$(NFTFW_BUILD_DISPOSITION)", makefile)
        self.assertIn("ArtifactIdentity=$(ARTIFACT_IDENTITY)", makefile)
        self.assertIn('BuildDisposition = "development"', version_source)
        self.assertIn('json:"build_disposition"', version_source)
        self.assertIn('json:"artifact_identity"', version_source)
        self.assertIn('StageRCandidateOnly = "stage-r-candidate-only"', version_source)
        self.assertIn('strings.Contains(Version, "~stage.r.")', version_source)

        self.assertLess(
            cli.index("version.IsStageRCandidateOnly()"),
            cli.index('configPath := os.Getenv("NFTFW_CONFIG")'),
            "candidate CLI quarantine must run before config/state/socket discovery",
        )
        self.assertIn('args[0] != "version"', cli)
        self.assertLess(
            daemon.index("candidateStartupGuard()"),
            daemon.index('flag.String("config"'),
            "candidate daemon must stop before flag/state/network setup",
        )
        self.assertLess(
            web.index("candidateStartupGuard()"),
            web.index('os.Getenv("NFTFW_WEB_BIND")'),
            "candidate web service must stop before bind/socket setup",
        )

        self.assertIn("build_disposition=${NFTFW_BUILD_DISPOSITION:-development}", builder)
        self.assertIn("for metadata_arch in amd64 arm64", builder)
        self.assertIn("for metadata_binary in nftfw nftfwd nftfw-web", builder)
        self.assertIn("go version -m", builder)
        self.assertIn("expected_artifact_identity=", builder)
        self.assertIn("Composite artifact identity is missing", builder)
        self.assertIn('"$version" != "$target_version~stage.r.${candidate_commit:0:12}"', builder)
        self.assertIn("Package payload hash differs from standalone", builder)
        self.assertIn("X-NFTFW-Build-Disposition: @BUILD_DISPOSITION@", control)
        self.assertIn("package_build_disposition='@BUILD_DISPOSITION@'", preinst)
        self.assertLess(
            preinst.index("action=${1:-}"),
            preinst.index('[ "$package_build_disposition" != release ]'),
            "abort/recovery callbacks must exit before candidate install refusal",
        )
        self.assertIn("*~stage.r.*)", preinst)

        self.assertIn("jq", installer.split("protected_root_file()", 1)[0])
        self.assertIn('"$binary" version --json', installer)
        self.assertIn('"$candidate_disposition" != release', installer)
        self.assertIn('"$candidate_version" == *~stage.r.*', installer)
        self.assertIn('"$candidate_version" == 2.1.0', installer)
        self.assertLess(
            installer.index('"$candidate_disposition" != release'),
            installer.index("validation_dir=\"\""),
            "source candidate refusal must precede target validation/install changes",
        )
        self.assertIn('COMMIT="$GITHUB_SHA" DISPOSITION=ci', ci)

    @unittest.skipUnless(shutil.which("make"), "make is required by build contracts")
    def test_release_metadata_gate_requires_full_commit_and_known_disposition(self) -> None:
        base = [
            "make",
            "release-metadata-check",
            "VERSION=2.1.0~stage.r.aaaaaaaaaaaa",
            "BUILD_DATE=2026-08-24T00:00:00Z",
        ]
        accepted = subprocess.run(
            base + ["COMMIT=" + "a" * 40, "DISPOSITION=stage-r-candidate-only"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        short = subprocess.run(
            base + ["COMMIT=" + "a" * 12, "DISPOSITION=stage-r-candidate-only"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(short.returncode, 0)
        self.assertIn("full 40-hex Git commit", short.stderr)
        unknown = subprocess.run(
            base + ["COMMIT=" + "a" * 40, "DISPOSITION=deployable-candidate"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(unknown.returncode, 0)
        self.assertIn("NFTFW_BUILD_DISPOSITION", unknown.stderr)
        forged_release = subprocess.run(
            base + ["COMMIT=" + "a" * 40, "DISPOSITION=release"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(forged_release.returncode, 0)
        self.assertIn("exact tracked release version", forged_release.stderr)
        forged_candidate = subprocess.run(
            [
                "make",
                "release-metadata-check",
                "VERSION=2.1.0",
                "BUILD_DATE=2026-08-24T00:00:00Z",
                "COMMIT=" + "a" * 40,
                "DISPOSITION=stage-r-candidate-only",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(forged_candidate.returncode, 0)
        self.assertIn("target~stage.r.commit12", forged_candidate.stderr)
        ci = subprocess.run(
            [
                "make",
                "release-metadata-check",
                "VERSION=2.1.0+ci",
                "BUILD_DATE=2026-08-24T00:00:00Z",
                "COMMIT=" + "a" * 40,
                "DISPOSITION=ci",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(ci.returncode, 0, ci.stderr)

    def test_ci_keeps_privileged_evidence_behind_separate_r2_gate(self) -> None:
        source = read(".github/workflows/ci.yml")
        for expected in (
            "stage-r2-privileged-namespace:",
            "NFTFW_STAGE_R2_APPROVED == 'enabled'",
            "NFTFW_PRIVILEGED_RUNNER == 'enabled'",
        ):
            if expected not in source:
                self.fail(f"CI is missing the separate R2 gate fragment {expected!r}")
        stage_r = source.split("  stage-r-contracts:", 1)[1].split("\n  package:", 1)[0]
        self.assertNotIn(
            "sudo ",
            stage_r,
            "source-only Stage R CI must not invoke privileged test commands",
        )
        if "R2 privileged package/boot/network/Docker/OVPN evidence was not executed." not in stage_r:
            self.fail("Stage R CI must explicitly report that R2 evidence was not executed")

    def test_current_evidence_does_not_claim_2_0_1_as_the_candidate(self) -> None:
        for relative in (
            "BUILD_STATUS.md",
            "TEST_RESULTS.md",
            "FINAL_ACCEPTANCE_REPORT.md",
        ):
            source = read(relative)
            stale = re.search(
                r"(?i)(?:current\s+`?2\.0\.1`?\s+(?:source\s+)?candidate|"
                r"`?2\.0\.1`?\s+candidate(?:\s+evidence)?|"
                r"`?2\.0\.1`?\s+is\s+a\s+completed)",
                source,
            )
            if stale:
                self.fail(
                    f"{relative} still presents 2.0.1 as current/completed candidate "
                    f"evidence near {stale.group(0)!r}"
                )
        changelog = read("CHANGELOG.md")
        first_heading = re.search(r"(?m)^## ([^\n]+)$", changelog)
        self.assertIsNotNone(first_heading, "CHANGELOG.md has no release heading")
        self.assertTrue(
            first_heading.group(1).startswith("2.1.0"),
            f"first changelog release must be 2.1.0, found {first_heading.group(1)!r}",
        )

    def test_untagged_builder_marks_private_rc_as_not_deployable(self) -> None:
        source = read("scripts/package-release.sh")
        if "--allow-untagged" not in source or "tag=unreleased" not in source:
            self.fail("release builder must retain its explicit untagged candidate mode")
        if "RELEASE CANDIDATE - NOT DEPLOYABLE" not in source:
            self.fail(
                "untagged output must carry `RELEASE CANDIDATE - NOT DEPLOYABLE`; "
                "checksums alone do not make it a final release"
            )


class AmendmentXContracts(unittest.TestCase):
    def test_grub_policy_is_fixed_strict_and_transaction_owned(self) -> None:
        boot = read("internal/setup/boot.go")
        system = read("internal/setup/system.go")
        for expected in (
            "/etc/default/grub.d/90-nftfw-ipv6-disabled.cfg",
            "/boot/grub/grub.cfg",
            "/usr/sbin/update-grub",
            "grub2-common",
            "unix.RENAME_NOREPLACE",
            "SETUP_BOOT_MOUNT_UNSUPPORTED",
            "SETUP_BOOT_MANAGER_AMBIGUOUS",
            "verifyGeneratedGRUB",
            "verifyRunningBoot",
        ):
            self.assertIn(expected, boot + system)
        self.assertIn("ipv6.disable=1", boot)
        self.assertIn("context.WithTimeout", boot)
        self.assertNotIn('"systemctl", "reboot"', boot + system)

    def test_efi_identity_and_prepolicy_boot_hold_fail_closed(self) -> None:
        boot = read("internal/setup/boot.go")
        system = read("internal/setup/system.go")
        command = read("cmd/nftfw/managed.go")
        service = parse_unit("packaging/systemd/nftfw-setup-boot-hold.service")
        generator = read("packaging/systemd/nftfw-setup-boot-hold-generator")
        for expected in (
            "/sys/firmware/efi",
            "/usr/bin/efibootmgr",
            "EFI firmware networking is enabled",
            "BootCurrent: ",
            "BootOrder: ",
            "BootNext: ",
            "setup-boot-hold-v1",
            "setup-boot-hold-ready",
            "setup-boot-release",
            "WaitBootHold",
            "releaseBootHold",
        ):
            self.assertIn(expected, boot + system)
        self.assertIn('args[0] == "boot-hold"', command)
        self.assertEqual(words(service, "Unit", "Before"), {"network-pre.target"})
        self.assertEqual(values(service, "Service", "Type"), ["oneshot"])
        self.assertEqual(values(service, "Service", "TimeoutStartSec"), ["infinity"])
        self.assertEqual(
            values(service, "Service", "ExecStart"),
            ["/usr/lib/nftfw/nftfw setup boot-hold"],
        )
        self.assertEqual(
            words(service, "Service", "RestrictAddressFamilies"),
            {"AF_UNIX", "AF_NETLINK"},
        )
        self.assertEqual(
            words(service, "Service", "CapabilityBoundingSet"),
            {"CAP_CHOWN", "CAP_NET_ADMIN"},
        )
        self.assertEqual(
            words(service, "Service", "AmbientCapabilities"),
            {"CAP_CHOWN", "CAP_NET_ADMIN"},
        )
        self.assertEqual(values(service, "Service", "ProtectSystem"), ["strict"])
        self.assertEqual(values(service, "Service", "PrivateTmp"), ["yes"])
        self.assertIn("/run/systemd/generator.early", generator)
        self.assertIn("/run/systemd/generator.late", generator)
        self.assertIn("network-pre.target.requires", generator)
        self.assertIn("network.target.d", generator)
        self.assertIn("Requires=network-pre.target", generator)
        self.assertIn("After=network-pre.target", generator)
        self.assertIn("nftfw-setup-docker-hold.service", generator)
        self.assertIn("for consumer in docker.service docker.socket", generator)
        self.assertIn("dropin_dir=$normal/$consumer.d", generator)
        self.assertIn('[ "$consumer" = docker.service ]', generator)
        self.assertIn("Ordering docker.socket after an indefinite oneshot", generator)
        docker_hold = parse_unit("packaging/systemd/nftfw-setup-docker-hold.service")
        self.assertEqual(words(docker_hold, "Unit", "Before"), {"docker.service"})
        self.assertIn("[ ! -e \"$marker\" ] && [ ! -L \"$marker\" ]", generator)
        self.assertNotIn("systemctl", generator)

    def test_boot_hold_lifecycle_and_direct_fixture_are_complete(self) -> None:
        builder = read("scripts/build-deb.sh")
        installer = read("scripts/install.sh")
        preinst = read("packaging/deb/preinst")
        prerm = read("packaging/deb/prerm")
        uninstall = read("scripts/uninstall.sh")
        artifact = "nftfw-setup-boot-hold-generator"
        for source in (builder, installer, preinst, uninstall):
            self.assertIn(artifact, source)
        self.assertIn("nftfw-setup-boot-hold.service", prerm)
        for shadow_root in (
            "/etc/systemd/system-generators",
            "/run/systemd/system-generators",
            "/usr/local/lib/systemd/system-generators",
        ):
            self.assertIn(shadow_root, preinst)
        self.assertIn("Refusing to overwrite a foreign systemd generator", installer)
        fixture = read("tests/packaging/setup_boot_hold_generator.sh")
        for expected in (
            "absent boot-hold marker emitted",
            "foreign dependency link was accepted",
            "unsafe marker did not fail closed",
            "unsafe generator output path was accepted",
            "symlinked generator dependency directory was accepted",
            "symlinked network target drop-in directory was accepted",
            "foreign network hold fragment was accepted",
            "symlinked network hold fragment was accepted",
        ):
            self.assertIn(expected, fixture)

    def test_setup_has_durable_reboot_resume_and_rollback_states(self) -> None:
        engine = read("internal/setup/engine.go")
        command = read("cmd/nftfw/managed.go")
        self.assertLess(engine.index("PhaseBootPrep"), engine.index("PhaseGuard"))
        for expected in (
            '"reboot_required"',
            '"resume_ready"',
            '"rollback_reboot_required"',
            "ErrRebootRequired",
            "ErrRollbackRebootRequired",
        ):
            self.assertIn(expected, engine + command)
        status = command.split("if len(args) > 0 && args[0] == \"status\"", 1)[1].split(
            'if len(args) > 0 && args[0] == "rollback"', 1
        )[0]
        self.assertNotIn('"backup_dir"', status)
        self.assertNotIn('"cmdline"', status)

    def test_native_guard_requires_kernel_disable_without_loopback_reenable(self) -> None:
        loader = read("packaging/initramfs/nftfw-ipv6-early")
        self.assertIn("/proc/cmdline", loader)
        self.assertIn("/sys/module/ipv6/parameters/disable", loader)
        self.assertIn("/proc/net/if_inet6", loader)
        self.assertNotIn("conf/lo/disable_ipv6", loader)
        self.assertIn("nft --check --file", loader)
        self.assertIn("ready_message='NFTFW initramfs guard ready'", loader)

    def test_package_and_exact_downgrade_restore_boot_ownership(self) -> None:
        for relative, argument in (
            ("packaging/deb/prerm", "--package-remove"),
            ("scripts/uninstall.sh", "--package-remove"),
            ("scripts/package-rollback.sh", "--package-downgrade"),
        ):
            source = read(relative)
            self.assertIn("90-nftfw-ipv6-disabled.cfg", source)
            self.assertIn("setup boot-handoff", source)
            self.assertIn(argument, source)
        command = read("cmd/nftfw/managed.go")
        preinst = read("packaging/deb/preinst")
        self.assertIn("package-upgrade-preflight", command)
        self.assertIn("setup package-upgrade-preflight", preinst)
        self.assertIn("incomplete or ambiguous managed boot transaction", preinst)

    def test_direct_boot_security_matrix_is_present(self) -> None:
        tests = read("internal/setup/boot_test.go")
        for expected in (
            "TestManagedGRUBIdentityAndArgumentMatrix",
            "TestManagedGRUBRefusesUnsafeIdentity",
            "TestManagedBootTwoPassTransaction",
            "TestManagedBootUpdateFailureRestoresExactly",
            "TestManagedBootHoldResumeReleaseHandshake",
            "TestManagedBootHoldRuntimeStateRefusalMatrix",
            "TestManagedBootHoldInvalidStateFailsClosed",
            "TestManagedGRUBEFIIdentityMatrix",
            "duplicate",
            "quoted-conflict",
            "symlink-config",
            "read-only-mount",
        ):
            self.assertIn(expected, tests)
        conflict = read("tests/packaging/managed_boot_grub_conflict.py")
        self.assertIn("ipv6.disable=0 ipv6.disable=1", conflict)
        self.assertIn("os.O_EXCL | os.O_NOFOLLOW", conflict)
        pcap = read("tests/packaging/managed_boot_pcap.py")
        self.assertIn("--expect-zero-guest", pcap)
        self.assertIn("failed boot identity emitted a guest frame", pcap)


if __name__ == "__main__":
    unittest.main(verbosity=2)
