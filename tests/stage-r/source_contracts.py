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
            "a 2.0.2 package must not open state from a future/newer package",
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
            "2.0.2 compatibility-family gate",
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
        staged = source.replace("@VERSION@", "2.0.2~rc1").replace(
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
                ["dash", script.name, "abort-upgrade", "2.0.2~rc0"],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("was not substituted safely", result.stderr)

    def test_deb_preinst_intrinsically_refuses_non_release_payloads(self) -> None:
        staged = (
            read("packaging/deb/preinst")
            .replace("@VERSION@", "2.0.2~stage.r.aaaaaaaaaaaa")
            .replace("@COMMIT@", "a" * 40)
            .replace("@BUILD_DISPOSITION@", "stage-r-candidate-only")
        )
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", prefix="nftfw-candidate-preinst-", delete=True
        ) as script:
            script.write(staged)
            script.flush()
            result = subprocess.run(
                ["dash", script.name, "install", "2.0.2~stage.r.old"],
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
                ["dash", script.name, "abort-upgrade", "2.0.2~stage.r.old"],
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

        self.assertTrue(compare("2.0.2~rc1", "lt", "2.0.2"))
        self.assertTrue(compare("2.0.2+ci", "gt", "2.0.2"))
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
            '{"version":"2.0.2~rc1","commit":"'
            + commit
            + '","build_date":"2026-08-24T00:00:00Z",'
            '"build_disposition":"release",'
            '"artifact_identity":"2.0.2~rc1|'
            + commit
            + '|2026-08-24T00:00:00Z|release"}'
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual(accepted.stdout, f"2.0.2~rc1 {commit} release\n")
        self.assertNotEqual(
            identify(
                '{"version":"2.0.2","commit":"unknown",'
                '"build_date":"unknown","build_disposition":"release",'
                '"artifact_identity":"2.0.2|unknown|unknown|release"}'
            ).returncode,
            0,
        )
        self.assertNotEqual(
            identify(
                '{"version":"2.0.2","commit":"'
                + commit
                + '","build_date":"now","build_disposition":"release",'
                '"artifact_identity":"2.0.2|'
                + commit
                + '|now|release"}'
            ).returncode,
            0,
        )
        self.assertEqual(
            identify(
                '{"version":"2.0.2","commit":"'
                + commit
                + '","build_date":"2026-08-24T00:00:00Z",'
                '"build_disposition":"stage-r-candidate-only",'
                '"artifact_identity":"2.0.2|'
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
            "2.0.2 never publishes the legacy active snapshot, so its absence must not "
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
            "early restore must use the complete 2.0.2 recovery operation",
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

    def test_ready_unit_is_nonactivating_and_read_only(self) -> None:
        relative = "packaging/systemd/nftfw-enforcement-ready.service"
        unit = parse_unit(relative)
        self.assertEqual(
            words(unit, "Unit", "Requisite"),
            {"nftfw-early.service"},
            "readiness must require early to be already active without activating it",
        )
        for key in self.ACTIVATING_KEYS:
            self.assertNotIn(
                "nftfw-early.service",
                words(unit, "Unit", key),
                f"readiness must use Requisite, not activating {key}=, for early restore",
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
                "2.0.2 static recovery must not silently fall back to the legacy database"
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


class ReleaseCandidateMetadataContracts(unittest.TestCase):
    def test_build_defaults_and_ci_identify_2_0_2(self) -> None:
        makefile = read("Makefile")
        if not (
            re.search(r"(?m)^TARGET_VERSION := .*RELEASE_VERSION", makefile)
            and "VERSION ?= $(TARGET_VERSION)" in makefile
        ):
            self.fail("Makefile must source its default VERSION from RELEASE_VERSION")
        if read("RELEASE_VERSION").strip() != "2.0.2":
            self.fail("tracked RELEASE_VERSION must identify the 2.0.2 source line")
        build_deb = read("scripts/build-deb.sh")
        if 'version=${1:-}' not in build_deb or "Usage: build-deb.sh <version>" not in build_deb:
            self.fail("build-deb.sh must require an explicit version argument")
        if re.search(r"version=\$\{1:-2\.0\.1\}", build_deb):
            self.fail("build-deb.sh retains the obsolete 2.0.1 default")
        if "make deb VERSION=2.0.2+ci" not in read(".github/workflows/ci.yml"):
            self.fail("CI package build must use the clearly non-final 2.0.2+ci version")
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
        self.assertIn('"$candidate_version" == 2.0.2', installer)
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
            "VERSION=2.0.2~stage.r.aaaaaaaaaaaa",
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
                "VERSION=2.0.2",
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
                "VERSION=2.0.2+ci",
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
            first_heading.group(1).startswith("2.0.2"),
            f"first changelog release must be 2.0.2, found {first_heading.group(1)!r}",
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
