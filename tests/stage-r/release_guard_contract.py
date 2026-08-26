#!/usr/bin/env python3
"""Static Stage R contracts for candidate/final release separation."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def read_from_release_tag(relative: str) -> str:
    result = subprocess.run(
        ["git", "show", f"v2.0.3:{relative}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


class ReleaseGuardContracts(unittest.TestCase):
    def test_git_archive_modes_are_hermetic(self) -> None:
        source = read("scripts/package-release.sh")
        self.assertIn(
            'git -c tar.umask=0022 archive --format=tar --output="$source_export" "$commit"',
            source,
        )

    def setUp(self) -> None:
        self.script = read("scripts/package-release.sh")
        self.report = read("FINAL_ACCEPTANCE_REPORT.md")

    def test_frozen_source_reports_remain_candidate_only(self) -> None:
        historical_report = read_from_release_tag("FINAL_ACCEPTANCE_REPORT.md")
        self.assertIn(
            "Release approval status: STAGE_R_CANDIDATE_ONLY",
            historical_report,
        )
        self.assertIn(
            "Release approval status: STAGE_R_CANDIDATE_ONLY",
            self.report,
        )

    def test_later_tagged_build_requires_external_exact_r2_attestation(self) -> None:
        self.assertIn(
            "Release approval status: STAGE_R_CANDIDATE_ONLY", self.report
        )
        required = (
            '$(git cat-file -t "refs/tags/$tag"',
            'r2_attestation=${NFTFW_R2_ATTESTATION:-}',
            '.status == "R2_PASSED_TAG_BUILD_AUTHORIZED"',
            '.target_version == $version and .git_commit == $commit',
            '.publication_authorized == false and .deployment_authorized == false',
            '.privileged_evidence_manifest_sha256 | test("^[0-9a-f]{64}$")',
            'publication_authorized:false',
        )
        missing = [fragment for fragment in required if fragment not in self.script]
        self.assertFalse(missing, f"tagged-build authorization is incomplete: {missing}")
        self.assertIn(
            "R2 PRIVILEGED PACKAGE/BOOT/NETWORK/DOCKER/OVPN EVIDENCE: NOT EXECUTED",
            self.report,
        )

    def test_allow_untagged_is_unambiguously_candidate_only(self) -> None:
        required = (
            'if [[ "$allow_untagged" == --allow-untagged ]]',
            'tag=unreleased',
            'candidate_mode=1',
            'release_disposition="RELEASE CANDIDATE - NOT DEPLOYABLE"',
            'artifact_version="$version~stage.r.${commit:0:12}"',
            'build_disposition="stage-r-candidate-only"',
            '"--allow-untagged refuses an existing release tag name;',
        )
        missing = [fragment for fragment in required if fragment not in self.script]
        self.assertFalse(
            missing,
            f"untagged candidate mode is missing mandatory guards: {missing}",
        )

    def test_candidate_paths_and_reports_are_visibly_quarantined(self) -> None:
        self.assertIn(
            'artifact_label="$version-RELEASE-CANDIDATE-NOT-DEPLOYABLE-${commit:0:12}"',
            self.script,
        )
        replacements = {
            "@RELEASE_DISPOSITION@": (
                '-e "s#@RELEASE_DISPOSITION@#$release_disposition#g"'
            ),
            "@RELEASE_ARTIFACT_LABEL@": (
                '-e "s#@RELEASE_ARTIFACT_LABEL@#$artifact_label#g"'
            ),
        }
        for token, replacement in replacements.items():
            self.assertIn(token, self.report)
            self.assertIn(
                replacement,
                self.script,
                f"release builder does not replace report token {token}",
            )

    def test_candidate_build_emits_external_temporally_scoped_evidence(self) -> None:
        required = (
            'build_evidence_name="CANDIDATE_BUILD_EVIDENCE-NOT-DEPLOYABLE.json"',
            'evidence_status="STAGE_R_CANDIDATE_BUILD_PASS"',
            'source_reports_scope:"FROZEN_PRE_BUILD_SOURCE_SNAPSHOT_ONLY"',
            'privileged_evidence_status="NOT_EXECUTED"',
            'install -m 0644 "$release_root/source/TEST_RESULTS.md" "$publish_dir/SOURCE_TEST_RESULTS.md"',
            '"SOURCE_HISTORY_SECRET_SCAN.json"',
            '"EXTRACTED_TREE_SECRET_SCAN.json"',
            'source_and_reachable_history_secret_scan:"PASS"',
            'both_extracted_archives_secret_scan:"PASS"',
        )
        missing = [fragment for fragment in required if fragment not in self.script]
        self.assertFalse(missing, f"candidate evidence remains self-stale: {missing}")

    def test_candidate_notice_is_embedded_external_and_checksummed(self) -> None:
        required = (
            'candidate_notice_name="RELEASE-CANDIDATE-NOT-DEPLOYABLE.txt"',
            '> "$release_root/$candidate_notice_name"',
            '"$publish_dir/$candidate_notice_name"',
            'external_artifacts+=("$candidate_notice_name")',
            "Do not install, deploy, publish, or represent these artifacts as a final release.",
        )
        missing = [fragment for fragment in required if fragment not in self.script]
        self.assertFalse(
            missing,
            f"candidate warning is not carried through every artifact boundary: {missing}",
        )

    def test_standalone_candidate_executables_are_visibly_quarantined(self) -> None:
        required = (
            'published_binary="$binary-linux-$arch-RELEASE-CANDIDATE-NOT-DEPLOYABLE-${commit:0:12}"',
            'published_package="nft-firewall-v2_${artifact_label}_${arch}.deb"',
            'external_artifacts+=("$published_binary")',
            'external_artifacts+=("$published_package")',
        )
        missing = [fragment for fragment in required if fragment not in self.script]
        self.assertFalse(
            missing,
            f"standalone candidate executables have ambiguous filenames: {missing}",
        )

    def test_final_approval_binds_named_post_tag_validation_manifest(self) -> None:
        approval = read("docs/FINAL_RELEASE_APPROVAL.example.json")
        validation = read("docs/POST_TAG_VALIDATION.example.json")
        self.assertIn('"post_tag_validation_manifest_sha256"', approval)
        self.assertIn('"git_tag_object"', approval)
        self.assertNotIn('"post_tag_gates"', approval)
        for gate in (
            "package_lifecycle",
            "boot_and_recovery",
            "network_provenance_and_zero_leak",
            "docker_bridge_lifecycle",
            "real_ovpn",
            "two_build_reproducibility",
            "package_and_archive_inspection",
            "source_history_and_extracted_tree_secret_scan",
        ):
            self.assertIn(f'"{gate}": "PASS"', validation)

    def test_release_output_uses_protected_parent_and_atomic_no_replace(self) -> None:
        for required in (
            "NFTFW_RELEASE_PARENT must be a pre-created protected directory",
            "info.st_uid != os.getuid() or mode & 0o022",
            "os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW",
            "renameat2 = libc.renameat2",
            "RENAME_NOREPLACE",
            "Atomic no-replace publication",
        ):
            self.assertIn(required, self.script)


if __name__ == "__main__":
    unittest.main(verbosity=2)
