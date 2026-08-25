#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import stat
import subprocess
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "scripts" / "compare-candidate-builds.py"
EVIDENCE = "CANDIDATE_BUILD_EVIDENCE-NOT-DEPLOYABLE.json"
CHECKSUMS = "SHA256SUMS"
REQUIRED_CHECKS = {
    "clean_commit_export": "PASS",
    "binary_identity_and_metadata": "PASS",
    "package_identity_and_payload": "PASS",
    "staged_systemd_verification": "PASS",
    "archive_integrity_and_internal_checksums": "PASS",
    "source_and_reachable_history_secret_scan": "PASS",
    "both_extracted_archives_secret_scan": "PASS",
    "extracted_archive_secret_evidence_byte_identical": "PASS",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rewrite_checksums(root: Path) -> None:
    checksummed = sorted(path for path in root.iterdir() if path.name != CHECKSUMS)
    lines = [f"{digest(path)}  {path.name}\n" for path in checksummed if path.is_file()]
    (root / CHECKSUMS).write_text("".join(lines), encoding="utf-8")


def rewrite_evidence(root: Path, mutate: Callable[[dict[str, object]], None]) -> None:
    path = root / EVIDENCE
    evidence = json.loads(path.read_text(encoding="utf-8"))
    mutate(evidence)
    path.write_text(json.dumps(evidence, sort_keys=True) + "\n", encoding="utf-8")
    rewrite_checksums(root)


def make_candidate(root: Path, payload: bytes = b"candidate payload\n") -> None:
    root.chmod(0o700)
    binary = root / "nftfw-linux-amd64-RELEASE-CANDIDATE-NOT-DEPLOYABLE-deadbeefcafe"
    binary.write_bytes(payload)
    binary.chmod(0o755)
    source_secret_scan = root / "SOURCE_HISTORY_SECRET_SCAN.json"
    source_secret_scan.write_text('{"status":"PASS","scope":"history"}\n', encoding="utf-8")
    extracted_secret_scan = root / "EXTRACTED_TREE_SECRET_SCAN.json"
    extracted_secret_scan.write_text('{"status":"PASS","scope":"tree"}\n', encoding="utf-8")
    subjects = (binary, source_secret_scan, extracted_secret_scan)
    evidence = {
        "schema": "nftfw.build-evidence.v1",
        "status": "STAGE_R_CANDIDATE_BUILD_PASS",
        "target_version": "2.0.3",
        "artifact_version": "2.0.3~stage.r.deadbeefcafe",
        "git_commit": "deadbeefcafe" + "0" * 28,
        "git_tag": "unreleased",
        "git_tag_object": "unreleased",
        "build_date": "2026-01-01T00:00:00Z",
        "build_disposition": "stage-r-candidate-only",
        "runtime_capable": False,
        "deployable": False,
        "deployment_authorized": False,
        "publication_authorized": False,
        "source_reports_scope": "FROZEN_PRE_BUILD_SOURCE_SNAPSHOT_ONLY",
        "toolchain": {"go": "go1.25.13"},
        "privileged_r2_evidence": "NOT_EXECUTED",
        "r2_attestation_sha256": "NOT_APPLICABLE",
        "checks": dict(REQUIRED_CHECKS),
        "secret_scan_evidence": {
            "scanner_sha256": "a" * 64,
            "source_history_sha256": digest(source_secret_scan),
            "extracted_tree_sha256": digest(extracted_secret_scan),
        },
        "artifacts": [
            {
                "path": subject.name,
                "sha256": digest(subject),
                "size": subject.stat().st_size,
                "mode": f"{stat.S_IMODE(subject.stat().st_mode):o}",
            }
            for subject in subjects
        ],
    }
    (root / EVIDENCE).write_text(json.dumps(evidence, sort_keys=True) + "\n", encoding="utf-8")
    rewrite_checksums(root)


class CandidateComparisonTests(unittest.TestCase):
    def compare(
        self, parent: Path, left: Path, right: Path
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        output = parent / "comparison.json"
        result = subprocess.run(
            [str(TOOL), "--left", str(left), "--right", str(right), "--output", str(output)],
            text=True,
            capture_output=True,
            check=False,
        )
        return result, output

    def assert_rejected(
        self, result: subprocess.CompletedProcess[str], output: Path, expected: str
    ) -> None:
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())
        self.assertIn(expected, result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_identical_candidates_emit_external_pass_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nftfw-compare-") as temporary:
            parent = Path(temporary).resolve()
            left, right = parent / "left", parent / "right"
            left.mkdir()
            right.mkdir()
            make_candidate(left)
            make_candidate(right)
            result, output = self.compare(parent, left, right)
            self.assertEqual(result.returncode, 0, result.stderr)
            evidence = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(evidence["status"], "STAGE_R_CANDIDATE_COMPARISON_PASS")
            self.assertEqual(evidence["build_disposition"], "stage-r-candidate-only")
            self.assertFalse(evidence["runtime_capable"])
            self.assertFalse(evidence["deployable"])
            self.assertFalse(evidence["deployment_authorized"])
            self.assertFalse(evidence["publication_authorized"])
            self.assertEqual(evidence["privileged_r2_evidence"], "NOT_EXECUTED")
            self.assertEqual(evidence["r2_attestation_sha256"], "NOT_APPLICABLE")
            self.assertEqual(evidence["toolchain"], {"go": "go1.25.13"})
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o644)

    def test_difference_fails_without_writing_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nftfw-compare-") as temporary:
            parent = Path(temporary).resolve()
            left, right = parent / "left", parent / "right"
            left.mkdir()
            right.mkdir()
            make_candidate(left)
            make_candidate(right, b"different payload\n")
            result, output = self.compare(parent, left, right)
            self.assert_rejected(result, output, "candidate outputs differ")

    def test_each_evidence_record_must_report_every_required_check_pass(self) -> None:
        for failed_check in REQUIRED_CHECKS:
            with self.subTest(check=failed_check), tempfile.TemporaryDirectory(
                prefix="nftfw-compare-"
            ) as temporary:
                parent = Path(temporary).resolve()
                left, right = parent / "left", parent / "right"
                left.mkdir()
                right.mkdir()
                make_candidate(left)
                make_candidate(right)

                def fail_check(evidence: dict[str, object]) -> None:
                    checks = evidence["checks"]
                    assert isinstance(checks, dict)
                    checks[failed_check] = "FAIL"

                rewrite_evidence(right, fail_check)
                result, output = self.compare(parent, left, right)
                self.assert_rejected(
                    result,
                    output,
                    f"candidate evidence check did not pass: {failed_check}",
                )

    def test_unrecognized_extra_check_cannot_hide_a_new_failed_gate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nftfw-compare-") as temporary:
            parent = Path(temporary).resolve()
            left, right = parent / "left", parent / "right"
            left.mkdir()
            right.mkdir()
            make_candidate(left)
            make_candidate(right)

            def add_failed_gate(evidence: dict[str, object]) -> None:
                checks = evidence["checks"]
                assert isinstance(checks, dict)
                checks["new_security_gate"] = "FAIL"

            rewrite_evidence(left, add_failed_gate)
            result, output = self.compare(parent, left, right)
            self.assert_rejected(result, output, "checks do not match the exact gate set")

    def test_evidence_subjects_must_cover_every_non_control_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nftfw-compare-") as temporary:
            parent = Path(temporary).resolve()
            left, right = parent / "left", parent / "right"
            left.mkdir()
            right.mkdir()
            make_candidate(left)
            make_candidate(right)
            for candidate in (left, right):
                (candidate / "unreported-artifact.txt").write_text("hidden\n", encoding="utf-8")
                rewrite_checksums(candidate)
            result, output = self.compare(parent, left, right)
            self.assert_rejected(
                result, output, "candidate evidence subjects do not cover the exact output"
            )

    def test_candidate_identity_and_authorization_fields_fail_closed(self) -> None:
        cases: tuple[tuple[str, Callable[[dict[str, object]], None], str], ...] = (
            (
                "artifact version",
                lambda evidence: evidence.__setitem__(
                    "artifact_version", "2.0.3~stage.r.000000000000"
                ),
                "artifact version is not commit-bound",
            ),
            (
                "build disposition",
                lambda evidence: evidence.__setitem__("build_disposition", "release"),
                "invalid build_disposition",
            ),
            (
                "tag object",
                lambda evidence: evidence.__setitem__("git_tag_object", "deadbeef"),
                "invalid git_tag_object",
            ),
            (
                "runtime capable",
                lambda evidence: evidence.__setitem__("runtime_capable", True),
                "invalid runtime_capable",
            ),
            (
                "deployable",
                lambda evidence: evidence.__setitem__("deployable", True),
                "invalid deployable",
            ),
            (
                "deployment authorization",
                lambda evidence: evidence.__setitem__("deployment_authorized", True),
                "invalid deployment_authorized",
            ),
            (
                "publication authorization",
                lambda evidence: evidence.__setitem__("publication_authorized", True),
                "invalid publication_authorized",
            ),
            (
                "R2 digest",
                lambda evidence: evidence.__setitem__("r2_attestation_sha256", "0" * 64),
                "invalid r2_attestation_sha256",
            ),
            (
                "source report scope",
                lambda evidence: evidence.__setitem__("source_reports_scope", "LIVE_TREE"),
                "invalid source_reports_scope",
            ),
            (
                "toolchain",
                lambda evidence: evidence.__setitem__("toolchain", {"go": "go1.27.0"}),
                "toolchain is not pinned",
            ),
        )
        for label, mutation, expected in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory(
                prefix="nftfw-compare-"
            ) as temporary:
                parent = Path(temporary).resolve()
                left, right = parent / "left", parent / "right"
                left.mkdir()
                right.mkdir()
                make_candidate(left)
                make_candidate(right)
                rewrite_evidence(left, mutation)
                rewrite_evidence(right, mutation)
                result, output = self.compare(parent, left, right)
                self.assert_rejected(result, output, expected)

    def test_secret_scan_digests_must_bind_the_external_scan_records(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nftfw-compare-") as temporary:
            parent = Path(temporary).resolve()
            left, right = parent / "left", parent / "right"
            left.mkdir()
            right.mkdir()
            make_candidate(left)
            make_candidate(right)

            def sever_digest_binding(evidence: dict[str, object]) -> None:
                secret_scan = evidence["secret_scan_evidence"]
                assert isinstance(secret_scan, dict)
                secret_scan["source_history_sha256"] = "0" * 64

            rewrite_evidence(left, sever_digest_binding)
            result, output = self.compare(parent, left, right)
            self.assert_rejected(
                result,
                output,
                "candidate secret-scan digest is not bound: source_history_sha256",
            )

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nftfw-compare-") as temporary:
            parent = Path(temporary).resolve()
            left, right = parent / "left", parent / "right"
            left.mkdir()
            right.mkdir()
            make_candidate(left)
            make_candidate(right)
            evidence_path = left / EVIDENCE
            original = evidence_path.read_text(encoding="utf-8")
            evidence_path.write_text('{"deployable":true,' + original[1:], encoding="utf-8")
            rewrite_checksums(left)
            result, output = self.compare(parent, left, right)
            self.assert_rejected(result, output, "duplicate JSON key")

    def test_subdirectories_are_rejected_even_when_not_checksummed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nftfw-compare-") as temporary:
            parent = Path(temporary).resolve()
            left, right = parent / "left", parent / "right"
            left.mkdir()
            right.mkdir()
            make_candidate(left)
            make_candidate(right)
            (left / "nested").mkdir()
            result, output = self.compare(parent, left, right)
            self.assert_rejected(result, output, "candidate subdirectories are forbidden: nested")

    def test_symlink_ancestor_traversal_fails_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nftfw-compare-") as temporary:
            parent = Path(temporary).resolve()
            real_left, right = parent / "real-left", parent / "right"
            real_left.mkdir()
            right.mkdir()
            make_candidate(real_left)
            make_candidate(right)
            alias = parent / "left"
            alias.symlink_to(real_left, target_is_directory=True)
            result, output = self.compare(parent, alias, right)
            self.assert_rejected(result, output, "cannot safely traverse candidate root")

    def test_group_or_other_writable_candidate_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nftfw-compare-") as temporary:
            parent = Path(temporary).resolve()
            left, right = parent / "left", parent / "right"
            left.mkdir()
            right.mkdir()
            make_candidate(left)
            make_candidate(right)
            left.chmod(0o777)
            result, output = self.compare(parent, left, right)
            self.assert_rejected(
                result, output, "candidate root is not protected by ownership and mode"
            )

    def test_comparator_uses_nofollow_dirfd_reads_instead_of_path_reopens(self) -> None:
        source = TOOL.read_text(encoding="utf-8")
        self.assertIn("os.O_NOFOLLOW", source)
        self.assertIn("dir_fd=root_descriptor", source)
        self.assertIn("os.fstat(descriptor)", source)
        self.assertIn("follow_symlinks=False", source)
        self.assertIn("comparison output changed during publication", source)
        self.assertNotIn("os.walk(", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
