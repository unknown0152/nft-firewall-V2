#!/usr/bin/env python3
"""Isolated contracts for the deterministic release secret scanner."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "scripts" / "secret-scan.py"


class SecretScanTests(unittest.TestCase):
    def git(self, repository: Path, *arguments: str) -> str:
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_AUTHOR_DATE": "2026-08-24T00:00:00Z",
                "GIT_COMMITTER_DATE": "2026-08-24T00:00:00Z",
                "LC_ALL": "C",
            }
        )
        completed = subprocess.run(
            ["git", "-C", os.fspath(repository), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )
        return completed.stdout.strip()

    def initialize_repository(self, repository: Path) -> None:
        self.git(repository, "init", "--quiet")
        self.git(repository, "config", "user.name", "Stage R Test")
        self.git(repository, "config", "user.email", "stage-r@example.invalid")
        self.git(repository, "config", "commit.gpgSign", "false")

    def commit_all(self, repository: Path, message: str) -> str:
        self.git(repository, "add", "--all")
        self.git(repository, "commit", "--quiet", "--no-gpg-sign", "-m", message)
        return self.git(repository, "rev-parse", "HEAD")

    def run_scan(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", os.fspath(SCANNER), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_clean_exact_commit_is_deterministic_and_allows_templates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            repository.mkdir()
            self.initialize_repository(repository)
            (repository / "README.md").write_text(
                "api_key = replace-with-production-secret\n"
                "Example URL: https://user:password@example.invalid/resource\n",
                encoding="utf-8",
            )
            (repository / ".env.example").write_text(
                "TOKEN=${TOKEN_FROM_ENVIRONMENT}\n", encoding="utf-8"
            )
            (repository / "ca.pem").write_text(
                "-----BEGIN CERTIFICATE-----\npublic-certificate-placeholder\n"
                "-----END CERTIFICATE-----\n",
                encoding="utf-8",
            )
            (repository / "logo.bin").write_bytes(b"image\x00payload")
            commit = self.commit_all(repository, "clean")

            first = self.run_scan(
                "git", "--repo", os.fspath(repository), "--commit", commit
            )
            second = self.run_scan(
                "git", "--repo", os.fspath(repository), "--commit", commit
            )

            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(first.stdout, second.stdout)
            evidence = json.loads(first.stdout)
            self.assertEqual(evidence["status"], "PASS")
            self.assertEqual(evidence["scope"]["commit"], commit)
            self.assertEqual(evidence["statistics"]["binary_files_skipped"], 1)
            self.assertEqual(evidence["findings"], [])

    def test_current_commit_provider_secret_fails_without_echoing_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            repository.mkdir()
            self.initialize_repository(repository)
            provider_value = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4P5q6R7s8"
            secret_named_path = repository / ("config-" + provider_value + ".txt")
            secret_named_path.write_text(
                "access_token = " + provider_value + "\n", encoding="utf-8"
            )
            commit = self.commit_all(repository, "secret in current tree")

            result = self.run_scan(
                "git", "--repo", os.fspath(repository), "--commit", commit
            )

            self.assertEqual(result.returncode, 1, result.stderr)
            evidence = json.loads(result.stdout)
            self.assertEqual(evidence["status"], "FAIL")
            categories = {finding["category"] for finding in evidence["findings"]}
            self.assertIn("provider_token_github", categories)
            self.assertNotIn(provider_value, result.stdout)
            self.assertNotIn(provider_value, result.stderr)
            self.assertTrue(
                all(
                    set(finding) <= {"category", "path", "line", "object"}
                    for finding in evidence["findings"]
                )
            )

    def test_deleted_secret_is_found_only_with_reachable_history_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            repository.mkdir()
            self.initialize_repository(repository)
            (repository / "README.md").write_text("clean\n", encoding="utf-8")
            self.commit_all(repository, "initial")

            historical_value = "aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xYzC"
            secret_path = repository / "old-config.txt"
            secret_path.write_text(
                "password = " + historical_value + "\n", encoding="utf-8"
            )
            self.commit_all(repository, "temporary secret")
            secret_path.unlink()
            final_commit = self.commit_all(repository, "remove secret")

            current_only = self.run_scan(
                "git", "--repo", os.fspath(repository), "--commit", final_commit
            )
            with_history = self.run_scan(
                "git",
                "--repo",
                os.fspath(repository),
                "--commit",
                final_commit,
                "--history",
            )

            self.assertEqual(current_only.returncode, 0, current_only.stderr)
            self.assertEqual(with_history.returncode, 1, with_history.stderr)
            evidence = json.loads(with_history.stdout)
            categories = {finding["category"] for finding in evidence["findings"]}
            self.assertIn("high_entropy_credential_assignment", categories)
            self.assertTrue(evidence["scope"]["include_reachable_history"])
            self.assertGreaterEqual(evidence["statistics"]["git_commits_examined"], 3)
            self.assertNotIn(historical_value, with_history.stdout)
            self.assertNotIn(historical_value, with_history.stderr)

    def test_forbidden_vpn_filename_fails_even_with_innocuous_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            repository.mkdir()
            self.initialize_repository(repository)
            (repository / "client.ovpn").write_text("client\n", encoding="utf-8")
            commit = self.commit_all(repository, "vpn profile")

            result = self.run_scan(
                "git", "--repo", os.fspath(repository), "--commit", commit
            )

            self.assertEqual(result.returncode, 1, result.stderr)
            evidence = json.loads(result.stdout)
            self.assertIn(
                "forbidden_credential_filename",
                {finding["category"] for finding in evidence["findings"]},
            )
            self.assertIn(
                "client.ovpn",
                {finding["path"] for finding in evidence["findings"]},
            )

    def test_tree_mode_rejects_symlink_without_following_or_echoing_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            tree = temporary_path / "tree"
            tree.mkdir()
            outside_value = "sk-" + "N7pQ2rS9tU4vW6xY8zA1bC3dE5fG7hJ9kL2mN4pQ"
            outside = temporary_path / "outside.txt"
            outside.write_text(outside_value + "\n", encoding="utf-8")
            (tree / "external-link").symlink_to(outside)

            result = self.run_scan("tree", "--root", os.fspath(tree))

            self.assertEqual(result.returncode, 1, result.stderr)
            evidence = json.loads(result.stdout)
            self.assertIn(
                "symlink_entry",
                {finding["category"] for finding in evidence["findings"]},
            )
            self.assertEqual(evidence["statistics"]["files_scanned"], 0)
            self.assertNotIn(outside_value, result.stdout)
            self.assertNotIn(outside_value, result.stderr)

    def test_requested_evidence_file_is_redacting_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            tree = temporary_path / "tree"
            tree.mkdir()
            embedded_value = "Z8yX6wV4uT2sR9qP7nM5kJ3hG1fD0cB2aE4v"
            (tree / "settings.toml").write_text(
                "client_secret = " + embedded_value + "\n", encoding="utf-8"
            )
            output = temporary_path / "evidence.json"

            result = self.run_scan(
                "tree", "--root", os.fspath(tree), "--output", os.fspath(output)
            )

            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(result.stdout, "")
            serialized = output.read_text(encoding="utf-8")
            evidence = json.loads(serialized)
            self.assertEqual(evidence["status"], "FAIL")
            self.assertNotIn(embedded_value, serialized)
            self.assertNotIn(embedded_value, result.stderr)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_private_key_header_and_url_userinfo_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary) / "tree"
            tree.mkdir()
            header = "-----BEGIN " + "PRIVATE KEY-----"
            url_password = "r7Qp2Vx9Lm4N"
            url = "https://" + "alice:" + url_password + "@service.invalid/path"
            (tree / "notes.txt").write_text(
                header + "\n" + url + "\n", encoding="utf-8"
            )

            result = self.run_scan("tree", "--root", os.fspath(tree))

            self.assertEqual(result.returncode, 1, result.stderr)
            evidence = json.loads(result.stdout)
            categories = {finding["category"] for finding in evidence["findings"]}
            self.assertIn("private_key_header", categories)
            self.assertIn("url_embedded_credentials", categories)
            self.assertNotIn(url_password, result.stdout)

    def test_tree_mode_hashes_control_paths_and_rejects_them(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary) / "tree"
            tree.mkdir()
            unsafe_name = "unsafe\nname.txt"
            (tree / unsafe_name).write_text("clean\n", encoding="utf-8")

            result = self.run_scan("tree", "--root", os.fspath(tree))

            self.assertEqual(result.returncode, 1, result.stderr)
            evidence = json.loads(result.stdout)
            unsafe_findings = [
                finding
                for finding in evidence["findings"]
                if finding["category"] == "unsafe_filesystem_path"
            ]
            self.assertEqual(len(unsafe_findings), 1)
            self.assertTrue(unsafe_findings[0]["path"].startswith("<unsafe-path-sha256:"))
            self.assertNotIn(unsafe_name, result.stdout)

    def test_oversized_recognized_binary_is_bounded_and_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary) / "tree"
            tree.mkdir()
            binary_path = tree / "application"
            with binary_path.open("wb") as stream:
                stream.write(b"\x7fELF")
                stream.seek((4 * 1024 * 1024) + 128)
                stream.write(b"\x00")

            result = self.run_scan("tree", "--root", os.fspath(tree))

            self.assertEqual(result.returncode, 0, result.stderr)
            evidence = json.loads(result.stdout)
            self.assertEqual(evidence["status"], "PASS")
            self.assertEqual(evidence["statistics"]["binary_files_skipped"], 1)
            self.assertLessEqual(evidence["statistics"]["bytes_scanned"], 64 * 1024)


if __name__ == "__main__":
    unittest.main(verbosity=2)
