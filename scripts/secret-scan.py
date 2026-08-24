#!/usr/bin/env python3
"""Deterministic, content-redacting secret scan for release evidence.

The scanner intentionally emits no matched text.  A finding contains only a
category, a repository/tree-relative safe path, and a line and/or Git object
identity.  Exit status 0 means PASS, 1 means findings or an incomplete scan,
and 2 means the scanner itself could not run safely.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
import unicodedata
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator, Sequence


SCHEMA_VERSION = "nftfw.secret-scan-evidence/v1"
RULES_VERSION = "nftfw.secret-rules/2026-08-24.1"

# Fixed limits are part of the rules version.  A limit hit is a FAIL finding,
# never a silent partial PASS.
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_FILES = 100_000
MAX_FINDINGS = 1_000
MAX_GIT_COMMITS = 20_000
MAX_GIT_TREE_ENTRIES = 1_000_000
MAX_PATH_BYTES = 4_096
MAX_TREE_DEPTH = 64

LIMITS = {
    "max_file_bytes": MAX_FILE_BYTES,
    "max_files": MAX_FILES,
    "max_findings": MAX_FINDINGS,
    "max_git_commits": MAX_GIT_COMMITS,
    "max_git_tree_entries": MAX_GIT_TREE_ENTRIES,
    "max_path_bytes": MAX_PATH_BYTES,
    "max_total_bytes": MAX_TOTAL_BYTES,
    "max_tree_depth": MAX_TREE_DEPTH,
}

GIT_OID_RE = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")
PRIVATE_KEY_HEADER_RE = re.compile(
    r"-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----"
    r"|-----BEGIN PGP "
    r"PRIVATE KEY BLOCK-----"
)

PROVIDER_TOKEN_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "provider_token_aws_access_key",
        re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    ),
    (
        "provider_token_github",
        re.compile(
            r"(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{36,255}"
            r"|github_pat_[A-Za-z0-9_]{22,255})(?![A-Za-z0-9_])"
        ),
    ),
    (
        "provider_token_gitlab",
        re.compile(r"(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"),
    ),
    (
        "provider_token_google_api",
        re.compile(r"(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])"),
    ),
    (
        "provider_token_slack",
        re.compile(r"(?<![A-Za-z0-9-])xox[baprs]-[A-Za-z0-9-]{20,}(?![A-Za-z0-9-])"),
    ),
    (
        "provider_token_stripe_live",
        re.compile(r"(?<![A-Za-z0-9_])sk_live_[A-Za-z0-9]{16,}(?![A-Za-z0-9])"),
    ),
    (
        "provider_token_openai_or_anthropic",
        re.compile(
            r"(?<![A-Za-z0-9_-])sk-(?:(?:proj|svcacct|ant)-)?"
            r"[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])"
        ),
    ),
    (
        "provider_token_jwt",
        re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\."
            r"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_-])"
        ),
    ),
)

CREDENTIAL_ASSIGNMENT_RE = re.compile(
    r"(?i)(?:^|[\s,{])['\"]?"
    r"(?:api[_-]?key|access[_-]?key|access[_-]?token|auth|auth[_-]?token|"
    r"authorization|bearer[_-]?token|client[_-]?secret|credential|"
    r"password|passwd|private[_-]?key|(?:aws[_-]?)?secret[_-]?access[_-]?key|"
    r"secret[_-]?key|token)"
    r"['\"]?\s*[:=]\s*['\"]?"
    r"(?P<value>[A-Za-z0-9_./+=:@!-]{20,})"
)

URL_USERINFO_RE = re.compile(
    r"(?i)\b[A-Za-z][A-Za-z0-9+.-]{1,20}://(?P<user>[^\s/:@]+):"
    r"(?P<password>[^\s/@]+)@[^\s/]+"
)

AUTHORIZATION_HEADER_RE = re.compile(
    r"(?i)\b(?:authorization|proxy-authorization)\s*[:=]\s*['\"]?"
    r"(?:basic|bearer)\s+(?P<value>[A-Za-z0-9._~+/=-]{20,})"
)

PLACEHOLDER_WORDS = (
    "example",
    "placeholder",
    "changeme",
    "change-me",
    "change_me",
    "replace-me",
    "replace_me",
    "replacewith",
    "replace-with",
    "redacted",
    "not-a-real",
    "not_a_real",
)

PUBLIC_PEM_NAMES = frozenset(("ca.pem", "ca-bundle.pem"))
FORBIDDEN_EXTENSIONS = frozenset(
    (".jks", ".kdbx", ".key", ".keytab", ".keystore", ".ovpn", ".p12", ".pem", ".pfx")
)
FORBIDDEN_EXACT_NAMES = frozenset(
    (".env", ".envrc", ".netrc", ".npmrc", ".pypirc", "_netrc", "auth.json", "kubeconfig")
)
ENV_TEMPLATE_SUFFIXES = frozenset(("dist", "example", "sample", "template"))


class ScanOperationalError(RuntimeError):
    """An error whose details must not be reflected to output."""


@dataclass(frozen=True)
class Finding:
    category: str
    path: str
    line: int | None = None
    object_id: str | None = None

    def evidence(self) -> dict[str, object]:
        value: dict[str, object] = {"category": self.category, "path": self.path}
        if self.line is not None:
            value["line"] = self.line
        if self.object_id is not None:
            value["object"] = self.object_id
        return value


class ScanEvidence:
    def __init__(self, scope: dict[str, object]) -> None:
        self.scope = scope
        self._findings: set[Finding] = set()
        self._findings_truncated = False
        self.stats: dict[str, int] = {
            "binary_files_skipped": 0,
            "bytes_scanned": 0,
            "files_scanned": 0,
            "files_seen": 0,
            "git_commits_examined": 0,
            "git_tree_entries_examined": 0,
            "oversize_files_skipped": 0,
            "paths_examined": 0,
            "filesystem_symlinks_rejected": 0,
            "git_symlink_blobs_scanned": 0,
            "unreadable_files": 0,
            "unique_git_blobs_seen": 0,
        }

    def add(
        self,
        category: str,
        path: str,
        *,
        line: int | None = None,
        object_id: str | None = None,
    ) -> None:
        finding = Finding(category, path, line, object_id)
        if finding in self._findings:
            return
        # Reserve one final slot for an explicit truncation finding.
        if len(self._findings) >= MAX_FINDINGS - 1:
            self._findings_truncated = True
            return
        self._findings.add(finding)

    def document(self) -> dict[str, object]:
        findings = set(self._findings)
        if self._findings_truncated:
            findings.add(
                Finding(
                    "findings_limit_exceeded",
                    "<scan-scope>",
                    object_id="findings-limit",
                )
            )
        ordered = sorted(
            findings,
            key=lambda item: (
                item.category,
                item.path,
                item.line if item.line is not None else -1,
                item.object_id or "",
            ),
        )
        return {
            "findings": [item.evidence() for item in ordered],
            "limits": LIMITS,
            "rules_version": RULES_VERSION,
            "schema_version": SCHEMA_VERSION,
            "scope": self.scope,
            "statistics": self.stats,
            "status": "FAIL" if ordered else "PASS",
        }


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.casefold()
    if any(word in lowered for word in PLACEHOLDER_WORDS):
        return True
    if lowered.startswith(("${", "{{", "<")) or lowered.endswith(("}", ">")):
        return True
    compact = re.sub(r"[^A-Za-z0-9]", "", value)
    if compact and len(set(compact.casefold())) <= 2:
        return True
    return False


def _looks_high_entropy(value: str) -> bool:
    if len(value) < 20 or _looks_like_placeholder(value):
        return False
    classes = sum(
        (
            any(character.islower() for character in value),
            any(character.isupper() for character in value),
            any(character.isdigit() for character in value),
            any(not character.isalnum() for character in value),
        )
    )
    return classes >= 3 and _shannon_entropy(value) >= 3.3


def _valid_relative_path(value: str) -> bool:
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or len(os.fsencode(value)) > MAX_PATH_BYTES
    ):
        return False
    components = value.replace("\\", "/").split("/")
    if any(component in ("", ".", "..") for component in components):
        return False
    for character in value:
        if character == "\x00" or character in ("\u2028", "\u2029"):
            return False
        if unicodedata.category(character).startswith("C"):
            return False
    return True


def _component_looks_sensitive(component: str) -> bool:
    if any(pattern.search(component) for _, pattern in PROVIDER_TOKEN_RULES):
        return True
    return len(component) >= 32 and _looks_high_entropy(component)


def _safe_path(value: str) -> str:
    encoded = value.encode("utf-8", "surrogatepass")
    if not _valid_relative_path(value):
        digest = hashlib.sha256(encoded).hexdigest()[:16]
        return f"<unsafe-path-sha256:{digest}>"
    safe_components: list[str] = []
    for component in value.replace("\\", "/").split("/"):
        if _component_looks_sensitive(component):
            digest = hashlib.sha256(component.encode("utf-8")).hexdigest()[:16]
            safe_components.append(f"<redacted-name-sha256:{digest}>")
        else:
            safe_components.append(component)
    return "/".join(safe_components)


def _public_pem_exception(basename: str) -> bool:
    lowered = basename.casefold()
    return (
        lowered in PUBLIC_PEM_NAMES
        or lowered.endswith(".crt.pem")
        or lowered.endswith(".cert.pem")
    )


def _forbidden_credential_filename(relative_path: str) -> bool:
    normalized = relative_path.replace("\\", "/")
    parts = [part.casefold() for part in normalized.split("/")]
    basename = parts[-1]
    suffix = Path(basename).suffix.casefold()

    if basename.startswith(".env."):
        if basename.rsplit(".", 1)[-1] not in ENV_TEMPLATE_SUFFIXES:
            return True
    elif basename in FORBIDDEN_EXACT_NAMES:
        return True

    if suffix in FORBIDDEN_EXTENSIONS:
        if suffix != ".pem" or not _public_pem_exception(basename):
            return True

    if re.fullmatch(r"id_(?:rsa|dsa|ecdsa|ed25519)(?:\..*)?", basename):
        if not basename.endswith(".pub"):
            return True

    if len(parts) >= 2 and parts[-2:] in ([".aws", "credentials"], [".docker", "config.json"]):
        return True
    if len(parts) >= 2 and parts[-2:] == [".kube", "config"]:
        return True
    return False


def _text_or_none(data: bytes) -> str | None:
    encodings = ()
    if data.startswith(b"\xef\xbb\xbf"):
        encodings = ("utf-8-sig",)
    elif data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        encodings = ("utf-32",)
    elif data.startswith((b"\xff\xfe", b"\xfe\xff")):
        encodings = ("utf-16",)
    for encoding in encodings:
        try:
            return data.decode(encoding, "strict")
        except UnicodeDecodeError:
            return None
    if b"\x00" in data:
        return None
    try:
        return data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return None


def _binary_probe(data: bytes) -> bool:
    """Recognize bounded binary data without relying on a filename suffix."""
    binary_magics = (
        b"\x7fELF",
        b"MZ",
        b"PK\x03\x04",
        b"PK\x05\x06",
        b"\x1f\x8b",
        b"\xfd7zXZ\x00",
        b"BZh",
        b"\x28\xb5\x2f\xfd",
        b"!<arch>\n",
        b"SQLite format 3\x00",
        b"\x89PNG\r\n\x1a\n",
        b"\xff\xd8\xff",
        b"%PDF-",
    )
    if data.startswith(binary_magics) or (len(data) >= 262 and data[257:262] == b"ustar"):
        return True
    return _text_or_none(data) is None


def _scan_text(
    scan: ScanEvidence,
    text: str,
    display_path: str,
    *,
    object_id: str | None = None,
) -> None:
    for line_number, line in enumerate(text.splitlines(), start=1):
        if PRIVATE_KEY_HEADER_RE.search(line):
            scan.add(
                "private_key_header",
                display_path,
                line=line_number,
                object_id=object_id,
            )

        for category, pattern in PROVIDER_TOKEN_RULES:
            if any(
                not _looks_like_placeholder(match.group(0))
                for match in pattern.finditer(line)
            ):
                scan.add(category, display_path, line=line_number, object_id=object_id)

        for match in CREDENTIAL_ASSIGNMENT_RE.finditer(line):
            if _looks_high_entropy(match.group("value")):
                scan.add(
                    "high_entropy_credential_assignment",
                    display_path,
                    line=line_number,
                    object_id=object_id,
                )
                break

        for match in AUTHORIZATION_HEADER_RE.finditer(line):
            if not _looks_like_placeholder(match.group("value")):
                scan.add(
                    "authorization_header_credential",
                    display_path,
                    line=line_number,
                    object_id=object_id,
                )
                break

        for match in URL_USERINFO_RE.finditer(line):
            password = match.group("password")
            if not _looks_like_placeholder(password) and password.casefold() not in {
                "pass",
                "password",
                "secret",
                "token",
            }:
                scan.add(
                    "url_embedded_credentials",
                    display_path,
                    line=line_number,
                    object_id=object_id,
                )
                break


def _git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    return environment


def _git_run(repo: Path, arguments: Sequence[str]) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(repo), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_git_environment(),
            check=False,
        )
    except (OSError, ValueError) as error:
        raise ScanOperationalError from error
    if completed.returncode != 0:
        raise ScanOperationalError
    return completed.stdout


def _resolve_exact_commit(repo: Path, requested: str) -> str:
    if not GIT_OID_RE.fullmatch(requested):
        raise ScanOperationalError
    object_type = _git_run(repo, ["cat-file", "-t", requested]).strip()
    if object_type != b"commit":
        raise ScanOperationalError
    resolved = _git_run(repo, ["rev-parse", "--verify", requested]).strip().decode("ascii")
    if resolved.casefold() != requested.casefold():
        raise ScanOperationalError
    return resolved.casefold()


def _iter_process_records(
    command: Sequence[str], *, delimiter: bytes, max_record_bytes: int
) -> Iterator[bytes]:
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_git_environment(),
        )
    except (OSError, ValueError) as error:
        raise ScanOperationalError from error
    assert process.stdout is not None
    buffer = bytearray()
    completed = False
    try:
        while True:
            chunk = process.stdout.read(64 * 1024)
            if not chunk:
                break
            buffer.extend(chunk)
            while True:
                position = buffer.find(delimiter)
                if position < 0:
                    if len(buffer) > max_record_bytes:
                        raise ScanOperationalError
                    break
                record = bytes(buffer[:position])
                del buffer[: position + len(delimiter)]
                if len(record) > max_record_bytes:
                    raise ScanOperationalError
                yield record
        if buffer:
            raise ScanOperationalError
        completed = True
    finally:
        process.stdout.close()
        if not completed and process.poll() is None:
            process.terminate()
        try:
            return_code = process.wait(timeout=5)
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.wait()
            raise ScanOperationalError from error
    if return_code != 0:
        raise ScanOperationalError


def _git_tree_records(repo: Path, commit: str) -> Iterator[bytes]:
    return _iter_process_records(
        [
            "git",
            "-C",
            os.fspath(repo),
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            commit,
        ],
        delimiter=b"\x00",
        max_record_bytes=MAX_PATH_BYTES + 256,
    )


def _git_history_commits(repo: Path, commit: str) -> Iterator[bytes]:
    return _iter_process_records(
        ["git", "-C", os.fspath(repo), "rev-list", "--topo-order", commit],
        delimiter=b"\n",
        max_record_bytes=128,
    )


def _parse_tree_record(record: bytes) -> tuple[str, str, str, str]:
    try:
        metadata, raw_path = record.split(b"\t", 1)
        mode_bytes, type_bytes, oid_bytes = metadata.split(b" ", 2)
        mode = mode_bytes.decode("ascii")
        object_type = type_bytes.decode("ascii")
        oid = oid_bytes.decode("ascii").casefold()
        if not GIT_OID_RE.fullmatch(oid):
            raise ValueError
        path = os.fsdecode(raw_path)
    except (UnicodeError, ValueError) as error:
        raise ScanOperationalError from error
    return mode, object_type, oid, path


class GitScanner:
    def __init__(self, repo: Path, commit: str, include_history: bool) -> None:
        self.repo = repo
        self.commit = commit
        self.include_history = include_history
        self.scan = ScanEvidence(
            {
                "commit": commit,
                "include_reachable_history": include_history,
                "mode": "git_commit",
            }
        )
        self.blob_paths: dict[str, str] = {}
        self.seen_entries: set[tuple[str, str, str]] = set()
        self._tree_limit_hit = False

    def _ingest_tree(self, tree_commit: str) -> None:
        records = _git_tree_records(self.repo, tree_commit)
        try:
            for record in records:
                self.scan.stats["git_tree_entries_examined"] += 1
                if self.scan.stats["git_tree_entries_examined"] > MAX_GIT_TREE_ENTRIES:
                    self.scan.add(
                        "git_tree_entries_limit_exceeded",
                        "<git-tree>",
                        object_id=tree_commit,
                    )
                    self._tree_limit_hit = True
                    break

                mode, object_type, oid, path = _parse_tree_record(record)
                entry_key = (mode, oid, path)
                if entry_key in self.seen_entries:
                    continue
                self.seen_entries.add(entry_key)
                self.scan.stats["paths_examined"] += 1
                display_path = _safe_path(path)
                if not _valid_relative_path(path):
                    self.scan.add("unsafe_git_path", display_path, object_id=oid)
                if _forbidden_credential_filename(path):
                    self.scan.add(
                        "forbidden_credential_filename",
                        display_path,
                        object_id=oid,
                    )

                if mode == "120000" and object_type == "blob":
                    # A Git symlink object stores only its target text.  Scan
                    # those bytes without resolving or following the target.
                    self.scan.stats["git_symlink_blobs_scanned"] += 1
                elif mode == "160000" or object_type == "commit":
                    self.scan.add("unscanned_git_submodule", display_path, object_id=oid)
                    continue
                elif object_type != "blob" or mode not in ("100644", "100755"):
                    self.scan.add("unsupported_git_entry", display_path, object_id=oid)
                    continue

                previous_path = self.blob_paths.get(oid)
                if previous_path is None:
                    if len(self.blob_paths) >= MAX_FILES:
                        self.scan.add(
                            "git_blob_count_limit_exceeded",
                            "<git-tree>",
                            object_id=tree_commit,
                        )
                        continue
                    self.blob_paths[oid] = display_path
                elif display_path < previous_path:
                    self.blob_paths[oid] = display_path
        finally:
            records.close()

    def _collect(self) -> None:
        self.scan.stats["git_commits_examined"] = 1
        self._ingest_tree(self.commit)
        if not self.include_history or self._tree_limit_hit:
            return

        commits = _git_history_commits(self.repo, self.commit)
        try:
            for raw_commit in commits:
                try:
                    history_commit = raw_commit.decode("ascii").casefold()
                except UnicodeDecodeError as error:
                    raise ScanOperationalError from error
                if not GIT_OID_RE.fullmatch(history_commit):
                    raise ScanOperationalError
                if history_commit == self.commit:
                    continue
                if self.scan.stats["git_commits_examined"] >= MAX_GIT_COMMITS:
                    self.scan.add(
                        "git_commit_count_limit_exceeded",
                        "<git-history>",
                        object_id=self.commit,
                    )
                    break
                self.scan.stats["git_commits_examined"] += 1
                self._ingest_tree(history_commit)
                if self._tree_limit_hit:
                    break
        finally:
            commits.close()

    def _batch_check_sizes(self, ordered_oids: Sequence[str]) -> dict[str, int]:
        command = [
            "git",
            "-C",
            os.fspath(self.repo),
            "cat-file",
            "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        ]
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=_git_environment(),
            )
        except OSError as error:
            raise ScanOperationalError from error
        assert process.stdin is not None and process.stdout is not None
        sizes: dict[str, int] = {}
        try:
            for oid in ordered_oids:
                process.stdin.write(oid.encode("ascii") + b"\n")
                process.stdin.flush()
                response = process.stdout.readline(256)
                fields = response.rstrip(b"\n").split(b" ")
                if len(fields) != 3:
                    self.scan.add(
                        "git_object_unavailable",
                        self.blob_paths[oid],
                        object_id=oid,
                    )
                    continue
                response_oid, object_type, size_bytes = fields
                try:
                    size = int(size_bytes, 10)
                except ValueError:
                    self.scan.add(
                        "git_object_unavailable",
                        self.blob_paths[oid],
                        object_id=oid,
                    )
                    continue
                if (
                    response_oid.decode("ascii").casefold() != oid
                    or object_type != b"blob"
                    or size < 0
                ):
                    self.scan.add(
                        "git_object_unavailable",
                        self.blob_paths[oid],
                        object_id=oid,
                    )
                    continue
                sizes[oid] = size
        finally:
            process.stdin.close()
            process.stdout.close()
            return_code = process.wait()
        if return_code != 0:
            raise ScanOperationalError
        return sizes

    def _scan_blobs(self) -> None:
        ordered_oids = sorted(self.blob_paths, key=lambda oid: (self.blob_paths[oid], oid))
        self.scan.stats["files_seen"] = len(ordered_oids)
        self.scan.stats["unique_git_blobs_seen"] = len(ordered_oids)
        sizes = self._batch_check_sizes(ordered_oids)

        eligible: list[tuple[str, int]] = []
        total_bytes = 0
        for oid in ordered_oids:
            size = sizes.get(oid)
            if size is None:
                continue
            if size > MAX_FILE_BYTES:
                self.scan.stats["oversize_files_skipped"] += 1
                self.scan.add(
                    "file_size_limit_exceeded",
                    self.blob_paths[oid],
                    object_id=oid,
                )
                continue
            if total_bytes + size > MAX_TOTAL_BYTES:
                self.scan.stats["oversize_files_skipped"] += 1
                self.scan.add(
                    "total_bytes_limit_exceeded",
                    self.blob_paths[oid],
                    object_id=oid,
                )
                continue
            total_bytes += size
            eligible.append((oid, size))

        command = ["git", "-C", os.fspath(self.repo), "cat-file", "--batch"]
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=_git_environment(),
            )
        except OSError as error:
            raise ScanOperationalError from error
        assert process.stdin is not None and process.stdout is not None
        try:
            for oid, expected_size in eligible:
                process.stdin.write(oid.encode("ascii") + b"\n")
                process.stdin.flush()
                header = process.stdout.readline(256).rstrip(b"\n").split(b" ")
                if len(header) != 3:
                    raise ScanOperationalError
                response_oid, object_type, raw_size = header
                try:
                    actual_size = int(raw_size, 10)
                except ValueError as error:
                    raise ScanOperationalError from error
                if (
                    response_oid.decode("ascii").casefold() != oid
                    or object_type != b"blob"
                    or actual_size != expected_size
                ):
                    raise ScanOperationalError
                data = _read_exact(process.stdout, actual_size)
                if process.stdout.read(1) != b"\n":
                    raise ScanOperationalError

                self.scan.stats["bytes_scanned"] += len(data)
                text = _text_or_none(data)
                if text is None:
                    self.scan.stats["binary_files_skipped"] += 1
                    continue
                self.scan.stats["files_scanned"] += 1
                _scan_text(
                    self.scan,
                    text,
                    self.blob_paths[oid],
                    object_id=oid,
                )
        finally:
            process.stdin.close()
            process.stdout.close()
            return_code = process.wait()
        if return_code != 0:
            raise ScanOperationalError

    def run(self) -> ScanEvidence:
        if self.include_history:
            shallow = _git_run(self.repo, ["rev-parse", "--is-shallow-repository"]).strip()
            if shallow == b"true":
                self.scan.add(
                    "shallow_git_history",
                    "<git-history>",
                    object_id=self.commit,
                )
            elif shallow != b"false":
                raise ScanOperationalError
        self._collect()
        self._scan_blobs()
        return self.scan


def _read_exact(stream: BinaryIO, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = stream.read(min(remaining, 64 * 1024))
        if not chunk:
            raise ScanOperationalError
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class FilesystemTreeScanner:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.scan = ScanEvidence({"mode": "filesystem_tree"})
        self._total_bytes = 0
        self._entry_count = 0

    def _entry_identity(self, path: str) -> str:
        digest = hashlib.sha256(path.encode("utf-8", "surrogatepass")).hexdigest()
        return f"path-sha256:{digest}"

    def _scan_file(self, path: Path, relative: str, initial: os.stat_result) -> None:
        display_path = _safe_path(relative)
        self.scan.stats["files_seen"] += 1
        if _forbidden_credential_filename(relative):
            self.scan.add(
                "forbidden_credential_filename",
                display_path,
                object_id=self._entry_identity(relative),
            )

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError:
            self.scan.stats["unreadable_files"] += 1
            self.scan.add(
                "unreadable_file",
                display_path,
                object_id=self._entry_identity(relative),
            )
            return
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
            ) != (
                initial.st_dev,
                initial.st_ino,
                initial.st_size,
                initial.st_mtime_ns,
            ):
                self.scan.add(
                    "file_changed_during_scan",
                    display_path,
                    object_id=self._entry_identity(relative),
                )
                return

            oversized = opened.st_size > MAX_FILE_BYTES
            read_length = min(opened.st_size, 64 * 1024) if oversized else opened.st_size
            if self._total_bytes + read_length > MAX_TOTAL_BYTES:
                self.scan.stats["oversize_files_skipped"] += 1
                self.scan.add(
                    "total_bytes_limit_exceeded",
                    display_path,
                    object_id=self._entry_identity(relative),
                )
                return
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                data = stream.read(read_length + (0 if oversized else 1))
            final = os.fstat(descriptor)
            expected_read = read_length if oversized else initial.st_size
            if len(data) != expected_read or (
                final.st_size,
                final.st_mtime_ns,
            ) != (opened.st_size, opened.st_mtime_ns):
                self.scan.add(
                    "file_changed_during_scan",
                    display_path,
                    object_id=self._entry_identity(relative),
                )
                return
        finally:
            os.close(descriptor)

        self._total_bytes += len(data)
        self.scan.stats["bytes_scanned"] += len(data)
        if initial.st_size > MAX_FILE_BYTES:
            if _binary_probe(data):
                self.scan.stats["binary_files_skipped"] += 1
            else:
                self.scan.stats["oversize_files_skipped"] += 1
                self.scan.add(
                    "file_size_limit_exceeded",
                    display_path,
                    object_id=self._entry_identity(relative),
                )
            return
        text = _text_or_none(data)
        if text is None:
            self.scan.stats["binary_files_skipped"] += 1
            return
        self.scan.stats["files_scanned"] += 1
        _scan_text(self.scan, text, display_path)

    def _walk(self, directory: Path, relative_directory: str, depth: int) -> None:
        if depth > MAX_TREE_DEPTH:
            display_path = _safe_path(relative_directory or ".")
            self.scan.add(
                "tree_depth_limit_exceeded",
                display_path,
                object_id="filesystem-entry",
            )
            return
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: os.fsencode(item.name))
        except OSError:
            display_path = _safe_path(relative_directory or ".")
            self.scan.add(
                "unreadable_directory",
                display_path,
                object_id="filesystem-entry",
            )
            return

        for entry in entries:
            self._entry_count += 1
            if self._entry_count > MAX_FILES:
                self.scan.add(
                    "filesystem_entry_count_limit_exceeded",
                    "<filesystem-tree>",
                    object_id="entries-limit",
                )
                return
            relative = f"{relative_directory}/{entry.name}" if relative_directory else entry.name
            self.scan.stats["paths_examined"] += 1
            display_path = _safe_path(relative)
            if not _valid_relative_path(relative):
                self.scan.add(
                    "unsafe_filesystem_path",
                    display_path,
                    object_id=self._entry_identity(relative),
                )
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError:
                self.scan.add(
                    "unreadable_filesystem_entry",
                    display_path,
                    object_id=self._entry_identity(relative),
                )
                continue

            if stat.S_ISLNK(entry_stat.st_mode):
                self.scan.stats["filesystem_symlinks_rejected"] += 1
                self.scan.add(
                    "symlink_entry",
                    display_path,
                    object_id=self._entry_identity(relative),
                )
            elif stat.S_ISDIR(entry_stat.st_mode):
                self._walk(Path(entry.path), relative, depth + 1)
            elif stat.S_ISREG(entry_stat.st_mode):
                self._scan_file(Path(entry.path), relative, entry_stat)
            else:
                self.scan.add(
                    "unsupported_filesystem_entry",
                    display_path,
                    object_id=self._entry_identity(relative),
                )

    def run(self) -> ScanEvidence:
        try:
            root_stat = os.lstat(self.root)
        except OSError as error:
            raise ScanOperationalError from error
        if stat.S_ISLNK(root_stat.st_mode):
            self.scan.stats["filesystem_symlinks_rejected"] += 1
            self.scan.add("symlink_entry", ".", object_id="filesystem-root")
            return self.scan
        if not stat.S_ISDIR(root_stat.st_mode):
            raise ScanOperationalError
        self._walk(self.root, "", 0)
        return self.scan


def _write_evidence(document: dict[str, object], destination: str) -> None:
    encoded = (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode(
        "utf-8"
    )
    if destination == "-":
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.flush()
        return

    target = Path(destination)
    parent = target.parent
    temporary = parent / f".{target.name}.tmp.{os.getpid()}"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, target)
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except OSError:
            pass
        raise ScanOperationalError from error


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate deterministic, redacted secret-scan evidence."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    git_parser = commands.add_parser("git", help="scan an exact Git commit")
    git_parser.add_argument("--repo", required=True, help="Git repository path")
    git_parser.add_argument(
        "--commit",
        required=True,
        help="full 40- or 64-hex commit object ID (symbolic refs are rejected)",
    )
    git_parser.add_argument(
        "--history",
        action="store_true",
        help="also scan every file blob reachable through commit ancestors",
    )
    git_parser.add_argument(
        "--output", default="-", help="evidence JSON path, or - for stdout"
    )

    tree_parser = commands.add_parser("tree", help="scan an extracted filesystem tree")
    tree_parser.add_argument("--root", required=True, help="tree root")
    tree_parser.add_argument(
        "--output", default="-", help="evidence JSON path, or - for stdout"
    )
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parser = _argument_parser()
    parsed = parser.parse_args(arguments)
    try:
        if parsed.command == "git":
            repository = Path(parsed.repo)
            commit = _resolve_exact_commit(repository, parsed.commit)
            scan = GitScanner(repository, commit, parsed.history).run()
        else:
            scan = FilesystemTreeScanner(Path(parsed.root)).run()
        document = scan.document()
        _write_evidence(document, parsed.output)
    except ScanOperationalError:
        # This intentionally contains no path, Git stderr, exception text, or
        # scanned bytes.  Operational failures cannot become secret or path
        # disclosure channels.
        print("secret scan could not complete safely", file=sys.stderr)
        return 2
    return 0 if document["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
