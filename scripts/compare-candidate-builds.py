#!/usr/bin/env python3
"""Compare two isolated Stage R candidate outputs without trusting their paths."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path


EVIDENCE = "CANDIDATE_BUILD_EVIDENCE-NOT-DEPLOYABLE.json"
CHECKSUMS = "SHA256SUMS"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]*$")
TARGET_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
BUILD_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
MAX_FILES = 10000
MAX_FILE_SIZE = 512 * 1024 * 1024
MAX_CONTROL_SIZE = 4 * 1024 * 1024
REQUIRED_CHECKS = (
    "clean_commit_export",
    "binary_identity_and_metadata",
    "package_identity_and_payload",
    "staged_systemd_verification",
    "archive_integrity_and_internal_checksums",
    "source_and_reachable_history_secret_scan",
    "both_extracted_archives_secret_scan",
    "extracted_archive_secret_evidence_byte_identical",
)
PINNED_GO = "go1.25.13"
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
FILE_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


class ComparisonError(Exception):
    pass


@dataclass(frozen=True)
class CandidateSnapshot:
    records: dict[str, tuple[int, int, str]]
    evidence: bytes
    checksums: bytes
    root_identity: tuple[int, int]


def open_absolute_directory(path: Path, label: str) -> int:
    if not path.is_absolute() or path == Path("/") or ".." in path.parts:
        raise ComparisonError(f"{label} must be an absolute canonical non-root path")
    descriptor = -1
    try:
        descriptor = os.open("/", DIRECTORY_FLAGS)
        components = path.parts[1:]
        for index, component in enumerate(components):
            if not component or component in (".", ".."):
                raise ComparisonError(f"{label} must be an absolute canonical non-root path")
            next_descriptor = os.open(component, DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            info = os.fstat(descriptor)
            mode = stat.S_IMODE(info.st_mode)
            is_final = index == len(components) - 1
            if is_final:
                if info.st_uid != os.getuid() or mode & 0o022:
                    raise ComparisonError(f"{label} is not protected by ownership and mode")
            elif mode & 0o022 and not (info.st_uid == 0 and mode & stat.S_ISVTX):
                raise ComparisonError(f"an ancestor of {label} has unsafe permissions")
        return descriptor
    except ComparisonError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise ComparisonError(f"cannot safely traverse {label}") from error


def directory_names(descriptor: int) -> list[str]:
    try:
        with os.scandir(descriptor) as entries:
            return sorted(entry.name for entry in entries)
    except OSError as error:
        raise ComparisonError("cannot enumerate candidate root") from error


def stable_stat(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_nlink,
    )


def file_digest(descriptor: int, expected_size: int, capture: bool) -> tuple[str, bytes]:
    digest = hashlib.sha256()
    captured = bytearray()
    total = 0
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FILE_SIZE:
                raise ComparisonError("candidate file grew beyond the size limit while reading")
            digest.update(chunk)
            if capture:
                captured.extend(chunk)
    except OSError as error:
        raise ComparisonError("cannot read candidate file") from error
    if total != expected_size:
        raise ComparisonError("candidate file changed size while reading")
    return digest.hexdigest(), bytes(captured)


def candidate_files(root: Path) -> CandidateSnapshot:
    root_descriptor = open_absolute_directory(root, "candidate root")
    records: dict[str, tuple[int, int, str]] = {}
    identities: dict[str, tuple[int, int, int, int, int, int, int]] = {}
    control_files: dict[str, bytes] = {}
    try:
        root_info = os.fstat(root_descriptor)
        names = directory_names(root_descriptor)
        if len(names) > MAX_FILES:
            raise ComparisonError(f"candidate file count exceeds {MAX_FILES}")
        for name in names:
            if not SAFE_NAME.fullmatch(name):
                raise ComparisonError(f"candidate contains an unsafe flat path: {name!r}")
            try:
                descriptor = os.open(name, FILE_FLAGS, dir_fd=root_descriptor)
            except OSError as error:
                raise ComparisonError(f"cannot safely open candidate entry: {name}") from error
            try:
                before = os.fstat(descriptor)
                if stat.S_ISDIR(before.st_mode):
                    raise ComparisonError(f"candidate subdirectories are forbidden: {name}")
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                    raise ComparisonError(f"candidate contains an unsafe file: {name}")
                if before.st_size < 0 or before.st_size > MAX_FILE_SIZE:
                    raise ComparisonError(f"candidate contains an oversized file: {name}")
                capture = name in (EVIDENCE, CHECKSUMS)
                if capture and before.st_size > MAX_CONTROL_SIZE:
                    raise ComparisonError(f"candidate control file is too large: {name}")
                checksum, raw = file_digest(descriptor, before.st_size, capture)
                after = os.fstat(descriptor)
                if stable_stat(before) != stable_stat(after):
                    raise ComparisonError(f"candidate file changed while reading: {name}")
                identities[name] = stable_stat(after)
                records[name] = (stat.S_IMODE(after.st_mode), after.st_size, checksum)
                if capture:
                    control_files[name] = raw
            finally:
                os.close(descriptor)
        if directory_names(root_descriptor) != names:
            raise ComparisonError("candidate root changed while reading")
        for name, identity in identities.items():
            try:
                current = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
            except OSError as error:
                raise ComparisonError(f"candidate entry changed while reading: {name}") from error
            if stable_stat(current) != identity:
                raise ComparisonError(f"candidate entry changed while reading: {name}")
        for required in (EVIDENCE, CHECKSUMS):
            if required not in control_files:
                raise ComparisonError(f"candidate is missing {required}")
        return CandidateSnapshot(
            records=records,
            evidence=control_files[EVIDENCE],
            checksums=control_files[CHECKSUMS],
            root_identity=(root_info.st_dev, root_info.st_ino),
        )
    except OSError as error:
        raise ComparisonError("cannot inspect candidate root") from error
    finally:
        os.close(root_descriptor)


def load_json(raw: bytes) -> dict[str, object]:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ComparisonError(f"duplicate JSON key in {EVIDENCE}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=unique_object)
    except ComparisonError:
        raise
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ComparisonError(f"cannot decode {EVIDENCE}") from error
    if not isinstance(value, dict):
        raise ComparisonError(f"JSON evidence is not an object: {EVIDENCE}")
    return value


def verify_checksums(snapshot: CandidateSnapshot) -> None:
    try:
        lines = snapshot.checksums.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise ComparisonError(f"cannot decode {CHECKSUMS}") from error
    declared: dict[str, str] = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise ComparisonError(f"malformed {CHECKSUMS} record")
        digest, relative = line[:64], line[66:]
        if not SHA256.fullmatch(digest) or not SAFE_NAME.fullmatch(relative):
            raise ComparisonError(f"unsafe {CHECKSUMS} record")
        if relative in declared or relative == CHECKSUMS:
            raise ComparisonError(f"duplicate or recursive {CHECKSUMS} record")
        declared[relative] = digest
    expected = set(snapshot.records) - {CHECKSUMS}
    if set(declared) != expected:
        raise ComparisonError(f"{CHECKSUMS} does not cover the exact candidate output")
    for relative, digest in declared.items():
        if snapshot.records[relative][2] != digest:
            raise ComparisonError(f"checksum mismatch for {relative}")


def validate_evidence(snapshot: CandidateSnapshot) -> dict[str, object]:
    evidence = load_json(snapshot.evidence)
    required = {
        "schema": "nftfw.build-evidence.v1",
        "status": "STAGE_R_CANDIDATE_BUILD_PASS",
        "git_tag": "unreleased",
        "git_tag_object": "unreleased",
        "build_disposition": "stage-r-candidate-only",
        "runtime_capable": False,
        "deployable": False,
        "deployment_authorized": False,
        "publication_authorized": False,
        "privileged_r2_evidence": "NOT_EXECUTED",
        "r2_attestation_sha256": "NOT_APPLICABLE",
        "source_reports_scope": "FROZEN_PRE_BUILD_SOURCE_SNAPSHOT_ONLY",
    }
    for key, expected in required.items():
        actual = evidence.get(key)
        if (isinstance(expected, bool) and actual is not expected) or (
            not isinstance(expected, bool) and actual != expected
        ):
            raise ComparisonError(f"candidate evidence has invalid {key}")
    for key in ("target_version", "artifact_version", "git_commit"):
        value = evidence.get(key)
        if not isinstance(value, str) or not value:
            raise ComparisonError(f"candidate evidence is missing {key}")
    target_version = str(evidence["target_version"])
    artifact_version = str(evidence["artifact_version"])
    commit = str(evidence["git_commit"])
    if not TARGET_VERSION.fullmatch(target_version):
        raise ComparisonError("candidate evidence target version is malformed")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ComparisonError("candidate evidence commit is malformed")
    if artifact_version != f"{target_version}~stage.r.{commit[:12]}":
        raise ComparisonError("candidate evidence artifact version is not commit-bound")
    build_date = evidence.get("build_date")
    if not isinstance(build_date, str) or not BUILD_DATE.fullmatch(build_date):
        raise ComparisonError("candidate evidence build date is malformed")
    checks = evidence.get("checks")
    if not isinstance(checks, dict):
        raise ComparisonError("candidate evidence checks are missing")
    if set(checks) != set(REQUIRED_CHECKS):
        raise ComparisonError("candidate evidence checks do not match the exact gate set")
    for check in REQUIRED_CHECKS:
        if checks.get(check) != "PASS":
            raise ComparisonError(f"candidate evidence check did not pass: {check}")
    if evidence.get("toolchain") != {"go": PINNED_GO}:
        raise ComparisonError("candidate evidence toolchain is not pinned")
    secret_scan = evidence.get("secret_scan_evidence")
    if not isinstance(secret_scan, dict) or set(secret_scan) != {
        "scanner_sha256",
        "source_history_sha256",
        "extracted_tree_sha256",
    }:
        raise ComparisonError("candidate secret-scan evidence is malformed")
    if any(
        not isinstance(value, str) or not SHA256.fullmatch(value)
        for value in secret_scan.values()
    ):
        raise ComparisonError("candidate secret-scan evidence digest is malformed")
    secret_bindings = {
        "source_history_sha256": "SOURCE_HISTORY_SECRET_SCAN.json",
        "extracted_tree_sha256": "EXTRACTED_TREE_SECRET_SCAN.json",
    }
    for evidence_key, subject_path in secret_bindings.items():
        if subject_path not in snapshot.records:
            raise ComparisonError(f"candidate is missing secret-scan subject: {subject_path}")
        if secret_scan[evidence_key] != snapshot.records[subject_path][2]:
            raise ComparisonError(f"candidate secret-scan digest is not bound: {evidence_key}")
    subjects = evidence.get("artifacts")
    if not isinstance(subjects, list) or not subjects:
        raise ComparisonError("candidate evidence has no artifact subjects")
    seen: set[str] = set()
    for subject in subjects:
        if not isinstance(subject, dict):
            raise ComparisonError("candidate evidence subject is malformed")
        relative = subject.get("path")
        digest = subject.get("sha256")
        size = subject.get("size")
        mode = subject.get("mode")
        if (
            not isinstance(relative, str)
            or not SAFE_NAME.fullmatch(relative)
            or relative in seen
            or relative not in snapshot.records
        ):
            raise ComparisonError("candidate evidence subject path is unsafe or duplicate")
        seen.add(relative)
        actual_mode, actual_size, actual_digest = snapshot.records[relative]
        if (
            not isinstance(digest, str)
            or not SHA256.fullmatch(digest)
            or type(size) is not int
            or not isinstance(mode, str)
            or digest != actual_digest
            or size != actual_size
            or mode != f"{actual_mode:o}"
        ):
            raise ComparisonError(f"candidate evidence subject mismatch for {relative}")
    expected_subjects = set(snapshot.records) - {EVIDENCE, CHECKSUMS}
    if seen != expected_subjects:
        raise ComparisonError("candidate evidence subjects do not cover the exact output")
    return evidence


def tree_digest(records: dict[str, tuple[int, int, str]]) -> str:
    digest = hashlib.sha256()
    for relative in sorted(records):
        mode, size, checksum = records[relative]
        digest.update(f"{mode:o}\0{size}\0{checksum}\0{relative}\n".encode("utf-8"))
    return digest.hexdigest()


def run(left: Path, right: Path, output: Path) -> None:
    if left == right:
        raise ComparisonError("candidate roots must be different")
    left_snapshot = candidate_files(left)
    right_snapshot = candidate_files(right)
    if left_snapshot.root_identity == right_snapshot.root_identity:
        raise ComparisonError("candidate roots must identify different directories")
    verify_checksums(left_snapshot)
    verify_checksums(right_snapshot)
    left_evidence = validate_evidence(left_snapshot)
    right_evidence = validate_evidence(right_snapshot)
    identity_keys = ("target_version", "artifact_version", "git_commit", "build_date")
    if any(left_evidence[key] != right_evidence[key] for key in identity_keys):
        raise ComparisonError("candidate build identities differ")
    left_records = left_snapshot.records
    right_records = right_snapshot.records
    if left_records != right_records:
        differing = sorted(set(left_records) ^ set(right_records))
        if not differing:
            differing = sorted(
                path for path in left_records if left_records[path] != right_records[path]
            )
        first_difference = differing[0] if differing else "unknown path"
        raise ComparisonError(f"candidate outputs differ at {first_difference}")
    if not output.is_absolute() or ".." in output.parts or not SAFE_NAME.fullmatch(output.name):
        raise ComparisonError("output must be a new absolute canonical flat path")
    parent = output.parent
    parent_descriptor = open_absolute_directory(parent, "output parent")
    try:
        parent_info = os.fstat(parent_descriptor)
        parent_identity = (parent_info.st_dev, parent_info.st_ino)
        if parent_identity in (left_snapshot.root_identity, right_snapshot.root_identity):
            raise ComparisonError("comparison evidence must be outside both candidate roots")
        try:
            os.stat(output.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as error:
            raise ComparisonError("cannot safely inspect comparison output") from error
        else:
            raise ComparisonError("output must be a new absolute path")
        evidence_digest = left_records[EVIDENCE][2]
        result = {
            "schema": "nftfw.stage-r-candidate-comparison.v1",
            "status": "STAGE_R_CANDIDATE_COMPARISON_PASS",
            "target_version": left_evidence["target_version"],
            "artifact_version": left_evidence["artifact_version"],
            "git_commit": left_evidence["git_commit"],
            "build_disposition": "stage-r-candidate-only",
            "candidate_build_evidence_sha256": evidence_digest,
            "candidate_tree_sha256": tree_digest(left_records),
            "file_count": len(left_records),
            "byte_for_byte_identical": True,
            "runtime_capable": False,
            "deployable": False,
            "deployment_authorized": False,
            "publication_authorized": False,
            "privileged_r2_evidence": "NOT_EXECUTED",
            "r2_attestation_sha256": "NOT_APPLICABLE",
            "source_reports_scope": "FROZEN_PRE_BUILD_SOURCE_SNAPSHOT_ONLY",
            "toolchain": {"go": PINNED_GO},
        }
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            descriptor = os.open(output.name, flags, 0o644, dir_fd=parent_descriptor)
        except OSError as error:
            raise ComparisonError("cannot safely create comparison output") from error
        created: os.stat_result | None = None
        try:
            os.fchmod(descriptor, 0o644)
            created = os.fstat(descriptor)
            handle = os.fdopen(descriptor, "w", encoding="utf-8")
            descriptor = -1
            with handle:
                json.dump(result, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
                written = os.fstat(handle.fileno())
                if (
                    not stat.S_ISREG(written.st_mode)
                    or stat.S_IMODE(written.st_mode) != 0o644
                ):
                    raise ComparisonError("comparison output has unsafe metadata")
                expected_size = written.st_size
            os.fsync(parent_descriptor)
            try:
                published = os.stat(output.name, dir_fd=parent_descriptor, follow_symlinks=False)
            except OSError as error:
                raise ComparisonError("cannot revalidate comparison output") from error
            if (
                (published.st_dev, published.st_ino) != (created.st_dev, created.st_ino)
                or not stat.S_ISREG(published.st_mode)
                or stat.S_IMODE(published.st_mode) != 0o644
                or published.st_size != expected_size
            ):
                raise ComparisonError("comparison output changed during publication")
        except Exception as error:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            try:
                current = os.stat(output.name, dir_fd=parent_descriptor, follow_symlinks=False)
                if created is not None and (current.st_dev, current.st_ino) == (
                    created.st_dev,
                    created.st_ino,
                ):
                    os.unlink(output.name, dir_fd=parent_descriptor)
            except OSError:
                pass
            if isinstance(error, ComparisonError):
                raise
            raise ComparisonError("cannot write comparison output") from error
    finally:
        os.close(parent_descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--left", required=True, type=Path)
    parser.add_argument("--right", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        run(arguments.left, arguments.right, arguments.output)
    except ComparisonError as error:
        print(f"candidate comparison: {error}", file=sys.stderr)
        return 1
    print(f"STAGE_R_CANDIDATE_COMPARISON: PASS ({arguments.output})")
    print("R2 PRIVILEGED PACKAGE/BOOT/NETWORK/DOCKER/OVPN EVIDENCE: NOT EXECUTED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
