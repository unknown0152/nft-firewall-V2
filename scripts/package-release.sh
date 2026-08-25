#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
export LC_ALL=C
export TZ=UTC
export GOENV=off
export GOFLAGS=-buildvcs=false
export GOEXPERIMENT=
export GOWORK=off
export GOAMD64=v1
export GOARM64=v8.0
unset CDPATH ENV BASH_ENV MAKEFLAGS MFLAGS TAR_OPTIONS TAPE ZIPOPT GZIP GZIP_OPT \
    DPKG_DEB_COMPRESSOR_TYPE DPKG_DEB_COMPRESSOR_LEVEL TMPDIR
unset BUILD_DATE COMMIT DISPOSITION NFTFW_BUILD_DISPOSITION VERSION
unset GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_DIR \
    GIT_INDEX_FILE GIT_NAMESPACE GIT_OBJECT_DIRECTORY GIT_WORK_TREE
export GIT_CONFIG_NOSYSTEM=1
export GIT_NO_LAZY_FETCH=1
export GIT_NO_REPLACE_OBJECTS=1
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
version=${1:-}
allow_untagged=${2:-}
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([~+][A-Za-z0-9.]+)?$ ]] || \
    [[ -n "$allow_untagged" && "$allow_untagged" != --allow-untagged ]] || (( $# > 2 )); then
    echo "Usage: package-release.sh <version> [--allow-untagged]" >&2
    exit 2
fi

for command_name in cp date dpkg-deb find flock git go grep gzip id install jq make mktemp mv python3 sed sha256sum sort stat tar touch uname unzip xargs zip; do
    command -v "$command_name" >/dev/null || { echo "Missing prerequisite: $command_name" >&2; exit 1; }
done

cd "$root_dir"
repository_top=$(git rev-parse --show-toplevel 2>/dev/null || true)
if [[ -z "$repository_top" ]] || \
    [[ $(cd "$repository_top" 2>/dev/null && pwd -P) != "$root_dir" ]]; then
    echo "Release packaging must run from the physical root of its own Git worktree" >&2
    exit 1
fi
commit=$(git rev-parse --verify 'HEAD^{commit}')
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || {
    echo "Release packaging requires a full immutable SHA-1 commit identity" >&2
    exit 1
}
if [[ -n $(git status --porcelain --untracked-files=normal) ]]; then
    echo "Release packaging requires a clean Git working tree" >&2
    exit 1
fi
committed_script_digest=$(git cat-file blob "$commit:scripts/package-release.sh" | sha256sum)
committed_script_digest=${committed_script_digest%% *}
running_script_digest=$(sha256sum "$root_dir/scripts/package-release.sh")
running_script_digest=${running_script_digest%% *}
if [[ "$running_script_digest" != "$committed_script_digest" ]]; then
    echo "Running release script does not match the exact release commit" >&2
    exit 1
fi
tracked_release_version=$(git show "$commit:RELEASE_VERSION")
tracked_release_version_size=$(git cat-file -s "$commit:RELEASE_VERSION")
if [[ "$tracked_release_version" != "$version" ]] || \
    [[ "$tracked_release_version_size" -ne $((${#version} + 1)) ]]; then
    echo "Requested version $version does not match tracked RELEASE_VERSION" >&2
    exit 1
fi
required_go_version=go1.25.13
go_version=$(go env GOVERSION)
if [[ "$go_version" != "$required_go_version" ]]; then
    echo "Release packaging requires $required_go_version (found $go_version); run with GOTOOLCHAIN=$required_go_version" >&2
    exit 1
fi
source_date_epoch=$(git show -s --format=%ct "$commit")
build_date=$(date -u -d "@$source_date_epoch" +%Y-%m-%dT%H:%M:%SZ)
release_tag="v$version"
tag="$release_tag"
tag_object="unreleased"
candidate_mode=0
release_disposition="TAGGED RELEASE BYTES - EXTERNAL FINAL APPROVAL REQUIRED"
artifact_label="$version"
artifact_version="$version"
build_disposition="release"
candidate_notice_name="RELEASE-CANDIDATE-NOT-DEPLOYABLE.txt"
tagged_notice_name="TAGGED-BUILD-REQUIRES-FINAL-APPROVAL.txt"
if [[ "$allow_untagged" == --allow-untagged ]]; then
    if [[ -n $(git rev-parse -q --verify "refs/tags/$release_tag" 2>/dev/null || true) ]]; then
        echo "--allow-untagged refuses an existing release tag name; tags are immutable" >&2
        exit 1
    fi
    tag=unreleased
    candidate_mode=1
    release_disposition="RELEASE CANDIDATE - NOT DEPLOYABLE"
    artifact_label="$version-RELEASE-CANDIDATE-NOT-DEPLOYABLE-${commit:0:12}"
    artifact_version="$version~stage.r.${commit:0:12}"
    build_disposition="stage-r-candidate-only"
elif [[ $(git rev-parse -q --verify "refs/tags/$tag^{commit}" 2>/dev/null || true) != "$commit" ]]; then
    echo "Tag $tag must point to HEAD before final packaging" >&2
    exit 1
elif [[ $(git cat-file -t "refs/tags/$tag" 2>/dev/null || true) != tag ]]; then
    echo "Tag $tag must be an annotated tag before tagged validation packaging" >&2
    exit 1
else
    tag_object=$(git rev-parse --verify "refs/tags/$tag")
    [[ "$tag_object" =~ ^[0-9a-f]{40}$ ]] || {
        echo "Tag $tag does not have a supported immutable object identity" >&2
        exit 1
    }
fi

approval_status=$(git show "$commit:FINAL_ACCEPTANCE_REPORT.md" | \
    sed -n 's/^Release approval status: \([A-Z0-9_]*\)$/\1/p')
if [[ "$approval_status" != STAGE_R_CANDIDATE_ONLY ]]; then
    echo "The frozen source report must remain STAGE_R_CANDIDATE_ONLY; later approvals are external attestations" >&2
    exit 1
fi
r2_attestation=""
r2_attestation_digest="NOT_APPLICABLE"
if (( candidate_mode )); then
    if [[ -n ${NFTFW_R2_ATTESTATION:-} ]]; then
        echo "Stage R candidate packaging must not consume R2 approval evidence" >&2
        exit 1
    fi
else
    r2_attestation=${NFTFW_R2_ATTESTATION:-}
    if [[ "$r2_attestation" != /* ]]; then
        echo "Tagged validation packaging requires an absolute external NFTFW_R2_ATTESTATION path" >&2
        exit 1
    fi
fi

work_root=$(cd "$root_dir/.." && pwd)
release_parent=${NFTFW_RELEASE_PARENT:-"$work_root/releases"}
if [[ "$release_parent" != /* || "$release_parent" == / ]]; then
    echo "NFTFW_RELEASE_PARENT must be an absolute, non-root path" >&2
    exit 1
fi
case "$release_parent/" in
    "$root_dir/"*)
        echo "NFTFW_RELEASE_PARENT must be outside the source repository" >&2
        exit 1
        ;;
esac
if [[ ! -d "$release_parent" || -L "$release_parent" ]]; then
    echo "NFTFW_RELEASE_PARENT must be a pre-created protected directory" >&2
    exit 1
fi
physical_release_parent=$(cd "$release_parent" 2>/dev/null && pwd -P)
if [[ "$physical_release_parent" != "$release_parent" ]]; then
    echo "NFTFW_RELEASE_PARENT must be an exact canonical path without symlink components" >&2
    exit 1
fi
if ! python3 - "$release_parent" <<'PY'
import os
import stat
import sys


try:
    requested = sys.argv[1]
    if not os.path.isabs(requested) or os.path.normpath(requested) != requested:
        raise ValueError
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        components = requested.split("/")[1:]
        for index, component in enumerate(components):
            if not component or component in (".", ".."):
                raise ValueError
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            info = os.fstat(descriptor)
            mode = stat.S_IMODE(info.st_mode)
            is_final = index == len(components) - 1
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError
            if is_final:
                if info.st_uid != os.getuid() or mode & 0o022:
                    raise ValueError
            elif mode & 0o022 and not (info.st_uid == 0 and mode & stat.S_ISVTX):
                raise ValueError
    finally:
        os.close(descriptor)
except (OSError, ValueError, IndexError):
    raise SystemExit(1)
PY
then
    echo "Release parent or an ancestor has unsafe ownership, permissions, or type" >&2
    exit 1
fi
case "$release_parent/" in
    "$root_dir/"*)
        echo "NFTFW_RELEASE_PARENT must be outside the source repository" >&2
        exit 1
        ;;
esac
exec 9<"$release_parent"
if ! flock -n 9; then
    echo "Another NFT Firewall release build holds the release-parent lock: $release_parent" >&2
    exit 1
fi
release_dir="$release_parent/nft-firewall-v2-$artifact_label"
if [[ -e "$release_dir" || -L "$release_dir" ]]; then
    echo "Release target already exists; refusing to overwrite it: $release_dir" >&2
    exit 1
fi

verify_repository_state() {
    if [[ $(git rev-parse --verify 'HEAD^{commit}') != "$commit" ]] || \
        [[ -n $(git status --porcelain --untracked-files=normal) ]]; then
        echo "Repository state changed after the release commit was captured" >&2
        return 1
    fi
    if [[ "$tag" != unreleased ]] && \
        [[ $(git rev-parse -q --verify "refs/tags/$tag^{commit}" 2>/dev/null || true) != "$commit" ]]; then
        echo "Tag $tag moved after the release commit was captured" >&2
        return 1
    fi
    if [[ "$tag" != unreleased ]] && \
        [[ $(git cat-file -t "refs/tags/$tag" 2>/dev/null || true) != tag ]]; then
        echo "Tag $tag is no longer an annotated tag" >&2
        return 1
    fi
    if [[ "$tag" != unreleased ]] && \
        [[ $(git rev-parse --verify "refs/tags/$tag" 2>/dev/null || true) != "$tag_object" ]]; then
        echo "Tag $tag object identity changed after it was captured" >&2
        return 1
    fi
    if (( candidate_mode )) && \
        [[ -n $(git rev-parse -q --verify "refs/tags/$release_tag" 2>/dev/null || true) ]]; then
        echo "Release tag $release_tag appeared during candidate construction" >&2
        return 1
    fi
}
verify_repository_state

temporary=$(mktemp -d "$release_parent/.nftfw-release-$version.XXXXXX")
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT
if (( ! candidate_mode )); then
    r2_attestation_copy="$temporary/R2_ATTESTATION.input.json"
    if ! python3 - "$root_dir" "$r2_attestation" "$r2_attestation_copy" <<'PY'
import os
import stat
import sys


def fail() -> None:
    raise SystemExit(1)


try:
    repository = os.path.realpath(sys.argv[1])
    source = sys.argv[2]
    destination = sys.argv[3]
    if not os.path.isabs(source) or not hasattr(os, "O_NOFOLLOW"):
        fail()
    descriptor = os.open(
        source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    )
    try:
        before = os.fstat(descriptor)
        opened_path = os.path.realpath(f"/proc/self/fd/{descriptor}")
        if opened_path.endswith(" (deleted)"):
            fail()
        if os.path.commonpath((repository, opened_path)) == repository:
            fail()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size <= 0
            or before.st_size > 1024 * 1024
        ):
            fail()
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                fail()
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            fail()
        after = os.fstat(descriptor)
        stable_fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
            fail()
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)
    output = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(output, view)
            if written <= 0:
                fail()
            view = view[written:]
        os.fsync(output)
    finally:
        os.close(output)
except (OSError, ValueError, IndexError):
    fail()
PY
    then
        echo "R2 attestation could not be captured as a safe immutable external input" >&2
        exit 1
    fi
    jq -e --arg version "$version" --arg commit "$commit" '
        .schema == "nftfw.r2-attestation.v1" and
        .status == "R2_PASSED_TAG_BUILD_AUTHORIZED" and
        .target_version == $version and .git_commit == $commit and
        .publication_authorized == false and .deployment_authorized == false and
        .privileged_evidence.package_boot_network_docker_ovpn == "PASS" and
        (.privileged_evidence_manifest_sha256 | test("^[0-9a-f]{64}$")) and
        (.stage_r_candidate_comparison_sha256 | test("^[0-9a-f]{64}$"))
    ' "$r2_attestation_copy" >/dev/null || {
        echo "R2 attestation does not authorize tagged validation for this exact version/commit" >&2
        exit 1
    }
    r2_attestation_digest=$(sha256sum "$r2_attestation_copy")
    r2_attestation_digest=${r2_attestation_digest%% *}
fi
stage="$temporary/stage"
release_root="$stage/nft-firewall-v2"
build_source="$temporary/build-source"
source_export="$temporary/source.tar"
publish_dir="$temporary/publish"
install -d "$release_root/source" "$release_root/binaries/linux-amd64" \
    "$release_root/binaries/linux-arm64" "$release_root/packages" "$build_source" "$publish_dir"

tracked_paths="$temporary/tracked-paths"
git ls-tree -r -z --name-only "$commit" > "$tracked_paths"
control_path_status=0
LC_ALL=C grep -z -E '[[:cntrl:]]' "$tracked_paths" >/dev/null || control_path_status=$?
if (( control_path_status == 0 )); then
    echo "Release commit contains a tracked path with an ASCII control character" >&2
    exit 1
elif (( control_path_status > 1 )); then
    echo "Could not validate tracked release paths" >&2
    exit 1
fi
tracked_entries="$temporary/tracked-entries"
git ls-tree -r -z "$commit" > "$tracked_entries"
if ! python3 - "$tracked_entries" <<'PY'
import re
import sys


try:
    records = open(sys.argv[1], "rb").read().split(b"\0")
except OSError:
    raise SystemExit(1)
if not records or records[-1] != b"":
    raise SystemExit(1)
for record in records[:-1]:
    try:
        metadata, path = record.split(b"\t", 1)
        mode, object_type, object_id = metadata.split(b" ", 2)
    except ValueError:
        raise SystemExit(1)
    if (
        mode not in (b"100644", b"100755")
        or object_type != b"blob"
        or re.fullmatch(rb"[0-9a-f]{40}", object_id) is None
        or not path
    ):
        raise SystemExit(1)
PY
then
    echo "Release commit contains a symlink, gitlink, or unsupported tracked entry" >&2
    exit 1
fi

git -c tar.umask=0022 archive --format=tar --output="$source_export" "$commit"
tar -xf "$source_export" -C "$build_source"
tar -xf "$source_export" -C "$release_root/source"
if ! python3 - "$tracked_entries" "$build_source" "$release_root/source" <<'PY'
import hashlib
import os
import stat
import sys


def expected_entries(path: str) -> dict[bytes, tuple[int, str]]:
    records = open(path, "rb").read().split(b"\0")
    if not records or records[-1] != b"":
        raise ValueError
    expected = {}
    for record in records[:-1]:
        metadata, relative = record.split(b"\t", 1)
        mode, object_type, object_id = metadata.split(b" ", 2)
        if object_type != b"blob" or mode not in (b"100644", b"100755"):
            raise ValueError
        if relative in expected:
            raise ValueError
        expected[relative] = (0o755 if mode == b"100755" else 0o644, object_id.decode("ascii"))
    return expected


def verify_export(root_text: str, expected: dict[bytes, tuple[int, str]]) -> None:
    root = os.fsencode(root_text)
    actual = set()

    def walk_error(_error: OSError) -> None:
        raise ValueError

    for directory, directory_names, file_names in os.walk(root, topdown=True, followlinks=False, onerror=walk_error):
        for name in directory_names:
            candidate = os.path.join(directory, name)
            if stat.S_ISLNK(os.lstat(candidate).st_mode):
                raise ValueError
        for name in file_names:
            candidate = os.path.join(directory, name)
            relative = os.path.relpath(candidate, root)
            metadata = os.lstat(candidate)
            if not stat.S_ISREG(metadata.st_mode) or relative in actual:
                raise ValueError
            actual.add(relative)
            required = expected.get(relative)
            if required is None or stat.S_IMODE(metadata.st_mode) != required[0]:
                raise ValueError
            digest = hashlib.sha1()
            size = metadata.st_size
            digest.update(b"blob " + str(size).encode("ascii") + b"\0")
            with open(candidate, "rb", buffering=0) as stream:
                while True:
                    chunk = stream.read(65536)
                    if not chunk:
                        break
                    digest.update(chunk)
            if digest.hexdigest() != required[1]:
                raise ValueError
    if actual != set(expected):
        raise ValueError


try:
    entries = expected_entries(sys.argv[1])
    verify_export(sys.argv[2], entries)
    verify_export(sys.argv[3], entries)
except (OSError, UnicodeError, ValueError, IndexError):
    raise SystemExit(1)
PY
then
    echo "Git archive export differs from the exact commit blob/mode inventory" >&2
    exit 1
fi
secret_scanner_digest=$(sha256sum "$build_source/scripts/secret-scan.py")
secret_scanner_digest=${secret_scanner_digest%% *}
source_secret_scan="$temporary/SOURCE_HISTORY_SECRET_SCAN.json"
python3 "$build_source/scripts/secret-scan.py" git \
    --repo "$root_dir" --commit "$commit" --history --output "$source_secret_scan"
jq -e --arg commit "$commit" '
    .schema_version == "nftfw.secret-scan-evidence/v1" and
    .rules_version == "nftfw.secret-rules/2026-08-24.1" and
    .status == "PASS" and .scope.mode == "git_commit" and
    .scope.commit == $commit and .scope.include_reachable_history == true and
    (.findings | type == "array" and length == 0) and
    .statistics.git_commits_examined >= 1 and
    .statistics.files_seen >= 1 and .statistics.files_scanned >= 1 and
    .statistics.bytes_scanned >= 1
' "$source_secret_scan" >/dev/null || {
    echo "Exact-commit and reachable-history secret scan did not produce complete PASS evidence" >&2
    exit 1
}
install -m 0644 "$source_secret_scan" "$release_root/SOURCE_HISTORY_SECRET_SCAN.json"

export SOURCE_DATE_EPOCH="$source_date_epoch"
(
    cd "$build_source"
    make clean
    make release VERSION="$artifact_version" COMMIT="$commit" BUILD_DATE="$build_date" \
        DISPOSITION="$build_disposition"
    ./tests/packaging/systemd_preflight.sh amd64
    NFTFW_BUILD_DISPOSITION="$build_disposition" ./scripts/build-deb.sh "$artifact_version" amd64
    NFTFW_BUILD_DISPOSITION="$build_disposition" ./scripts/build-deb.sh "$artifact_version" arm64
)
for arch in amd64 arm64; do
    for binary in nftfw nftfwd nftfw-web; do
        binary_path="$build_source/dist/$binary-linux-$arch"
        binary_metadata=$(go version -m "$binary_path")
        grep -Fq ": $required_go_version" <<< "${binary_metadata%%$'\n'*}"
        grep -Fq $'\tbuild\tCGO_ENABLED=0' <<< "$binary_metadata"
        grep -Fq $'\tbuild\t-trimpath=true' <<< "$binary_metadata"
        grep -Fq $'\tbuild\tGOOS=linux' <<< "$binary_metadata"
        grep -Fq $'\tbuild\tGOARCH='"$arch" <<< "$binary_metadata"
        if grep -Fq $'\tbuild\tvcs=' <<< "$binary_metadata"; then
            echo "Release binary unexpectedly contains ambient VCS metadata: $binary_path" >&2
            exit 1
        fi
        if [[ "$arch" == amd64 ]]; then
            grep -Fq $'\tbuild\tGOAMD64=v1' <<< "$binary_metadata"
        else
            grep -Fq $'\tbuild\tGOARM64=v8.0' <<< "$binary_metadata"
        fi
    done
done
case $(uname -m) in
    x86_64) native_arch=amd64 ;;
    aarch64|arm64) native_arch=arm64 ;;
    *) echo "Release metadata verification requires an amd64 or arm64 build host" >&2; exit 1 ;;
esac
jq -e --arg version "$artifact_version" --arg commit "$commit" --arg date "$build_date" \
    --arg disposition "$build_disposition" \
    '.version == $version and .commit == $commit and .build_date == $date and
     .build_disposition == $disposition and
     .artifact_identity == ($version + "|" + $commit + "|" + $date + "|" + $disposition)' \
    < <("$build_source/dist/nftfw-linux-$native_arch" version --json) >/dev/null

for arch in amd64 arm64; do
    for binary in nftfw nftfwd nftfw-web; do
        install -m 0755 "$build_source/dist/$binary-linux-$arch" "$release_root/binaries/linux-$arch/$binary"
    done
    install -m 0644 "$build_source/dist/nft-firewall-v2_${artifact_version}_${arch}.deb" "$release_root/packages/"
done
cp -a "$release_root/source/packaging" "$release_root/packaging"
cp -a "$release_root/source/configs" "$release_root/configs"
cp -a "$release_root/source/docs" "$release_root/docs"
cp -a "$release_root/source/tests" "$release_root/tests"
for document in README.md START-HERE.md INSTALL.md SECURITY.md CHANGELOG.md LICENSE \
    FINAL_ACCEPTANCE_REPORT.md SECURITY_AUDIT.md TEST_RESULTS.md; do
    install -m 0644 "$release_root/source/$document" "$release_root/$document"
done
install -m 0644 "$release_root/source/docs/ARCHITECTURE.md" "$release_root/ARCHITECTURE.md"
install -m 0644 "$release_root/source/docs/V1_FEATURE_PARITY.md" "$release_root/V1_FEATURE_PARITY.md"
install -m 0644 "$release_root/source/docs/V1_SECURITY_INVARIANTS.md" "$release_root/SECURITY_INVARIANTS.md"
sed -i \
    -e "s#@RELEASE_VERSION@#$version#g" \
    -e "s#@RELEASE_ARTIFACT_VERSION@#$artifact_version#g" \
    -e "s#@GIT_COMMIT@#$commit#g" \
    -e "s#@GIT_TAG@#$tag#g" \
    -e "s#@BUILD_DATE@#$build_date#g" \
    -e "s#@RELEASE_DISPOSITION@#$release_disposition#g" \
    -e "s#@RELEASE_ARTIFACT_LABEL@#$artifact_label#g" \
    "$release_root/FINAL_ACCEPTANCE_REPORT.md"
if (( candidate_mode )); then
    {
        echo "$release_disposition"
        echo
        echo "Version: $version"
        echo "Artifact version: $artifact_version"
        echo "Commit: $commit"
        echo "Git tag: unreleased"
        echo
        echo "Stage R source testing is not Stage R2 acceptance."
        echo "Do not install, deploy, publish, or represent these artifacts as a final release."
    } > "$release_root/$candidate_notice_name"
else
    {
        echo "$release_disposition"
        echo
        echo "Version: $version"
        echo "Artifact version: $artifact_version"
        echo "Commit: $commit"
        echo "Git tag: $tag"
        echo "R2 attestation SHA-256: $r2_attestation_digest"
        echo
        echo "These exact bytes require an external FINAL_RELEASE_APPROVED record before publication or deployment."
    } > "$release_root/$tagged_notice_name"
fi
{
    echo
    echo "## Embedded binary and package checksums"
    echo
    echo '```text'
    (
        cd "$release_root"
        find binaries packages -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum
    )
    echo '```'
} >> "$release_root/FINAL_ACCEPTANCE_REPORT.md"

debris_file="$temporary/release-debris"
if ! find "$release_root" \
    \( -type l -o \
    \( -type d \( -name .git -o -name __pycache__ -o -name .pytest_cache -o -name .mypy_cache -o -name .cache \) \) -o \
    \( -type f \( -name '*.pyc' -o -name '*.pyo' -o -name '.DS_Store' -o -name '*~' -o \
        -name '*.swp' -o -name '*.tmp' -o -name '*.log' -o -name '*.db' -o -name '*.db-wal' -o \
        -name '*.db-shm' -o -name 'wg-test.conf' \) \) \) -print0 > "$debris_file"; then
    echo "Could not validate the release tree for forbidden entries" >&2
    exit 1
fi
release_debris=()
mapfile -d '' release_debris < "$debris_file"
if (( ${#release_debris[@]} > 0 )); then
    echo "Release tree contains forbidden cache, runtime, secret, or symlink entries:" >&2
    printf '  %s\n' "${release_debris[@]}" >&2
    exit 1
fi

source_checksums="$temporary/SOURCE_MANIFEST.sha256"
(
    cd "$release_root"
    find source -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum > "$source_checksums"
)
install -m 0644 "$source_checksums" "$release_root/SOURCE_MANIFEST.sha256"
manifest_args=(
    --root "$release_root"
    --version "$artifact_version"
    --commit "$commit"
    --tag "$tag"
    --build-date "$build_date"
    --source-date-epoch "$source_date_epoch"
    --go-version "$go_version"
)
preliminary_manifest="$release_root/.RELEASE_MANIFEST.preliminary.json"
(
    cd "$build_source"
    go run ./scripts/release-manifest.go "${manifest_args[@]}" \
        --output "$preliminary_manifest"
)
git_version=$(git --version)
tar_version=$(tar --version | sed -n '1p')
gzip_version=$(gzip --version | sed -n '1p')
zip_version=$(zip -v 2>&1 | sed -n '/^This is Zip /p')
dpkg_deb_version=$(dpkg-deb --version | sed -n '1p')
jq_version=$(jq --version)
flock_version=$(flock --version | sed -n '1p')
make_version=$(make --version | sed -n '1p')
coreutils_version=$(sha256sum --version | sed -n '1p')
unzip_version=$(unzip -v | sed -n '1p')
release_script_digest=$(sha256sum "$build_source/scripts/package-release.sh")
release_script_digest=${release_script_digest%% *}
working_script_digest=$(sha256sum "$root_dir/scripts/package-release.sh")
working_script_digest=${working_script_digest%% *}
if [[ "$working_script_digest" != "$release_script_digest" ]]; then
    echo "Running release script does not match the captured release commit" >&2
    exit 1
fi
jq --arg target_version "$version" --arg artifact_version "$artifact_version" \
    --arg disposition "$build_disposition" --arg commit "$commit" --arg tag "$tag" \
    --arg tag_object "$tag_object" \
    --arg go_version "$go_version" --arg git_version "$git_version" \
    --arg tar_version "$tar_version" --arg gzip_version "$gzip_version" \
    --arg zip_version "$zip_version" --arg dpkg_deb_version "$dpkg_deb_version" \
    --arg jq_version "$jq_version" --arg flock_version "$flock_version" \
    --arg make_version "$make_version" --arg coreutils_version "$coreutils_version" \
    --arg unzip_version "$unzip_version" \
    --arg release_script_digest "$release_script_digest" \
    --argjson source_date_epoch "$source_date_epoch" '
    {
      "_type": "https://in-toto.io/Statement/v1",
      "subject": [.artifacts[] | {name: .path, digest: {sha256: .sha256}}],
      "predicateType": "https://slsa.dev/provenance/v1",
      "predicate": {
        "buildDefinition": {
          "buildType": "file:source/scripts/package-release.sh",
          "externalParameters": {
            targetVersion: $target_version,
            artifactVersion: $artifact_version,
            buildDisposition: $disposition,
            gitTag: $tag,
            gitTagObject: $tag_object
          },
          "internalParameters": {
            gitCommit: $commit,
            sourceDateEpoch: $source_date_epoch,
            cgoEnabled: false,
            targets: ["linux/amd64", "linux/arm64"],
            targetTuning: {GOAMD64: "v1", GOARM64: "v8.0"},
            tools: {
              go: $go_version,
              git: $git_version,
              tar: $tar_version,
              gzip: $gzip_version,
              zip: $zip_version,
              dpkgDeb: $dpkg_deb_version,
              jq: $jq_version,
              flock: $flock_version,
              make: $make_version,
              coreutils: $coreutils_version,
              unzip: $unzip_version
            }
          },
          "resolvedDependencies": [{
            uri: "git+file:source",
            digest: {sha1: $commit}
          }]
        },
        "runDetails": {
          "builder": {
            id: "file:source/scripts/package-release.sh",
            version: {sha256: $release_script_digest}
          },
          "metadata": {invocationId: $commit}
        }
      }
    }' "$preliminary_manifest" > "$temporary/BUILD_PROVENANCE.json"
rm -f -- "$preliminary_manifest"
install -m 0644 "$temporary/BUILD_PROVENANCE.json" "$release_root/BUILD_PROVENANCE.json"
(
    cd "$build_source"
    go run ./scripts/release-manifest.go "${manifest_args[@]}" \
        --output "$release_root/RELEASE_MANIFEST.json"
)
internal_checksums="$temporary/internal-SHA256SUMS"
(
    cd "$release_root"
    find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | \
        xargs -0 -r sha256sum | sed 's#  \./#  #' > "$internal_checksums"
)
install -m 0644 "$internal_checksums" "$release_root/SHA256SUMS"
jq -e --arg version "$artifact_version" --arg commit "$commit" --arg go_version "$go_version" \
    '.schema_version == 2 and .version == $version and .git_commit == $commit and .go_version == $go_version and (.files | length > 0) and (.artifacts | length == 8)' \
    "$release_root/RELEASE_MANIFEST.json" >/dev/null
find "$release_root" -print0 | xargs -0 -r touch -h -d "@$source_date_epoch"

zip_tmp="$temporary/nft-firewall-v2-$artifact_label.zip"
tar_tmp="$temporary/nft-firewall-v2-$artifact_label.tar.gz"
(
    cd "$stage"
    find nft-firewall-v2 -type f -print | LC_ALL=C sort | zip -X -q "$zip_tmp" -@
    tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner \
        --format=posix --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
        -cf - nft-firewall-v2 | gzip -n > "$tar_tmp"
)
unzip -tq "$zip_tmp" >/dev/null
tar -tzf "$tar_tmp" >/dev/null
zip_verify="$temporary/verify-zip"
tar_verify="$temporary/verify-tar"
install -d "$zip_verify" "$tar_verify"
unzip -q "$zip_tmp" -d "$zip_verify"
tar -xzf "$tar_tmp" -C "$tar_verify"
for verify_root in "$zip_verify/nft-firewall-v2" "$tar_verify/nft-firewall-v2"; do
    (
        cd "$verify_root"
        sha256sum -c SHA256SUMS >/dev/null
        sha256sum -c SOURCE_MANIFEST.sha256 >/dev/null
    )
done
if ! python3 - "$release_root" "$zip_verify/nft-firewall-v2" "$tar_verify/nft-firewall-v2" <<'PY'
import hashlib
import os
import stat
import sys


def snapshot(root: str) -> tuple[dict[str, int], dict[str, tuple[int, int, str]]]:
    directory_modes = {}
    files = {}

    def walk_error(_error: OSError) -> None:
        raise ValueError

    for directory, directory_names, file_names in os.walk(
        root, topdown=True, followlinks=False, onerror=walk_error
    ):
        relative_directory = os.path.relpath(directory, root)
        if relative_directory != ".":
            directory_info = os.lstat(directory)
            if not stat.S_ISDIR(directory_info.st_mode):
                raise ValueError
            directory_modes[relative_directory] = stat.S_IMODE(directory_info.st_mode)
        for name in directory_names:
            candidate = os.path.join(directory, name)
            if not stat.S_ISDIR(os.lstat(candidate).st_mode):
                raise ValueError
        for name in file_names:
            candidate = os.path.join(directory, name)
            relative = os.path.relpath(candidate, root)
            info = os.lstat(candidate)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or relative in files:
                raise ValueError
            digest = hashlib.sha256()
            with open(candidate, "rb", buffering=0) as stream:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
            files[relative] = (stat.S_IMODE(info.st_mode), info.st_size, digest.hexdigest())
    return directory_modes, files


try:
    reference = snapshot(sys.argv[1])
    for extracted in sys.argv[2:]:
        if snapshot(extracted) != reference:
            raise ValueError
except (OSError, UnicodeError, ValueError, IndexError):
    raise SystemExit(1)
PY
then
    echo "Extracted archive path, type, mode, size, or content differs from the staged release tree" >&2
    exit 1
fi
zip_secret_scan="$temporary/ZIP_EXTRACTED_TREE_SECRET_SCAN.json"
tar_secret_scan="$temporary/TAR_EXTRACTED_TREE_SECRET_SCAN.json"
python3 "$build_source/scripts/secret-scan.py" tree \
    --root "$zip_verify/nft-firewall-v2" --output "$zip_secret_scan"
python3 "$build_source/scripts/secret-scan.py" tree \
    --root "$tar_verify/nft-firewall-v2" --output "$tar_secret_scan"
for extracted_scan in "$zip_secret_scan" "$tar_secret_scan"; do
    jq -e '
        .schema_version == "nftfw.secret-scan-evidence/v1" and
        .rules_version == "nftfw.secret-rules/2026-08-24.1" and
        .status == "PASS" and .scope.mode == "filesystem_tree" and
        (.findings | type == "array" and length == 0) and
        .statistics.files_seen >= 1 and .statistics.files_scanned >= 1 and
        .statistics.bytes_scanned >= 1
    ' "$extracted_scan" >/dev/null || {
        echo "Extracted candidate tree secret scan did not produce complete PASS evidence" >&2
        exit 1
    }
done
zip_secret_digest=$(sha256sum "$zip_secret_scan")
zip_secret_digest=${zip_secret_digest%% *}
tar_secret_digest=$(sha256sum "$tar_secret_scan")
tar_secret_digest=${tar_secret_digest%% *}
if [[ "$zip_secret_digest" != "$tar_secret_digest" ]]; then
    echo "ZIP and tar extracted-tree secret scan evidence differs" >&2
    exit 1
fi

zip_name="nft-firewall-v2-$artifact_label.zip"
tar_name="nft-firewall-v2-$artifact_label.tar.gz"
install -m 0644 "$zip_tmp" "$publish_dir/$zip_name"
install -m 0644 "$tar_tmp" "$publish_dir/$tar_name"
for arch in amd64 arm64; do
    for binary in nftfw nftfwd nftfw-web; do
        published_binary="$binary-linux-$arch"
        if (( candidate_mode )); then
            published_binary="$binary-linux-$arch-RELEASE-CANDIDATE-NOT-DEPLOYABLE-${commit:0:12}"
        fi
        install -m 0755 "$build_source/dist/$binary-linux-$arch" "$publish_dir/$published_binary"
    done
    published_package="nft-firewall-v2_${artifact_version}_${arch}.deb"
    published_package="nft-firewall-v2_${artifact_label}_${arch}.deb"
    install -m 0644 "$build_source/dist/nft-firewall-v2_${artifact_version}_${arch}.deb" \
        "$publish_dir/$published_package"
done
install -m 0644 "$release_root/source/SECURITY_AUDIT.md" "$publish_dir/SOURCE_SECURITY_AUDIT.md"
install -m 0644 "$release_root/source/TEST_RESULTS.md" "$publish_dir/SOURCE_TEST_RESULTS.md"
install -m 0644 "$source_secret_scan" "$publish_dir/SOURCE_HISTORY_SECRET_SCAN.json"
install -m 0644 "$zip_secret_scan" "$publish_dir/EXTRACTED_TREE_SECRET_SCAN.json"
if (( candidate_mode )); then
    install -m 0644 "$release_root/$candidate_notice_name" "$publish_dir/$candidate_notice_name"
else
    install -m 0644 "$release_root/$tagged_notice_name" "$publish_dir/$tagged_notice_name"
fi
{
    cat "$release_root/FINAL_ACCEPTANCE_REPORT.md"
    echo
    echo "## Enclosing release artifacts"
    echo
    echo "The enclosing archive cannot contain its own checksum. These exact checksums are added to the external acceptance report after archive creation."
    echo
    (cd "$publish_dir" && sha256sum "$zip_name" "$tar_name")
} > "$temporary/FINAL_ACCEPTANCE_REPORT.md"
install -m 0644 "$temporary/FINAL_ACCEPTANCE_REPORT.md" "$publish_dir/FINAL_ACCEPTANCE_REPORT.md"

external_artifacts=(
    "FINAL_ACCEPTANCE_REPORT.md"
    "SOURCE_SECURITY_AUDIT.md"
    "SOURCE_TEST_RESULTS.md"
    "SOURCE_HISTORY_SECRET_SCAN.json"
    "EXTRACTED_TREE_SECRET_SCAN.json"
    "$zip_name"
    "$tar_name"
)
if (( candidate_mode )); then
    external_artifacts+=("$candidate_notice_name")
else
    external_artifacts+=("$tagged_notice_name")
fi
for arch in amd64 arm64; do
    for binary in nftfw nftfwd nftfw-web; do
        published_binary="$binary-linux-$arch"
        if (( candidate_mode )); then
            published_binary="$binary-linux-$arch-RELEASE-CANDIDATE-NOT-DEPLOYABLE-${commit:0:12}"
        fi
        external_artifacts+=("$published_binary")
    done
    published_package="nft-firewall-v2_${artifact_label}_${arch}.deb"
    external_artifacts+=("$published_package")
done
if (( candidate_mode )); then
    build_evidence_name="CANDIDATE_BUILD_EVIDENCE-NOT-DEPLOYABLE.json"
    evidence_status="STAGE_R_CANDIDATE_BUILD_PASS"
    privileged_evidence_status="NOT_EXECUTED"
else
    build_evidence_name="TAGGED_BUILD_EVIDENCE-REQUIRES-FINAL-APPROVAL.json"
    evidence_status="TAGGED_BUILD_PASS_FINAL_APPROVAL_REQUIRED"
    privileged_evidence_status="EXTERNAL_R2_ATTESTATION_CONSUMED"
fi
evidence_artifacts="$temporary/evidence-artifacts.jsonl"
: > "$evidence_artifacts"
for artifact in "${external_artifacts[@]}"; do
    artifact_path="$publish_dir/$artifact"
    [[ -f "$artifact_path" && ! -L "$artifact_path" ]] || {
        echo "Build evidence subject is absent or unsafe: $artifact" >&2
        exit 1
    }
    artifact_sha256=$(sha256sum "$artifact_path")
    artifact_sha256=${artifact_sha256%% *}
    artifact_size=$(stat -c '%s' "$artifact_path")
    artifact_mode=$(stat -c '%a' "$artifact_path")
    jq -cn --arg path "$artifact" --arg sha256 "$artifact_sha256" \
        --arg mode "$artifact_mode" --argjson size "$artifact_size" \
        '{path:$path,sha256:$sha256,size:$size,mode:$mode}' >> "$evidence_artifacts"
done
source_secret_digest=$(sha256sum "$source_secret_scan")
source_secret_digest=${source_secret_digest%% *}
jq -s --arg status "$evidence_status" --arg target_version "$version" \
    --arg artifact_version "$artifact_version" --arg commit "$commit" --arg tag "$tag" \
    --arg tag_object "$tag_object" \
    --arg build_date "$build_date" --arg disposition "$build_disposition" \
    --arg go_version "$go_version" --arg privileged "$privileged_evidence_status" \
    --arg r2_attestation_sha256 "$r2_attestation_digest" \
    --arg source_secret_sha256 "$source_secret_digest" \
    --arg extracted_secret_sha256 "$zip_secret_digest" \
    --arg secret_scanner_sha256 "$secret_scanner_digest" '
    {
      schema:"nftfw.build-evidence.v1",
      status:$status,
      product:"NFT Firewall V2",
      target_version:$target_version,
      artifact_version:$artifact_version,
      git_commit:$commit,
      git_tag:$tag,
      git_tag_object:$tag_object,
      build_date:$build_date,
      build_disposition:$disposition,
      runtime_capable:($disposition == "release"),
      deployable:false,
      deployment_authorized:false,
      publication_authorized:false,
      source_reports_scope:"FROZEN_PRE_BUILD_SOURCE_SNAPSHOT_ONLY",
      toolchain:{go:$go_version},
      checks:{
        clean_commit_export:"PASS",
        binary_identity_and_metadata:"PASS",
        package_identity_and_payload:"PASS",
        staged_systemd_verification:"PASS",
        archive_integrity_and_internal_checksums:"PASS",
        source_and_reachable_history_secret_scan:"PASS",
        both_extracted_archives_secret_scan:"PASS",
        extracted_archive_secret_evidence_byte_identical:"PASS"
      },
      secret_scan_evidence:{
        scanner_sha256:$secret_scanner_sha256,
        source_history_sha256:$source_secret_sha256,
        extracted_tree_sha256:$extracted_secret_sha256
      },
      privileged_r2_evidence:$privileged,
      r2_attestation_sha256:$r2_attestation_sha256,
      artifacts:.
    }
    ' "$evidence_artifacts" > "$temporary/$build_evidence_name"
install -m 0644 "$temporary/$build_evidence_name" "$publish_dir/$build_evidence_name"
external_artifacts+=("$build_evidence_name")
external_checksums="$temporary/external-SHA256SUMS"
(
    cd "$publish_dir"
    printf '%s\0' "${external_artifacts[@]}" | LC_ALL=C sort -z | \
        xargs -0 -r sha256sum > "$external_checksums"
    install -m 0644 "$external_checksums" SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
)
if ! python3 - "$publish_dir" "${external_artifacts[@]}" <<'PY'
import os
import sys


root = sys.argv[1]
listed = sys.argv[2:]
expected = set(listed)
if len(expected) != len(listed) or "SHA256SUMS" in expected:
    raise SystemExit(1)
expected.add("SHA256SUMS")
try:
    entries = list(os.scandir(root))
except OSError:
    raise SystemExit(1)
actual = set()
for entry in entries:
    if entry.name in actual or not entry.is_file(follow_symlinks=False):
        raise SystemExit(1)
    actual.add(entry.name)
if actual != expected:
    raise SystemExit(1)
PY
then
    echo "Release output contains an unexpected, missing, or unsafe artifact" >&2
    exit 1
fi
verify_repository_state
publish_relative=${publish_dir#"$release_parent/"}
release_name=${release_dir#"$release_parent/"}
if ! python3 - "$release_parent" "$publish_relative" "$release_name" <<'PY'
import ctypes
import os
import stat
import sys


try:
    parent, source, destination = sys.argv[1:]
    if not source or source.startswith("/") or "/../" in f"/{source}/":
        raise ValueError
    if not destination or "/" in destination or destination in (".", ".."):
        raise ValueError
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    parent_descriptor = os.open(parent, flags)
    try:
        source_info = os.stat(source, dir_fd=parent_descriptor, follow_symlinks=False)
        if not stat.S_ISDIR(source_info.st_mode):
            raise ValueError
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
        renameat2.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        renameat2.restype = ctypes.c_int
        if renameat2(
            parent_descriptor,
            os.fsencode(source),
            parent_descriptor,
            os.fsencode(destination),
            1,  # RENAME_NOREPLACE
        ) != 0:
            raise OSError(ctypes.get_errno(), "renameat2")
        published = os.stat(destination, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISDIR(published.st_mode)
            or (published.st_dev, published.st_ino)
            != (source_info.st_dev, source_info.st_ino)
        ):
            raise ValueError
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)
except (AttributeError, OSError, ValueError, IndexError):
    raise SystemExit(1)
PY
then
    echo "Atomic no-replace publication into the protected release parent failed" >&2
    exit 1
fi

zip_final="$release_dir/$zip_name"
tar_final="$release_dir/$tar_name"
if (( candidate_mode )); then
    echo "$release_disposition"
    echo "R2 PRIVILEGED PACKAGE/BOOT/NETWORK/DOCKER/OVPN EVIDENCE: NOT EXECUTED"
fi
echo "Release directory: $release_dir"
echo "Release ZIP: $zip_final"
echo "Release tarball: $tar_final"
sha256sum "$zip_final" "$tar_final"
