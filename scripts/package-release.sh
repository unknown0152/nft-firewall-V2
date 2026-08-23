#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export LC_ALL=C
export TZ=UTC
export GOENV=off
export GOFLAGS=-buildvcs=false
export GOEXPERIMENT=
export GOWORK=off
export GOAMD64=v1
export GOARM64=v8.0
version=${1:-}
allow_untagged=${2:-}
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([~+][A-Za-z0-9.]+)?$ ]] || \
    [[ -n "$allow_untagged" && "$allow_untagged" != --allow-untagged ]] || (( $# > 2 )); then
    echo "Usage: package-release.sh <version> [--allow-untagged]" >&2
    exit 2
fi

for command_name in cp date dpkg-deb find flock git go grep gzip install jq make mktemp mv sed sha256sum sort tar touch uname unzip xargs zip; do
    command -v "$command_name" >/dev/null || { echo "Missing prerequisite: $command_name" >&2; exit 1; }
done

cd "$root_dir"
if [[ -n $(git status --porcelain --untracked-files=normal) ]]; then
    echo "Release packaging requires a clean Git working tree" >&2
    exit 1
fi
required_go_version=go1.25.13
go_version=$(go env GOVERSION)
if [[ "$go_version" != "$required_go_version" ]]; then
    echo "Release packaging requires $required_go_version (found $go_version); run with GOTOOLCHAIN=$required_go_version" >&2
    exit 1
fi
commit=$(git rev-parse --verify 'HEAD^{commit}')
source_date_epoch=$(git show -s --format=%ct "$commit")
build_date=$(date -u -d "@$source_date_epoch" +%Y-%m-%dT%H:%M:%SZ)
tag="v$version"
if [[ "$allow_untagged" == --allow-untagged ]]; then
    if [[ $(git tag --points-at HEAD --list "$tag") != "$tag" ]]; then
        tag=unreleased
    fi
elif [[ $(git rev-parse -q --verify "refs/tags/$tag^{commit}" 2>/dev/null || true) != "$commit" ]]; then
    echo "Tag $tag must point to HEAD before final packaging" >&2
    exit 1
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
if [[ -L "$release_parent" ]]; then
    echo "Release parent must not be a symlink: $release_parent" >&2
    exit 1
fi
if [[ -e "$release_parent" ]]; then
    if [[ ! -d "$release_parent" ]]; then
        echo "Release parent exists but is not a directory: $release_parent" >&2
        exit 1
    fi
else
    install -d -m 0755 "$release_parent"
fi
release_parent=$(cd "$release_parent" && pwd -P)
if [[ "$release_parent" == / ]]; then
    echo "NFTFW_RELEASE_PARENT must not resolve to the filesystem root" >&2
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
release_dir="$release_parent/nft-firewall-v2-$version"
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
}
verify_repository_state

temporary=$(mktemp -d "$release_parent/.nftfw-release-$version.XXXXXX")
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT
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

git archive --format=tar --output="$source_export" "$commit"
tar -xf "$source_export" -C "$build_source"
tar -xf "$source_export" -C "$release_root/source"

export SOURCE_DATE_EPOCH="$source_date_epoch"
(
    cd "$build_source"
    make clean
    make release VERSION="$version" COMMIT="$commit" BUILD_DATE="$build_date"
    ./tests/packaging/systemd_preflight.sh amd64
    ./scripts/build-deb.sh "$version" amd64
    ./scripts/build-deb.sh "$version" arm64
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
jq -e --arg version "$version" --arg commit "$commit" --arg date "$build_date" \
    '.version == $version and .commit == $commit and .build_date == $date' \
    < <("$build_source/dist/nftfw-linux-$native_arch" version --json) >/dev/null

for arch in amd64 arm64; do
    for binary in nftfw nftfwd nftfw-web; do
        install -m 0755 "$build_source/dist/$binary-linux-$arch" "$release_root/binaries/linux-$arch/$binary"
    done
    install -m 0644 "$build_source/dist/nft-firewall-v2_${version}_${arch}.deb" "$release_root/packages/"
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
    -e "s#@GIT_COMMIT@#$commit#g" \
    -e "s#@GIT_TAG@#$tag#g" \
    -e "s#@BUILD_DATE@#$build_date#g" \
    "$release_root/FINAL_ACCEPTANCE_REPORT.md"
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
    --version "$version"
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
jq --arg version "$version" --arg commit "$commit" --arg tag "$tag" \
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
          "externalParameters": {version: $version, gitTag: $tag},
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
jq -e --arg version "$version" --arg commit "$commit" --arg go_version "$go_version" \
    '.schema_version == 2 and .version == $version and .git_commit == $commit and .go_version == $go_version and (.files | length > 0) and (.artifacts | length == 8)' \
    "$release_root/RELEASE_MANIFEST.json" >/dev/null
find "$release_root" -print0 | xargs -0 -r touch -h -d "@$source_date_epoch"

zip_tmp="$temporary/nft-firewall-v2-$version.zip"
tar_tmp="$temporary/nft-firewall-v2-$version.tar.gz"
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

zip_name="nft-firewall-v2-$version.zip"
tar_name="nft-firewall-v2-$version.tar.gz"
install -m 0644 "$zip_tmp" "$publish_dir/$zip_name"
install -m 0644 "$tar_tmp" "$publish_dir/$tar_name"
for arch in amd64 arm64; do
    for binary in nftfw nftfwd nftfw-web; do
        install -m 0755 "$build_source/dist/$binary-linux-$arch" "$publish_dir/$binary-linux-$arch"
    done
    install -m 0644 "$build_source/dist/nft-firewall-v2_${version}_${arch}.deb" "$publish_dir/"
done
for report in SECURITY_AUDIT.md TEST_RESULTS.md; do
    install -m 0644 "$release_root/source/$report" "$publish_dir/$report"
done
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
    "SECURITY_AUDIT.md"
    "TEST_RESULTS.md"
    "$zip_name"
    "$tar_name"
)
for arch in amd64 arm64; do
    for binary in nftfw nftfwd nftfw-web; do
        external_artifacts+=("$binary-linux-$arch")
    done
    external_artifacts+=("nft-firewall-v2_${version}_${arch}.deb")
done
external_checksums="$temporary/external-SHA256SUMS"
(
    cd "$publish_dir"
    printf '%s\0' "${external_artifacts[@]}" | LC_ALL=C sort -z | \
        xargs -0 -r sha256sum > "$external_checksums"
    install -m 0644 "$external_checksums" SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
)
verify_repository_state
if [[ -e "$release_dir" || -L "$release_dir" ]]; then
    echo "Release target appeared during the build; refusing publication: $release_dir" >&2
    exit 1
fi
mv -T -- "$publish_dir" "$release_dir"

zip_final="$release_dir/$zip_name"
tar_final="$release_dir/$tar_name"
echo "Release directory: $release_dir"
echo "Release ZIP: $zip_final"
echo "Release tarball: $tar_final"
sha256sum "$zip_final" "$tar_final"
