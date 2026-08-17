#!/usr/bin/env bash
set -Eeuo pipefail

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
version=${1:-}
allow_untagged=${2:-}
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([~+][A-Za-z0-9.]+)?$ ]] || \
    [[ -n "$allow_untagged" && "$allow_untagged" != --allow-untagged ]] || (( $# > 2 )); then
    echo "Usage: package-release.sh <version> [--allow-untagged]" >&2
    exit 2
fi

for command_name in cp date find git go gzip install jq make mktemp sed sha256sum sort tar touch unzip xargs zip; do
    command -v "$command_name" >/dev/null || { echo "Missing prerequisite: $command_name" >&2; exit 1; }
done

cd "$root_dir"
if [[ -n $(git status --porcelain --untracked-files=normal) ]]; then
    echo "Release packaging requires a clean Git working tree" >&2
    exit 1
fi
commit=$(git rev-parse HEAD)
source_date_epoch=$(git show -s --format=%ct HEAD)
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
release_dir="$work_root/releases"
install -d -m 0755 "$release_dir"
temporary=$(mktemp -d "$release_dir/.nftfw-release-$version.XXXXXX")
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT
stage="$temporary/stage"
release_root="$stage/nft-firewall-v2"
install -d "$release_root/source" "$release_root/binaries/linux-amd64" \
    "$release_root/binaries/linux-arm64" "$release_root/packages"

export SOURCE_DATE_EPOCH="$source_date_epoch"
make clean
make release VERSION="$version" COMMIT="$commit" BUILD_DATE="$build_date"
./scripts/build-deb.sh "$version" amd64
./scripts/build-deb.sh "$version" arm64

git archive --format=tar HEAD | tar -xf - -C "$release_root/source"
for arch in amd64 arm64; do
    for binary in nftfw nftfwd nftfw-web; do
        install -m 0755 "dist/$binary-linux-$arch" "$release_root/binaries/linux-$arch/$binary"
    done
    install -m 0644 "dist/nft-firewall-v2_${version}_${arch}.deb" "$release_root/packages/"
done
cp -a "$release_root/source/packaging" "$release_root/packaging"
cp -a "$release_root/source/configs" "$release_root/configs"
cp -a "$release_root/source/docs" "$release_root/docs"
cp -a "$release_root/source/tests" "$release_root/tests"
for document in README.md START-HERE.md INSTALL.md SECURITY.md LICENSE \
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

mapfile -d '' release_debris < <(find "$release_root" \
    \( -type d \( -name .git -o -name __pycache__ -o -name .pytest_cache -o -name .mypy_cache -o -name .cache \) \) -o \
    \( -type f \( -name '*.pyc' -o -name '*.pyo' -o -name '.DS_Store' -o -name '*~' -o \
        -name '*.swp' -o -name '*.tmp' -o -name '*.log' -o -name '*.db' -o -name '*.db-wal' -o \
        -name '*.db-shm' -o -name 'wg-test.conf' \) \) -o -type l \) -print0)
if (( ${#release_debris[@]} > 0 )); then
    echo "Release tree contains forbidden cache, runtime, secret, or symlink entries:" >&2
    printf '  %s\n' "${release_debris[@]}" >&2
    exit 1
fi

(
    cd "$release_root"
    find source -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum > SOURCE_MANIFEST.sha256
)
go run ./scripts/release-manifest.go \
    --root "$release_root" \
    --version "$version" \
    --commit "$commit" \
    --tag "$tag" \
    --build-date "$build_date" \
    --source-date-epoch "$source_date_epoch" \
    --output "$release_root/RELEASE_MANIFEST.json"
internal_checksums="$temporary/internal-SHA256SUMS"
(
    cd "$release_root"
    find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | \
        xargs -0 -r sha256sum | sed 's#  \./#  #' > "$internal_checksums"
)
install -m 0644 "$internal_checksums" "$release_root/SHA256SUMS"
find "$release_root" -print0 | xargs -0 -r touch -h -d "@$source_date_epoch"

zip_tmp="$temporary/nft-firewall-v2-$version.zip"
tar_tmp="$temporary/nft-firewall-v2-$version.tar.gz"
(
    cd "$stage"
    find nft-firewall-v2 -type f -print | LC_ALL=C sort | zip -X -q "$zip_tmp" -@
    tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner \
        --format=posix --pax-option=delete=atime,delete=ctime -cf - nft-firewall-v2 | gzip -n > "$tar_tmp"
)
unzip -tq "$zip_tmp" >/dev/null
tar -tzf "$tar_tmp" >/dev/null

zip_final="$release_dir/nft-firewall-v2-$version.zip"
tar_final="$release_dir/nft-firewall-v2-$version.tar.gz"
install -m 0644 "$zip_tmp" "$zip_final"
install -m 0644 "$tar_tmp" "$tar_final"
for arch in amd64 arm64; do
    for binary in nftfw nftfwd nftfw-web; do
        install -m 0755 "dist/$binary-linux-$arch" "$release_dir/$binary-linux-$arch"
    done
    install -m 0644 "dist/nft-firewall-v2_${version}_${arch}.deb" "$release_dir/"
done
for report in SECURITY_AUDIT.md TEST_RESULTS.md; do
    install -m 0644 "$report" "$release_dir/$report"
done
{
    cat "$release_root/FINAL_ACCEPTANCE_REPORT.md"
    echo
    echo "## Enclosing release artifacts"
    echo
    echo "The enclosing archive cannot contain its own checksum. These exact checksums are added to the external acceptance report after archive creation."
    echo
    (cd "$release_dir" && sha256sum "$(basename "$zip_final")" "$(basename "$tar_final")")
} > "$temporary/FINAL_ACCEPTANCE_REPORT.md"
install -m 0644 "$temporary/FINAL_ACCEPTANCE_REPORT.md" "$release_dir/FINAL_ACCEPTANCE_REPORT.md"

external_checksums="$temporary/external-SHA256SUMS"
(
    cd "$release_dir"
    find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | \
        xargs -0 -r sha256sum | sed 's#  \./#  #' > "$external_checksums"
    install -m 0644 "$external_checksums" SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
)
jq -e --arg version "$version" --arg commit "$commit" \
    '.version == $version and .git_commit == $commit and (.files | length > 0) and (.artifacts | length == 8)' \
    "$release_root/RELEASE_MANIFEST.json" >/dev/null

echo "Release ZIP: $zip_final"
echo "Source archive: $tar_final"
sha256sum "$zip_final" "$tar_final"
