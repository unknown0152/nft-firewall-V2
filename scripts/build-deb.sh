#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
version=${1:-}
arch=${2:-}
build_disposition=${NFTFW_BUILD_DISPOSITION:-development}
if (( $# < 1 || $# > 2 )) || [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([~+][A-Za-z0-9.]+)?$ ]]; then
    echo "Usage: build-deb.sh <version> [amd64|arm64]" >&2
    exit 2
fi
if [[ -z "$arch" ]]; then
    case $(uname -m) in
        x86_64) arch=amd64 ;;
        aarch64|arm64) arch=arm64 ;;
        *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
    esac
fi
[[ "$arch" == amd64 || "$arch" == arm64 ]] || { echo "Architecture must be amd64 or arm64" >&2; exit 2; }
case "$build_disposition" in
    development|ci|stage-r-candidate-only|release) ;;
    *)
        echo "NFTFW_BUILD_DISPOSITION must be development, ci, stage-r-candidate-only, or release" >&2
        exit 2
        ;;
esac
target_version=$(sed -n '1p' "$root_dir/RELEASE_VERSION")
[[ "$target_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && \
    $(wc -l < "$root_dir/RELEASE_VERSION") -eq 1 ]] || {
    echo "Tracked release target is malformed" >&2
    exit 1
}
case "$build_disposition" in
    release)
        [[ "$version" == "$target_version" ]] || {
            echo "Release disposition requires the exact tracked release version" >&2
            exit 1
        }
        ;;
    stage-r-candidate-only)
        [[ "$version" =~ ^${target_version//./\.}~stage\.r\.[0-9a-f]{12}$ ]] || {
            echo "Stage R disposition requires target~stage.r.commit12 identity" >&2
            exit 1
        }
        ;;
    development|ci)
        [[ "$version" == "$target_version" || "$version" == "$target_version"+* ]] || {
            echo "Development/CI versions must remain bound to the tracked release target" >&2
            exit 1
        }
        ;;
esac
for command_name in chmod dpkg-deb go grep install jq mktemp mv sed sha256sum strings; do
    command -v "$command_name" >/dev/null || { echo "Missing prerequisite: $command_name" >&2; exit 1; }
done
for binary in nftfw nftfwd nftfw-web; do
    [[ -x "$root_dir/dist/$binary-linux-$arch" ]] || { echo "Missing dist/$binary-linux-$arch" >&2; exit 1; }
done
case $(uname -m) in
    x86_64) native_arch=amd64 ;;
    aarch64|arm64) native_arch=arm64 ;;
    *) echo "Package identity binding requires an amd64 or arm64 build host" >&2; exit 1 ;;
esac
native_nftfw="$root_dir/dist/nftfw-linux-$native_arch"
[[ -x "$native_nftfw" ]] || {
    echo "Missing native nftfw binary required for package identity binding: $native_nftfw" >&2
    exit 1
}
identity_output=$("$native_nftfw" version --json 2>/dev/null) || {
    echo "Cannot extract package candidate identity from $native_nftfw" >&2
    exit 1
}
identity_version=$(jq -er '.version | select(type == "string")' <<< "$identity_output") || {
    echo "Package candidate version identity is malformed" >&2
    exit 1
}
candidate_commit=$(jq -er '.commit | select(type == "string")' <<< "$identity_output") || {
    echo "Package candidate commit identity is malformed" >&2
    exit 1
}
identity_date=$(jq -er '.build_date | select(type == "string")' <<< "$identity_output") || {
    echo "Package candidate build-date identity is malformed" >&2
    exit 1
}
identity_disposition=$(jq -er '.build_disposition | select(type == "string")' <<< "$identity_output") || {
    echo "Package candidate build disposition is malformed" >&2
    exit 1
}
identity_artifact=$(jq -er '.artifact_identity | select(type == "string")' <<< "$identity_output") || {
    echo "Package candidate composite artifact identity is malformed" >&2
    exit 1
}
expected_artifact_identity="$version|$candidate_commit|$identity_date|$build_disposition"
[[ "$identity_version" == "$version" && "$candidate_commit" =~ ^[0-9a-f]{40}$ && \
    "$identity_date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ && \
    "$identity_disposition" == "$build_disposition" && \
    "$identity_artifact" == "$expected_artifact_identity" ]] || {
    echo "Package version/commit/date/disposition does not match the protected build identity" >&2
    exit 1
}
if [[ "$build_disposition" == stage-r-candidate-only && \
    "$version" != "$target_version~stage.r.${candidate_commit:0:12}" ]]; then
    echo "Stage R package version is not bound to the protected commit identity" >&2
    exit 1
fi

module=github.com/unknown0152/nft-firewall-v2
for metadata_arch in amd64 arm64; do
    for metadata_binary in nftfw nftfwd nftfw-web; do
        metadata_path="$root_dir/dist/$metadata_binary-linux-$metadata_arch"
        metadata=$(go version -m "$metadata_path") || {
            echo "Cannot read Go build metadata from $metadata_path" >&2
            exit 1
        }
        grep -Fqx $'\tpath\t'"$module/cmd/$metadata_binary" <<< "$metadata" || {
            echo "Unexpected Go package identity in $metadata_path" >&2
            exit 1
        }
        for setting in $'\tbuild\tCGO_ENABLED=0' $'\tbuild\t-trimpath=true' \
            $'\tbuild\tGOOS=linux' $'\tbuild\tGOARCH='"$metadata_arch"; do
            grep -Fqx "$setting" <<< "$metadata" || {
                echo "Required Go build setting $setting is missing from $metadata_path" >&2
                exit 1
            }
        done
        if grep -Fq $'\tbuild\tvcs=' <<< "$metadata"; then
            echo "Unexpected ambient VCS metadata in $metadata_path" >&2
            exit 1
        fi
        # Go deliberately redacts -ldflags from `go version -m` output when
        # -trimpath is enabled. Bind its structural metadata above, then
        # require one unique composite -X identity in every cross binary.
        strings -n 2 "$metadata_path" | grep -Fx -- "$expected_artifact_identity" >/dev/null || {
            echo "Composite artifact identity is missing from $metadata_path" >&2
            exit 1
        }
    done
done

stage=$(mktemp -d /tmp/nftfw-deb.XXXXXX)
chmod 0755 "$stage"
output_stage=""
cleanup() {
    rm -rf -- "$stage"
    [[ -z "$output_stage" ]] || rm -rf -- "$output_stage"
}
trap cleanup EXIT
install -d "$stage/DEBIAN" "$stage/usr/lib/nftfw" "$stage/usr/sbin" \
    "$stage/usr/lib/systemd/system" "$stage/usr/share/doc/nft-firewall-v2" "$stage/etc/nftfw"
sed -e "s/@VERSION@/$version/g" -e "s/@ARCH@/$arch/g" \
    -e "s/@BUILD_DISPOSITION@/$build_disposition/g" \
    "$root_dir/packaging/deb/control" > "$stage/DEBIAN/control"
chmod 0644 "$stage/DEBIAN/control"
install -m 0644 "$root_dir/packaging/deb/conffiles" "$stage/DEBIAN/conffiles"
sed -e "s/@VERSION@/$version/g" -e "s/@COMMIT@/$candidate_commit/g" \
    -e "s/@BUILD_DISPOSITION@/$build_disposition/g" \
    "$root_dir/packaging/deb/preinst" > "$stage/DEBIAN/preinst"
chmod 0755 "$stage/DEBIAN/preinst"
for script in postinst prerm postrm; do
    install -m 0755 "$root_dir/packaging/deb/$script" "$stage/DEBIAN/$script"
done
for binary in nftfw nftfwd nftfw-web; do
    install -m 0755 "$root_dir/dist/$binary-linux-$arch" "$stage/usr/lib/nftfw/$binary"
done
ln -s ../lib/nftfw/nftfw "$stage/usr/sbin/nftfw"
systemd_units=(
    nftfw-early.service
    nftfw-enforcement-ready.service
    nftfw-rollback.service
    nftfw-rollback.timer
    nftfw-setup-rollback.service
    nftfw-setup-rollback.timer
    nftfw-managed-rollback.service
    nftfw-managed-rollback.timer
    nftfw-vpn.service
    nftfw-web.service
    nftfwd.service
)
for unit in "${systemd_units[@]}"; do
    install -m 0644 "$root_dir/packaging/systemd/$unit" "$stage/usr/lib/systemd/system/$unit"
done
install -d "$stage/usr/share/doc/nft-firewall-v2/examples"
for example in nftfwd-docker-access.conf.example nftfwd-final-early.conf.example \
    nftfw-rollback-final-early.conf.example nftfw-consumer-final-ready.conf.example; do
    install -m 0644 "$root_dir/packaging/systemd/$example" \
        "$stage/usr/share/doc/nft-firewall-v2/examples/$example"
done
install -m 0640 "$root_dir/configs/nftfw.example.toml" "$stage/etc/nftfw/nftfw.toml"
for document in README.md QUICKSTART.md START-HERE.md INSTALL.md SECURITY.md \
    SUPPORTED-PLATFORMS.md VPN-PROFILES.md CHANGELOG.md; do
    install -m 0644 "$root_dir/$document" "$stage/usr/share/doc/nft-firewall-v2/$document"
done
install -m 0644 "$root_dir/LICENSE" "$stage/usr/share/doc/nft-firewall-v2/LICENSE"
install -m 0644 "$root_dir/packaging/deb/copyright" "$stage/usr/share/doc/nft-firewall-v2/copyright"
for document in ARCHITECTURE.md CLI.md CONFIGURATION.md DOCKER.md OPERATIONS.md \
    RECOVERY.md STATUS-API.md THREAT-MODEL.md TROUBLESHOOTING.md UPGRADING.md \
    UNINSTALL.md; do
    install -m 0644 "$root_dir/docs/$document" "$stage/usr/share/doc/nft-firewall-v2/$document"
done

output="$root_dir/dist/nft-firewall-v2_${version}_${arch}.deb"
output_stage=$(mktemp -d "$root_dir/dist/.nftfw-deb-output.XXXXXX")
output_tmp="$output_stage/package.deb"
dpkg-deb --root-owner-group --build "$stage" "$output_tmp" >/dev/null
dpkg-deb --info "$output_tmp" >/dev/null
dpkg-deb --contents "$output_tmp" >/dev/null
[[ $(dpkg-deb -f "$output_tmp" Package) == nft-firewall-v2 ]] || { echo "Package name verification failed" >&2; exit 1; }
[[ $(dpkg-deb -f "$output_tmp" Version) == "$version" ]] || { echo "Package version verification failed" >&2; exit 1; }
[[ $(dpkg-deb -f "$output_tmp" Architecture) == "$arch" ]] || { echo "Package architecture verification failed" >&2; exit 1; }
[[ $(dpkg-deb -f "$output_tmp" X-NFTFW-Build-Disposition) == "$build_disposition" ]] || { echo "Package build-disposition verification failed" >&2; exit 1; }
payload_verify="$output_stage/payload"
install -d "$payload_verify"
dpkg-deb -x "$output_tmp" "$payload_verify"
for binary in nftfw nftfwd nftfw-web; do
    standalone_hash=$(sha256sum "$root_dir/dist/$binary-linux-$arch")
    standalone_hash=${standalone_hash%% *}
    payload_hash=$(sha256sum "$payload_verify/usr/lib/nftfw/$binary")
    payload_hash=${payload_hash%% *}
    [[ "$payload_hash" == "$standalone_hash" ]] || {
        echo "Package payload hash differs from standalone $binary-linux-$arch" >&2
        exit 1
    }
done
mv -f -- "$output_tmp" "$output"
echo "$output"
