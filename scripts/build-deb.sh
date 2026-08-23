#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
version=${1:-2.0.1}
arch=${2:-}
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([~+][A-Za-z0-9.]+)?$ ]]; then
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
for command_name in chmod dpkg-deb install mktemp mv sed; do
    command -v "$command_name" >/dev/null || { echo "Missing prerequisite: $command_name" >&2; exit 1; }
done
for binary in nftfw nftfwd nftfw-web; do
    [[ -x "$root_dir/dist/$binary-linux-$arch" ]] || { echo "Missing dist/$binary-linux-$arch" >&2; exit 1; }
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
sed -e "s/@VERSION@/$version/g" -e "s/@ARCH@/$arch/g" "$root_dir/packaging/deb/control" > "$stage/DEBIAN/control"
chmod 0644 "$stage/DEBIAN/control"
install -m 0644 "$root_dir/packaging/deb/conffiles" "$stage/DEBIAN/conffiles"
for script in preinst postinst prerm postrm; do
    install -m 0755 "$root_dir/packaging/deb/$script" "$stage/DEBIAN/$script"
done
for binary in nftfw nftfwd nftfw-web; do
    install -m 0755 "$root_dir/dist/$binary-linux-$arch" "$stage/usr/lib/nftfw/$binary"
done
ln -s ../lib/nftfw/nftfw "$stage/usr/sbin/nftfw"
install -m 0644 "$root_dir"/packaging/systemd/*.{service,timer} "$stage/usr/lib/systemd/system/"
install -d "$stage/usr/share/doc/nft-firewall-v2/examples"
install -m 0644 "$root_dir/packaging/systemd/nftfwd-docker-access.conf.example" \
    "$stage/usr/share/doc/nft-firewall-v2/examples/"
install -m 0640 "$root_dir/configs/nftfw.example.toml" "$stage/etc/nftfw/nftfw.toml"
for document in README.md START-HERE.md INSTALL.md SECURITY.md CHANGELOG.md; do
    install -m 0644 "$root_dir/$document" "$stage/usr/share/doc/nft-firewall-v2/$document"
done
install -m 0644 "$root_dir/LICENSE" "$stage/usr/share/doc/nft-firewall-v2/LICENSE"
install -m 0644 "$root_dir/packaging/deb/copyright" "$stage/usr/share/doc/nft-firewall-v2/copyright"
for document in ARCHITECTURE.md CONFIGURATION.md OPERATIONS.md RECOVERY.md STATUS-API.md THREAT-MODEL.md UPGRADING.md UNINSTALL.md; do
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
mv -f -- "$output_tmp" "$output"
echo "$output"
