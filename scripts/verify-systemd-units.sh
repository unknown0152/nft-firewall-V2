#!/usr/bin/env bash
set -Eeuo pipefail

if (( $# != 2 )); then
    echo "Usage: verify-systemd-units.sh <source-root> <amd64|arm64>" >&2
    exit 2
fi

root_dir=$(cd "$1" && pwd -P)
arch=$2
case "$arch" in
    amd64|arm64) ;;
    *) echo "Unsupported architecture: $arch" >&2; exit 2 ;;
esac

for command_name in find grep install mktemp sed systemd-analyze; do
    command -v "$command_name" >/dev/null || {
        echo "Missing prerequisite: $command_name" >&2
        exit 1
    }
done
for binary in nftfw nftfwd nftfw-web; do
    [[ -x "$root_dir/dist/$binary-linux-$arch" ]] || {
        echo "Missing executable: $root_dir/dist/$binary-linux-$arch" >&2
        exit 1
    }
done

validation_dir=$(mktemp -d /tmp/nftfw-systemd-verify.XXXXXX)
cleanup() {
    find "$validation_dir" -depth -delete
}
trap cleanup EXIT
install -d -m 0700 "$validation_dir/bin" "$validation_dir/units"
install -m 0755 "$root_dir/dist/nftfw-linux-$arch" "$validation_dir/bin/nftfw"
install -m 0755 "$root_dir/dist/nftfwd-linux-$arch" "$validation_dir/bin/nftfwd"
install -m 0755 "$root_dir/dist/nftfw-web-linux-$arch" "$validation_dir/bin/nftfw-web"

for unit in "$root_dir"/packaging/systemd/*.service "$root_dir"/packaging/systemd/*.timer; do
    name=${unit##*/}
    sed \
        -e "s#/usr/lib/nftfw/nftfw-web#$validation_dir/bin/nftfw-web#g" \
        -e "s#/usr/lib/nftfw/nftfwd#$validation_dir/bin/nftfwd#g" \
        -e "s#/usr/lib/nftfw/nftfw#$validation_dir/bin/nftfw#g" \
        "$unit" > "$validation_dir/units/$name"
done

if grep -R -E '^Exec(Start|StartPre|StartPost|Stop|StopPost|Reload)=/usr/lib/nftfw/' \
    "$validation_dir/units" >/dev/null; then
    echo "A staged unit still references an unstaged NFT Firewall executable" >&2
    exit 1
fi
systemd-analyze verify \
    "$validation_dir"/units/*.service \
    "$validation_dir"/units/*.timer
