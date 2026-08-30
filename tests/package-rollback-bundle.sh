#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
[[ ${EUID:-$(id -u)} -eq 0 ]] || {
    echo "SKIP: package rollback bundle regression requires root"
    exit 77
}
temporary=$(mktemp -d /tmp/nftfw-package-rollback-test.XXXXXX)
cleanup() {
    rm -rf -- "$temporary"
}
trap cleanup EXIT

architecture=$(dpkg --print-architecture)
case "$architecture" in amd64|arm64) ;; *) echo "SKIP: unsupported architecture"; exit 77 ;; esac
helper=$temporary/package-rollback
install -o root -g root -m 0755 "$root_dir/scripts/package-rollback.sh" "$helper"

make_package() {
    local version=$1 destination=$2 root
    root=$temporary/root-$version
    install -d -o root -g root -m 0755 "$root/DEBIAN" "$root/usr/lib/nftfw" "$root/etc/nftfw"
    cat >"$root/DEBIAN/control" <<EOF
Package: nft-firewall-v2
Version: $version
Architecture: $architecture
Maintainer: test <test@example.invalid>
X-NFTFW-Build-Disposition: release
Description: disposable rollback test package
EOF
    printf '/etc/nftfw/nftfw.toml\n' >"$root/DEBIAN/conffiles"
    printf 'fixture %s\n' "$version" >"$root/usr/lib/nftfw/nftfw"
    chmod 0755 "$root/usr/lib/nftfw/nftfw"
    printf 'fixture config\n' >"$root/etc/nftfw/nftfw.toml"
    chmod 0640 "$root/etc/nftfw/nftfw.toml"
    for script in preinst postinst prerm postrm; do
        printf '#!/bin/sh\nexit 0\n' >"$root/DEBIAN/$script"
        chmod 0755 "$root/DEBIAN/$script"
    done
    if [[ $version == 2.1.0 ]]; then
        install -o root -g root -m 0755 "$helper" "$root/usr/lib/nftfw/package-rollback"
    fi
    dpkg-deb --root-owner-group --build "$root" "$destination" >/dev/null
    chmod 0600 "$destination"
}

old=$temporary/old.deb
new=$temporary/new.deb
bundle=$temporary/bundle
make_package 2.0.3 "$old"
make_package 2.1.0 "$new"
old_sha=$(sha256sum "$old" | awk '{print $1}')
new_sha=$(sha256sum "$new" | awk '{print $1}')
before=$(dpkg-query -W -f='${db:Status-Abbrev} ${Version}' nft-firewall-v2 2>/dev/null || true)

unsafe_parent=$temporary/unsafe-parent
install -d -o root -g root -m 0777 "$unsafe_parent"
install -o root -g root -m 0600 "$old" "$unsafe_parent/old.deb"
if "$helper" prepare --old-package "$unsafe_parent/old.deb" --new-package "$new" \
    --old-sha256 "$old_sha" --new-sha256 "$new_sha" \
    --bundle "$temporary/unsafe-bundle" >/dev/null 2>&1; then
    echo "FAIL: package beneath an unsafe parent was accepted"
    exit 1
fi

"$helper" prepare --old-package "$old" --new-package "$new" \
    --old-sha256 "$old_sha" --new-sha256 "$new_sha" --bundle "$bundle" >/dev/null
"$bundle/execute" verify --bundle "$bundle" >/dev/null
after=$(dpkg-query -W -f='${db:Status-Abbrev} ${Version}' nft-firewall-v2 2>/dev/null || true)
[[ $before == "$after" ]]
[[ $(stat -c '%a:%u:%g' "$bundle") == 700:0:0 ]]
[[ $(dpkg-deb -f "$bundle/bridge.deb" Version) == 2.0.3~nftfwrollback1.* ]]

old_root=$temporary/old-payload
bridge_root=$temporary/bridge-payload
install -d -o root -g root -m 0700 "$old_root" "$bridge_root"
dpkg-deb -x "$old" "$old_root"
dpkg-deb -x "$bundle/bridge.deb" "$bridge_root"
diff -ruN "$old_root" "$bridge_root" >/dev/null

cp "$bundle/manifest" "$temporary/manifest.backup"
printf 'unexpected=value\n' >>"$bundle/manifest"
if "$bundle/execute" verify --bundle "$bundle" >/dev/null 2>&1; then
    echo "FAIL: extended rollback manifest was accepted"
    exit 1
fi
install -o root -g root -m 0600 "$temporary/manifest.backup" "$bundle/manifest"
printf 'tamper\n' >>"$bundle/bridge.deb"
if "$bundle/execute" verify --bundle "$bundle" >/dev/null 2>&1; then
    echo "FAIL: tampered rollback bridge was accepted"
    exit 1
fi

echo "PACKAGE_ROLLBACK_BUNDLE_PASS"
