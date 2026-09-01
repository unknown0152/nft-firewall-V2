#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
[[ ${EUID:-$(id -u)} -eq 0 ]] || {
    echo "SKIP: package rollback bundle regression requires root"
    exit 77
}
for tool in busybox chroot dpkg-deb ldd; do
    command -v "$tool" >/dev/null || {
        echo "SKIP: missing package rollback bundle prerequisite"
        exit 77
    }
done
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

linked_old=$temporary/linked-old.deb
ln "$old" "$linked_old"
if "$helper" prepare --old-package "$linked_old" --new-package "$new" \
    --old-sha256 "$old_sha" --new-sha256 "$new_sha" \
    --bundle "$temporary/linked-bundle" >/dev/null 2>&1; then
    echo "FAIL: hard-linked package input was accepted"
    exit 1
fi
rm -f "$linked_old"

"$helper" prepare --old-package "$old" --new-package "$new" \
    --old-sha256 "$old_sha" --new-sha256 "$new_sha" --bundle "$bundle" >/dev/null
"$bundle/execute" verify --bundle "$bundle" >/dev/null
after=$(dpkg-query -W -f='${db:Status-Abbrev} ${Version}' nft-firewall-v2 2>/dev/null || true)
[[ $before == "$after" ]]
[[ $(stat -c '%a:%u:%g' "$bundle") == 700:0:0 ]]
[[ $(dpkg-deb -f "$bundle/bridge.deb" Version) == 2.0.3~nftfwrollback1.* ]]
transition_sha=$(sed -n 's/^transition_sha256=//p' "$bundle/manifest")
[[ $transition_sha =~ ^[0-9a-f]{64}$ ]]
[[ $(dpkg-deb -f "$bundle/bridge.deb" X-NFTFW-Rollback-Transition) == "$transition_sha" ]]

old_root=$temporary/old-payload
bridge_root=$temporary/bridge-payload
install -d -o root -g root -m 0700 "$old_root" "$bridge_root"
dpkg-deb -x "$old" "$old_root"
dpkg-deb -x "$bundle/bridge.deb" "$bridge_root"
diff -ruN "$old_root" "$bridge_root" >/dev/null

control_root=$temporary/bridge-control
dpkg-deb -e "$bundle/bridge.deb" "$control_root"
bridge_version=$(sed -n 's/^bridge_version=//p' "$bundle/manifest")
new_binary_sha=$(sed -n 's/^new_binary_sha256=//p' "$bundle/manifest")
transition_root=$temporary/transition-root
install -d -o root -g root -m 0755 \
    "$transition_root/bin" "$transition_root/test/bin" \
    "$transition_root/usr" "$transition_root/usr/lib" "$transition_root/usr/lib/nftfw" \
    "$transition_root/var" "$transition_root/var/lib"
install -d -o root -g root -m 0700 \
    "$transition_root/var/lib/nftfw" "$transition_root/var/lib/nftfw/generation-state"
busybox=$(command -v busybox)
install -o root -g root -m 0755 "$busybox" "$transition_root/bin/busybox"
while IFS= read -r library; do
    [[ -f $library ]]
    install -D -o root -g root -m 0755 "$library" "$transition_root$library"
done < <(ldd "$busybox" | awk '{ for (field = 1; field <= NF; field++) if ($field ~ /^\//) print $field }' | sort -u)
for applet in awk cat sha256sum sh stat; do
    ln -s busybox "$transition_root/bin/$applet"
done
install -o root -g root -m 0755 "$control_root/preinst" "$transition_root/preinst"
dpkg-deb -x "$new" "$temporary/new-payload"
install -o root -g root -m 0755 "$temporary/new-payload/usr/lib/nftfw/nftfw" \
    "$transition_root/test/new-binary"
install -o root -g root -m 0755 "$transition_root/test/new-binary" \
    "$transition_root/usr/lib/nftfw/nftfw"
[[ $(sha256sum "$transition_root/usr/lib/nftfw/nftfw" | awk '{print $1}') == "$new_binary_sha" ]]
printf 'fixture database\n' >"$transition_root/var/lib/nftfw/generation-state/state.db"
chmod 0600 "$transition_root/var/lib/nftfw/generation-state/state.db"
printf '%s\n' "$architecture" >"$transition_root/test/architecture"
printf 'iHR 2.1.0\n' >"$transition_root/test/status"
printf '1,2,3,4,5,6\n' >"$transition_root/test/history"
printf '106\n' >"$transition_root/test/state-gid"
chown root:106 "$transition_root/var/lib/nftfw/generation-state/state.db"

cat >"$transition_root/test/bin/dpkg" <<'EOF'
#!/bin/sh
[ "$#" -eq 1 ] && [ "$1" = --print-architecture ] || exit 1
cat /test/architecture
EOF
cat >"$transition_root/test/bin/dpkg-query" <<'EOF'
#!/bin/sh
[ "$#" -eq 3 ] && [ "$1" = -W ] && \
    [ "$2" = '-f=${db:Status-Abbrev} ${Version}' ] && \
    [ "$3" = nft-firewall-v2 ] || exit 1
cat /test/status
EOF
cat >"$transition_root/test/bin/sqlite3" <<'EOF'
#!/bin/sh
[ "$#" -eq 4 ] && [ "$1" = -batch ] && [ "$2" = -noheader ] && \
    [ "$3" = 'file:/var/lib/nftfw/generation-state/state.db?mode=ro&immutable=1' ] && \
    [ "$4" = "SELECT group_concat(version, ',') FROM (SELECT version FROM schema_migrations ORDER BY version);" ] || exit 1
cat /test/history
EOF
cat >"$transition_root/test/bin/id" <<'EOF'
#!/bin/sh
[ "$#" -eq 2 ] && [ "$1" = -g ] && [ "$2" = nftfw-web ] || exit 1
cat /test/state-gid
EOF
chmod 0755 "$transition_root/test/bin/dpkg" "$transition_root/test/bin/dpkg-query" \
    "$transition_root/test/bin/id" "$transition_root/test/bin/sqlite3"

run_preinst() {
    chroot "$transition_root" /bin/sh -c 'PATH=/test/bin:/bin; export PATH; exec /preinst "$@"' preinst "$@"
}

expect_refusal() {
    local name=$1
    shift
    if run_preinst "$@" >/dev/null 2>&1; then
        echo "FAIL: bridge preinst accepted $name"
        exit 1
    fi
}

# Exact Debian 13 downgrade boundary observed by the disposable dpkg probe.
run_preinst upgrade 2.1.0 "$bridge_version"
chown root:root "$transition_root/var/lib/nftfw/generation-state/state.db"
run_preinst upgrade 2.1.0 "$bridge_version"
chown root:106 "$transition_root/var/lib/nftfw/generation-state/state.db"
mv "$transition_root/var/lib/nftfw/generation-state/state.db" \
    "$transition_root/test/database.absent"
run_preinst upgrade 2.1.0 "$bridge_version"
mv "$transition_root/test/database.absent" \
    "$transition_root/var/lib/nftfw/generation-state/state.db"
expect_refusal 'missing arguments'
expect_refusal 'missing bridge version' upgrade 2.1.0
expect_refusal 'extra argument' upgrade 2.1.0 "$bridge_version" unexpected
expect_refusal 'reordered arguments' 2.1.0 upgrade "$bridge_version"
expect_refusal 'unsupported action' install 2.1.0 "$bridge_version"
expect_refusal 'wrong previous version' upgrade 2.0.3 "$bridge_version"
expect_refusal 'wrong generated bridge version' upgrade 2.1.0 2.0.3

printf 'ii  2.1.0\n' >"$transition_root/test/status"
expect_refusal 'configured package state' upgrade 2.1.0 "$bridge_version"
for refused_status in \
    'iU  2.1.0' 'iF  2.1.0' 'iH  2.1.0' \
    'iHR 2.0.3' 'iHR 2.1.0 unexpected' ''; do
    printf '%s\n' "$refused_status" >"$transition_root/test/status"
    expect_refusal "package state [$refused_status]" upgrade 2.1.0 "$bridge_version"
done
printf 'iHR 2.1.0\nunexpected\n' >"$transition_root/test/status"
expect_refusal 'ambiguous multi-line package state' upgrade 2.1.0 "$bridge_version"
printf 'iHR 2.1.0\n' >"$transition_root/test/status"

printf 'arm64\n' >"$transition_root/test/architecture"
expect_refusal 'architecture mismatch' upgrade 2.1.0 "$bridge_version"
printf '%s\n' "$architecture" >"$transition_root/test/architecture"

printf '0,1,2,3,4,5,6\n' >"$transition_root/test/history"
expect_refusal 'schema-history mismatch' upgrade 2.1.0 "$bridge_version"
printf '1,2,3,4,5,6\n' >"$transition_root/test/history"

binary=$transition_root/usr/lib/nftfw/nftfw
database=$transition_root/var/lib/nftfw/generation-state/state.db
printf 'tamper\n' >>"$binary"
expect_refusal 'binary checksum mismatch' upgrade 2.1.0 "$bridge_version"
install -o root -g root -m 0755 "$transition_root/test/new-binary" "$binary"
chmod 0775 "$binary"
expect_refusal 'binary permission mismatch' upgrade 2.1.0 "$bridge_version"
chmod 0755 "$binary"
chown 65534:65534 "$binary"
expect_refusal 'binary ownership mismatch' upgrade 2.1.0 "$bridge_version"
chown root:root "$binary"
ln "$binary" "$transition_root/test/binary-hardlink"
expect_refusal 'hard-linked binary' upgrade 2.1.0 "$bridge_version"
rm -f "$transition_root/test/binary-hardlink"
rm -f "$binary"
ln -s /test/new-binary "$binary"
expect_refusal 'symlinked binary' upgrade 2.1.0 "$bridge_version"
rm -f "$binary"
install -o root -g root -m 0755 "$transition_root/test/new-binary" "$binary"

chmod 0620 "$database"
expect_refusal 'database permission mismatch' upgrade 2.1.0 "$bridge_version"
chmod 0600 "$database"
chown 65534:65534 "$database"
expect_refusal 'database ownership mismatch' upgrade 2.1.0 "$bridge_version"
chown root:106 "$database"
printf '0\n' >"$transition_root/test/state-gid"
expect_refusal 'root runtime group' upgrade 2.1.0 "$bridge_version"
printf 'unexpected\n' >"$transition_root/test/state-gid"
expect_refusal 'malformed runtime group' upgrade 2.1.0 "$bridge_version"
printf '106\n' >"$transition_root/test/state-gid"
chown root:65534 "$database"
expect_refusal 'unrecognized database group' upgrade 2.1.0 "$bridge_version"
chown root:106 "$database"
ln "$database" "$transition_root/test/database-hardlink"
expect_refusal 'hard-linked database' upgrade 2.1.0 "$bridge_version"
rm -f "$transition_root/test/database-hardlink"
rm -f "$database"
ln -s /test/history "$database"
expect_refusal 'symlinked database' upgrade 2.1.0 "$bridge_version"
rm -f "$database"
printf 'fixture database\n' >"$database"
chmod 0600 "$database"
chown root:106 "$database"
chmod 0770 "$transition_root/var/lib/nftfw/generation-state"
expect_refusal 'writable database parent' upgrade 2.1.0 "$bridge_version"
chmod 0700 "$transition_root/var/lib/nftfw/generation-state"

cp "$transition_root/preinst" "$transition_root/test/preinst.backup"
sed -i 's/^old_sha256=.*/old_sha256=0000000000000000000000000000000000000000000000000000000000000000/' \
    "$transition_root/preinst"
expect_refusal 'transition identity mismatch' upgrade 2.1.0 "$bridge_version"
install -o root -g root -m 0755 "$transition_root/test/preinst.backup" "$transition_root/preinst"
run_preinst upgrade 2.1.0 "$bridge_version"

linked_bundle_file=$bundle/old.deb.link
ln "$bundle/old.deb" "$linked_bundle_file"
if "$bundle/execute" verify --bundle "$bundle" >/dev/null 2>&1; then
    echo "FAIL: hard-linked rollback bundle member was accepted"
    exit 1
fi
rm -f "$linked_bundle_file"

cp "$bundle/manifest" "$temporary/manifest.backup"
sed -i 's/^transition_sha256=.*/transition_sha256=0000000000000000000000000000000000000000000000000000000000000000/' \
    "$bundle/manifest"
if "$bundle/execute" verify --bundle "$bundle" >/dev/null 2>&1; then
    echo "FAIL: mismatched transition identity was accepted"
    exit 1
fi
install -o root -g root -m 0600 "$temporary/manifest.backup" "$bundle/manifest"
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
