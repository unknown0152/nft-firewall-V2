#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

readonly package=${1:?private release package required}
readonly manager=/usr/lib/nftfw/initramfs/nftfw-initramfs-manage
readonly marker=/etc/nftfw/initramfs-managed-disabled-v1
readonly owner=/etc/nftfw/initramfs-source-owner-v1
readonly source_root=/etc/initramfs-tools/scripts/init-top
readonly source_loader=$source_root/nftfw-ipv6-early
readonly source_gate=$source_root/udev
readonly installed_loader=/usr/lib/nftfw/initramfs/nftfw-ipv6-early
readonly installed_gate=/usr/lib/nftfw/initramfs/nftfw-udev-gate
readonly vendor_udev=/usr/share/initramfs-tools/scripts/init-top/udev
image=/boot/initrd.img-$(uname -r)
readonly image

[[ ${EUID:-$(id -u)} -eq 0 ]] || {
    echo "BLOCKED: disposable initramfs test requires guest root"
    exit 77
}
for tool in awk cmp dpkg dpkg-query find grep lsinitramfs sha256sum stat \
    unmkinitramfs update-initramfs; do
    command -v "$tool" >/dev/null || {
        echo "BLOCKED: missing disposable initramfs prerequisite: $tool"
        exit 77
    }
done
[[ -f $package && ! -L $package && -f $image && ! -L $image ]] || {
    echo "BLOCKED: package or current initramfs is absent or unsafe"
    exit 77
}
[[ -f $vendor_udev && ! -L $vendor_udev && -x $vendor_udev ]] || {
    echo "BLOCKED: Debian vendor udev init-top source is absent or unsafe"
    exit 77
}
[[ ! -e $source_loader && ! -L $source_loader &&
    ! -e $source_gate && ! -L $source_gate ]] || {
    echo "BLOCKED: disposable guest does not have a clean native source directory"
    exit 77
}

temporary=$(mktemp -d /tmp/nftfw-initramfs-disposable.XXXXXX)
readonly temporary
package_installed=0

cleanup() {
    set +e
    if [[ -e $source_gate && ! -L $source_gate ]]; then
        chmod 0755 "$source_gate"
    fi
    if [[ -x $manager ]]; then
        "$manager" disable >/dev/null 2>&1 || true
    fi
    if ((package_installed == 1)); then
        dpkg --purge nft-firewall-v2 >/dev/null 2>&1 || true
    fi
    if [[ $temporary == /tmp/nftfw-initramfs-disposable.* ]]; then
        find "$temporary" -depth -delete
    fi
}
trap cleanup EXIT

digest() {
    sha256sum "$1" | awk '{print $1}'
}

one_path() {
    local root=$1 suffix=$2
    local -a matches=()
    mapfile -d '' -t matches < <(find "$root" -type f -path "*/$suffix" -print0)
    [[ ${#matches[@]} -eq 1 ]] || return 1
    printf '%s\n' "${matches[0]}"
}

extract_image() {
    local destination=$1
    install -d -o root -g root -m 0700 "$destination"
    unmkinitramfs "$image" "$destination" >/dev/null
}

assert_native_order() {
    local order=$1
    awk -v loader='/scripts/init-top/nftfw-ipv6-early "$@"' \
        -v refresh='[ -e /conf/param.conf ] && . /conf/param.conf' \
        -v gate='/scripts/init-top/udev "$@"' '
        { line[NR]=$0 }
        index($0, "/scripts/init-top/nftfw-ipv6-early") { loader_mentions++ }
        index($0, "/scripts/init-top/nftfw-udev-vendor") { vendor_mentions++ }
        index($0, "/scripts/init-top/udev") { gate_mentions++ }
        $0 == loader { loader_exact++; loader_line=NR }
        $0 == gate { gate_exact++; gate_line=NR }
        END {
            exit !(loader_mentions == 1 && loader_exact == 1 &&
                vendor_mentions == 0 && gate_mentions == 1 && gate_exact == 1 &&
                line[loader_line + 1] == refresh && gate_line == loader_line + 2 &&
                line[gate_line + 1] == refresh)
        }
    ' "$order"
}

assert_enabled_image() {
    local root
    local loader gate vendor order
    root=$(mktemp -d "$temporary/enabled.XXXXXX")
    extract_image "$root"
    loader=$(one_path "$root" scripts/init-top/nftfw-ipv6-early)
    gate=$(one_path "$root" scripts/init-top/udev)
    vendor=$(one_path "$root" scripts/init-top/nftfw-udev-vendor)
    order=$(one_path "$root" scripts/init-top/ORDER)
    [[ $(digest "$loader") == $(digest "$installed_loader") ]]
    [[ $(digest "$gate") == $(digest "$installed_gate") ]]
    [[ $(digest "$vendor") == $(digest "$vendor_udev") ]]
    [[ $("$gate" prereqs) == nftfw-ipv6-early ]]
    assert_native_order "$order"
}

assert_disabled_image() {
    local root=$1
    local order udev
    if lsinitramfs "$image" |
        grep -Eq '(^|/)(nftfw-ipv6-early|nftfw-udev-vendor|initramfs-guard\.nft|initramfs-guard\.sha256|initramfs-managed-disabled-v1)$'; then
        return 1
    fi
    extract_image "$root"
    order=$(one_path "$root" scripts/init-top/ORDER)
    udev=$(one_path "$root" scripts/init-top/udev)
    cmp -s "$udev" "$vendor_udev"
    ! grep -F nftfw "$order" >/dev/null
}

package_status=$(dpkg-query -W -f='${db:Status-Status}' nft-firewall-v2 2>/dev/null || true)
if [[ -n $package_status && $package_status != not-installed ]]; then
    echo "BLOCKED: disposable guest has retained NFT Firewall V2 package state"
    exit 77
fi

package_installed=1
before_package=$(digest "$image")
dpkg --install "$package"
[[ -x $manager && -x $installed_loader && -x $installed_gate ]]
[[ $(stat -c '%a:%U:%G:%h' "$installed_gate") == 755:root:root:1 ]]
for path in "$marker" "$owner" "$source_loader" "$source_gate"; do
    [[ ! -e $path && ! -L $path ]]
done
"$manager" verify-disabled
echo "DISPOSABLE PACKAGE INERT INSTALL: PASS"

# A pre-existing administrator source must be refused without mutation or an
# initramfs replacement. Remove only this exact disposable test fixture.
foreign='#!/bin/sh
echo administrator-owned-udev-fixture'
printf '%s\n' "$foreign" >"$source_gate"
chmod 0755 "$source_gate"
foreign_hash=$(digest "$source_gate")
before_refusal=$(digest "$image")
if "$manager" rebuild-enabled >"$temporary/foreign.stdout" 2>"$temporary/foreign.stderr"; then
    echo "FAIL: foreign native udev source was accepted"
    exit 1
fi
grep -Fq 'partial or ambiguous' "$temporary/foreign.stderr"
[[ $(digest "$source_gate") == "$foreign_hash" && $(digest "$image") == "$before_refusal" ]]
rm -f -- "$source_gate"
echo "DISPOSABLE FOREIGN SOURCE REFUSAL: PASS"

"$manager" rebuild-enabled
"$manager" verify-enabled
[[ $(stat -c '%a:%U:%G:%h' "$marker") == 600:root:root:1 ]]
[[ $(stat -c '%a:%U:%G:%h' "$owner") == 600:root:root:1 ]]
[[ $(stat -c '%a:%U:%G:%h' "$source_loader") == 755:root:root:1 ]]
[[ $(stat -c '%a:%U:%G:%h' "$source_gate") == 755:root:root:1 ]]
cmp -s "$source_loader" "$installed_loader"
cmp -s "$source_gate" "$installed_gate"
assert_enabled_image
enabled_hash=$(digest "$image")
echo "DISPOSABLE NATIVE ENABLED ORDER/DELEGATION: PASS"

"$manager" rebuild-enabled
"$manager" verify-enabled
assert_enabled_image
enabled_hash=$(digest "$image")
echo "DISPOSABLE ENABLE IDEMPOTENCE: PASS"

chmod 0777 "$source_gate"
if "$manager" rebuild-enabled >"$temporary/tamper.stdout" 2>"$temporary/tamper.stderr"; then
    echo "FAIL: writable managed gate was accepted"
    exit 1
fi
grep -Fq 'group- or other-writable' "$temporary/tamper.stderr"
[[ $(digest "$image") == "$enabled_hash" ]]
chmod 0755 "$source_gate"
"$manager" verify-enabled
assert_enabled_image
echo "DISPOSABLE TAMPER REFUSAL PRESERVED GOOD IMAGE: PASS"

"$manager" disable
"$manager" verify-disabled
for path in "$marker" "$owner" "$source_loader" "$source_gate"; do
    [[ ! -e $path && ! -L $path ]]
done
assert_disabled_image "$temporary/disabled"
echo "DISPOSABLE DISABLED NATIVE RESTORE: PASS"

"$manager" rebuild-enabled
"$manager" verify-enabled
dpkg --purge nft-firewall-v2
package_installed=0
for path in "$marker" "$owner" "$source_loader" "$source_gate"; do
    [[ ! -e $path && ! -L $path ]]
done
[[ ! -e $manager && ! -L $manager ]]
assert_disabled_image "$temporary/removed"
after_remove=$(digest "$image")
[[ $before_package != "$after_remove" ]]
echo "DISPOSABLE PACKAGE PURGE OWNERSHIP CLEANUP: PASS"
echo "DISPOSABLE INITRAMFS NATIVE SOURCE LIFECYCLE: PASS"
