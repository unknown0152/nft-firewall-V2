#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
[[ ${EUID:-$(id -u)} -eq 0 ]] || {
    echo "SKIP: initramfs guard namespace regression requires root"
    exit 77
}
for tool in ip mount nft sha256sum sysctl timeout unshare; do
    command -v "$tool" >/dev/null || { echo "SKIP: missing $tool"; exit 77; }
done

# shellcheck disable=SC2016
timeout 30s unshare --mount --net --fork --kill-child bash -Eeuo pipefail -c '
    root_dir=$1
    mount --make-rprivate /
    mount -t tmpfs -o mode=0700 tmpfs /run
    mount -t tmpfs -o mode=0750 tmpfs /etc/nftfw
    install -o root -g root -m 0600 \
        "$root_dir/packaging/initramfs/nftfw-initramfs-guard.nft" \
        /etc/nftfw/initramfs-guard.nft
    printf "%s\n" nftfw.initramfs-managed-disabled.v1 \
        >/etc/nftfw/initramfs-managed-disabled-v1
    chmod 0600 /etc/nftfw/initramfs-managed-disabled-v1
    sha256sum /etc/nftfw/initramfs-guard.nft \
        >/etc/nftfw/initramfs-guard.sha256
    chmod 0600 /etc/nftfw/initramfs-guard.sha256
    before_default=$(sysctl -n net.ipv6.conf.default.disable_ipv6)
    before_loopback=$(sysctl -n net.ipv6.conf.lo.disable_ipv6)
    printf "%s\n" "root=/dev/test ro ipv6.disable=1" >/run/nftfw-test-cmdline
    printf "%s\n" Y >/run/nftfw-test-ipv6-disable
    : >/run/nftfw-test-if-inet6
    sed \
        -e "s|/proc/cmdline|/run/nftfw-test-cmdline|g" \
        -e "s|/sys/module/ipv6/parameters/disable|/run/nftfw-test-ipv6-disable|g" \
        -e "s|/proc/net/if_inet6|/run/nftfw-test-if-inet6|g" \
        "$root_dir/packaging/initramfs/nftfw-ipv6-early" \
        >/run/nftfw-ipv6-early-test
    chmod 0700 /run/nftfw-ipv6-early-test
    /run/nftfw-ipv6-early-test
    [[ $(sysctl -n net.ipv6.conf.default.disable_ipv6) == "$before_default" ]]
    [[ $(sysctl -n net.ipv6.conf.lo.disable_ipv6) == "$before_loopback" ]]
    ip link add nftfwtest0 type dummy
    [[ $(sysctl -n net.ipv6.conf.nftfwtest0.disable_ipv6) == "$before_default" ]]
    nft --json list table inet nftfw_initramfs_guard >/dev/null
    [[ -s /run/nftfw-initramfs/guard-ready.sha256 ]]

    # A failed archive listing must never be classified as proof that the
    # guard is absent. Exercise that fail-closed branch without touching the
    # host boot filesystem.
    mount -t tmpfs -o mode=0700 tmpfs /boot
    : >/boot/initrd.img-test
    rm -f /etc/nftfw/initramfs-managed-disabled-v1
    install -d -m 0700 /run/nftfw-test-bin
    printf "%s\n" "#!/bin/sh" "echo test" >/run/nftfw-test-bin/uname
    printf "%s\n" "#!/bin/sh" "/usr/bin/touch /run/nftfw-ls-called" "exit 1" \
        >/run/nftfw-test-bin/lsinitramfs
    chmod 0700 /run/nftfw-test-bin/uname /run/nftfw-test-bin/lsinitramfs
    if PATH=/run/nftfw-test-bin:/usr/sbin:/usr/bin:/sbin:/bin \
        "$root_dir/packaging/initramfs/nftfw-initramfs-manage" verify-disabled \
        >/dev/null 2>&1; then
        echo "failed initramfs listing was accepted as disabled" >&2
        exit 1
    fi
    [[ -e /run/nftfw-ls-called ]]
' bash "$root_dir"

echo "INITRAMFS_GUARD_NAMESPACE_PASS"
