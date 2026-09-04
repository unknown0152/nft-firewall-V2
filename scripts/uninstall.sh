#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "uninstall.sh must run as root" >&2; exit 1; fi
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=scripts/docker-handoff.sh
source "$script_dir/docker-handoff.sh"
purge=0
for arg in "$@"; do
    case "$arg" in
        --purge-state) purge=1 ;;
        *) echo "Usage: uninstall.sh [--purge-state]" >&2; exit 2 ;;
    esac
done
readonly setup_journal=/var/lib/nftfw/setup/journal.json
if [[ -L $setup_journal ]]; then
    echo "Refusing uninstall: setup journal is an unsafe link." >&2
    exit 1
fi
network_gate_present=false
for producer in NetworkManager.service dhcpcd.service dhcpcd@.service \
    ifup@.service networking.service systemd-networkd.service; do
    producer_gate=/etc/systemd/system/$producer.d/50-nftfw-enforcement-ready.conf
    if [[ -e $producer_gate || -L $producer_gate ]]; then
        network_gate_present=true
        break
    fi
done
if [[ -e /etc/default/grub.d/90-nftfw-ipv6-disabled.cfg || \
    -L /etc/default/grub.d/90-nftfw-ipv6-disabled.cfg || \
    $network_gate_present == true || \
    ( -f $setup_journal && $(grep -Fc '"boot_policy": "debian-grub-ipv6-disabled-v1"' "$setup_journal") -ge 1 ) ]]; then
    [[ -x /usr/lib/nftfw/nftfw ]] || {
        echo "Refusing uninstall: managed boot-policy helper is missing." >&2
        exit 1
    }
    /usr/lib/nftfw/nftfw setup boot-handoff --package-remove
    boot_handoff=1
else
    boot_handoff=0
fi
if [[ -e /etc/nftfw/initramfs-managed-disabled-v1 || \
    -L /etc/nftfw/initramfs-managed-disabled-v1 || \
    -e /etc/nftfw/initramfs-source-owner-v1 || \
    -L /etc/nftfw/initramfs-source-owner-v1 || \
    -e /etc/initramfs-tools/scripts/init-top/nftfw-ipv6-early || \
    -L /etc/initramfs-tools/scripts/init-top/nftfw-ipv6-early || \
    -e /etc/initramfs-tools/scripts/init-top/udev || \
    -L /etc/initramfs-tools/scripts/init-top/udev ]] && \
    [[ ! -x /usr/lib/nftfw/initramfs/nftfw-initramfs-manage ]]; then
    echo "Refusing uninstall: managed initramfs guard helper is missing." >&2
    exit 1
fi
if (( ! boot_handoff )) && [[ -x /usr/lib/nftfw/initramfs/nftfw-initramfs-manage ]]; then
    /usr/lib/nftfw/initramfs/nftfw-initramfs-manage disable
fi
systemctl disable --now nftfw-web.service nftfw-vpn.service nftfw-setup-rollback.timer nftfw-setup-rollback.service nftfw-setup-boot-hold.service nftfw-setup-docker-hold.service nftfw-managed-rollback.timer nftfw-managed-rollback.service nftfw-rollback.timer nftfwd.service nftfw-enforcement-ready.service nftfw-early.service 2>/dev/null || true
nftfw_remove_managed_docker_dropin ""
rm -f /etc/systemd/system/nftfw-early.service /etc/systemd/system/nftfw-enforcement-ready.service /etc/systemd/system/nftfwd.service /etc/systemd/system/nftfw-web.service /etc/systemd/system/nftfw-vpn.service /etc/systemd/system/nftfw-setup-rollback.service /etc/systemd/system/nftfw-setup-rollback.timer /etc/systemd/system/nftfw-setup-boot-hold.service /etc/systemd/system/nftfw-setup-docker-hold.service /etc/systemd/system/nftfw-managed-rollback.service /etc/systemd/system/nftfw-managed-rollback.timer /etc/systemd/system/nftfw-rollback.service /etc/systemd/system/nftfw-rollback.timer
rm -f /usr/lib/systemd/system-generators/nftfw-setup-boot-hold-generator
systemctl daemon-reload
rm -f /usr/sbin/nftfw
rm -f /usr/sbin/nftfw-package-rollback
rm -f /usr/share/initramfs-tools/hooks/nftfw-early-guard
rm -rf /usr/lib/nftfw
if (( purge )); then
    rm -rf /etc/nftfw /var/lib/nftfw
    echo "Removed NFT Firewall V2 configuration and state by explicit request."
    echo "Docker daemon and sysctl files remain fail-closed and require explicit operator handoff."
else
    echo "Preserved /etc/nftfw and /var/lib/nftfw; pass --purge-state to remove them."
    echo "Preserved Docker daemon and sysctl ownership fail-closed; see /var/lib/nftfw/setup/UNINSTALL_HANDOFF."
fi
echo "Uninstall does not flush nftables or touch unrelated tables."
