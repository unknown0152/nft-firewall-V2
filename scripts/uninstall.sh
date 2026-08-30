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
if [[ -e /etc/nftfw/initramfs-managed-disabled-v1 || \
    -L /etc/nftfw/initramfs-managed-disabled-v1 ]] && \
    [[ ! -x /usr/lib/nftfw/initramfs/nftfw-initramfs-manage ]]; then
    echo "Refusing uninstall: managed initramfs guard helper is missing." >&2
    exit 1
fi
if [[ -x /usr/lib/nftfw/initramfs/nftfw-initramfs-manage ]]; then
    /usr/lib/nftfw/initramfs/nftfw-initramfs-manage disable
fi
systemctl disable --now nftfw-web.service nftfw-vpn.service nftfw-setup-rollback.timer nftfw-setup-rollback.service nftfw-managed-rollback.timer nftfw-managed-rollback.service nftfw-rollback.timer nftfwd.service nftfw-enforcement-ready.service nftfw-early.service 2>/dev/null || true
nftfw_remove_managed_docker_dropin ""
rm -f /etc/systemd/system/nftfw-early.service /etc/systemd/system/nftfw-enforcement-ready.service /etc/systemd/system/nftfwd.service /etc/systemd/system/nftfw-web.service /etc/systemd/system/nftfw-vpn.service /etc/systemd/system/nftfw-setup-rollback.service /etc/systemd/system/nftfw-setup-rollback.timer /etc/systemd/system/nftfw-managed-rollback.service /etc/systemd/system/nftfw-managed-rollback.timer /etc/systemd/system/nftfw-rollback.service /etc/systemd/system/nftfw-rollback.timer
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
