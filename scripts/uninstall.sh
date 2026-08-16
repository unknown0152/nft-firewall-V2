#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "uninstall.sh must run as root" >&2; exit 1; fi
purge=0; for arg in "$@"; do [[ "$arg" == "--purge-state" ]] && purge=1; done
systemctl disable --now nftfw-web.service nftfw-rollback.timer nftfwd.service 2>/dev/null || true
rm -f /etc/systemd/system/nftfwd.service /etc/systemd/system/nftfw-web.service /etc/systemd/system/nftfw-rollback.service /etc/systemd/system/nftfw-rollback.timer
systemctl daemon-reload
rm -f /usr/sbin/nftfw
rm -rf /usr/lib/nftfw
if (( purge )); then rm -rf /etc/nftfw /var/lib/nftfw; echo "Removed NFT Firewall V2 configuration and state by explicit request."; else echo "Preserved /etc/nftfw and /var/lib/nftfw; pass --purge-state to remove them."; fi
echo "Uninstall does not flush nftables or touch unrelated tables."
