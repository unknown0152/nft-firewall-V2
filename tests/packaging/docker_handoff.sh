#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
source "$root_dir/scripts/docker-handoff.sh"

test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT

mkdir -p "$test_root/etc/systemd/system/nftfwd.service.d" \
    "$test_root/etc/docker" "$test_root/etc/sysctl.d"
printf '[Service]\nInaccessiblePaths=\n' \
    > "$test_root/etc/systemd/system/nftfwd.service.d/docker-access.conf"
printf '{}\n' > "$test_root/etc/docker/daemon.json"
printf 'net.ipv4.ip_forward = 1\n' \
    > "$test_root/etc/sysctl.d/90-nftfw-managed.conf"

nftfw_remove_managed_docker_dropin "$test_root"

test ! -e "$test_root/etc/systemd/system/nftfwd.service.d/docker-access.conf"
test -f "$test_root/var/lib/nftfw/setup/UNINSTALL_HANDOFF"
grep -Fqx 'status=preserved-fail-closed' \
    "$test_root/var/lib/nftfw/setup/UNINSTALL_HANDOFF"

mkdir -p "$test_root/etc/systemd/system/nftfwd.service.d"
printf '[Service]\nInaccessiblePaths=\nEnvironment=LOCAL_CHANGE=1\n' \
    > "$test_root/etc/systemd/system/nftfwd.service.d/docker-access.conf"
nftfw_remove_managed_docker_dropin "$test_root"
grep -Fqx 'Environment=LOCAL_CHANGE=1' \
    "$test_root/etc/systemd/system/nftfwd.service.d/docker-access.conf"

echo "Docker uninstall handoff tests passed"
