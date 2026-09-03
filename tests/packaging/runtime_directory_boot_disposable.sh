#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Read-only per-boot assertion used by the external disposable-VM controller.
# The controller supplies packet-capture and reboot isolation; this fixture
# proves each guest boot reached the exact fail-closed systemd handoff.

readonly expected_ready_sha256=${1:-}
readonly ordinal=${2:-}
readonly required_boots=20
readonly guest_marker=/run/nftfw-disposable-test-guest
readonly state_root=/opt/nftfw-amendment-ac
readonly ledger=$state_root/boot-ids
readonly ready_unit=nftfw-enforcement-ready.service
readonly early_unit=nftfw-early.service
readonly runtime_dir=/run/nftfw

blocked() {
    echo "BLOCKED: $*"
    exit 77
}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

[[ ${EUID:-$(id -u)} -eq 0 ]] || blocked "guest root is required"
[[ $expected_ready_sha256 =~ ^[0-9a-f]{64}$ ]] ||
    blocked "readiness unit SHA-256 is required"
[[ $ordinal =~ ^[0-9]+$ && $ordinal -ge 1 && $ordinal -le $required_boots ]] ||
    blocked "boot ordinal must be 1..$required_boots"
[[ -f $guest_marker && ! -L $guest_marker ]] ||
    blocked "disposable guest marker is absent or unsafe"
[[ $(stat -c '%a:%u:%g:%s:%h' "$guest_marker") == 600:0:0:0:1 ]] ||
    blocked "disposable guest marker metadata is invalid"
for command_name in awk getent grep install journalctl jq nft sha256sum sort stat \
    sync systemctl tr; do
    command -v "$command_name" >/dev/null || blocked "missing prerequisite: $command_name"
done

fragment=$(systemctl show --value --property=FragmentPath "$ready_unit")
[[ -f $fragment && ! -L $fragment ]] || fail "readiness unit fragment is unavailable"
[[ $(sha256sum "$fragment" | awk '{print $1}') == "$expected_ready_sha256" ]] ||
    fail "installed readiness unit differs from the source-bound fixture"

systemctl is-active --quiet "$early_unit" || fail "early enforcement is not active"
systemctl is-active --quiet "$ready_unit" || fail "enforcement readiness is not active"
systemctl is-active --quiet ssh.service || fail "SSH did not wait for readiness"
[[ $(systemctl show --value --property=Result "$early_unit") == success ]]
[[ $(systemctl show --value --property=Result "$ready_unit") == success ]]
[[ $(systemctl show --value --property=ExecMainStatus "$ready_unit") == 0 ]]
[[ $(systemctl show --value --property=ConditionResult "$early_unit") == yes ]]

ready_at=$(systemctl show --value --property=ActiveEnterTimestampMonotonic "$ready_unit")
ssh_at=$(systemctl show --value --property=ActiveEnterTimestampMonotonic ssh.service)
[[ $ready_at =~ ^[0-9]+$ && $ready_at -gt 0 ]]
[[ $ssh_at =~ ^[0-9]+$ && $ssh_at -gt "$ready_at" ]] ||
    fail "SSH activation did not follow enforcement readiness"

nftfw_web_gid=$(getent group nftfw-web | awk -F: 'NR == 1 {print $3}')
[[ $nftfw_web_gid =~ ^[0-9]+$ ]]
[[ -d $runtime_dir && ! -L $runtime_dir ]]
[[ $(stat -c '%a:%u:%g:%h' "$runtime_dir") == 750:0:$nftfw_web_gid:2 ]]
[[ ! -e $runtime_dir/status.sock || -S $runtime_dir/status.sock ]]
[[ ! -e $runtime_dir/control.sock || -S $runtime_dir/control.sock ]]

/usr/lib/nftfw/nftfwd --verify-enforcement --state-dir /var/lib/nftfw
for transient_table in nftfw_initramfs_guard nftfw_setup_guard nftfw_setup_resume_guard; do
    if nft list table inet "$transient_table" >/dev/null 2>&1; then
        fail "transient guard remains after readiness: $transient_table"
    fi
done

boot_id=$(tr -d '\n' </proc/sys/kernel/random/boot_id)
[[ $boot_id =~ ^[0-9a-f-]{36}$ ]] || fail "kernel boot ID is malformed"
if [[ $ordinal -eq 1 ]]; then
    [[ ! -e $state_root && ! -L $state_root ]] || blocked "boot ledger already exists"
    install -d -o root -g root -m 0700 "$state_root"
    install -o root -g root -m 0600 /dev/null "$ledger"
else
    [[ -d $state_root && ! -L $state_root ]]
    [[ $(stat -c '%a:%u:%g:%h' "$state_root") == 700:0:0:2 ]]
    [[ -f $ledger && ! -L $ledger ]]
    [[ $(stat -c '%a:%u:%g:%h' "$ledger") == 600:0:0:1 ]]
fi
[[ $(grep -c . "$ledger" || true) -eq $((ordinal - 1)) ]]
! grep -Fxq "$boot_id" "$ledger" || fail "boot ID was reused"
printf '%s\n' "$boot_id" >>"$ledger"
sync -f "$ledger"
[[ $(grep -c . "$ledger") -eq "$ordinal" ]]

journalctl -b -u "$ready_unit" --no-pager -o cat | grep -Fq \
    'Failed to set up mount namespacing' && fail "readiness namespace failure is present"
journalctl -b --no-pager -o cat | grep -Fq \
    'Found ordering cycle on nftfw-' && fail "NFTFW boot ordering cycle is present"

printf 'AMENDMENT_AC_BOOT_%02d_PASS\n' "$ordinal"
if [[ $ordinal -eq $required_boots ]]; then
    [[ $(sort -u "$ledger" | grep -c .) -eq $required_boots ]]
    echo "AMENDMENT_AC_20_CONSECUTIVE_BOOT_HANDOFFS_PASS"
fi
