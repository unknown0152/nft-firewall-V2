#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

readonly expected_fragment_sha256=${1:-}
readonly guest_marker=/run/nftfw-disposable-test-guest
readonly service=nftfw-setup-rollback.service
readonly timer=nftfw-setup-rollback.timer
readonly state_path=/var/lib/initramfs-tools
readonly sentinel=$state_path/nftfw-amendment-o-sentinel
readonly journal=/var/lib/nftfw/setup/journal.json

blocked() {
    echo "BLOCKED: $*"
    exit 77
}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

[[ ${EUID:-$(id -u)} -eq 0 ]] || blocked "root is required"
[[ -n $expected_fragment_sha256 && $expected_fragment_sha256 =~ ^[0-9a-f]{64}$ ]] ||
    blocked "expected unit SHA-256 argument is required"
[[ -f $guest_marker && ! -L $guest_marker ]] ||
    blocked "disposable guest marker is absent or unsafe"
[[ $(stat -c '%a:%u:%g:%s:%h' "$guest_marker") == 600:0:0:0:1 ]] ||
    blocked "disposable guest marker metadata is invalid"
[[ -d /run/systemd/system && -d /var/lib/nftfw && -d /etc/nftfw ]] ||
    blocked "installed package and systemd guest are required"
for command_name in awk flock grep install jq mktemp mv rm rmdir seq sha256sum sleep stat \
    systemctl systemd-analyze; do
    command -v "$command_name" >/dev/null || blocked "missing prerequisite"
done
[[ ! -e $journal && ! -L $journal ]] || blocked "setup journal already exists"
[[ ! -e $state_path && ! -L $state_path ]] ||
    blocked "clean-host initramfs-tools state path must initially be absent"
systemctl is-active --quiet "$timer" && blocked "setup rollback timer is already active"
systemctl is-enabled --quiet "$timer" && blocked "setup rollback timer is already enabled"

fragment=$(systemctl show --value --property=FragmentPath "$service")
[[ -f $fragment && ! -L $fragment ]] || blocked "installed rollback unit is unavailable"
[[ $(sha256sum "$fragment" | awk '{print $1}') == "$expected_fragment_sha256" ]] ||
    fail "installed rollback unit differs from the source-bound test input"
grep -Fqx \
    'ReadWritePaths=/boot -/var/lib/initramfs-tools /etc/nftfw -/etc/default/grub.d -/etc/initramfs-tools/scripts/init-top -/etc/wireguard -/etc/docker /etc/sysctl.d /etc/systemd/system /var/lib/nftfw /run/nftfw -/run/resolvconf -/run/systemd/resolve' \
    "$fragment" || fail "installed rollback unit lacks the exact optional-path contract"
systemd-analyze verify "$fragment" "$(systemctl show --value --property=FragmentPath "$timer")"

cleanup() {
    local rc=$?
    set +e
    if [[ -n ${lock_fd:-} ]]; then
        flock -u "$lock_fd" >/dev/null 2>&1
        eval "exec ${lock_fd}>&-"
    fi
    systemctl stop "$timer" "$service" >/dev/null 2>&1
    rm -f -- "$journal" "$sentinel"
    rmdir -- "$state_path" 2>/dev/null
    exit "$rc"
}
trap cleanup EXIT

install -d -o root -g root -m 0700 "${journal%/*}" /run/nftfw
write_journal() {
    local deadline=$1 transaction=$2 started_at=${3:-2026-08-30T00:00:00Z}
    local temporary
    temporary=$(mktemp "${journal%/*}/.journal.XXXXXX")
    jq -n \
        --arg transaction "$transaction" \
        --arg deadline "$deadline" --arg started_at "$started_at" \
        '{
            schema:"nftfw.setup-journal.v1",
            transaction:$transaction,
            phase:"inspect",
            status:"running",
            started_at:$started_at,
            updated_at:$started_at,
            deadline:$deadline,
            summary:{schema:"nftfw.setup-plan.v1"}
        }' >"$temporary"
    chmod 0600 "$temporary"
    mv -f -- "$temporary" "$journal"
}

write_journal '2099-01-01T00:00:00Z' 'amendment-o-immediate'
exec {lock_fd}>/run/nftfw/setup.lock
chmod 0600 /run/nftfw/setup.lock
flock -n "$lock_fd" || fail "could not model the foreground setup lock"
before_invocation=$(systemctl show --value --property=InvocationID "$service")
systemctl start "$timer"
for _ in $(seq 1 240); do
    after_invocation=$(systemctl show --value --property=InvocationID "$service")
    [[ -n $after_invocation && $after_invocation != "$before_invocation" ]] && break
    sleep 0.1
done
[[ -n ${after_invocation:-} && $after_invocation != "$before_invocation" ]] ||
    fail "timer did not activate the rollback service immediately"
[[ $(systemctl show --value --property=Result "$service") == success ]] ||
    fail "absent-path rollback service activation failed"
jq -e '.status == "running" and .transaction == "amendment-o-immediate"' \
    "$journal" >/dev/null || fail "unexpired activation changed the setup journal"
[[ ! -e $state_path && ! -L $state_path ]] ||
    fail "optional systemd path declaration created the absent state path"
flock -u "$lock_fd"
eval "exec ${lock_fd}>&-"
unset lock_fd

install -d -o root -g root -m 0755 "$state_path"
printf '%s\n' 'amendment-o-preserve-exactly' >"$sentinel"
chmod 0640 "$sentinel"
sentinel_before=$(stat -c '%a:%u:%g:%s:%h' "$sentinel")
sentinel_hash=$(sha256sum "$sentinel" | awk '{print $1}')
write_journal '2000-01-01T00:00:00Z' 'amendment-o-expired' '1999-01-01T00:00:00Z'
exec {lock_fd}>/run/nftfw/setup.lock
flock -n "$lock_fd" || fail "could not model the expired live lock owner"
if systemctl start "$service"; then
    fail "expired watchdog bypassed the live foreground lock"
fi
jq -e '.status == "running" and .transaction == "amendment-o-expired"' \
    "$journal" >/dev/null || fail "lock-contended expiry changed the setup journal"
[[ $(systemctl show --value --property=Result "$service") == exit-code ]] ||
    fail "expired lock contention did not remain visible to systemd"
flock -u "$lock_fd"
eval "exec ${lock_fd}>&-"
unset lock_fd
systemctl reset-failed "$service"
for _ in $(seq 1 240); do
    status=$(jq -r '.status' "$journal")
    [[ $status == rolled_back ]] && break
    sleep 0.1
done
[[ ${status:-} == rolled_back ]] || fail "timer did not process the expired journal"
jq -e '.phase == "failed" and (.error_code // "") == ""' "$journal" >/dev/null ||
    fail "expired pre-mutation journal did not reach the exact terminal state"
[[ $(systemctl show --value --property=Result "$service") == success ]] ||
    fail "present-path rollback service activation failed"
[[ $(stat -c '%a:%u:%g:%s:%h' "$sentinel") == "$sentinel_before" ]] ||
    fail "rollback activation changed pre-existing initramfs-tools metadata"
[[ $(sha256sum "$sentinel" | awk '{print $1}') == "$sentinel_hash" ]] ||
    fail "rollback activation changed pre-existing initramfs-tools contents"

echo "DISPOSABLE SETUP ROLLBACK SYSTEMD PATH AND LOCK: PASS"
