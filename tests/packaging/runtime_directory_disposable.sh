#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Run only in a disposable Debian guest containing an installed candidate.
# This exercises systemd's RuntimeDirectory creation before mount namespacing;
# it must never be run on an operator or production host.

readonly expected_ready_sha256=${1:-}
readonly expected_managed_sha256=${2:-}
readonly expected_setup_sha256=${3:-}
readonly guest_marker=/run/nftfw-disposable-test-guest
readonly runtime_dir=/run/nftfw
readonly fixture_root=/opt/nftfw-amendment-ac-runtime-test
readonly fixture=$fixture_root/runtime-owner
readonly -a owners=(
    nftfw-enforcement-ready.service
    nftfw-managed-rollback.service
    nftfw-setup-rollback.service
)

blocked() {
    echo "BLOCKED: $*"
    exit 77
}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

[[ ${EUID:-$(id -u)} -eq 0 ]] || blocked "guest root is required"
[[ -f $guest_marker && ! -L $guest_marker ]] ||
    blocked "disposable guest marker is absent or unsafe"
[[ $(stat -c '%a:%u:%g:%s:%h' "$guest_marker") == 600:0:0:0:1 ]] ||
    blocked "disposable guest marker metadata is invalid"
for digest in "$expected_ready_sha256" "$expected_managed_sha256" "$expected_setup_sha256"; do
    [[ $digest =~ ^[0-9a-f]{64}$ ]] || blocked "three unit SHA-256 arguments are required"
done
for command_name in awk find getent grep install rm rmdir seq sha256sum sleep stat \
    systemctl systemd-analyze; do
    command -v "$command_name" >/dev/null || blocked "missing prerequisite: $command_name"
done

nftfw_web_gid=$(getent group nftfw-web | awk -F: 'NR == 1 {print $3}')
readonly nftfw_web_gid
[[ $nftfw_web_gid =~ ^[0-9]+$ ]] || blocked "nftfw-web group is unavailable"
readonly expected_metadata="750:0:$nftfw_web_gid"

declare -A expected_hashes=(
    [nftfw-enforcement-ready.service]="$expected_ready_sha256"
    [nftfw-managed-rollback.service]="$expected_managed_sha256"
    [nftfw-setup-rollback.service]="$expected_setup_sha256"
)

for unit in "${owners[@]}" nftfw-early.service nftfwd.service \
    nftfw-rollback.service nftfw-setup-boot-hold.service \
    nftfw-setup-docker-hold.service; do
    systemctl is-active --quiet "$unit" && blocked "$unit is already active"
done
for timer in nftfw-managed-rollback.timer nftfw-setup-rollback.timer nftfw-rollback.timer; do
    systemctl is-active --quiet "$timer" && blocked "$timer is already active"
    systemctl is-enabled --quiet "$timer" && blocked "$timer is already enabled"
done
[[ ! -e /var/lib/nftfw/enforcement-enabled &&
    ! -L /var/lib/nftfw/enforcement-enabled ]] ||
    blocked "committed enforcement state is present"

for unit in "${owners[@]}"; do
    fragment=$(systemctl show --value --property=FragmentPath "$unit")
    [[ -f $fragment && ! -L $fragment ]] || blocked "$unit fragment is unavailable"
    [[ $(sha256sum "$fragment" | awk '{print $1}') == "${expected_hashes[$unit]}" ]] ||
        fail "$unit differs from the source-bound fixture"
    systemd-analyze verify "$fragment"
done

if [[ -e $runtime_dir || -L $runtime_dir ]]; then
    [[ -d $runtime_dir && ! -L $runtime_dir ]] ||
        blocked "pre-existing runtime directory is unsafe"
    [[ $(stat -c '%a:%u:%g' "$runtime_dir") == "$expected_metadata" ]] ||
        blocked "pre-existing runtime directory metadata is unexpected"
    [[ -z $(find "$runtime_dir" -mindepth 1 -maxdepth 1 -print -quit) ]] ||
        blocked "pre-existing runtime directory is not empty"
    rmdir -- "$runtime_dir"
fi
for path in "$fixture_root" \
    /run/systemd/system/nftfw-enforcement-ready.service.d \
    /run/systemd/system/nftfw-managed-rollback.service.d \
    /run/systemd/system/nftfw-setup-rollback.service.d \
    /run/systemd/system/nftfw-early.service.d; do
    [[ ! -e $path && ! -L $path ]] || blocked "test path already exists: $path"
done

cleanup() {
    local rc=$?
    set +e
    systemctl stop "${owners[@]}" nftfw-early.service >/dev/null 2>&1
    rm -rf -- \
        /run/systemd/system/nftfw-enforcement-ready.service.d \
        /run/systemd/system/nftfw-managed-rollback.service.d \
        /run/systemd/system/nftfw-setup-rollback.service.d \
        /run/systemd/system/nftfw-early.service.d
    systemctl daemon-reload >/dev/null 2>&1
    systemctl reset-failed "${owners[@]}" nftfw-early.service >/dev/null 2>&1
    if [[ -d $runtime_dir && ! -L $runtime_dir ]]; then
        find "$runtime_dir" -mindepth 1 -maxdepth 1 -type f \
            \( -name 'mutation.lock' -o -name 'ac-*.ready' \) -delete
        rmdir -- "$runtime_dir" >/dev/null 2>&1
    fi
    rm -rf -- "$fixture_root"
    install -d -o root -g nftfw-web -m 0750 "$runtime_dir"
    exit "$rc"
}
trap cleanup EXIT

# Model the real failed boot: early is independently scheduled but condition
# skipped, and readiness starts with /run/nftfw absent. The verifier must fail
# on missing committed state, never at systemd's 226/NAMESPACE boundary.
systemctl start nftfw-early.service
[[ $(systemctl show --value --property=ActiveState nftfw-early.service) == inactive ]]
if systemctl start nftfw-enforcement-ready.service; then
    fail "readiness accepted missing committed enforcement"
fi
[[ $(systemctl show --value --property=Result nftfw-enforcement-ready.service) == exit-code ]]
[[ $(systemctl show --value --property=ExecMainStatus nftfw-enforcement-ready.service) != 226 ]] ||
    fail "readiness failed during systemd namespace construction"
[[ $(stat -c '%a:%u:%g' "$runtime_dir") == "$expected_metadata" ]]
[[ $(systemctl show --value --property=ActiveState nftfw-early.service) == inactive ]]
systemctl stop nftfw-enforcement-ready.service
systemctl reset-failed nftfw-enforcement-ready.service
if [[ -e $runtime_dir/mutation.lock || -L $runtime_dir/mutation.lock ]]; then
    [[ -f $runtime_dir/mutation.lock && ! -L $runtime_dir/mutation.lock ]]
    [[ $(stat -c '%a:%u:%g:%h' "$runtime_dir/mutation.lock") == 600:0:$nftfw_web_gid:1 ]]
    rm -f -- "$runtime_dir/mutation.lock"
fi
rmdir -- "$runtime_dir"
echo "AMENDMENT_AC_ABSENT_DIRECTORY_FAIL_CLOSED_PASS"

# A deliberately failed early restorer must not be activated or bypassed by a
# manual readiness start. Both units still establish the namespace path before
# their own process executes.
install -d -o root -g root -m 0700 /run/systemd/system/nftfw-early.service.d
install -o root -g root -m 0600 /dev/null \
    /run/systemd/system/nftfw-early.service.d/ac-failure.conf
printf '%s\n' '[Unit]' 'ConditionPathExists=' '[Service]' 'ExecStart=' \
    'ExecStart=/usr/bin/false' \
    >/run/systemd/system/nftfw-early.service.d/ac-failure.conf
systemctl daemon-reload
if systemctl start nftfw-early.service; then
    fail "injected early failure was accepted"
fi
[[ $(systemctl show --value --property=Result nftfw-early.service) == exit-code ]]
[[ $(systemctl show --value --property=ExecMainStatus nftfw-early.service) != 226 ]]
if systemctl start nftfw-enforcement-ready.service; then
    fail "readiness bypassed failed early enforcement"
fi
[[ $(systemctl show --value --property=Result nftfw-enforcement-ready.service) == exit-code ]]
[[ $(systemctl show --value --property=ExecMainStatus nftfw-enforcement-ready.service) != 226 ]]
[[ $(systemctl show --value --property=Result nftfw-early.service) == exit-code ]]
systemctl stop nftfw-enforcement-ready.service nftfw-early.service
systemctl reset-failed nftfw-enforcement-ready.service nftfw-early.service
rm -rf -- /run/systemd/system/nftfw-early.service.d
systemctl daemon-reload
if [[ -e $runtime_dir/mutation.lock || -L $runtime_dir/mutation.lock ]]; then
    [[ -f $runtime_dir/mutation.lock && ! -L $runtime_dir/mutation.lock ]]
    rm -f -- "$runtime_dir/mutation.lock"
fi
rmdir -- "$runtime_dir"
echo "AMENDMENT_AC_EARLY_FAILURE_FAIL_CLOSED_PASS"

# Replace only ExecStart inside this disposable guest. The exact installed unit
# metadata, sandbox, credentials, and RuntimeDirectory directives stay active.
install -d -o root -g root -m 0700 "$fixture_root"
install -o root -g root -m 0700 /dev/null "$fixture"
# These literal lines are the contents of the disposable guest helper.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    'unit=$1' \
    'delay=$2' \
    'gid=$(getent group nftfw-web | awk -F: '\''NR == 1 {print $3}'\'')' \
    '[ "$(stat -c '\''%a:%u:%g'\'' /run/nftfw)" = "750:0:$gid" ]' \
    ': >"/run/nftfw/ac-${unit}.ready"' \
    '[ "$delay" -eq 0 ] || sleep "$delay"' \
    >"$fixture"

write_dropins() {
    local delay=$1 unit dropin
    for unit in "${owners[@]}"; do
        dropin=/run/systemd/system/$unit.d
        install -d -o root -g root -m 0700 "$dropin"
        install -o root -g root -m 0600 /dev/null "$dropin/ac-runtime.conf"
        {
            printf '%s\n' '[Service]' 'ExecStart='
            printf 'ExecStart=%s %s %s\n' "$fixture" "$unit" "$delay"
            [[ $unit != nftfw-enforcement-ready.service ]] || printf '%s\n' 'ExecStartPost='
        } >"$dropin/ac-runtime.conf"
    done
    systemctl daemon-reload
}

write_dropins 0
for unit in "${owners[@]}"; do
    for _ in $(seq 1 50); do
        [[ ! -e $runtime_dir && ! -L $runtime_dir ]]
        systemctl start "$unit"
        [[ $(systemctl show --value --property=Result "$unit") == success ]]
        [[ $(systemctl show --value --property=ExecMainStatus "$unit") != 226 ]]
        [[ $(stat -c '%a:%u:%g' "$runtime_dir") == "$expected_metadata" ]]
        [[ -f $runtime_dir/ac-${unit}.ready && ! -L $runtime_dir/ac-${unit}.ready ]]
        systemctl stop "$unit"
        [[ -d $runtime_dir && ! -L $runtime_dir ]]
        rm -f -- "$runtime_dir/ac-${unit}.ready"
        rmdir -- "$runtime_dir"
    done
done
echo "AMENDMENT_AC_150_ABSENT_DIRECTORY_STARTS_PASS"

write_dropins 30
for unit in "${owners[@]}"; do
    systemctl start --no-block "$unit"
done
for _ in $(seq 1 100); do
    ready=1
    for unit in "${owners[@]}"; do
        [[ -f $runtime_dir/ac-${unit}.ready ]] || ready=0
    done
    [[ $ready -eq 1 ]] && break
    sleep 0.05
done
[[ ${ready:-0} -eq 1 ]] || fail "concurrent owners did not all enter the fixture"
[[ $(stat -c '%a:%u:%g' "$runtime_dir") == "$expected_metadata" ]]
systemctl stop nftfw-enforcement-ready.service
[[ -d $runtime_dir && ! -L $runtime_dir ]]
for unit in nftfw-managed-rollback.service nftfw-setup-rollback.service; do
    [[ -f $runtime_dir/ac-${unit}.ready && ! -L $runtime_dir/ac-${unit}.ready ]]
done
systemctl stop nftfw-managed-rollback.service nftfw-setup-rollback.service
[[ -d $runtime_dir && ! -L $runtime_dir ]]
echo "AMENDMENT_AC_SHARED_LIFETIME_PASS"
echo "DISPOSABLE SYSTEMD RUNTIME DIRECTORY AND READINESS ORDERING: PASS"
