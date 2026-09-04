#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

readonly guest_marker=/run/nftfw-disposable-test-guest
readonly fixture_root=/run/systemd/system
readonly state_root=/run/nftfw-network-producer-test

blocked() {
    echo "BLOCKED: $*" >&2
    exit 2
}
fail() {
    echo "FAIL: $*" >&2
    exit 1
}

[[ ${EUID:-$(id -u)} -eq 0 ]] || blocked "network-producer gate test requires disposable guest root"
[[ -f $guest_marker && ! -L $guest_marker ]] || blocked "exact disposable guest marker is absent"
[[ $(stat -c '%u:%g:%a:%h' "$guest_marker") == 0:0:600:1 ]] || blocked "disposable guest marker is unsafe"
for tool in cat chmod install rm rmdir sed stat systemctl tail touch; do
    command -v "$tool" >/dev/null || blocked "missing disposable prerequisite: $tool"
done

cleanup() {
    systemctl stop nftfw-ad-producer.service 'nftfw-ad-producer@nftfw-test.service' \
        nftfw-ad-ready.service >/dev/null 2>&1 || true
    rm -f -- \
        "$fixture_root/nftfw-ad-ready.service" \
        "$fixture_root/nftfw-ad-producer.service" \
        "$fixture_root/nftfw-ad-producer@.service" \
        "$fixture_root/nftfw-ad-producer.service.d/50-nftfw-enforcement-ready.conf" \
        "$fixture_root/nftfw-ad-producer@.service.d/50-nftfw-enforcement-ready.conf"
    rmdir "$fixture_root/nftfw-ad-producer.service.d" \
        "$fixture_root/nftfw-ad-producer@.service.d" 2>/dev/null || true
    rm -rf -- "$state_root"
    systemctl daemon-reload >/dev/null 2>&1 || true
}
trap cleanup EXIT

[[ ! -e $state_root && ! -L $state_root ]] || blocked "disposable fixture state already exists"
for fixture_path in \
    "$fixture_root/nftfw-ad-ready.service" \
    "$fixture_root/nftfw-ad-producer.service" \
    "$fixture_root/nftfw-ad-producer@.service" \
    "$fixture_root/nftfw-ad-producer.service.d" \
    "$fixture_root/nftfw-ad-producer@.service.d"; do
    [[ ! -e $fixture_path && ! -L $fixture_path ]] || blocked "disposable systemd fixture already exists"
done
install -d -o root -g root -m 0700 "$state_root" \
    "$fixture_root/nftfw-ad-producer.service.d" \
    "$fixture_root/nftfw-ad-producer@.service.d"

cat >"$fixture_root/nftfw-ad-ready.service" <<'UNIT'
[Unit]
Description=Disposable NFTFW readiness semantic probe
[Service]
Type=oneshot
ExecStart=/usr/bin/touch /run/nftfw-network-producer-test/ready
RemainAfterExit=yes
UNIT
cat >"$fixture_root/nftfw-ad-producer.service" <<'UNIT'
[Unit]
Description=Disposable NFTFW ordinary producer semantic probe
[Service]
Type=simple
ExecStart=/usr/bin/tail -f /dev/null
ExecStartPost=/usr/bin/touch /run/nftfw-network-producer-test/ordinary
UNIT
cat >"$fixture_root/nftfw-ad-producer@.service" <<'UNIT'
[Unit]
Description=Disposable NFTFW template producer semantic probe
[Service]
Type=oneshot
ExecStart=/usr/bin/touch /run/nftfw-network-producer-test/template-%i
RemainAfterExit=yes
UNIT

final_gate='[Unit]
Requires=nftfw-ad-ready.service
BindsTo=nftfw-ad-ready.service
After=nftfw-ad-ready.service'
printf '%s\n' "$final_gate" >"$fixture_root/nftfw-ad-producer.service.d/50-nftfw-enforcement-ready.conf"
printf '%s\n' "$final_gate" >"$fixture_root/nftfw-ad-producer@.service.d/50-nftfw-enforcement-ready.conf"
chmod 0644 "$fixture_root"/nftfw-ad-*.service \
    "$fixture_root"/nftfw-ad-producer*.service.d/50-nftfw-enforcement-ready.conf
systemctl daemon-reload

systemctl start nftfw-ad-producer.service
[[ -f $state_root/ready && -f $state_root/ordinary ]] || fail "ordinary direct activation escaped readiness ordering"
systemctl stop nftfw-ad-ready.service
[[ $(systemctl show --value --property=ActiveState nftfw-ad-producer.service) == inactive ]] ||
    fail "BindsTo did not stop an active producer when readiness stopped"

rm -f -- "$state_root/ready" "$state_root/ordinary"
sed -i 's#ExecStart=/usr/bin/touch /run/nftfw-network-producer-test/ready#ExecStart=/usr/bin/false#' \
    "$fixture_root/nftfw-ad-ready.service"
systemctl daemon-reload
systemctl reset-failed nftfw-ad-ready.service >/dev/null 2>&1 || true
systemctl reset-failed nftfw-ad-producer.service >/dev/null 2>&1 || true
if systemctl start nftfw-ad-producer.service >/dev/null 2>&1; then
    fail "failed readiness allowed ordinary producer activation"
fi
[[ ! -e $state_root/ordinary ]] || fail "failed readiness executed ordinary producer payload"

cat >"$fixture_root/nftfw-ad-ready.service" <<'UNIT'
[Unit]
Description=Disposable NFTFW skipped-readiness semantic probe
ConditionPathExists=/run/nftfw-network-producer-test/condition-that-must-remain-absent
[Service]
Type=oneshot
ExecStart=/usr/bin/touch /run/nftfw-network-producer-test/ready
RemainAfterExit=yes
UNIT
systemctl daemon-reload
systemctl reset-failed nftfw-ad-ready.service >/dev/null 2>&1 || true
systemctl reset-failed 'nftfw-ad-producer@nftfw-test.service' >/dev/null 2>&1 || true
if systemctl start 'nftfw-ad-producer@nftfw-test.service' >/dev/null 2>&1; then
    fail "skipped readiness allowed direct template activation"
fi
[[ ! -e $state_root/template-nftfw-test ]] || fail "skipped readiness executed template producer payload"

requires=$(systemctl show --value --property=Requires 'nftfw-ad-producer@nftfw-test.service')
binds=$(systemctl show --value --property=BindsTo 'nftfw-ad-producer@nftfw-test.service')
after=$(systemctl show --value --property=After 'nftfw-ad-producer@nftfw-test.service')
[[ " $requires " == *' nftfw-ad-ready.service '* && \
    " $binds " == *' nftfw-ad-ready.service '* && \
    " $after " == *' nftfw-ad-ready.service '* ]] || fail "effective template graph omitted a required readiness edge"

echo "NETWORK_PRODUCER_GATE_DISPOSABLE_PASS"
