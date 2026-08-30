#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

readonly marker=/run/nftfw-disposable-test-guest
readonly package=nft-firewall-v2
readonly old_version=2.0.3
readonly new_version=2.1.0
readonly work_root=/opt/nftfw-package-rollback-disposable

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

[[ ${EUID:-$(id -u)} -eq 0 ]] || {
    echo "BLOCKED: disposable package rollback test requires guest root"
    exit 77
}
[[ $# -eq 4 ]] || {
    echo "usage: $0 OLD_DEB NEW_DEB OLD_SHA256 NEW_SHA256" >&2
    exit 64
}
readonly old_deb=$1 new_deb=$2 old_sha=$3 new_sha=$4

[[ -f $marker && ! -L $marker && $(stat -c '%u:%g:%a:%h' "$marker") == 0:0:600:1 ]] || {
    echo "BLOCKED: exact protected disposable-guest marker is required"
    exit 77
}
for tool in awk cmp docker dpkg dpkg-deb dpkg-query find install ip jq \
    lsinitramfs nft realpath sed sha256sum sort sqlite3 stat systemctl tar xargs; do
    command -v "$tool" >/dev/null || {
        echo "BLOCKED: missing disposable rollback prerequisite"
        exit 77
    }
done
[[ $old_deb == /* && $old_deb == "$(realpath -m -- "$old_deb")" && \
    -f $old_deb && ! -L $old_deb ]] || fail "old package path is unsafe"
[[ $new_deb == /* && $new_deb == "$(realpath -m -- "$new_deb")" && \
    -f $new_deb && ! -L $new_deb ]] || fail "new package path is unsafe"
[[ $old_sha =~ ^[0-9a-f]{64}$ && $new_sha =~ ^[0-9a-f]{64}$ ]] || fail "package hashes are malformed"
[[ $(sha256sum "$old_deb" | awk '{print $1}') == "$old_sha" ]] || fail "old package hash mismatch"
[[ $(sha256sum "$new_deb" | awk '{print $1}') == "$new_sha" ]] || fail "new package hash mismatch"
[[ $(dpkg-deb -f "$old_deb" Package) == "$package" && \
    $(dpkg-deb -f "$old_deb" Version) == "$old_version" ]] || fail "old package identity mismatch"
[[ $(dpkg-deb -f "$new_deb" Package) == "$package" && \
    $(dpkg-deb -f "$new_deb" Version) == "$new_version" ]] || fail "new package identity mismatch"
[[ $(dpkg-query -W -f='${db:Status-Abbrev} ${Version}' "$package") == "ii  $old_version" ]] || \
    fail "guest must begin with configured exact 2.0.3"
resolver_ready=0
for resolver_package in openresolv resolvconf systemd-resolved; do
    resolver_status=$(dpkg-query -W -f='${db:Status-Abbrev}' "$resolver_package" 2>/dev/null || true)
    if [[ $resolver_status == 'ii ' ]]; then
        resolver_ready=1
        break
    fi
done
((resolver_ready == 1)) || {
    echo "BLOCKED: disposable guest lacks a configured resolver package dependency"
    exit 77
}
[[ ! -e $work_root && ! -L $work_root ]] || fail "disposable work root already exists"
install -d -o root -g root -m 0700 "$work_root"

cleanup() {
    systemctl start nftfwd.service nftfw-web.service >/dev/null 2>&1 || true
}
trap cleanup EXIT

tree_digest() {
    local root=$1
    find "$root" -xdev -type f -print0 | sort -z |
        xargs -0 -r sha256sum | sha256sum | awk '{print $1}'
}

state_digest() {
    {
        find /var/lib/nftfw -xdev -type f \
            ! -path '/var/lib/nftfw/audit*' \
            ! -path '/var/lib/nftfw/backups/*' \
            ! -path '/var/lib/nftfw/generation-state/state.db' \
            ! -path '/var/lib/nftfw/generation-state/state.db-*' -print0 |
            sort -z | xargs -0 -r sha256sum
        printf '%s  %s\n' \
            "$(sqlite3 /var/lib/nftfw/generation-state/state.db .dump | sha256sum | awk '{print $1}')" \
            '/var/lib/nftfw/generation-state/state.db.logical-dump'
    } | sort | sha256sum | awk '{print $1}'
}

structural_nft() {
    nft -j list ruleset | jq -S '
        walk(if type == "object" then del(.handle, .packets, .bytes) else . end)
        | .nftables | map(select(.metainfo? | not))
    ' | sha256sum | awk '{print $1}'
}

docker_digest() {
    local -a ids
    mapfile -t ids < <(docker network ls -q)
    ((${#ids[@]} > 0)) || fail "Docker network inventory is empty"
    docker network inspect "${ids[@]}" |
        jq -S 'map(del(.Created,.Peers,.Containers)) | sort_by(.Name)' |
        sha256sum | awk '{print $1}'
}

unit_digest() {
    local unit fragment
    for unit in \
        nftfw-early.service nftfw-enforcement-ready.service \
        nftfw-rollback.service nftfw-rollback.timer \
        nftfw-setup-rollback.service nftfw-setup-rollback.timer \
        nftfw-managed-rollback.service nftfw-managed-rollback.timer \
        nftfw-vpn.service nftfw-web.service nftfwd.service; do
        systemctl show "$unit" --property=Id,LoadState,ActiveState,UnitFileState,FragmentPath
        fragment=$(systemctl show "$unit" --property=FragmentPath --value)
        if [[ -n $fragment && -f $fragment && ! -L $fragment ]]; then
            sha256sum "$fragment"
        fi
    done | sha256sum | awk '{print $1}'
}

initramfs_digest() {
    local image
    for image in /boot/initrd.img-*; do
        [[ -f $image && ! -L $image ]] || continue
        printf 'IMAGE %s\n' "${image##*/}"
        lsinitramfs -l "$image" | awk '$NF ~ /nftfw/ {print}' | sort
    done | sha256sum | awk '{print $1}'
}

snapshot() {
    printf 'CONFIG %s\n' "$(tree_digest /etc/nftfw)"
    printf 'STATE %s\n' "$(state_digest)"
    printf 'NFT %s\n' "$(structural_nft)"
    printf 'ROUTES %s\n' "$(ip -j -4 route show table all | jq -S . | sha256sum | awk '{print $1}')"
    printf 'RULES %s\n' "$(ip -j -4 rule show | jq -S . | sha256sum | awk '{print $1}')"
    printf 'SCHEMA %s\n' "$(sqlite3 /var/lib/nftfw/generation-state/state.db \
        "SELECT group_concat(version, ',') FROM (SELECT version FROM schema_migrations ORDER BY version);")"
    printf 'DOCKER %s\n' "$(docker_digest)"
    printf 'UNITS %s\n' "$(unit_digest)"
    printf 'INITRAMFS %s\n' "$(initramfs_digest)"
}

restore_fixture_units() {
    systemctl daemon-reload
    systemctl enable --now nftfwd.service nftfw-web.service >/dev/null
    systemctl disable --now nftfw-rollback.timer nftfw-early.service \
        nftfw-enforcement-ready.service >/dev/null 2>&1 || true
    systemctl is-active --quiet nftfwd.service nftfw-web.service
}

assert_exact_old() {
    local verification line
    [[ $(dpkg-query -W -f='${db:Status-Abbrev} ${Version}' "$package") == "ii  $old_version" ]] || \
        fail "exact 2.0.3 is not configured"
    [[ $(sha256sum /usr/lib/nftfw/nftfw | awk '{print $1}') == \
        "$(sed -n 's/^old_binary_sha256=//p' "$work_root/bundle/manifest")" ]] || \
        fail "restored binary differs from exact 2.0.3"
    verification=$(dpkg --verify "$package") || fail "dpkg could not verify restored 2.0.3"
    while IFS= read -r line; do
        [[ -n $line ]] || continue
        case "$line" in
            ?????????\ c\ /etc/nftfw/nftfw.toml) ;;
            *) fail "restored package payload verification failed" ;;
        esac
    done <<<"$verification"
    [[ ! -e /etc/nftfw/initramfs-managed-disabled-v1 && \
        ! -L /etc/nftfw/initramfs-managed-disabled-v1 ]] || \
        fail "managed initramfs disable marker remains"
}

payload=$work_root/new-payload
bundle=$work_root/bundle
install -d -o root -g root -m 0700 "$payload"
dpkg-deb -x "$new_deb" "$payload"
helper=$payload/usr/lib/nftfw/package-rollback
[[ -f $helper && ! -L $helper ]]
"$helper" prepare --old-package "$old_deb" --new-package "$new_deb" \
    --old-sha256 "$old_sha" --new-sha256 "$new_sha" --bundle "$bundle"
"$bundle/execute" verify --bundle "$bundle"

restore_fixture_units
snapshot >"$work_root/before.snapshot"

# Complete both package-manager steps from configured exact 2.1.0.
dpkg --install "$new_deb" >"$work_root/upgrade-complete.log" 2>&1
[[ $(dpkg-query -W -f='${db:Status-Abbrev} ${Version}' "$package") == "ii  $new_version" ]]
systemctl stop nftfw-web.service nftfwd.service
"$bundle/execute" execute --bundle "$bundle" >"$work_root/rollback-complete.log" 2>&1
restore_fixture_units
assert_exact_old
snapshot >"$work_root/after-complete.snapshot"
cmp -s "$work_root/before.snapshot" "$work_root/after-complete.snapshot" || \
    fail "complete two-step rollback changed protected state"

# Interrupt after the exact bridge configures, then resume the second step.
dpkg --install "$new_deb" >"$work_root/upgrade-resume.log" 2>&1
systemctl stop nftfw-web.service nftfwd.service
dpkg --force-downgrade --install "$bundle/bridge.deb" >"$work_root/bridge-resume.log" 2>&1
bridge_version=$(sed -n 's/^bridge_version=//p' "$bundle/manifest")
[[ $(dpkg-query -W -f='${db:Status-Abbrev} ${Version}' "$package") == "ii  $bridge_version" ]] || \
    fail "rollback bridge did not configure"
"$bundle/execute" execute --bundle "$bundle" >"$work_root/rollback-resume.log" 2>&1
restore_fixture_units
assert_exact_old
snapshot >"$work_root/after-resume.snapshot"
cmp -s "$work_root/before.snapshot" "$work_root/after-resume.snapshot" || \
    fail "resumed rollback changed protected state"

# A repeated request from already restored exact 2.0.3 is a verified no-op.
"$bundle/execute" execute --bundle "$bundle" >"$work_root/rollback-idempotent.log" 2>&1
assert_exact_old
snapshot >"$work_root/after-idempotent.snapshot"
cmp -s "$work_root/before.snapshot" "$work_root/after-idempotent.snapshot" || \
    fail "idempotent rollback changed protected state"

echo "PACKAGE_ROLLBACK_DISPOSABLE_COMPLETE_PASS"
