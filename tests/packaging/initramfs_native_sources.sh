#!/usr/bin/env bash
# The fixture deliberately overrides manager-dispatched commands after sourcing
# the exact product functions so conditional-context failures can be injected.
# shellcheck disable=SC2154,SC2218,SC2317
set -Eeuo pipefail
umask 077

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
[[ ${EUID:-$(id -u)} -eq 0 ]] || {
    echo "SKIP: native initramfs source regression requires root"
    exit 77
}
for tool in awk chmod chown cp find grep install mktemp rmdir sed sha256sum stat sync; do
    command -v "$tool" >/dev/null || { echo "SKIP: missing $tool"; exit 77; }
done

fixture=$(mktemp -d /tmp/nftfw-initramfs-native.XXXXXX)
cleanup() {
    find "$fixture" -depth -delete
}
trap cleanup EXIT

etc_nftfw=$fixture/etc/nftfw
etc_initramfs=$fixture/etc/initramfs-tools
source_root=$etc_initramfs/scripts/init-top
installed_root=$fixture/usr/lib/nftfw/initramfs
vendor_root=$fixture/usr/share/initramfs-tools/scripts/init-top
install -d -o root -g root -m 0755 "$source_root" \
    "$installed_root" "$vendor_root" "$fixture/run" "$fixture/boot"
install -d -o root -g root -m 0750 "$etc_nftfw"
install -o root -g root -m 0755 \
    "$root_dir/packaging/initramfs/nftfw-ipv6-early" "$installed_root/nftfw-ipv6-early"
install -o root -g root -m 0755 \
    "$root_dir/packaging/initramfs/nftfw-udev-gate" "$installed_root/nftfw-udev-gate"
install -o root -g root -m 0644 \
    "$root_dir/packaging/initramfs/nftfw-initramfs-guard.nft" \
    "$installed_root/nftfw-initramfs-guard.nft"
cat >"$vendor_root/udev" <<'VENDOR'
#!/bin/sh
set -eu
PREREQ=
case "${1:-}" in prereqs) echo "$PREREQ"; exit 0 ;; esac
printf '%s\n' vendor-ran
VENDOR
chmod 0755 "$vendor_root/udev"

# Load the exact manager functions with only absolute fixture roots rewritten;
# the command dispatcher is deliberately excluded from this isolated test.
sed \
    -e "s|/etc/nftfw|$etc_nftfw|g" \
    -e "s|/etc/initramfs-tools|$etc_initramfs|g" \
    -e "s|/usr/lib/nftfw/initramfs|$installed_root|g" \
    -e "s|/usr/share/initramfs-tools|$fixture/usr/share/initramfs-tools|g" \
    -e "s|/run/nftfw-initramfs|$fixture/run/nftfw-initramfs|g" \
    -e "s|/boot|$fixture/boot|g" \
    "$root_dir/packaging/initramfs/nftfw-initramfs-manage" |
    awk '/^require_root$/ { exit } { print }' >"$fixture/manager-library"
# shellcheck source=/dev/null
source "$fixture/manager-library"
original_verify_all_definition=$(declare -f verify_all)
test_cleanup() {
    set +e
    command find "$fixture" -depth -delete
}
trap test_cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

bin=$fixture/bin
install -d -o root -g root -m 0700 "$bin"
cat >"$bin/getent" <<'GETENT'
#!/bin/sh
set -eu
test "$#" -eq 2 && test "$1" = group && test "$2" = nftfw
case "${NFTFW_TEST_GETENT_MODE:-pass}" in
    pass) printf '%s\n' 'nftfw:x:0:' ;;
    absent) exit 2 ;;
    ambiguous) printf '%s\n' 'nftfw:x:0:' 'nftfw:x:1:' ;;
    invalid) printf '%s\n' 'nftfw:x:not-a-gid:' ;;
    *) exit 2 ;;
esac
GETENT
chmod 0700 "$bin/getent"
real_update_count=$fixture/update-count
cat >"$bin/update-initramfs" <<'UPDATE'
#!/bin/sh
set -eu
count=0
test ! -f "$NFTFW_TEST_UPDATE_COUNT" || count=$(cat "$NFTFW_TEST_UPDATE_COUNT")
count=$((count + 1))
printf '%s\n' "$count" >"$NFTFW_TEST_UPDATE_COUNT"
if test "${NFTFW_TEST_UPDATE_MODE:-pass}" = fail-first && test "$count" -eq 1; then
    exit 1
fi
exit 0
UPDATE
chmod 0700 "$bin/update-initramfs"
export PATH="$bin:$PATH" NFTFW_TEST_UPDATE_COUNT=$real_update_count

verify_all() {
    count=0
    test ! -f "$fixture/verify-count" || count=$(cat "$fixture/verify-count")
    count=$((count + 1))
    printf '%s\n' "$count" >"$fixture/verify-count"
    if [[ ${NFTFW_TEST_VERIFY_MODE:-pass} == fail-first && $count -eq 1 ]]; then
        return 1
    fi
}

reset_disabled() {
    rm -f -- "$marker" "$owner" "$source_loader" "$source_gate" \
        "$source_root/nftfw-udev-vendor" "$fixture/hardlink"
    rm -f -- "$real_update_count" "$fixture/verify-count"
    export NFTFW_TEST_GETENT_MODE=pass NFTFW_TEST_UPDATE_MODE=pass NFTFW_TEST_VERIFY_MODE=pass
    [[ $(state) == disabled ]]
}

assert_state_directory_refused() {
    if (require_state_directory "$etc_nftfw") >/dev/null 2>&1; then
        echo "FAIL: unsafe NFTFW package state directory was accepted" >&2
        exit 1
    fi
}

# The package state directory has a distinct root:nftfw 0750 contract. The
# fixture's protected getent maps nftfw to gid 0 so the checks remain isolated
# from host account databases while still exercising numeric group binding.
reset_disabled
[[ $(require_state_directory "$etc_nftfw") == *:0:0:750 ]]
chmod 0755 "$etc_nftfw"
assert_state_directory_refused
chmod 0750 "$etc_nftfw"
chown 0:1 "$etc_nftfw"
assert_state_directory_refused
chown 1:0 "$etc_nftfw"
assert_state_directory_refused
chown 0:0 "$etc_nftfw"
mv "$etc_nftfw" "$etc_nftfw.saved"
ln -s "$etc_nftfw.saved" "$etc_nftfw"
assert_state_directory_refused
rm -f -- "$etc_nftfw"
mv "$etc_nftfw.saved" "$etc_nftfw"
mv "$etc_nftfw" "$etc_nftfw.absent"
assert_state_directory_refused
mv "$etc_nftfw.absent" "$etc_nftfw"
for group_mode in absent ambiguous invalid; do
    export NFTFW_TEST_GETENT_MODE=$group_mode
    assert_state_directory_refused
done
export NFTFW_TEST_GETENT_MODE=pass

# Directory identities are bound before publication. Replacing either target
# directory between preflight and publication must be refused before a target
# file is created.
require_installed_inputs
mv "$source_root" "$source_root.saved"
install -d -o root -g root -m 0755 "$source_root"
if (publish_file "$installed_loader" "$source_loader" 0755) >/dev/null 2>&1; then
    echo "FAIL: changed native source directory was accepted" >&2
    exit 1
fi
[[ ! -e $source_loader && ! -L $source_loader ]]
rmdir "$source_root"
mv "$source_root.saved" "$source_root"
require_installed_inputs
mv "$etc_nftfw" "$etc_nftfw.saved"
install -d -o root -g root -m 0750 "$etc_nftfw"
if (publish_text test "$marker" 0600) >/dev/null 2>&1; then
    echo "FAIL: changed NFTFW state directory was accepted" >&2
    exit 1
fi
[[ ! -e $marker && ! -L $marker ]]
rmdir "$etc_nftfw"
mv "$etc_nftfw.saved" "$etc_nftfw"

reset_disabled
rebuild_enabled
[[ $(state) == enabled ]]
first_state=$(sha256sum "$marker" "$owner" "$source_loader" "$source_gate")
rebuild_enabled
[[ $(sha256sum "$marker" "$owner" "$source_loader" "$source_gate") == "$first_state" ]]
disable_transaction
[[ $(state) == disabled ]]

# A failed first rebuild and a failed first verification both return to the
# exact disabled source state through a second successful disabled rebuild.
for failure in update verify; do
    reset_disabled
    if [[ $failure == update ]]; then
        export NFTFW_TEST_UPDATE_MODE=fail-first
    else
        export NFTFW_TEST_VERIFY_MODE=fail-first
    fi
    if (rebuild_enabled) >/dev/null 2>&1; then
        echo "FAIL: failed $failure enable was reported as successful" >&2
        exit 1
    fi
    rollback_state=$(state)
    [[ $rollback_state == disabled ]] || {
        echo "FAIL: failed $failure enable left source state $rollback_state" >&2
        exit 1
    }
done

# Publication failures before and after atomic rename are caught from nested
# subshell/OR-list contexts and return to the exact disabled state.
for failure in marker-mktemp loader-install gate-move owner-post-sync; do
    reset_disabled
    export NFTFW_TEST_PUBLICATION_FAILURE=$failure
    mktemp() {
        if [[ ${NFTFW_TEST_PUBLICATION_FAILURE:-} == marker-mktemp &&
            $1 == "$marker.nftfw.XXXXXX" ]]; then
            return 1
        fi
        command mktemp "$@"
    }
    install() {
        local target=${!#}
        if [[ ${NFTFW_TEST_PUBLICATION_FAILURE:-} == loader-install &&
            $target == "$source_loader.nftfw."* ]]; then
            return 1
        fi
        command install "$@"
    }
    mv() {
        local target=${!#}
        if [[ ${NFTFW_TEST_PUBLICATION_FAILURE:-} == gate-move && $target == "$source_gate" ]]; then
            return 1
        fi
        command mv "$@"
    }
    sync() {
        if [[ ${NFTFW_TEST_PUBLICATION_FAILURE:-} == owner-post-sync &&
            ${1:-} == -f && ${2:-} == "$etc_nftfw" && -e $owner ]]; then
            return 1
        fi
        command sync "$@"
    }
    if (rebuild_enabled) >/dev/null 2>&1; then
        echo "FAIL: $failure publication failure was reported as successful" >&2
        exit 1
    fi
    unset -f mktemp install mv sync
    unset NFTFW_TEST_PUBLICATION_FAILURE
    [[ $(state) == disabled ]]
done

# A failed disable rebuild restores all four exact ownership files and proves
# the enabled state again before returning failure.
reset_disabled
rebuild_enabled
rm -f -- "$real_update_count" "$fixture/verify-count"
export NFTFW_TEST_UPDATE_MODE=fail-first NFTFW_TEST_VERIFY_MODE=pass
if (disable_transaction) >/dev/null 2>&1; then
    echo "FAIL: failed disable was reported as successful" >&2
    exit 1
fi
[[ $(state) == enabled ]]
disable_transaction

# Partial, foreign, symlinked, writable, hard-linked, and colliding states are
# never adopted as NFTFW ownership.
reset_disabled
install -o root -g root -m 0755 "$installed_loader" "$source_loader"
if (state) >/dev/null 2>&1; then echo "FAIL: partial state accepted" >&2; exit 1; fi
reset_disabled
printf '%s\n' foreign >"$source_gate"
if (state) >/dev/null 2>&1; then echo "FAIL: foreign gate accepted" >&2; exit 1; fi
reset_disabled
ln -s missing "$source_gate"
if (state) >/dev/null 2>&1; then echo "FAIL: symlink gate accepted" >&2; exit 1; fi
reset_disabled
rebuild_enabled
chmod 0775 "$source_loader"
if (state) >/dev/null 2>&1; then echo "FAIL: writable loader accepted" >&2; exit 1; fi
chmod 0755 "$source_loader"
ln "$source_loader" "$fixture/hardlink"
if (state) >/dev/null 2>&1; then echo "FAIL: hard-linked loader accepted" >&2; exit 1; fi
rm -f "$fixture/hardlink"
disable_transaction
install -o root -g root -m 0755 "$vendor_udev" "$source_root/nftfw-udev-vendor"
if (require_installed_inputs) >/dev/null 2>&1; then
    echo "FAIL: delegated vendor collision accepted" >&2
    exit 1
fi
rm -f "$source_root/nftfw-udev-vendor"

mv "$source_root" "$source_root.absent"
if (require_installed_inputs) >/dev/null 2>&1; then
    echo "FAIL: absent native source parent accepted" >&2
    exit 1
fi
mv "$source_root.absent" "$source_root"

# The build hook is marker-inert, validates the native staged sources, and
# copies the current vendor implementation under the non-ordered alias.
sed \
    -e "s|^marker=/etc/nftfw/initramfs-managed-disabled-v1$|marker=$etc_nftfw/initramfs-managed-disabled-v1|" \
    -e "s|^owner=/etc/nftfw/initramfs-source-owner-v1$|owner=$etc_nftfw/initramfs-source-owner-v1|" \
    -e "s|^loader=/usr/lib/nftfw/initramfs/nftfw-ipv6-early$|loader=$installed_root/nftfw-ipv6-early|" \
    -e "s|^gate=/usr/lib/nftfw/initramfs/nftfw-udev-gate$|gate=$installed_root/nftfw-udev-gate|" \
    -e "s|^rules=/usr/lib/nftfw/initramfs/nftfw-initramfs-guard.nft$|rules=$installed_root/nftfw-initramfs-guard.nft|" \
    -e "s|^source_loader=/etc/initramfs-tools/scripts/init-top/nftfw-ipv6-early$|source_loader=$source_root/nftfw-ipv6-early|" \
    -e "s|^source_gate=/etc/initramfs-tools/scripts/init-top/udev$|source_gate=$source_root/udev|" \
    -e "s|^vendor_udev=/usr/share/initramfs-tools/scripts/init-top/udev$|vendor_udev=$vendor_root/udev|" \
    -e "s|/etc/initramfs-tools/scripts/init-top/\$vendor_alias|$source_root/\$vendor_alias|" \
    -e "s|/usr/share/initramfs-tools/scripts/init-top/\$vendor_alias|$vendor_root/\$vendor_alias|" \
    -e "s|^\. /usr/share/initramfs-tools/hook-functions$|. $fixture/usr/share/initramfs-tools/hook-functions|" \
    "$root_dir/packaging/initramfs/nftfw-early-guard-hook" >"$fixture/hook"
chmod 0700 "$fixture/hook"
cat >"$fixture/usr/share/initramfs-tools/hook-functions" <<'HOOK_FUNCTIONS'
manual_add_modules() { :; }
copy_exec() { :; }
copy_file() { install -D -o root -g root -m 0755 "$2" "$DESTDIR$3"; }
HOOK_FUNCTIONS

prepare_dest() {
    export DESTDIR=$fixture/dest-$1
    install -d -o root -g root -m 0755 "$DESTDIR/scripts/init-top" "$DESTDIR/etc/nftfw"
    if [[ -e $source_loader ]]; then
        install -o root -g root -m 0755 "$source_loader" "$DESTDIR/scripts/init-top/nftfw-ipv6-early"
    fi
    if [[ -e $source_gate ]]; then
        install -o root -g root -m 0755 "$source_gate" "$DESTDIR/scripts/init-top/udev"
    else
        install -o root -g root -m 0755 "$vendor_udev" "$DESTDIR/scripts/init-top/udev"
    fi
}

reset_disabled
prepare_dest inert
before=$(find "$DESTDIR" -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum)
"$fixture/hook"
after=$(find "$DESTDIR" -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum)
[[ $before == "$after" ]]

rebuild_enabled
prepare_dest enabled
"$fixture/hook"
[[ $(sha256sum "$DESTDIR/scripts/init-top/nftfw-udev-vendor" | awk '{print $1}') == \
    $(sha256sum "$vendor_udev" | awk '{print $1}') ]]
[[ ! -e $DESTDIR/scripts/init-top/ORDER ]]
[[ $(wc -l <"$DESTDIR/etc/nftfw/initramfs-guard.sha256") -eq 2 ]]

prepare_dest changed-gate
printf '%s\n' '# changed' >>"$DESTDIR/scripts/init-top/udev"
if "$fixture/hook" >/dev/null 2>&1; then
    echo "FAIL: changed staged gate accepted" >&2
    exit 1
fi

verify_enabled_base=$fixture/verify-enabled-base
verify_disabled_base=$fixture/verify-disabled-base
install -d -o root -g root -m 0700 \
    "$verify_enabled_base/scripts/init-top" "$verify_enabled_base/etc/nftfw" \
    "$verify_disabled_base/scripts/init-top"
install -o root -g root -m 0755 "$installed_loader" \
    "$verify_enabled_base/scripts/init-top/nftfw-ipv6-early"
install -o root -g root -m 0755 "$installed_gate" \
    "$verify_enabled_base/scripts/init-top/udev"
install -o root -g root -m 0755 "$vendor_udev" \
    "$verify_enabled_base/scripts/init-top/nftfw-udev-vendor"
install -o root -g root -m 0644 "$installed_rules" \
    "$verify_enabled_base/etc/nftfw/initramfs-guard.nft"
printf '%s\n' "$marker_value" >"$verify_enabled_base/etc/nftfw/initramfs-managed-disabled-v1"
chmod 0600 "$verify_enabled_base/etc/nftfw/initramfs-managed-disabled-v1"
printf '%s  %s\n%s  %s\n' \
    "$(sha256sum "$installed_rules" | awk '{print $1}')" "$etc_nftfw/initramfs-guard.nft" \
    "$(sha256sum "$vendor_udev" | awk '{print $1}')" /scripts/init-top/nftfw-udev-vendor \
    >"$verify_enabled_base/etc/nftfw/initramfs-guard.sha256"
chmod 0600 "$verify_enabled_base/etc/nftfw/initramfs-guard.sha256"
cat >"$verify_enabled_base/scripts/init-top/ORDER" <<'ENABLED_ORDER'
/scripts/init-top/nftfw-ipv6-early "$@"
[ -e /conf/param.conf ] && . /conf/param.conf
/scripts/init-top/udev "$@"
[ -e /conf/param.conf ] && . /conf/param.conf
ENABLED_ORDER
chmod 0644 "$verify_enabled_base/scripts/init-top/ORDER"

install -o root -g root -m 0755 "$vendor_udev" \
    "$verify_disabled_base/scripts/init-top/udev"
cat >"$verify_disabled_base/scripts/init-top/ORDER" <<'DISABLED_ORDER'
/scripts/init-top/udev "$@"
[ -e /conf/param.conf ] && . /conf/param.conf
DISABLED_ORDER
chmod 0644 "$verify_disabled_base/scripts/init-top/ORDER"

verify_source=
verify_unmk_mode=pass
unmkinitramfs() {
    [[ $verify_unmk_mode == pass ]] || return 1
    cp -a "$verify_source/." "$2/" || return 1
}
lsinitramfs() {
    [[ $verify_unmk_mode != listing-fail ]] || return 1
    (cd "$verify_source" && command find . -mindepth 1 -printf '%P\n')
}

verify_case=
prepare_verify_case() {
    local base=$1
    verify_case=$(mktemp -d "$fixture/verify-case.XXXXXX")
    cp -a "$base/." "$verify_case/"
    verify_source=$verify_case
    verify_unmk_mode=pass
}
clear_verify_case() {
    [[ -z $verify_case ]] || find "$verify_case" -depth -delete
    verify_case=
}
expect_enabled_rejected() {
    local name=$1 check
    check=$(mktemp -d "$fixture/verify-check.XXXXXX")
    if (true && verify_image_enabled "$fixture/fake-image" "$check"); then
        echo "FAIL: enabled verifier accepted $name" >&2
        exit 1
    fi
    find "$check" -depth -delete
    clear_verify_case
}
expect_disabled_rejected() {
    local name=$1 check
    check=$(mktemp -d "$fixture/verify-check.XXXXXX")
    if (verify_image_disabled "$fixture/fake-image" "$check" || false); then
        echo "FAIL: disabled verifier accepted $name" >&2
        exit 1
    fi
    find "$check" -depth -delete
    clear_verify_case
}

prepare_verify_case "$verify_enabled_base"
valid_check=$(mktemp -d "$fixture/verify-check.XXXXXX")
if ! (true && verify_image_enabled "$fixture/fake-image" "$valid_check"); then
    echo "FAIL: valid enabled verifier fixture was rejected" >&2
    exit 1
fi
find "$valid_check" -depth -delete
clear_verify_case

for mutation in loader gate vendor rules marker checksum order mode owner missing symlink duplicate; do
    prepare_verify_case "$verify_enabled_base"
    case $mutation in
        loader) printf '%s\n' '# changed' >>"$verify_case/scripts/init-top/nftfw-ipv6-early" ;;
        gate) printf '%s\n' '# changed' >>"$verify_case/scripts/init-top/udev" ;;
        vendor) printf '%s\n' '# changed' >>"$verify_case/scripts/init-top/nftfw-udev-vendor" ;;
        rules) printf '%s\n' '# changed' >>"$verify_case/etc/nftfw/initramfs-guard.nft" ;;
        marker) printf '%s\n' changed >"$verify_case/etc/nftfw/initramfs-managed-disabled-v1" ;;
        checksum) printf '%s\n' changed >"$verify_case/etc/nftfw/initramfs-guard.sha256" ;;
        order) sed -i '/param.conf/{x;p;x;}' "$verify_case/scripts/init-top/ORDER" ;;
        mode) chmod 0700 "$verify_case/scripts/init-top/nftfw-ipv6-early" ;;
        owner) chown 1:0 "$verify_case/scripts/init-top/nftfw-ipv6-early" ;;
        missing) rm -f -- "$verify_case/scripts/init-top/nftfw-ipv6-early" ;;
        symlink)
            rm -f -- "$verify_case/scripts/init-top/udev"
            ln -s nftfw-ipv6-early "$verify_case/scripts/init-top/udev"
            ;;
        duplicate)
            install -d -o root -g root -m 0700 "$verify_case/duplicate/scripts/init-top"
            install -o root -g root -m 0755 "$installed_loader" \
                "$verify_case/duplicate/scripts/init-top/nftfw-ipv6-early"
            ;;
    esac
    expect_enabled_rejected "$mutation mutation"
done

gate_backup=$fixture/installed-gate.backup
install -o root -g root -m 0755 "$installed_gate" "$gate_backup"
prepare_verify_case "$verify_enabled_base"
sed -i 's/^PREREQ=.*/PREREQ=wrong-prerequisite/' "$installed_gate" \
    "$verify_case/scripts/init-top/udev"
expect_enabled_rejected "wrong gate prerequisite"
install -o root -g root -m 0755 "$gate_backup" "$installed_gate"

prepare_verify_case "$verify_enabled_base"
verify_unmk_mode=fail
expect_enabled_rejected "failed extraction"

prepare_verify_case "$verify_disabled_base"
valid_check=$(mktemp -d "$fixture/verify-check.XXXXXX")
if ! (verify_image_disabled "$fixture/fake-image" "$valid_check" || false); then
    echo "FAIL: valid disabled verifier fixture was rejected" >&2
    exit 1
fi
find "$valid_check" -depth -delete
clear_verify_case

for mutation in gate order artifact mode owner missing duplicate listing; do
    prepare_verify_case "$verify_disabled_base"
    case $mutation in
        gate) printf '%s\n' '# changed' >>"$verify_case/scripts/init-top/udev" ;;
        order) printf '%s\n' '/scripts/init-top/nftfw-ipv6-early "$@"' >>"$verify_case/scripts/init-top/ORDER" ;;
        artifact)
            install -o root -g root -m 0755 "$installed_loader" \
                "$verify_case/scripts/init-top/nftfw-ipv6-early"
            ;;
        mode) chmod 0700 "$verify_case/scripts/init-top/udev" ;;
        owner) chown 1:0 "$verify_case/scripts/init-top/udev" ;;
        missing) rm -f -- "$verify_case/scripts/init-top/udev" ;;
        duplicate)
            install -d -o root -g root -m 0700 "$verify_case/duplicate/scripts/init-top"
            install -o root -g root -m 0755 "$vendor_udev" \
                "$verify_case/duplicate/scripts/init-top/udev"
            ;;
        listing) verify_unmk_mode=listing-fail ;;
    esac
    expect_disabled_rejected "$mutation mutation"
done

vendor_backup=$fixture/vendor-udev.backup
install -o root -g root -m 0755 "$vendor_udev" "$vendor_backup"
prepare_verify_case "$verify_disabled_base"
sed -i 's/^PREREQ=.*/PREREQ=nftfw-ipv6-early/' "$vendor_udev" \
    "$verify_case/scripts/init-top/udev"
expect_disabled_rejected "NFTFW disabled prerequisite"
install -o root -g root -m 0755 "$vendor_backup" "$vendor_udev"

# Restore the exact aggregate verifier and prove that a later invalid image and
# a successful EXIT cleanup cannot be masked by nested conditional contexts.
eval "$original_verify_all_definition"
mktemp() {
    if [[ $# -eq 1 && $1 == /tmp/nftfw-initramfs-images.XXXXXX ]]; then
        command mktemp "$fixture/aggregate-images.XXXXXX"
    elif [[ $# -eq 1 && $1 == /tmp/nftfw-initramfs-paths.XXXXXX ]]; then
        command mktemp "$fixture/aggregate-paths.XXXXXX"
    elif [[ $# -eq 2 && $1 == -d && $2 == /tmp/nftfw-initramfs-verify.XXXXXX ]]; then
        command mktemp -d "$fixture/aggregate-verify.XXXXXX"
    else
        command mktemp "$@"
    fi
}
aggregate_bad=$fixture/verify-aggregate-bad
install -d -o root -g root -m 0700 "$aggregate_bad"
cp -a "$verify_enabled_base/." "$aggregate_bad/"
printf '%s\n' '# changed' >>"$aggregate_bad/scripts/init-top/nftfw-ipv6-early"

# The exact aggregate verifier returns its result to the enable transaction.
# A failed rebuilt image must therefore reach the disabled rollback instead of
# exiting from inside an AND-list and leaving the four ownership files live.
initrds() {
    printf '%s\0' "$fixture/transaction-image"
}
unmkinitramfs() {
    local source=$verify_disabled_base
    [[ ! -e $marker ]] || source=$aggregate_bad
    cp -a "$source/." "$2/"
}
lsinitramfs() {
    local source=$verify_disabled_base
    [[ ! -e $marker ]] || source=$aggregate_bad
    (cd "$source" && command find . -mindepth 1 -printf '%P\n')
}
reset_disabled
if (true && rebuild_enabled) >/dev/null 2>&1; then
    echo "FAIL: exact verifier failure bypassed enable rollback" >&2
    exit 1
fi
[[ $(state) == disabled ]]

initrds() {
    printf '%s\0' "$fixture/good-image" "$fixture/bad-image"
}
unmkinitramfs() {
    local source
    case $1 in
        "$fixture/good-image") source=$verify_enabled_base ;;
        "$fixture/bad-image") source=$aggregate_bad ;;
        *) return 1 ;;
    esac
    cp -a "$source/." "$2/"
}
if (true && verify_all enabled); then
    echo "FAIL: aggregate verifier masked a later invalid image" >&2
    exit 1
fi

initrds() {
    printf '%s\0' "$fixture/good-image"
}
find() {
    if [[ ${NFTFW_TEST_FIND_CLEANUP:-} == fail-once && $# -eq 3 &&
        $2 == -depth && $3 == -delete ]]; then
        NFTFW_TEST_FIND_CLEANUP=passed
        return 1
    fi
    command find "$@"
}
export NFTFW_TEST_FIND_CLEANUP=fail-once
if (verify_all enabled || false); then
    echo "FAIL: aggregate verifier masked cleanup failure" >&2
    exit 1
fi
unset -f find
unset -f mktemp
unset NFTFW_TEST_FIND_CLEANUP

echo "INITRAMFS_NATIVE_SOURCES_PASS"
