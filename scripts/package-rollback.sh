#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

readonly package_name=nft-firewall-v2
readonly old_version=2.0.3
readonly new_version=2.1.0
readonly manifest_schema=nftfw.package-rollback.v1

fail() {
    echo "NFTFW package rollback: $*" >&2
    exit 1
}

require_root() {
    [[ ${EUID:-$(id -u)} -eq 0 ]] || fail "root is required"
}

regular_protected() {
    local path=$1
    [[ -f $path && ! -L $path ]] || return 1
    [[ $(stat -c '%u:%g' "$path") == 0:0 ]] || return 1
    [[ $(stat -c '%h' "$path") == 1 ]] || return 1
    [[ -z $(find "$path" -maxdepth 0 -type f -perm /022 -print -quit) ]]
}

protected_directory_chain() {
    local path=$1
    [[ $path == /* && $path != / && $path == "$(realpath -m -- "$path")" ]] || return 1
    while :; do
        [[ -d $path && ! -L $path ]] || return 1
        [[ $(stat -c %u "$path") == 0 ]] || return 1
        if [[ $path != /tmp && $path != /var/tmp ]]; then
            [[ -z $(find "$path" -maxdepth 0 -type d -perm /022 ! -perm -1000 -print -quit) ]] || return 1
        fi
        [[ $path == / ]] && return 0
        path=${path%/*}
        [[ -n $path ]] || path=/
    done
}

sha() {
    sha256sum "$1" | awk '{print $1}'
}

deb_field() {
    dpkg-deb -f "$1" "$2"
}

validate_deb() {
    local path=$1 version=$2 expected_sha=$3 architecture=$4
    protected_directory_chain "${path%/*}" || fail "package input parent is not protected"
    regular_protected "$path" || fail "package input is not a protected root-owned regular file"
    [[ $(sha "$path") == "$expected_sha" ]] || fail "package input checksum mismatch"
    [[ $(deb_field "$path" Package) == "$package_name" ]] || fail "unexpected package name"
    [[ $(deb_field "$path" Version) == "$version" ]] || fail "unexpected package version"
    [[ $(deb_field "$path" Architecture) == "$architecture" ]] || fail "package architecture mismatch"
    [[ $(deb_field "$path" X-NFTFW-Build-Disposition) == release ]] || fail "package is not a release build"
    dpkg-deb --info "$path" >/dev/null
    dpkg-deb --contents "$path" >/dev/null
}

payload_digest() {
    local package=$1 temporary root
    temporary=$(mktemp -d /tmp/nftfw-rollback-payload.XXXXXX)
    root=$temporary/root
    install -d -o root -g root -m 0700 "$root"
    dpkg-deb -x "$package" "$root"
    tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
        -C "$root" -cf - . | sha256sum | awk '{print $1}'
    rm -rf -- "$temporary"
}

transition_digest() {
    local architecture=$1 bridge_version=$2 old_sha=$3 new_sha=$4 old_binary_sha=$5 new_binary_sha=$6
    printf '%s\n' \
        "schema=$manifest_schema" \
        "package=$package_name" \
        "architecture=$architecture" \
        "old_version=$old_version" \
        "new_version=$new_version" \
        "bridge_version=$bridge_version" \
        "old_sha256=$old_sha" \
        "new_sha256=$new_sha" \
        "old_binary_sha256=$old_binary_sha" \
        "new_binary_sha256=$new_binary_sha" |
        sha256sum | awk '{print $1}'
}

write_bridge_scripts() {
    local control=$1 architecture=$2 bridge_version=$3 old_sha=$4 new_sha=$5
    local old_binary_sha=$6 new_binary_sha=$7 expected_transition_sha=$8
    apply_control_version "$control/control" "$bridge_version"
    printf 'X-NFTFW-Rollback-Bridge: %s:%s\n' "$old_sha" "$new_sha" >>"$control/control"
    printf 'X-NFTFW-Rollback-Transition: %s\n' "$expected_transition_sha" >>"$control/control"
    cat >"$control/preinst" <<EOF
#!/bin/sh
set -eu
package=$package_name
architecture=$architecture
old_version=$old_version
new_version=$new_version
bridge_version=$bridge_version
old_sha256=$old_sha
new_sha256=$new_sha
old_binary_sha256=$old_binary_sha
new_binary_sha256=$new_binary_sha
expected_transition_sha256=$expected_transition_sha
binary=/usr/lib/nftfw/nftfw
database=/var/lib/nftfw/generation-state/state.db

[ "\$#" -eq 3 ]
[ "\$1" = upgrade ]
[ "\$2" = "\$new_version" ]
[ "\$3" = "\$bridge_version" ]
[ "\$(dpkg --print-architecture)" = "\$architecture" ]
[ "\$(dpkg-query -W -f='\${db:Status-Abbrev} \${Version}' "\$package")" = "iHR \$new_version" ]

transition_sha256=\$(
    printf '%s\n' \\
        "schema=$manifest_schema" \\
        "package=\$package" \\
        "architecture=\$architecture" \\
        "old_version=\$old_version" \\
        "new_version=\$new_version" \\
        "bridge_version=\$bridge_version" \\
        "old_sha256=\$old_sha256" \\
        "new_sha256=\$new_sha256" \\
        "old_binary_sha256=\$old_binary_sha256" \\
        "new_binary_sha256=\$new_binary_sha256" |
        sha256sum | awk '{print \$1}'
)
[ "\$transition_sha256" = "\$expected_transition_sha256" ]

for directory in /usr /usr/lib /usr/lib/nftfw; do
    [ -d "\$directory" ] && [ ! -L "\$directory" ]
    directory_metadata=\$(stat -c '%u:%a' "\$directory")
    directory_owner=\${directory_metadata%%:*}
    directory_mode=\${directory_metadata#*:}
    case "\$directory_mode" in *[!0-7]*|'') exit 1 ;; esac
    [ "\$directory_owner" = 0 ]
    [ "\$((0\$directory_mode & 0022))" -eq 0 ]
done
[ -f "\$binary" ] && [ ! -L "\$binary" ]
[ "\$(stat -c '%u:%g:%a:%h' "\$binary")" = '0:0:755:1' ]
[ "\$(sha256sum "\$binary" | awk '{print \$1}')" = "\$new_binary_sha256" ]

if [ -e "\$database" ] || [ -L "\$database" ]; then
    for directory in /var /var/lib /var/lib/nftfw /var/lib/nftfw/generation-state; do
        [ -d "\$directory" ] && [ ! -L "\$directory" ]
        directory_metadata=\$(stat -c '%u:%a' "\$directory")
        directory_owner=\${directory_metadata%%:*}
        directory_mode=\${directory_metadata#*:}
        case "\$directory_mode" in *[!0-7]*|'') exit 1 ;; esac
        [ "\$directory_owner" = 0 ]
        [ "\$((0\$directory_mode & 0022))" -eq 0 ]
    done
    [ -f "\$database" ] && [ ! -L "\$database" ]
    state_gid=\$(id -g nftfw-web)
    case "\$state_gid" in *[!0-9]*|'') exit 1 ;; esac
    [ "\$state_gid" -gt 0 ]
    database_metadata=\$(stat -c '%u:%g:%a:%h' "\$database")
    case "\$database_metadata" in
        '0:0:600:1'|"0:\$state_gid:600:1") ;;
        *) exit 1 ;;
    esac
    history=\$(sqlite3 -batch -noheader "file:\$database?mode=ro&immutable=1" \
        "SELECT group_concat(version, ',') FROM (SELECT version FROM schema_migrations ORDER BY version);")
    [ "\$history" = '1,2,3,4,5,6' ]
fi
exit 0
EOF
    cat >"$control/postinst" <<EOF
#!/bin/sh
set -eu
[ "\${1:-}" = configure ]
exit 0
EOF
    cat >"$control/prerm" <<EOF
#!/bin/sh
set -eu
[ "\${1:-}" = upgrade ]
[ "\${2:-}" = "$old_version" ]
exit 0
EOF
    cat >"$control/postrm" <<EOF
#!/bin/sh
set -eu
case "\${1:-}" in upgrade|abort-upgrade|failed-upgrade) exit 0 ;; *) exit 1 ;; esac
EOF
    chmod 0755 "$control/preinst" "$control/postinst" "$control/prerm" "$control/postrm"
}

apply_control_version() {
    local control=$1 version=$2 temporary
    temporary=$control.nftfw
    [[ $(grep -c '^Version: ' "$control") -eq 1 ]]
    awk -v version="$version" '
        /^Version: / { print "Version: " version; next }
        { print }
    ' "$control" >"$temporary"
    mv -f -- "$temporary" "$control"
}

prepare_bundle() {
    local old_package='' new_package='' bundle='' expected_old_sha='' expected_new_sha=''
    while (( $# > 0 )); do
        case "$1" in
            --old-package) old_package=${2:-}; shift 2 ;;
            --new-package) new_package=${2:-}; shift 2 ;;
            --bundle) bundle=${2:-}; shift 2 ;;
            --old-sha256) expected_old_sha=${2:-}; shift 2 ;;
            --new-sha256) expected_new_sha=${2:-}; shift 2 ;;
            *) fail "unknown prepare argument" ;;
        esac
    done
    [[ $expected_old_sha =~ ^[0-9a-f]{64}$ && $expected_new_sha =~ ^[0-9a-f]{64}$ ]] || fail "package checksums are required"
    for package_path in "$old_package" "$new_package"; do
        [[ $package_path == /* && $package_path != / && $package_path == "$(realpath -m -- "$package_path")" ]] || fail "package input path must be absolute and canonical"
    done
    [[ $bundle == /* && $bundle != / && $bundle == "$(realpath -m -- "$bundle")" ]] || fail "bundle path must be absolute and canonical"
    [[ ! -e $bundle && ! -L $bundle ]] || fail "bundle target already exists"
    protected_directory_chain "${bundle%/*}" || fail "bundle parent is not protected"
    local architecture helper new_root stage bridge_tmp old_payload bridge_payload old_binary_sha new_binary_sha
    local bridge_version transition_sha
    architecture=$(dpkg --print-architecture)
    case "$architecture" in amd64|arm64) ;; *) fail "unsupported architecture" ;; esac
    validate_deb "$old_package" "$old_version" "$expected_old_sha" "$architecture"
    validate_deb "$new_package" "$new_version" "$expected_new_sha" "$architecture"
    helper=$(realpath -- "$0")
    protected_directory_chain "${helper%/*}" || fail "rollback helper parent is not protected"
    regular_protected "$helper" || fail "rollback helper is not protected"

    new_root=$(mktemp -d /tmp/nftfw-rollback-new.XXXXXX)
    stage=$(mktemp -d /tmp/nftfw-rollback-bridge.XXXXXX)
    bridge_tmp=$(mktemp /tmp/nftfw-rollback-bridge.XXXXXX.deb)
    trap 'rm -rf -- "$new_root" "$stage"; rm -f -- "$bridge_tmp"' RETURN
    dpkg-deb -x "$new_package" "$new_root"
    regular_protected "$new_root/usr/lib/nftfw/package-rollback" || fail "new package rollback helper is unsafe"
    regular_protected "$new_root/usr/lib/nftfw/nftfw" || fail "new package binary is unsafe"
    [[ $(sha "$helper") == $(sha "$new_root/usr/lib/nftfw/package-rollback") ]] || fail "helper is not bound to the new package"
    old_binary_sha=$(dpkg-deb --fsys-tarfile "$old_package" | tar -xOf - ./usr/lib/nftfw/nftfw | sha256sum | awk '{print $1}')
    new_binary_sha=$(sha "$new_root/usr/lib/nftfw/nftfw")

    dpkg-deb --raw-extract "$old_package" "$stage"
    local old_sha=$expected_old_sha new_sha=$expected_new_sha
    bridge_version="$old_version~nftfwrollback1.${new_sha:0:12}"
    transition_sha=$(transition_digest "$architecture" "$bridge_version" "$old_sha" "$new_sha" \
        "$old_binary_sha" "$new_binary_sha")
    write_bridge_scripts "$stage/DEBIAN" "$architecture" "$bridge_version" "$old_sha" "$new_sha" \
        "$old_binary_sha" "$new_binary_sha" "$transition_sha"
    dpkg-deb --root-owner-group --build "$stage" "$bridge_tmp" >/dev/null
    [[ $(deb_field "$bridge_tmp" Version) == "$bridge_version" ]] || fail "rollback bridge version is invalid"
    [[ $(deb_field "$bridge_tmp" X-NFTFW-Rollback-Bridge) == "$old_sha:$new_sha" ]] || fail "rollback bridge identity is invalid"
    [[ $(deb_field "$bridge_tmp" X-NFTFW-Rollback-Transition) == "$transition_sha" ]] || fail "rollback transition identity is invalid"
    old_payload=$(payload_digest "$old_package")
    bridge_payload=$(payload_digest "$bridge_tmp")
    [[ $old_payload == "$bridge_payload" ]] || fail "rollback bridge payload differs from exact 2.0.3"

    install -d -o root -g root -m 0700 "$bundle"
    install -o root -g root -m 0600 "$old_package" "$bundle/old.deb"
    install -o root -g root -m 0600 "$new_package" "$bundle/new.deb"
    install -o root -g root -m 0600 "$bridge_tmp" "$bundle/bridge.deb"
    install -o root -g root -m 0700 "$helper" "$bundle/execute"
    cat >"$bundle/manifest" <<EOF
schema=$manifest_schema
package=$package_name
architecture=$architecture
old_version=$old_version
new_version=$new_version
bridge_version=$bridge_version
old_sha256=$old_sha
new_sha256=$new_sha
bridge_sha256=$(sha "$bundle/bridge.deb")
helper_sha256=$(sha "$bundle/execute")
old_payload_sha256=$old_payload
old_binary_sha256=$old_binary_sha
new_binary_sha256=$new_binary_sha
transition_sha256=$transition_sha
EOF
    chmod 0600 "$bundle/manifest"
    verify_bundle "$bundle"
    trap - RETURN
    rm -rf -- "$new_root" "$stage"
    rm -f -- "$bridge_tmp"
    echo "Verified rollback bundle: $bundle"
}

manifest_value() {
    local manifest=$1 key=$2
    [[ $(grep -c "^$key=" "$manifest") -eq 1 ]] || return 1
    sed -n "s/^$key=//p" "$manifest"
}

verify_bundle() {
    local bundle=$1 manifest key value architecture bridge_version old_sha new_sha
    manifest=$bundle/manifest
    protected_directory_chain "$bundle" || fail "bundle directory chain is not protected"
    [[ $(stat -c %a "$bundle") == 700 ]] || fail "bundle mode is not 0700"
    for file in manifest old.deb new.deb bridge.deb execute; do
        regular_protected "$bundle/$file" || fail "bundle file is unsafe"
    done
    [[ $(wc -l <"$manifest") -eq 14 ]] || fail "bundle manifest field count is invalid"
    [[ $(manifest_value "$manifest" schema) == "$manifest_schema" ]]
    [[ $(manifest_value "$manifest" package) == "$package_name" ]]
    architecture=$(manifest_value "$manifest" architecture)
    case "$architecture" in amd64|arm64) ;; *) fail "bundle architecture is invalid" ;; esac
    [[ $(manifest_value "$manifest" old_version) == "$old_version" ]]
    [[ $(manifest_value "$manifest" new_version) == "$new_version" ]]
    bridge_version=$(manifest_value "$manifest" bridge_version)
    [[ $bridge_version =~ ^2\.0\.3~nftfwrollback1\.[0-9a-f]{12}$ ]]
    for key in old_sha256 new_sha256 bridge_sha256 helper_sha256 old_payload_sha256 old_binary_sha256 new_binary_sha256 transition_sha256; do
        value=$(manifest_value "$manifest" "$key")
        [[ $value =~ ^[0-9a-f]{64}$ ]] || fail "bundle digest is invalid"
    done
    old_sha=$(manifest_value "$manifest" old_sha256)
    new_sha=$(manifest_value "$manifest" new_sha256)
    [[ $(sha "$bundle/old.deb") == "$old_sha" ]]
    [[ $(sha "$bundle/new.deb") == "$new_sha" ]]
    [[ $(sha "$bundle/bridge.deb") == $(manifest_value "$manifest" bridge_sha256) ]]
    [[ $(sha "$bundle/execute") == $(manifest_value "$manifest" helper_sha256) ]]
    validate_deb "$bundle/old.deb" "$old_version" "$old_sha" "$architecture"
    validate_deb "$bundle/new.deb" "$new_version" "$new_sha" "$architecture"
    [[ $(deb_field "$bundle/bridge.deb" Package) == "$package_name" ]]
    [[ $(deb_field "$bundle/bridge.deb" Version) == "$bridge_version" ]]
    [[ $(deb_field "$bundle/bridge.deb" Architecture) == "$architecture" ]]
    [[ $(deb_field "$bundle/bridge.deb" X-NFTFW-Rollback-Bridge) == "$old_sha:$new_sha" ]]
    [[ $(deb_field "$bundle/bridge.deb" X-NFTFW-Rollback-Transition) == $(manifest_value "$manifest" transition_sha256) ]]
    [[ $(manifest_value "$manifest" transition_sha256) == $(transition_digest "$architecture" "$bridge_version" \
        "$old_sha" "$new_sha" "$(manifest_value "$manifest" old_binary_sha256)" \
        "$(manifest_value "$manifest" new_binary_sha256)") ]]
    [[ $(payload_digest "$bundle/old.deb") == $(manifest_value "$manifest" old_payload_sha256) ]]
    [[ $(payload_digest "$bundle/bridge.deb") == $(manifest_value "$manifest" old_payload_sha256) ]]
}

installed_version() {
    local status
    status=$(dpkg-query -W -f='${db:Status-Abbrev} ${Version}' "$package_name" 2>/dev/null) || return 1
    [[ $status == ii\ \ * ]] || return 1
    printf '%s\n' "${status#ii  }"
}

verify_installed_payload() {
    local output line
    output=$(dpkg --verify "$package_name") || fail "dpkg could not verify the installed package"
    while IFS= read -r line; do
        [[ -n $line ]] || continue
        case "$line" in
            ?????????\ c\ /etc/nftfw/nftfw.toml) ;;
            *) fail "installed package-owned payload verification failed" ;;
        esac
    done <<<"$output"
}

validate_exact_old_configuration() {
    local bundle=$1 temporary root binary expected
    temporary=$(mktemp -d /tmp/nftfw-rollback-config.XXXXXX)
    root=$temporary/root
    install -d -o root -g root -m 0700 "$root"
    if ! dpkg-deb -x "$bundle/old.deb" "$root"; then
        rm -rf -- "$temporary"
        fail "cannot inspect the exact 2.0.3 configuration contract"
    fi
    binary=$root/usr/lib/nftfw/nftfw
    expected=$(manifest_value "$bundle/manifest" old_binary_sha256)
    if ! regular_protected "$binary" || [[ $(sha "$binary") != "$expected" ]] ||
        ! "$binary" config validate /etc/nftfw/nftfw.toml >/dev/null 2>&1; then
        rm -rf -- "$temporary"
        fail "current configuration is not exact 2.0.3-compatible; restore the protected pre-2.1.0 configuration or use package removal"
    fi
    rm -rf -- "$temporary"
}

install_exact_old_package() {
    local package_path=$1 private_lock canonical_identity private_identity status
    private_lock=$(mktemp /run/nftfw/.package-rollback-maintscript-lock.XXXXXX)
    chmod 0600 "$private_lock"
    regular_protected "$private_lock" || fail "private maintainer-script lock is unsafe"
    canonical_identity=$(stat -Lc '%d:%i' /run/nftfw/mutation.lock)
    private_identity=$(stat -Lc '%d:%i' "$private_lock")
    [[ $canonical_identity != "$private_identity" ]] || fail "private maintainer-script lock aliases the canonical lock"

    # Exact 2.0.3's preinst deliberately takes /run/nftfw/mutation.lock while
    # creating its verified state backup.  The rollback parent must retain the
    # real global lock for the entire dpkg transaction, so give only dpkg and
    # its descendants a private mount-namespace view of that one pathname.
    # External NFTFW processes continue to see the parent-held canonical lock;
    # the legacy preinst sees and locks the protected transaction-local inode.
    # The private shell expands only its positional parameters.
    # shellcheck disable=SC2016
    if unshare --mount --propagation private /bin/sh -eu -c '
        private_lock=$1
        package_path=$2
        canonical_lock=/run/nftfw/mutation.lock
        [ -f "$private_lock" ] && [ ! -L "$private_lock" ]
        [ "$(stat -c "%u:%g:%a:%h" "$private_lock")" = 0:0:600:1 ]
        [ -f "$canonical_lock" ] && [ ! -L "$canonical_lock" ]
        [ "$(stat -c "%u:%g:%a:%h" "$canonical_lock")" = 0:0:600:1 ]
        [ "$(stat -Lc "%d:%i" "$private_lock")" != "$(stat -Lc "%d:%i" "$canonical_lock")" ]
        mount --bind "$private_lock" "$canonical_lock"
        [ "$(stat -Lc "%d:%i" "$private_lock")" = "$(stat -Lc "%d:%i" "$canonical_lock")" ]
        [ "$(stat -c "%u:%g:%a:%h" "$canonical_lock")" = 0:0:600:1 ]
        exec dpkg --install "$package_path"
    ' nftfw-package-rollback "$private_lock" "$package_path"; then
        status=0
    else
        status=$?
    fi
    regular_protected "$private_lock" || fail "private maintainer-script lock changed during dpkg"
    rm -f -- "$private_lock"
    return "$status"
}

execute_bundle() {
    local bundle='' version manifest bridge current_helper
    while (( $# > 0 )); do
        case "$1" in
            --bundle) bundle=${2:-}; shift 2 ;;
            *) fail "unknown execute argument" ;;
        esac
    done
    [[ -n $bundle ]] || fail "bundle is required"
    verify_bundle "$bundle"
    manifest=$bundle/manifest
    current_helper=$(realpath -- "$0")
    [[ $(sha "$current_helper") == $(manifest_value "$manifest" helper_sha256) ]] || fail "executing helper is not bundle-bound"
    version=$(installed_version) || fail "installed package state is not configured"
    bridge=$(manifest_value "$manifest" bridge_version)
    if [[ $version == "$old_version" ]]; then
        [[ $(sha /usr/lib/nftfw/nftfw) == $(manifest_value "$manifest" old_binary_sha256) ]] || fail "installed 2.0.3 binary is not exact"
        verify_installed_payload
        echo "Exact NFT Firewall V2 2.0.3 package already restored."
        return
    fi
    [[ $version == "$new_version" || $version == "$bridge" ]] || fail "installed package is outside the resumable rollback states"

    install -d -o root -g nftfw-web -m 0750 /run/nftfw
    [[ ! -L /run/nftfw/mutation.lock && ( ! -e /run/nftfw/mutation.lock || -f /run/nftfw/mutation.lock ) ]] || fail "mutation lock is unsafe"
    exec 9<>/run/nftfw/mutation.lock
    chmod 0600 /run/nftfw/mutation.lock
    flock -w 30 9 || fail "mutation lock is busy"
    chown root:root /run/nftfw/mutation.lock
    regular_protected /run/nftfw/mutation.lock || fail "canonical mutation lock is unsafe"
    [[ $(stat -c '%u:%g:%a:%h' /run/nftfw/mutation.lock) == 0:0:600:1 ]] ||
        fail "canonical mutation lock identity is unsafe"

    if [[ $version == "$new_version" ]]; then
        # Refuse before the boot-policy handoff or dpkg can mutate anything.
        # Exact 2.0.3 deliberately rejects 2.1-only configuration fields; a
        # package rollback must never discover that incompatibility after the
        # old payload has already been unpacked.
        validate_exact_old_configuration "$bundle"
        [[ -x /usr/lib/nftfw/initramfs/nftfw-initramfs-manage ]] || fail "managed initramfs rollback helper is missing"
        local setup_journal=/var/lib/nftfw/setup/journal.json
        [[ ! -L $setup_journal ]] || fail "setup journal is an unsafe link"
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
            [[ -x /usr/lib/nftfw/nftfw ]] || fail "managed boot-policy helper is missing"
            /usr/lib/nftfw/nftfw setup boot-handoff --package-downgrade
        else
            /usr/lib/nftfw/initramfs/nftfw-initramfs-manage disable
        fi
        # The handoff may run update-initramfs and update-grub. Revalidate the
        # old parser contract immediately before package replacement so a
        # concurrent privileged edit cannot turn a preflight pass into a
        # half-configured downgrade.
        validate_exact_old_configuration "$bundle"
        dpkg --force-downgrade --install "$bundle/bridge.deb"
        [[ $(installed_version) == "$bridge" ]] || fail "rollback bridge did not configure"
        [[ $(sha /usr/lib/nftfw/nftfw) == $(manifest_value "$manifest" old_binary_sha256) ]] || fail "rollback bridge payload is not exact 2.0.3"
    fi
    install_exact_old_package "$bundle/old.deb"
    [[ $(installed_version) == "$old_version" ]] || fail "exact 2.0.3 package did not configure"
    [[ $(sha /usr/lib/nftfw/nftfw) == $(manifest_value "$manifest" old_binary_sha256) ]] || fail "restored binary is not exact 2.0.3"
    verify_installed_payload
    echo "Exact NFT Firewall V2 2.0.3 package rollback complete."
}

require_root
for tool in awk cat chmod chown dpkg dpkg-deb dpkg-query find flock grep id install mktemp mount mv realpath rm sed sha256sum sort sqlite3 stat tar unshare wc; do
    command -v "$tool" >/dev/null || fail "missing prerequisite: $tool"
done
case "${1:-}" in
    prepare)
        shift
        prepare_bundle "$@"
        ;;
    verify)
        shift
        [[ ${1:-} == --bundle && -n ${2:-} && $# -eq 2 ]] || fail "usage: package-rollback verify --bundle PATH"
        verify_bundle "$2"
        echo "Rollback bundle verified."
        ;;
    execute)
        shift
        execute_bundle "$@"
        ;;
    *)
        fail "usage: package-rollback {prepare|verify|execute} ..."
        ;;
esac
