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

write_bridge_scripts() {
    local control=$1 expected_new_sha=$2
    apply_control_version "$control/control" "$bridge_version"
    printf 'X-NFTFW-Rollback-Bridge: %s:%s\n' "$old_sha" "$new_sha" >>"$control/control"
    cat >"$control/preinst" <<EOF
#!/bin/sh
set -eu
action=\${1:-}
previous=\${2:-}
[ "\$action" = upgrade ]
[ "\$previous" = "$new_version" ]
[ "\$(dpkg-query -W -f='\${db:Status-Abbrev} \${Version}' $package_name 2>/dev/null)" = "ii  $new_version" ]
[ "\$(sha256sum /usr/lib/nftfw/nftfw | awk '{print \$1}')" = "$expected_new_sha" ]
database=/var/lib/nftfw/generation-state/state.db
if [ -e "\$database" ]; then
    [ -f "\$database" ] && [ ! -L "\$database" ]
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
    [[ -f $new_root/usr/lib/nftfw/package-rollback && ! -L $new_root/usr/lib/nftfw/package-rollback ]] || fail "new package omits rollback helper"
    [[ $(sha "$helper") == $(sha "$new_root/usr/lib/nftfw/package-rollback") ]] || fail "helper is not bound to the new package"
    old_binary_sha=$(dpkg-deb --fsys-tarfile "$old_package" | tar -xOf - ./usr/lib/nftfw/nftfw | sha256sum | awk '{print $1}')
    new_binary_sha=$(sha "$new_root/usr/lib/nftfw/nftfw")

    dpkg-deb --raw-extract "$old_package" "$stage"
    old_sha=$expected_old_sha
    new_sha=$expected_new_sha
    bridge_version="$old_version~nftfwrollback1.${new_sha:0:12}"
    write_bridge_scripts "$stage/DEBIAN" "$new_binary_sha"
    dpkg-deb --root-owner-group --build "$stage" "$bridge_tmp" >/dev/null
    [[ $(deb_field "$bridge_tmp" Version) == "$bridge_version" ]] || fail "rollback bridge version is invalid"
    [[ $(deb_field "$bridge_tmp" X-NFTFW-Rollback-Bridge) == "$old_sha:$new_sha" ]] || fail "rollback bridge identity is invalid"
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
    [[ $(wc -l <"$manifest") -eq 13 ]] || fail "bundle manifest field count is invalid"
    [[ $(manifest_value "$manifest" schema) == "$manifest_schema" ]]
    [[ $(manifest_value "$manifest" package) == "$package_name" ]]
    architecture=$(manifest_value "$manifest" architecture)
    case "$architecture" in amd64|arm64) ;; *) fail "bundle architecture is invalid" ;; esac
    [[ $(manifest_value "$manifest" old_version) == "$old_version" ]]
    [[ $(manifest_value "$manifest" new_version) == "$new_version" ]]
    bridge_version=$(manifest_value "$manifest" bridge_version)
    [[ $bridge_version =~ ^2\.0\.3~nftfwrollback1\.[0-9a-f]{12}$ ]]
    for key in old_sha256 new_sha256 bridge_sha256 helper_sha256 old_payload_sha256 old_binary_sha256 new_binary_sha256; do
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

    if [[ $version == "$new_version" ]]; then
        [[ -x /usr/lib/nftfw/initramfs/nftfw-initramfs-manage ]] || fail "managed initramfs rollback helper is missing"
        /usr/lib/nftfw/initramfs/nftfw-initramfs-manage disable
        dpkg --force-downgrade --install "$bundle/bridge.deb"
        [[ $(installed_version) == "$bridge" ]] || fail "rollback bridge did not configure"
        [[ $(sha /usr/lib/nftfw/nftfw) == $(manifest_value "$manifest" old_binary_sha256) ]] || fail "rollback bridge payload is not exact 2.0.3"
    fi
    dpkg --install "$bundle/old.deb"
    [[ $(installed_version) == "$old_version" ]] || fail "exact 2.0.3 package did not configure"
    [[ $(sha /usr/lib/nftfw/nftfw) == $(manifest_value "$manifest" old_binary_sha256) ]] || fail "restored binary is not exact 2.0.3"
    verify_installed_payload
    echo "Exact NFT Firewall V2 2.0.3 package rollback complete."
}

require_root
for tool in awk cat chmod dpkg dpkg-deb dpkg-query find flock grep id install mktemp mv realpath rm sed sha256sum sort sqlite3 stat tar wc; do
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
