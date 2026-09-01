#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "install.sh must run as root" >&2; exit 1; fi
if (( $# != 0 )); then echo "Usage: install.sh" >&2; exit 2; fi
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
BIN_DIR=/usr/lib/nftfw
CONF_DIR=/etc/nftfw
STATE_DIR=/var/lib/nftfw
DATABASE=$STATE_DIR/generation-state/state.db
DOC_DIR=/usr/share/doc/nft-firewall-v2
DOC_EXAMPLE_DIR=$DOC_DIR/examples
RUNTIME_DIR=/run/nftfw
case "$(uname -m)" in x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;; esac

for command_name in nft ip wg systemctl systemd-analyze sha256sum awk getent groupadd useradd install readlink mktemp sed grep find findmnt dpkg dpkg-query jq sqlite3 lsinitramfs unmkinitramfs update-initramfs update-grub efibootmgr; do
    command -v "$command_name" >/dev/null || { echo "Missing prerequisite: $command_name" >&2; exit 1; }
done
protected_root_file() {
    local path=$1
    [[ -f "$path" && ! -L "$path" ]] || return 1
    [[ $(find "$path" -maxdepth 0 -type f -uid 0 ! -perm /022 -print -quit) == "$path" ]]
}
protected_root_directory() {
    local path=$1
    [[ -d "$path" && ! -L "$path" ]] || return 1
    [[ $(find "$path" -maxdepth 0 -type d -uid 0 ! -perm /022 -print -quit) == "$path" ]]
}
protected_root_directory_chain() {
    local path=$1
    while :; do
        # A sticky root-owned parent (for example /var/tmp) cannot be used by
        # another user to rename this root-owned extraction out from under the
        # installer. Other ancestors must not be group/other writable.
        [[ $(find "$path" -maxdepth 0 -type d -uid 0 \
            \( ! -perm /022 -o -perm -1000 \) -print -quit) == "$path" ]] || return 1
        [[ "$path" == / ]] && return 0
        path=${path%/*}
        [[ -n "$path" ]] || path=/
    done
}
binary_identity() {
    local binary=$1 output version commit build_date disposition artifact_identity
    output=$("$binary" version --json 2>/dev/null) || return 1
    version=$(jq -er '.version | select(type == "string")' <<< "$output") || return 1
    commit=$(jq -er '.commit | select(type == "string")' <<< "$output") || return 1
    build_date=$(jq -er '.build_date | select(type == "string")' <<< "$output") || return 1
    disposition=$(jq -er '.build_disposition | select(type == "string")' <<< "$output") || return 1
    artifact_identity=$(jq -er '.artifact_identity | select(type == "string")' <<< "$output") || return 1
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([~+][A-Za-z0-9.]+)?$ ]] || return 1
    [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || return 1
    [[ "$build_date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || return 1
    case "$disposition" in development|ci|stage-r-candidate-only|release) ;; *) return 1 ;; esac
    [[ "$artifact_identity" == "$version|$commit|$build_date|$disposition" ]] || return 1
    printf '%s %s %s\n' "$version" "$commit" "$disposition"
}
schema_is_exact_v6() {
    local database=$1 history
    history=$(
        sqlite3 -batch -noheader "file:$database?mode=ro&immutable=1" \
            "SELECT group_concat(version, ',') FROM (SELECT version FROM schema_migrations ORDER BY version);" \
            2>/dev/null
    ) || return 1
    [[ "$history" == '1,2,3,4,5,6' ]]
}
protected_root_directory_chain "$ROOT_DIR" || {
    echo "The release source must be extracted beneath a protected root-owned directory chain." >&2
    exit 1
}
for directory in "$ROOT_DIR/dist" "$ROOT_DIR/configs" \
    "$ROOT_DIR/packaging" "$ROOT_DIR/packaging/systemd" \
    "$ROOT_DIR/packaging/initramfs" "$ROOT_DIR/scripts"; do
    protected_root_directory "$directory" || {
        echo "Release input directory must be protected and root-owned: $directory" >&2
        exit 1
    }
done
for input in \
    "$ROOT_DIR/scripts/install.sh" \
    "$ROOT_DIR/scripts/package-rollback.sh" \
    "$ROOT_DIR/scripts/verify-systemd-units.sh" \
    "$ROOT_DIR/configs/nftfw.example.toml" \
    "$ROOT_DIR/packaging/systemd/nftfw-early.service" \
    "$ROOT_DIR/packaging/systemd/nftfw-enforcement-ready.service" \
    "$ROOT_DIR/packaging/systemd/nftfw-rollback.service" \
    "$ROOT_DIR/packaging/systemd/nftfw-rollback.timer" \
    "$ROOT_DIR/packaging/systemd/nftfw-setup-rollback.service" \
    "$ROOT_DIR/packaging/systemd/nftfw-setup-rollback.timer" \
    "$ROOT_DIR/packaging/systemd/nftfw-setup-boot-hold.service" \
    "$ROOT_DIR/packaging/systemd/nftfw-setup-docker-hold.service" \
    "$ROOT_DIR/packaging/systemd/nftfw-setup-boot-hold-generator" \
    "$ROOT_DIR/packaging/systemd/nftfw-managed-rollback.service" \
    "$ROOT_DIR/packaging/systemd/nftfw-managed-rollback.timer" \
    "$ROOT_DIR/packaging/systemd/nftfw-vpn.service" \
    "$ROOT_DIR/packaging/systemd/nftfw-web.service" \
    "$ROOT_DIR/packaging/systemd/nftfwd.service" \
    "$ROOT_DIR/packaging/systemd/nftfwd-docker-access.conf.example" \
    "$ROOT_DIR/packaging/systemd/nftfwd-final-early.conf.example" \
    "$ROOT_DIR/packaging/systemd/nftfw-rollback-final-early.conf.example" \
    "$ROOT_DIR/packaging/systemd/nftfw-consumer-final-ready.conf.example"; do
    protected_root_file "$input" || {
        echo "Release input must be a protected root-owned regular file: $input" >&2
        exit 1
    }
done
for input in \
    "$ROOT_DIR/packaging/initramfs/nftfw-ipv6-early" \
    "$ROOT_DIR/packaging/initramfs/nftfw-udev-gate" \
    "$ROOT_DIR/packaging/initramfs/nftfw-initramfs-guard.nft" \
    "$ROOT_DIR/packaging/initramfs/nftfw-initramfs-manage" \
    "$ROOT_DIR/packaging/initramfs/nftfw-early-guard-hook"; do
    protected_root_file "$input" || {
        echo "Release initramfs input must be a protected root-owned regular file: $input" >&2
        exit 1
    }
done
protected_root_file "$ROOT_DIR/dist/SHA256SUMS" || {
    echo "dist/SHA256SUMS must be a protected root-owned regular file." >&2
    exit 1
}
for binary in nftfw nftfwd nftfw-web; do [[ -x "$ROOT_DIR/dist/$binary-linux-$ARCH" ]] || { echo "Missing dist/$binary-linux-$ARCH; run make release" >&2; exit 1; }; done
for binary in nftfw nftfwd nftfw-web; do
    protected_root_file "$ROOT_DIR/dist/$binary-linux-$ARCH" || {
        echo "Candidate binary must be a protected root-owned regular file: dist/$binary-linux-$ARCH" >&2
        exit 1
    }
    expected=$(awk -v file="$binary-linux-$ARCH" '$2 == file { print $1 }' "$ROOT_DIR/dist/SHA256SUMS")
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || { echo "Missing checksum for $binary-linux-$ARCH" >&2; exit 1; }
    actual=$(sha256sum "$ROOT_DIR/dist/$binary-linux-$ARCH" | awk '{ print $1 }')
    [[ "$actual" == "$expected" ]] || { echo "Checksum mismatch for $binary-linux-$ARCH" >&2; exit 1; }
done
read -r candidate_version candidate_commit candidate_disposition candidate_extra < <(
    binary_identity "$ROOT_DIR/dist/nftfw-linux-$ARCH"
) || {
    echo "Candidate NFTFW version/commit/date/disposition identity is malformed or unknown." >&2
    exit 1
}
if [[ -n "$candidate_extra" || "$candidate_disposition" != release || \
    "$candidate_version" == *~stage.r.* ]]; then
    echo "Refusing non-release NFTFW source artifacts (build disposition: ${candidate_disposition:-unknown})." >&2
    echo "Development, CI, and Stage R candidate artifacts are intrinsically non-installable." >&2
    exit 1
fi
[[ "$candidate_version" == 2.1.0 ]] || {
    echo "Refusing source installer candidate version ${candidate_version:-unknown}; expected exact release 2.1.0." >&2
    exit 1
}
dpkg --validate-version "$candidate_version" >/dev/null 2>&1 || {
    echo "Candidate NFTFW version is not a valid Debian version: $candidate_version" >&2
    exit 1
}

for directory in "$BIN_DIR" "$CONF_DIR" "$STATE_DIR" "$STATE_DIR/backups" \
    "$STATE_DIR/generation-state" "$STATE_DIR/generations" "$DOC_DIR" \
    "$DOC_EXAMPLE_DIR" "$RUNTIME_DIR"; do
    [[ ! -L "$directory" && ( ! -e "$directory" || -d "$directory" ) ]] || {
        echo "Refusing unsafe installation directory: $directory" >&2
        exit 1
    }
    if [[ -d "$directory" ]] && ! protected_root_directory "$directory"; then
        echo "Refusing an installation directory with unsafe ownership or permissions: $directory" >&2
        exit 1
    fi
done

validation_dir=""
candidate_config=""
if [[ -e "$CONF_DIR/nftfw.toml" || -L "$CONF_DIR/nftfw.toml" ]]; then
    protected_root_file "$CONF_DIR/nftfw.toml" || {
        echo "Configuration must be a protected root-owned regular file: $CONF_DIR/nftfw.toml" >&2
        exit 1
    }
    candidate_config="$CONF_DIR/nftfw.toml"
else
    validation_dir=$(mktemp -d /run/nftfw-install-validate.XXXXXX)
    trap '[[ -z "$validation_dir" ]] || rm -rf -- "$validation_dir"' EXIT
    install -o root -g root -m 0600 "$ROOT_DIR/configs/nftfw.example.toml" "$validation_dir/nftfw.toml"
    candidate_config="$validation_dir/nftfw.toml"
fi
"$ROOT_DIR/dist/nftfw-linux-$ARCH" config validate "$candidate_config" >/dev/null || {
    echo "Candidate configuration is invalid; installation made no changes." >&2
    exit 1
}
bash "$ROOT_DIR/scripts/verify-systemd-units.sh" "$ROOT_DIR" "$ARCH" >/dev/null
if [[ -n "$validation_dir" ]]; then
    rm -rf -- "$validation_dir"
    validation_dir=""
    trap - EXIT
fi

if [[ -e "$STATE_DIR/state.db" || -L "$STATE_DIR/state.db" ]]; then
    echo "Refusing legacy state at $STATE_DIR/state.db; no 2.0.2 migration was executed." >&2
    exit 1
fi
if [[ -e "$BIN_DIR/nftfw" || -L "$BIN_DIR/nftfw" ]]; then
    if ! protected_root_file "$BIN_DIR/nftfw" || [[ ! -x "$BIN_DIR/nftfw" ]]; then
        echo "Refusing to execute an unprotected installed NFTFW binary: $BIN_DIR/nftfw" >&2
        exit 1
    fi
    read -r installed_version installed_commit installed_disposition installed_extra < <(
        binary_identity "$BIN_DIR/nftfw"
    ) || {
        echo "Refusing an installed NFTFW binary with malformed or unknown version/commit/date/disposition identity." >&2
        exit 1
    }
    if [[ -n "$installed_extra" || "$installed_disposition" != release ]]; then
        echo "Refusing an installed NFTFW binary whose build disposition is not release." >&2
        exit 1
    fi
    dpkg --validate-version "$installed_version" >/dev/null 2>&1 || {
        echo "Refusing an installed NFTFW binary with an invalid version identity." >&2
        exit 1
    }
    if dpkg --compare-versions "$installed_version" gt "$candidate_version"; then
        echo "Refusing to downgrade NFT Firewall V2 from $installed_version to $candidate_version." >&2
        echo "A newer generation schema must not be opened by an older source installation." >&2
        exit 1
    fi
    if dpkg --compare-versions "$installed_version" lt '2.0.2~'; then
        echo "Refusing an in-place source upgrade from NFT Firewall V2 $installed_version." >&2
        echo "Pre-2.0.2 state requires the separately reviewed offline migration command and contract." >&2
        echo "No installed service or file was changed." >&2
        exit 1
    fi
    case "$installed_version" in
        2.0.2|2.0.2-*|2.0.2+*|2.0.2~*|2.0.3|2.0.3-*|2.0.3+*|2.0.3~*|2.1.0|2.1.0-*|2.1.0+*|2.1.0~*) ;;
        *)
            echo "Refusing an incompatible NFT Firewall V2 version identity: $installed_version" >&2
            exit 1
            ;;
    esac
    if dpkg --compare-versions "$installed_version" eq "$candidate_version" &&
        [[ "$installed_commit" != "$candidate_commit" ]]; then
        echo "Refusing same-version NFT Firewall overwrite with a different commit." >&2
        echo "installed=$installed_version@$installed_commit candidate=$candidate_version@$candidate_commit" >&2
        exit 1
    fi
elif [[ -e "$DATABASE" || -L "$DATABASE" || \
        -e "$STATE_DIR/enforcement-enabled" || -L "$STATE_DIR/enforcement-enabled" || \
        -e "$STATE_DIR/provenance-ledger.db" || -L "$STATE_DIR/provenance-ledger.db" || \
        -e /etc/systemd/system/nftfwd.service || -L /etc/systemd/system/nftfwd.service || \
        -e /usr/lib/systemd/system/nftfwd.service || -L /usr/lib/systemd/system/nftfwd.service ]]; then
    echo "Refusing an in-place source upgrade whose installed NFT Firewall version cannot be established." >&2
    echo "The separately reviewed offline migration command and contract are required." >&2
    exit 1
fi
existing_canonical_state=false
if [[ -L "$DATABASE" ]]; then
    echo "Refusing symlinked state database: $DATABASE" >&2
    exit 1
elif [[ -s "$DATABASE" ]]; then
    schema_is_exact_v6 "$DATABASE" || {
        echo "Refusing canonical state whose migration history is not exactly schema 1..6: $DATABASE" >&2
        echo "No implicit state migration was executed." >&2
        exit 1
    }
    existing_canonical_state=true
elif [[ -e "$DATABASE" ]]; then
    echo "Refusing an unsafe or empty state database: $DATABASE" >&2
    exit 1
fi
if [[ -e /usr/sbin/nftfw || -L /usr/sbin/nftfw ]]; then
    [[ -L /usr/sbin/nftfw && $(readlink /usr/sbin/nftfw) == "$BIN_DIR/nftfw" ]] || { echo "Refusing to replace unrelated /usr/sbin/nftfw" >&2; exit 1; }
fi
install -d -o root -g root -m 0755 "$BIN_DIR"
if ! getent group nftfw >/dev/null; then groupadd --system nftfw; fi
if ! getent group nftfw-web >/dev/null; then groupadd --system nftfw-web; fi
if ! id nftfw-web >/dev/null 2>&1; then useradd --system --gid nftfw-web --home-dir /var/empty --shell /usr/sbin/nologin nftfw-web; fi
install -d -o root -g nftfw -m 0750 "$CONF_DIR"
install -d -o root -g nftfw-web -m 0750 "$RUNTIME_DIR"
install -d -o root -g root -m 0700 "$STATE_DIR" "$STATE_DIR/backups" \
    "$STATE_DIR/generation-state" "$STATE_DIR/generations"
install -d -o root -g root -m 0755 "$DOC_DIR" "$DOC_EXAMPLE_DIR"
if [[ "$existing_canonical_state" == true ]]; then
    backup="$STATE_DIR/backups/state-before-install-$(date -u +%Y%m%dT%H%M%SZ)-$$.db"
    [[ ! -e "$backup" && ! -L "$backup" ]] || {
        echo "Refusing to overwrite an existing pre-install backup: $backup" >&2
        exit 1
    }
    [[ -x "$BIN_DIR/nftfw" ]] || {
        echo "Cannot safely back up existing state: the installed NFTFW backup command is unavailable." >&2
        exit 1
    }
    if ! NFTFW_RUNTIME_DIR="$RUNTIME_DIR" NFTFW_STATE_DB='' \
        "$BIN_DIR/nftfw" state backup "$backup" --database "$DATABASE"; then
        if [[ -e "$backup" || -L "$backup" ]]; then
            echo "Installed backup command failed after creating $backup; preserving it for diagnosis and stopping." >&2
        else
            echo "Installed backup command or canonical mutation lock failed; no unlocked fallback was attempted." >&2
        fi
        exit 1
    fi
    if ! NFTFW_RUNTIME_DIR="$RUNTIME_DIR" NFTFW_STATE_DB='' \
        "$BIN_DIR/nftfw" state verify --database "$backup"; then
        echo "Pre-install backup failed nonmutating verification; preserving $backup and stopping." >&2
        exit 1
    fi
    schema_is_exact_v6 "$backup" || {
        echo "Pre-install backup is not exact schema 6; preserving $backup and stopping." >&2
        exit 1
    }
fi
install -o root -g root -m 0755 "$ROOT_DIR/dist/nftfw-linux-$ARCH" "$BIN_DIR/nftfw"
install -o root -g root -m 0755 "$ROOT_DIR/dist/nftfwd-linux-$ARCH" "$BIN_DIR/nftfwd"
install -o root -g root -m 0755 "$ROOT_DIR/dist/nftfw-web-linux-$ARCH" "$BIN_DIR/nftfw-web"
install -o root -g root -m 0755 "$ROOT_DIR/scripts/package-rollback.sh" "$BIN_DIR/package-rollback"
install -d -o root -g root -m 0755 "$BIN_DIR/initramfs" /usr/share/initramfs-tools/hooks /etc/default/grub.d
install -o root -g root -m 0755 "$ROOT_DIR/packaging/initramfs/nftfw-ipv6-early" \
    "$BIN_DIR/initramfs/nftfw-ipv6-early"
install -o root -g root -m 0755 "$ROOT_DIR/packaging/initramfs/nftfw-udev-gate" \
    "$BIN_DIR/initramfs/nftfw-udev-gate"
install -o root -g root -m 0644 "$ROOT_DIR/packaging/initramfs/nftfw-initramfs-guard.nft" \
    "$BIN_DIR/initramfs/nftfw-initramfs-guard.nft"
install -o root -g root -m 0755 "$ROOT_DIR/packaging/initramfs/nftfw-initramfs-manage" \
    "$BIN_DIR/initramfs/nftfw-initramfs-manage"
install -o root -g root -m 0755 "$ROOT_DIR/packaging/initramfs/nftfw-early-guard-hook" \
    /usr/share/initramfs-tools/hooks/nftfw-early-guard
ln -sfn "$BIN_DIR/nftfw" /usr/sbin/nftfw
ln -sfn "$BIN_DIR/package-rollback" /usr/sbin/nftfw-package-rollback
if [[ -L "$CONF_DIR/nftfw.toml" ]]; then
    echo "Refusing symlinked configuration: $CONF_DIR/nftfw.toml" >&2
    exit 1
elif [[ ! -e "$CONF_DIR/nftfw.toml" ]]; then
    install -o root -g nftfw -m 0640 "$ROOT_DIR/configs/nftfw.example.toml" "$CONF_DIR/nftfw.toml"
    echo "Installed example config at $CONF_DIR/nftfw.toml; edit it before applying."
elif [[ ! -f "$CONF_DIR/nftfw.toml" ]]; then
    echo "Configuration path is not a regular file: $CONF_DIR/nftfw.toml" >&2
    exit 1
fi
systemd_units=(
    nftfw-early.service
    nftfw-enforcement-ready.service
    nftfw-rollback.service
    nftfw-rollback.timer
    nftfw-setup-rollback.service
    nftfw-setup-rollback.timer
    nftfw-setup-boot-hold.service
    nftfw-setup-docker-hold.service
    nftfw-managed-rollback.service
    nftfw-managed-rollback.timer
    nftfw-vpn.service
    nftfw-web.service
    nftfwd.service
)
for unit in "${systemd_units[@]}"; do
    target="/etc/systemd/system/$unit"
    [[ ! -L "$target" && ( ! -e "$target" || -f "$target" ) ]] || {
        echo "Refusing unsafe systemd unit target: $target" >&2
        exit 1
    }
    install -o root -g root -m 0644 "$ROOT_DIR/packaging/systemd/$unit" "$target"
done
generator_dir=/usr/lib/systemd/system-generators
generator_target=$generator_dir/nftfw-setup-boot-hold-generator
[[ ! -L "$generator_dir" && ( ! -e "$generator_dir" || -d "$generator_dir" ) &&
    ! -L "$generator_target" && ( ! -e "$generator_target" || -f "$generator_target" ) ]] || {
    echo "Refusing unsafe systemd generator target: $generator_target" >&2
    exit 1
}
if [[ -f "$generator_target" ]]; then
    installed_generator_sha=$(sha256sum "$generator_target" | awk '{ print $1 }')
    source_generator_sha=$(sha256sum \
        "$ROOT_DIR/packaging/systemd/nftfw-setup-boot-hold-generator" | awk '{ print $1 }')
    [[ "$installed_generator_sha" == "$source_generator_sha" ]] || {
        echo "Refusing to overwrite a foreign systemd generator: $generator_target" >&2
        exit 1
    }
fi
install -d -o root -g root -m 0755 "$generator_dir"
install -o root -g root -m 0755 \
    "$ROOT_DIR/packaging/systemd/nftfw-setup-boot-hold-generator" "$generator_target"
for example in nftfwd-docker-access.conf.example nftfwd-final-early.conf.example \
    nftfw-rollback-final-early.conf.example nftfw-consumer-final-ready.conf.example; do
    install -o root -g root -m 0644 "$ROOT_DIR/packaging/systemd/$example" \
        "$DOC_EXAMPLE_DIR/$example"
done
systemctl daemon-reload
echo "NFT Firewall V2 installed without enabling, starting, stopping, or restarting any unit."
echo "Pre-existing unit lifecycle state was preserved; a fresh installation remains inactive."
echo "No firewall policy, VPN interface, route, or enforcement pointer was created."
echo "Clean Debian 13 setup: sudo nftfw setup --vpn /path/to/working-vpn.conf"
