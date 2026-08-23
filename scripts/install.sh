#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "install.sh must run as root" >&2; exit 1; fi
if (( $# != 0 )); then echo "Usage: install.sh" >&2; exit 2; fi
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BIN_DIR=/usr/lib/nftfw
CONF_DIR=/etc/nftfw
STATE_DIR=/var/lib/nftfw
case "$(uname -m)" in x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;; esac

for command_name in nft ip wg systemctl systemd-analyze sha256sum awk getent groupadd useradd install readlink mktemp sed grep find; do
    command -v "$command_name" >/dev/null || { echo "Missing prerequisite: $command_name" >&2; exit 1; }
done
for binary in nftfw nftfwd nftfw-web; do [[ -x "$ROOT_DIR/dist/$binary-linux-$ARCH" ]] || { echo "Missing dist/$binary-linux-$ARCH; run make release" >&2; exit 1; }; done
for binary in nftfw nftfwd nftfw-web; do
    expected=$(awk -v file="$binary-linux-$ARCH" '$2 == file { print $1 }' "$ROOT_DIR/dist/SHA256SUMS")
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || { echo "Missing checksum for $binary-linux-$ARCH" >&2; exit 1; }
    actual=$(sha256sum "$ROOT_DIR/dist/$binary-linux-$ARCH" | awk '{ print $1 }')
    [[ "$actual" == "$expected" ]] || { echo "Checksum mismatch for $binary-linux-$ARCH" >&2; exit 1; }
done

validation_dir=""
candidate_config=""
if [[ -e "$CONF_DIR/nftfw.toml" || -L "$CONF_DIR/nftfw.toml" ]]; then
    [[ -f "$CONF_DIR/nftfw.toml" && ! -L "$CONF_DIR/nftfw.toml" ]] || { echo "Configuration path is not a regular, non-symlink file: $CONF_DIR/nftfw.toml" >&2; exit 1; }
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

for directory in "$BIN_DIR" "$CONF_DIR" "$STATE_DIR"; do
    [[ ! -L "$directory" ]] || { echo "Refusing symlinked installation directory: $directory" >&2; exit 1; }
done
if [[ -e /usr/sbin/nftfw || -L /usr/sbin/nftfw ]]; then
    [[ -L /usr/sbin/nftfw && $(readlink /usr/sbin/nftfw) == "$BIN_DIR/nftfw" ]] || { echo "Refusing to replace unrelated /usr/sbin/nftfw" >&2; exit 1; }
fi
install -d -o root -g root -m 0755 "$BIN_DIR"
install -d -m 0750 "$CONF_DIR" "$STATE_DIR"
if ! getent group nftfw >/dev/null; then groupadd --system nftfw; fi
if ! getent group nftfw-web >/dev/null; then groupadd --system nftfw-web; fi
if ! id nftfw-web >/dev/null 2>&1; then useradd --system --gid nftfw-web --home-dir /var/empty --shell /usr/sbin/nologin nftfw-web; fi
install -d -o root -g nftfw -m 0750 "$CONF_DIR"
install -d -o root -g root -m 0700 "$STATE_DIR" "$STATE_DIR/backups"
if [[ -L "$STATE_DIR/state.db" ]]; then
    echo "Refusing symlinked state database: $STATE_DIR/state.db" >&2
    exit 1
elif [[ -s "$STATE_DIR/state.db" ]]; then
    backup="$STATE_DIR/backups/state-before-install-$(date -u +%Y%m%dT%H%M%SZ).db"
    if [[ -x "$BIN_DIR/nftfw" ]] && "$BIN_DIR/nftfw" state backup "$backup" --database "$STATE_DIR/state.db"; then
        :
    else
        rm -f "$backup"
        command -v sqlite3 >/dev/null || { echo "Cannot back up existing state before upgrade: installed nftfw failed and sqlite3 is unavailable." >&2; exit 1; }
        sqlite3 "$STATE_DIR/state.db" ".timeout 5000" ".backup '$backup'"
        chmod 0600 "$backup"
        [[ $(sqlite3 "$backup" 'PRAGMA quick_check;') == ok ]] || { rm -f "$backup"; echo "Pre-upgrade SQLite backup failed verification." >&2; exit 1; }
        echo "SQLite backup created: $backup"
    fi
fi
install -o root -g root -m 0755 "$ROOT_DIR/dist/nftfw-linux-$ARCH" "$BIN_DIR/nftfw"
install -o root -g root -m 0755 "$ROOT_DIR/dist/nftfwd-linux-$ARCH" "$BIN_DIR/nftfwd"
install -o root -g root -m 0755 "$ROOT_DIR/dist/nftfw-web-linux-$ARCH" "$BIN_DIR/nftfw-web"
ln -sfn "$BIN_DIR/nftfw" /usr/sbin/nftfw
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
install -o root -g root -m 0644 "$ROOT_DIR/packaging/systemd/nftfwd.service" /etc/systemd/system/nftfwd.service
install -o root -g root -m 0644 "$ROOT_DIR/packaging/systemd/nftfw-early.service" /etc/systemd/system/nftfw-early.service
install -o root -g root -m 0644 "$ROOT_DIR/packaging/systemd/nftfw-web.service" /etc/systemd/system/nftfw-web.service
install -o root -g root -m 0644 "$ROOT_DIR/packaging/systemd/nftfw-rollback.service" /etc/systemd/system/nftfw-rollback.service
install -o root -g root -m 0644 "$ROOT_DIR/packaging/systemd/nftfw-rollback.timer" /etc/systemd/system/nftfw-rollback.timer
systemctl daemon-reload
systemctl reset-failed nftfw-early.service nftfwd.service nftfw-web.service nftfw-rollback.service 2>/dev/null || true
systemctl enable nftfw-early.service nftfwd.service nftfw-rollback.timer nftfw-web.service
systemctl restart nftfwd.service
systemctl restart nftfw-rollback.timer
systemctl restart nftfw-web.service
systemctl is-active --quiet nftfwd.service nftfw-rollback.timer nftfw-web.service
echo "NFT Firewall V2 installed. Validate with: nftfw config validate && nftfw plan"
echo "No firewall policy was applied by this installer."
