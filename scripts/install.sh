#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "install.sh must run as root" >&2; exit 1; fi
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BIN_DIR=/usr/lib/nftfw
CONF_DIR=/etc/nftfw
STATE_DIR=/var/lib/nftfw
case "$(uname -m)" in x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;; esac

command -v nft >/dev/null || { echo "Missing nftables (nft); install it first" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "Missing systemd systemctl" >&2; exit 1; }
for binary in nftfw nftfwd nftfw-web; do [[ -x "$ROOT_DIR/dist/$binary-linux-$ARCH" ]] || { echo "Missing dist/$binary-linux-$ARCH; run make release" >&2; exit 1; }; done
for binary in nftfw nftfwd nftfw-web; do
    expected=$(awk -v file="$binary-linux-$ARCH" '$2 == file { print $1 }' "$ROOT_DIR/dist/SHA256SUMS")
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || { echo "Missing checksum for $binary-linux-$ARCH" >&2; exit 1; }
    actual=$(sha256sum "$ROOT_DIR/dist/$binary-linux-$ARCH" | awk '{ print $1 }')
    [[ "$actual" == "$expected" ]] || { echo "Checksum mismatch for $binary-linux-$ARCH" >&2; exit 1; }
done

install -d -o root -g root -m 0755 "$BIN_DIR"
install -d -m 0750 "$CONF_DIR" "$STATE_DIR"
if ! getent group nftfw >/dev/null; then groupadd --system nftfw; fi
if ! getent group nftfw-web >/dev/null; then groupadd --system nftfw-web; fi
if ! id nftfw-web >/dev/null 2>&1; then useradd --system --gid nftfw-web --home-dir /var/empty --shell /usr/sbin/nologin nftfw-web; fi
install -d -o root -g nftfw -m 0750 "$CONF_DIR"
install -d -o root -g root -m 0700 "$STATE_DIR" "$STATE_DIR/backups"
if [[ -s "$STATE_DIR/state.db" ]]; then
    backup="$STATE_DIR/backups/state-before-install-$(date -u +%Y%m%dT%H%M%SZ).db"
    "$ROOT_DIR/dist/nftfw-linux-$ARCH" state backup "$backup" --database "$STATE_DIR/state.db"
fi
install -o root -g root -m 0755 "$ROOT_DIR/dist/nftfw-linux-$ARCH" "$BIN_DIR/nftfw"
install -o root -g root -m 0755 "$ROOT_DIR/dist/nftfwd-linux-$ARCH" "$BIN_DIR/nftfwd"
install -o root -g root -m 0755 "$ROOT_DIR/dist/nftfw-web-linux-$ARCH" "$BIN_DIR/nftfw-web"
ln -sfn "$BIN_DIR/nftfw" /usr/sbin/nftfw
if [[ ! -e "$CONF_DIR/nftfw.toml" ]]; then install -o root -g nftfw -m 0640 "$ROOT_DIR/configs/nftfw.example.toml" "$CONF_DIR/nftfw.toml"; echo "Installed example config at $CONF_DIR/nftfw.toml; edit it before applying."; fi
install -o root -g root -m 0644 "$ROOT_DIR/packaging/systemd/nftfwd.service" /etc/systemd/system/nftfwd.service
install -o root -g root -m 0644 "$ROOT_DIR/packaging/systemd/nftfw-web.service" /etc/systemd/system/nftfw-web.service
install -o root -g root -m 0644 "$ROOT_DIR/packaging/systemd/nftfw-rollback.service" /etc/systemd/system/nftfw-rollback.service
install -o root -g root -m 0644 "$ROOT_DIR/packaging/systemd/nftfw-rollback.timer" /etc/systemd/system/nftfw-rollback.timer
systemctl daemon-reload
systemctl reset-failed nftfwd.service nftfw-web.service nftfw-rollback.service 2>/dev/null || true
systemctl enable nftfwd.service nftfw-rollback.timer nftfw-web.service
systemctl restart nftfwd.service
systemctl restart nftfw-rollback.timer
systemctl restart nftfw-web.service
echo "NFT Firewall V2 installed. Validate with: nftfw config validate && nftfw plan"
echo "No firewall policy was applied by this installer."
