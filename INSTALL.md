# Installation

Requirements: Linux, nftables, WireGuard tools, systemd, and root for service
installation. The Go toolchain is needed only when building from source.

```bash
make release VERSION=2.0.0
sudo ./scripts/install.sh
```

The script installs binaries under `/usr/lib/nftfw`, policy under
`/etc/nftfw`, state under `/var/lib/nftfw`, and hardened systemd units. It
preserves an existing configuration and does not apply policy.

Verify the independent rollback mechanism before host testing:

```bash
systemctl status nftfw-rollback.timer
systemctl list-timers nftfw-rollback.timer
sudo nftfw config validate
sudo nftfw plan
```
