# Installation

## Requirements

- Linux with nftables kernel support
- nftables 1.0 or newer with JSON output
- iproute2 and WireGuard tools
- systemd
- root for installation and control operations
- Go 1.25.13 only when building from source

The installer does not install or start a VPN profile. Prepare WireGuard
separately and declare its interface, endpoint, port, and fwmark in the policy.

## Release archive

```bash
unzip nft-firewall-v2-2.0.0.zip
cd nft-firewall-v2
sha256sum -c SHA256SUMS
sudo apt install ./packages/nft-firewall-v2_2.0.0_$(dpkg --print-architecture).deb
```

The final release archive provides Debian packages and architecture-specific
executables under `packages/` and `binaries/`. Its clean `source/` directory
contains no generated `dist/`; build it first when using the source installer.

## Debian package

On amd64:

```bash
sudo apt install ./nft-firewall-v2_2.0.0_amd64.deb
```

Use the arm64 package on arm64 systems. Package installation creates the
service identities and directories, validates the configuration, and enables
the services. It does not apply a new candidate policy. Before an upgrade, the
package creates and verifies an online state database backup.

## Source tree

```bash
make release VERSION=2.0.0
sudo ./scripts/install.sh
```

The source installer verifies binary checksums, validates the candidate
configuration, checks systemd units, preserves an existing configuration,
backs up existing SQLite state, installs binaries in `/usr/lib/nftfw`, and
starts the daemon, timer, and dashboard. It makes no firewall change unless a
previous committed generation already requires reconciliation.

## First apply

```bash
sudoedit /etc/nftfw/nftfw.toml
sudo nftfw config validate
sudo nftfw doctor
sudo nftfw plan
systemctl is-enabled --quiet nftfw-rollback.timer
systemctl is-active --quiet nftfw-rollback.timer
sudo nftfw apply --safe
sudo nftfw status
sudo nftfw commit <generation>
```

Use a second management session for the first host apply. Do not use
`--unsafe` remotely unless another independent recovery mechanism has already
been proven.

## Installed paths

| Path | Purpose | Expected access |
| --- | --- | --- |
| `/usr/lib/nftfw/` | Executables | root-owned, not writable by group/other |
| `/etc/nftfw/nftfw.toml` | Desired policy | root-owned, `0640` or stricter |
| `/var/lib/nftfw/state.db` | Operational state | root-only directory |
| `/var/lib/nftfw/active.nft` | Committed boot snapshot | root-only directory |
| `/run/nftfw/control.sock` | Mutating API | root peer only |
| `/run/nftfw/status.sock` | Read-only API | dashboard group readable |

Run `sudo nftfw doctor` after installation and after topology changes.
