# Installation

NFT Firewall V2 2.1.0 supports Debian 13 on amd64 and arm64. Read
`SUPPORTED-PLATFORMS.md` before installation. A Stage E-R candidate labeled
`RELEASE-CANDIDATE-NOT-DEPLOYABLE` is intentionally non-runnable and
non-installable; use only a final approved package.

## Package install

Verify the final release checksum manifest, then install the package matching
the server architecture:

```bash
sha256sum -c --ignore-missing NFTFW-2.1.0-SHA256SUMS
sudo apt install "./nft-firewall-v2_2.1.0_$(dpkg --print-architecture).deb"
```

Package installation:

- installs static binaries, systemd units, documentation, and an inert
  example advanced configuration;
- creates protected service users and directories;
- may run `systemctl daemon-reload`;
- does not enable, start, stop, or restart NFTFW services;
- does not import a VPN, create an interface, alter routes, apply nftables,
  disable IPv6, or open a port.

The package also installs inert initramfs, Debian GRUB, and exact-package
rollback tooling. Package installation does not publish the managed GRUB
fragment or regenerate GRUB/initramfs state; only an approved managed setup
transaction can take that ownership. Advanced-mode upgrades remain inert.

## Clean-server setup

Place an already-working supported WireGuard profile in a protected file and
run:

```bash
sudo nftfw setup --vpn /path/to/working-vpn.conf
```

NFTFW prints the discovered plan and asks for confirmation. When Docker daemon
ownership settings must change, it asks again immediately before one Docker
restart. For noninteractive provisioning:

```bash
sudo nftfw setup --vpn /path/to/working-vpn.conf --yes
```

Inspect without mutation:

```bash
sudo nftfw setup --vpn /path/to/working-vpn.conf --dry-run
```

The first real invocation prepares and verifies the native initramfs guard and
one fixed Debian GRUB fragment, then exits successfully with
`reboot_required`. It does not yet apply NFTFW policy, start the tunnel, alter
Docker, or enable forwarding. Reboot explicitly and resume the same protected
transaction with the same profile-only command:

```bash
sudo reboot
sudo nftfw setup status
sudo nftfw setup --vpn /path/to/working-vpn.conf
```

`setup status` changes to `resume_ready` only after the boot ID changes and the
prepared GRUB, kernel argument, kernel disable parameter, empty IPv6 address
state, and native guard all verify. NFTFW never reboots automatically.
Before normal networking starts, the generated boot dependency swaps the
exact initramfs deny table for a checksum-bound resume guard that allows only
DHCP, reviewed LAN management, and the privately cached provider endpoint.
Docker service/socket activation stays blocked until the same setup command
has written NFTFW ownership, applied IPv4 forwarding, and received the
immediate restart confirmation.

Setup fails before mutation when the OS, route, LAN, resolver, firewall
ownership, Docker topology, existing NFTFW state, reserved routing identities,
or VPN profile cannot be proved safe. Docker must have no running or retained
containers. Eligible empty Docker IPv4 bridges are adopted automatically; the
plan names them and states that NFTFW will own kernel IPv4 forwarding while
Docker's own forwarding/firewall mutation remains disabled.

## Verify

```bash
sudo nftfw health
sudo nftfw tunnel status
sudo nftfw exposure list
sudo nftfw config show --effective
systemctl is-enabled nftfw-early nftfw-enforcement-ready nftfwd \
  nftfw-rollback.timer nftfw-setup-rollback.timer \
  nftfw-managed-rollback.timer nftfw-vpn nftfw-web
```

The initial public exposure must be empty. The dashboard remains on
`127.0.0.1:8787` unless a separately authenticated reverse proxy is approved.

## Existing installations

A package upgrade from 2.0.3 to 2.1.0 is nonactivating and preserves schema-6
state, advanced TOML, generations, snapshots, the enforcement pointer,
provenance ledger, unit state, and existing exposure. It does not convert an
advanced host to managed routing.

An existing NFTFW host is not eligible for automatic clean setup. Running or
retained Docker/application workloads are also never eligible for that path.
The read-only adoption planner may classify them for a separate plan when
every Docker network satisfies `docs/DOCKER.md`; unsupported network drivers,
IPv6, internal networks, overlap, ambiguity, or an unreadable local socket
stop planning. Do not delete state, containers, or firewall evidence merely to
bypass refusal.

Before an approved 2.0.3-to-2.1.0 upgrade, extract the 2.1.0 package and use
its `usr/lib/nftfw/package-rollback` helper to prepare and verify the exact
rollback bundle as described in `docs/UPGRADING.md`. Do not install 2.1.0
until that bundle exists and its exact 2.0.3 parser accepts the configuration
that would be restored. A managed 2.1-only configuration is not an exact
package-downgrade target; use the protected pre-upgrade configuration or the
documented package-removal handoff instead.

Generate the nonactivating local adoption worksheet with:

```bash
sudo nftfw setup adopt --vpn /path/to/working-vpn.conf --dry-run
```

It reads the protected advanced configuration, exact schema-6 state,
enforcement pointer and snapshot, provenance ledger, systemd states, routing,
resolver, and local Docker topology twice. It prints no provider key,
endpoint/address, public IP, domain, container/image/volume identity, or Docker
network name. It creates no journal or backup and changes no file, firewall,
route, interface, sysctl, resolver, service, or Docker object. Actual adoption
is deliberately not a generic 2.1.0 command; prepare a separately approved
Stage E-L plan from the worksheet.

## Source builds

Final release builds require exact Go 1.27.0. Build from the exact approved
tag in a clean protected worktree:

```bash
test -z "$(git status --porcelain)"
make check
make deb \
  VERSION=2.1.0 \
  COMMIT="$(git rev-parse HEAD)" \
  BUILD_DATE="$(date -u -d "@$(git show -s --format=%ct HEAD)" +%Y-%m-%dT%H:%M:%SZ)" \
  DISPOSITION=release
```

The portable source installer accepts only exact final-release binary
identity, verifies checksums and systemd units, preserves compatible state,
and remains nonactivating.

## Installed paths

| Path | Purpose |
| --- | --- |
| `/usr/lib/nftfw/` | NFTFW executables |
| `/etc/nftfw/nftfw.toml` | Generated or advanced policy |
| `/etc/nftfw/intent.toml` | Non-secret managed intent |
| `/etc/wireguard/nftfw0.conf` | Root-only normalized VPN profile |
| `/var/lib/nftfw/generation-state/state.db` | Generation and runtime state |
| `/var/lib/nftfw/provenance-ledger.db` | Monotonic interface identities |
| `/var/lib/nftfw/setup/` | Setup journal, verified backups, and result |
| `/etc/docker/daemon.json` | Semantically merged Docker ownership settings when adopted |
| `/etc/sysctl.d/90-nftfw-managed.conf` | Managed IPv4 forwarding and IPv6 disablement |
| `/etc/nftfw/initramfs-managed-disabled-v1` | Managed-only initramfs guard activation marker |
| `/etc/default/grub.d/90-nftfw-ipv6-disabled.cfg` | Managed root-only kernel-wide IPv6-disable fragment |
| `/usr/lib/nftfw/initramfs/` | Guard loader, rules, archive verifier, and reversible removal tool |
| `/usr/lib/nftfw/package-rollback` | Pre-upgrade exact-package rollback bundle tool |
| `/run/nftfw/control.sock` | Root-only mutation API |
| `/run/nftfw/status.sock` | Read-only status API |
