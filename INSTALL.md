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

Setup fails before mutation when the OS, route, LAN, resolver, firewall
ownership, Docker topology, existing NFTFW state, reserved routing identities,
or VPN profile cannot be proved safe. Eligible Docker IPv4 bridges are adopted
automatically; the plan names them and states that NFTFW will own kernel IPv4
forwarding while Docker's own forwarding/firewall mutation remains disabled.

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

An existing NFTFW host is not eligible for automatic clean setup. Docker and
application workloads are eligible only when every Docker network satisfies
the managed bridge contract in `docs/DOCKER.md`; unsupported network drivers,
IPv6, internal networks, overlap, ambiguity, or an unreadable local socket
stop setup before mutation. Do not delete state or disable a firewall manager
to bypass refusal.

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
| `/run/nftfw/control.sock` | Root-only mutation API |
| `/run/nftfw/status.sock` | Read-only status API |
