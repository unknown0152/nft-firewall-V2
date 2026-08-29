# NFT Firewall V2

NFT Firewall V2 2.1.0 turns a working WireGuard provider profile into a
managed, fail-closed Debian firewall. On a supported clean server, setup has
one operator input:

```bash
sudo apt install "./nft-firewall-v2_2.1.0_$(dpkg --print-architecture).deb"
sudo nftfw setup --vpn /path/to/working-vpn.conf
```

The package installation is inert. The setup command then discovers the
uplink, private LAN, SSH management ports, resolver, firewall ownership, and
container state. It imports the VPN profile without printing secrets,
generates the strict policy, creates the managed WireGuard interface and
policy routing, installs an independent rollback guard, applies safely,
validates the tunnel and kill switch, commits, and enables boot protection.

The clean-host result is:

- IPv4 Internet through the WireGuard VPN only;
- no physical-uplink fallback;
- IPv6 disabled;
- eligible Docker IPv4 bridge networks routed through the VPN only;
- current private-LAN SSH management preserved;
- no public inbound exposure;
- a loopback-only read-only dashboard;
- durable boot recovery and automatic rollback.

## Release status

The current tree targets **2.1.0** and requires **Go 1.27.0**. Until Stage
E-R2, tagging, and final publication approval are complete, local Stage E-R
candidate artifacts are deliberately quarantined and cannot run or install.
The last published stable line remains 2.0.3.

## Supported clean-host setup

The one-file path intentionally supports a narrow first matrix:

- Debian 13 stable with systemd;
- amd64 or arm64;
- exactly one usable IPv4 default uplink;
- local console or directly connected private LAN management;
- one strict wg-quick-style profile with one peer and `0.0.0.0/0`;
- nftables JSON support and no competing firewall owner;
- no existing NFTFW state;
- Docker absent, or reachable only through the local socket with no running
  or retained containers and only eligible, non-overlapping IPv4 bridge
  networks.

Managed setup may adopt the built-in bridge and normal Compose-style bridge
networks when they contain no workload. Eligible empty custom networks remain
supported so containers can be created after protection is active. Any
running or retained container requires a separate existing-host plan and is
refused by clean-host setup. Setup shows every network and ownership change
before mutation. If Docker daemon settings must change, setup asks again
immediately before one Docker restart. Macvlan, ipvlan, overlay, Swarm,
Kubernetes, internal, IPv6, overlapping, malformed, or changing Docker
topologies are refused.

Existing NFTFW installations, multiple uplinks, split tunnels, provider
hooks, multiple peers, and native IPv6 are not silently changed. An existing
compatible 2.0.3 advanced-mode installation can generate a redacted worksheet:

```bash
sudo nftfw setup adopt --vpn /path/to/working-vpn.conf --dry-run
```

The 2.1.0 adoption command is planning-only. It verifies the configuration,
schema-6 generation, enforcement pointer, immutable snapshot, provenance,
unit states, routing, resolver, and eligible Docker topology twice without a
mutation lock or host changes. Actual conversion remains a separately
approved, topology-specific Stage E-L operation.

## Daily commands

```bash
sudo nftfw health
sudo nftfw tunnel status
sudo nftfw exposure list
sudo nftfw lan list
sudo nftfw config show --effective
```

With managed Docker enabled, `health` and `config show` report the adopted
network names and prove that kernel IPv4 forwarding is NFTFW-owned.

Later exposure remains explicit and VPN-side only:

```bash
sudo nftfw expose add tcp 80 443
sudo nftfw expose remove tcp 80 443
sudo nftfw lan allow tcp 8096
sudo nftfw lan deny tcp 8096
```

Mutating managed commands show the resulting policy and require confirmation.
Use `--dry-run`, `--yes`, and `--json` for automation.
Each committed change is compiled from the exact protected files and guarded
by independent file-transaction and pending-generation rollback timers.

## Security model

NFTFW owns only `inet nftfw_filter`, `ip nftfw_nat`, and
`ip6 nftfw_filter6`. It never runs `nft flush ruleset`. Safe apply,
generation commit, exact rollback, immutable boot snapshots, a monotonic
provenance ledger, and independent systemd rollback services protect the
transition.

The VPN importer accepts only documented WireGuard data fields. It rejects
hooks, commands, `SaveConfig`, provider routing directives, split tunnels,
IPv6 values, unknown fields, multiple peers, unsafe files, and replacement
during read. VPN keys are stored only in the root-owned managed WireGuard
file, never in intent, status, logs, evidence, or the dashboard.

The dashboard is read-only, binds to loopback by default, and has no control
socket, nftables, WireGuard, or Docker privilege.

## Documentation

- `QUICKSTART.md`: supported two-command setup and verification.
- `SUPPORTED-PLATFORMS.md`: exact accepted and refused topologies.
- `VPN-PROFILES.md`: strict provider-profile contract.
- `INSTALL.md`: package and source installation behavior.
- `docs/CLI.md`: managed and advanced commands.
- `docs/RECOVERY.md`: setup, tunnel, generation, boot, and database recovery.
- `docs/UPGRADING.md`: compatible 2.0.3-to-2.1.0 upgrade behavior.
- `SECURITY.md`: security boundary and reporting.
- `docs/ARCHITECTURE.md`: compiler, state, setup, routing, and service design.
