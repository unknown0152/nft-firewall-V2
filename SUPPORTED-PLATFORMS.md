# Supported Platforms

## Managed one-file setup in 2.1.0

| Item | Supported |
| --- | --- |
| OS | Debian 13 stable |
| Init | systemd |
| Boot chain | Local Debian GRUB only: `grub-pc` on amd64 BIOS, `grub-efi-amd64` on amd64 EFI, or `grub-efi-arm64` on arm64 EFI; local writable boot storage, fixed source/generated paths, exact active kernel, and `initramfs-tools` must all verify |
| Architectures | amd64, arm64 |
| Network | Exactly one usable IPv4 default uplink |
| Management | Local console or directly connected private LAN |
| Firewall | nftables with JSON output; no competing owner |
| VPN | One IPv4-default-route WireGuard peer |
| Resolver | `resolvectl` or `resolvconf` when profile DNS is present |
| IPv6 | Disabled by managed setup |
| Public inbound | None initially |
| Docker | Absent, or local-socket Docker with no running/retained containers and eligible IPv4 bridge networks |

Setup refuses before mutation when the topology cannot be proved to match this
matrix.

## Not automatically adopted

- Debian 12, Ubuntu, or another distribution;
- multiple default uplinks or ambiguous policy routing;
- split-tunnel, multi-peer, hook-bearing, or IPv6 WireGuard profiles;
- Wi-Fi-specific handoff requirements;
- UFW, firewalld, nftables.service, netfilter-persistent, or foreign nftables
  tables;
- existing NFTFW state or deterministic routing identities;
- any running or retained Docker container;
- macvlan, ipvlan, overlay, Swarm, Kubernetes, Podman, internal-only, IPv6,
  overlapping, malformed, or changing Docker networks;
- public administration or automatic public SSH;
- network-root/read-only boot, systemd-boot, UKI, extlinux, multiple/wrong GRUB
  families, alternate GRUB trees, an unsupported initramfs generator, or a
  boot identity that cannot be backed up and verified exactly;
- native IPv6 or VPN IPv6.

These cases require an explicit advanced/adoption design and their own
validation. Refusal is not a prompt to disable security controls or erase
state.

The empty built-in bridge and empty Compose-style user-defined bridges are
supported when every current bridge, canonical IPv4 subnet, and gateway is
unambiguous and non-overlapping. Setup adopts all eligible bridge networks
together so workloads can start after protection is active; it never selects
only a convenient subset or assumes ownership around an existing workload.

## Existing-host adoption planning

The dry-run-only `nftfw setup adopt` planner supports Debian 13 amd64/arm64
with a compatible 2.0.3 or inertly upgraded 2.1.0 advanced installation,
exact contiguous schema-6 state, a matching committed enforcement snapshot
and provenance ledger, one IPv4 uplink, disabled IPv6 mode, supported resolver
ownership, and only eligible local Docker bridges.

It refuses a clean or already-managed host, older/unknown/future package or
state versions, pending or corrupt generations, inconsistent provenance,
competing/foreign firewall ownership, ambiguous routes, native/VPN IPv6, and
unsupported or changing Docker topology. Success authorizes no conversion;
it produces only a redacted worksheet for a separate Stage E-L plan.

## Advanced mode

The existing strict TOML compiler and schema-6 state remain compatible with
2.0.3. Advanced mode supports broader reviewed topologies, but it is not the
one-file setup contract and remains operator-authored.
