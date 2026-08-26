# Supported Platforms

## Managed one-file setup in 2.1.0

| Item | Supported |
| --- | --- |
| OS | Debian 13 stable |
| Init | systemd |
| Architectures | amd64, arm64 |
| Network | Exactly one usable IPv4 default uplink |
| Management | Local console or directly connected private LAN |
| Firewall | nftables with JSON output; no competing owner |
| VPN | One IPv4-default-route WireGuard peer |
| Resolver | `resolvectl` or `resolvconf` when profile DNS is present |
| IPv6 | Disabled by managed setup |
| Public inbound | None initially |
| Docker | Absent, or installed but empty/inactive; integration remains off |

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
- active Docker, Cosmos, Kubernetes, Podman, or application workloads;
- public administration or automatic public SSH;
- native IPv6 or VPN IPv6.

These cases require an explicit advanced/adoption design and their own
validation. Refusal is not a prompt to disable security controls or erase
state.

## Advanced mode

The existing strict TOML compiler and schema-6 state remain compatible with
2.0.3. Advanced mode supports broader reviewed topologies, but it is not the
one-file setup contract and remains operator-authored.
