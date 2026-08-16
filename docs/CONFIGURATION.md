# Configuration

`/etc/nftfw/nftfw.toml` is decoded strictly. Unknown keys, symlinks,
group/world-writable files, invalid interfaces, duplicate names/ports,
unknown references, `/0` networks, mismatched WireGuard/uplink interfaces,
and malformed endpoints are rejected before compilation.

Sections:

- `system`: `ipv6_mode` (`disabled`, `vpn`, `native`) and `strict_vpn`.
- `interfaces`: logical role (`uplink`, `vpn`, `lan`, `container`), zone, CIDRs.
- `zones`: named networks/interfaces.
- `services`: protocol plus ports.
- `policies`: named `from`, `to`, `service`, and `allow`/`deny` action.
- `nat`: explicit IPv4 DNAT bindings. Targets must be inside an observed
  container network, and a separate forward policy must allow the translated
  destination service.
- `wireguard`: interface, endpoint, fwmark, bounded bootstrap addresses/cache,
  and a bidirectional container TCP MSS clamp (`tcp_mss`, default `1360`).
- `runtime`: claim/set limits, the bounded safe-apply timeout (30-600 seconds),
  and the exact TCP/UDP `trusted_services` a temporary access lease may open.
- `state`: SQLite paths.
- `integrations`: explicit optional feature switches.

The complete schema example is `configs/nftfw.example.toml`. Configuration
parsing has no firewall side effects.
