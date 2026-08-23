# Configuration

The default path is `/etc/nftfw/nftfw.toml`. `NFTFW_CONFIG` can select another
path for development or isolated tests. Loading a configuration never mutates
the firewall.

The decoder rejects unknown fields. The file is limited to 1 MiB and must be a
regular, non-symlink file owned by the effective service user, not writable by
group or other, beneath an equivalently protected parent. System
configuration under `/etc/nftfw` must be root-owned.

Start with `configs/nftfw.example.toml`, then validate:

```bash
sudo nftfw config validate
sudo nftfw doctor
sudo nftfw plan
```

## System

```toml
[system]
ipv6_mode = "disabled"
strict_vpn = true
```

`strict_vpn` must be true in v2.0.0. Supported IPv6 modes are:

| Mode | Behavior |
| --- | --- |
| `disabled` | Early-priority input, output, and forward IPv6 drop hooks; loopback only |
| `vpn` | Typed IPv6 policy with public egress pinned to WireGuard |
| `native` | Typed default-deny IPv6 policy; public host policy still follows strict VPN pinning |

`native` means IPv6 addressing and neighbor discovery are native; it does not
disable the release's strict public egress requirement.

## Interfaces and zones

Exactly one `uplink` and at least one `vpn` interface matching the WireGuard
section are required. Other roles are `lan` and `container`. Linux interface
names are limited to 15 safe characters.

```toml
[[interfaces]]
name = "eth0"
role = "uplink"
zone = "wan"
cidrs = ["192.0.2.10/32"]

[[zones]]
name = "lan"
networks = ["192.168.1.0/24"]
interfaces = []
```

Zone networks cannot overlap, `/0` is forbidden, and every interface/zone
reference must exist. A zone must contain at least one network or interface.
Interface CIDRs describe observed topology; zone networks are policy
selectors.

## Services and policies

```toml
[[services]]
name = "ssh"
protocol = "tcp"
ports = [22]

[[policies]]
name = "lan-to-ssh"
from = "lan"
to = "host"
service = "ssh"
action = "allow"
```

Protocols are `tcp`, `udp`, and `icmp`. TCP/UDP require unique ports from 1 to
65535; ICMP has no ports. Policy endpoints are a declared zone, `host`, or
`any`. Actions are `allow` or `deny`. Duplicate flow tuples are rejected so a
single tuple cannot contain contradictory actions.

Direction follows endpoints:

- zone to `host`: input chain
- `host` to zone/`any`: output chain
- zone to zone/`any`: forward chain

Public output and `to = "any"` forwarding are pinned to the configured VPN.
An output policy may not name the physical uplink zone as a destination.
Explicit denies are emitted before stateful accepts; the physical forward drop
also precedes established/related acceptance.

## NAT

Only explicit IPv4 DNAT is implemented.

```toml
[[nat]]
name = "lan-web"
source = "lan"
external_interface = "eth0"
protocol = "tcp"
external_port = 8443
destination = "172.30.0.10"
destination_port = 8443
```

`source` is `any` or an IPv4 zone. The incoming interface must have role
`uplink` or `lan`. At compilation, the destination must be inside a currently
observed container network. DNAT does not imply permission: a separate forward
policy must allow the translated flow. IPv6 NAT is not implemented.

## WireGuard

```toml
[wireguard]
interface = "wg0"
endpoint_host = "vpn.example.net"
endpoint_port = 51820
fwmark = "0xca6c"
bootstrap_ips = ["198.51.100.10/32"]
bootstrap_ips_v6 = []
bootstrap_hosts = ["vpn.example.net"]
keep_recent = 2
tcp_mss = 1360
config_path = "/etc/wireguard/wg0.conf"
handshake_timeout_seconds = 180
```

The interface must be declared with role `vpn` and differ from the uplink. The
fwmark must be a nonzero 32-bit decimal or hexadecimal value and must match
the live tunnel. Static bootstrap entries must be usable unicast host prefixes
(`/32` or `/128`), never networks. At most 64 static addresses and 16 hostnames
are accepted; `keep_recent` is 0 through 16.

`tcp_mss` is a bidirectional container/VPN SYN clamp from 536 through 8960.
The optional config path must be absolute, named `<interface>.conf`,
root-owned, non-symlinked, and mode `0600` or stricter. Its private key is not
read for status or logged.

DNS endpoints refresh every 60 seconds. Bounded recently valid addresses are
retained during rollover and aged out; authoritative DNS TTLs are not exposed
by the current resolver and are not claimed.

## Runtime and state

```toml
[runtime]
max_block_claims = 100000
max_set_members = 65536
safe_apply_timeout_seconds = 90
trusted_services = ["ssh"]

[state]
directory = "/var/lib/nftfw"
database = "/var/lib/nftfw/state.db"
```

Claim/set limits are 1 through 1,000,000. Safe apply timeout is 30 through 600
seconds. At most 32 trusted services may be listed, and each must be an
existing TCP/UDP service. Temporary `allow` claims can open only those exact
ports. A permanent allow claim is invalid.

The database must be a direct child of an absolute non-root state directory.
Production units allow writes only under `/var/lib/nftfw` and `/run/nftfw`.

## Docker

```toml
[integrations]
docker_enabled = true
threat_feed = false
geoip = false
notifications = false
```

Docker integration reads the local Docker socket from the privileged daemon;
socket access is effectively root-equivalent. The observer refuses operation
unless `/etc/docker/daemon.json` is protected and explicitly contains:

```json
{
  "iptables": false,
  "ip6tables": false,
  "ip-forward": false,
  "ip-masq": false,
  "userland-proxy": false
}
```

Restart Docker after changing those settings. V2 then observes validated
bridge prefixes and owns forwarding/NAT. The dashboard never receives Docker
socket access.

## Threat feeds

The enable flag must exactly match whether feed entries exist.

```toml
[integrations]
threat_feed = true

[[threat_feeds]]
name = "example"
url = "https://feeds.example.net/addresses.txt"
max_entries = 10000
max_bytes = 8388608
min_entries = 10
refresh_seconds = 3600
```

URLs must be credential-free HTTPS. The built-in client disables proxy
environment use, rejects non-public targets, caps redirects at five, and has a
15-second timeout. Responses are capped at 64 MiB by configuration, entries
are strict IPs/CIDRs with `/0` rejected, and source replacement is atomic. Zero
uses defaults of 10,000 entries, 8 MiB, one minimum entry, and one hour.

On download, parse, threshold, or kernel-update failure, prior claims remain
active and the integration becomes degraded. Manual and other integration
claims are unaffected.

## GeoIP

V2 bundles no country database. Supply a licensed, pre-generated plain CIDR
file appropriate to your provider's terms.

```toml
[integrations]
geoip = true

[[geo_sets]]
name = "example-country"
country = "XX"
cidr_file = "/var/lib/nftfw/geo/XX.cidr"
max_entries = 100000
min_entries = 100
refresh_seconds = 3600
```

The file and parent must be owned by the service user, non-symlinked, not
group/other writable, and no larger than 64 MiB. Country identifiers are
metadata only; the file defines membership. Refresh uses `geo/<name>`
provenance and retains the previous known-good claim set on failure.

Notifications and remote commands are not implemented in the core.
`integrations.notifications = true` is rejected.
