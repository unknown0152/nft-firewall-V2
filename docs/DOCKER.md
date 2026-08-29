# Docker

Managed setup adopts Docker automatically when the local daemon and every
routed network can be proved safe. The operator still supplies only the
working WireGuard profile.

## Eligible networks

NFTFW queries only `unix:///var/run/docker.sock`.

- Built-in `host` and `none` networks are ignored.
- The built-in `bridge` network and user-defined bridge networks are adopted
  when their current Linux bridge exists and every canonical IPv4 subnet has
  exactly one usable gateway.
- All adopted subnets must be mutually disjoint and must not overlap the
  uplink/LAN, managed VPN address, WireGuard bootstrap address, or reserved
  IPv4 ranges.
- Macvlan, ipvlan, overlay, Swarm, third-party drivers, internal-only
  networks, Docker IPv6, malformed IPAM, shared bridges, missing links,
  changing observations, and unsupported network counts stop setup before
  mutation.

Setup adopts all eligible routed bridges together. It never ignores an
unknown bridge while enabling forwarding for the rest.

## Ownership transaction

Before changing Docker, setup:

1. strictly reads `/etc/docker/daemon.json`, rejecting duplicate keys,
   symlinks, unsafe ownership/mode, oversized input, non-object JSON, and
   change-during-read;
2. preserves every unrelated JSON key semantically;
3. sets `iptables`, `ip6tables`, `ip-forward`, `ip-masq`, and
   `userland-proxy` to `false`;
4. generates the exact container interfaces, stable network identities,
   zones, VPN-only policy, and masquerade rules;
5. proves the generated nftables transaction with `nft --check`;
6. backs up exact files, checksums, unit state, and runtime sysctls;
7. persists and applies `net.ipv4.ip_forward = 1` while keeping IPv6
   forwarding disabled; and
8. installs the exact `nftfwd.service` Docker-socket sandbox drop-in.

`"ip-forward": false` in Docker and `net.ipv4.ip_forward = 1` in the kernel
are intentional together. Docker is forbidden from changing host forwarding;
NFTFW owns the required runtime and persistent value.

If daemon settings changed, setup shows the adopted network names and asks
again immediately before one Docker restart. A compliant unchanged
`daemon.json` does not restart Docker. After any restart, NFTFW revalidates
the daemon settings, socket drop-in, kernel forwarding value, every network
tuple, and current bridge before applying the firewall.

Any failure or expired setup journal restores the exact prior daemon JSON,
sysctl file and runtime values, socket drop-in, Docker active/enabled state,
generated policy, and firewall generation.

## Runtime behavior

Containers receive IPv4 DNS, TCP, UDP, and ICMP egress only through the
managed VPN. The compiler emits exact interface-and-prefix guards, explicit
physical-uplink drops, VPN-only masquerade, and default-deny forwarding. NFTFW
never enables a broad `FORWARD` accept.

Docker network IDs are observation-only. The durable authorization identity
is the network name, bridge driver, canonical subnet/gateway tuple, and stable
NFTFW provenance name. When Docker recreates an authorized network with a new
full ID and Linux bridge, the daemon re-observes the unchanged tuple, compiles
and commits a new generation bound to the new bridge, persists the generated
binding, and records Docker healthy. Semantic drift or an added undeclared
bridge degrades the integration and leaves forwarding fail-closed.

Docker-published ports are not public NFTFW exposure. Public VPN-side access
still requires an explicit `nftfw expose`/NAT policy.

## Operations

```bash
sudo nftfw health
sudo nftfw config show --effective
sudo nftfw doctor
sudo journalctl -u nftfwd -u docker
```

Healthy managed status reports the Docker network count and
`ipv4_forwarding: true`. Do not enable Docker firewall management, add manual
uplink forwarding rules, or edit generated bridge bindings.

Package/source uninstall removes only the exact NFTFW socket drop-in. It
deliberately preserves the daemon and sysctl ownership fail-closed and writes
`/var/lib/nftfw/setup/UNINSTALL_HANDOFF`; establish a replacement firewall
before restoring Docker defaults.
