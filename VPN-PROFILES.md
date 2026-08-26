# VPN Profiles

NFTFW 2.1.0 imports a strict wg-quick-style configuration containing exactly
one `[Interface]` and one `[Peer]`.

## Accepted fields

```text
[Interface]
PrivateKey
Address
DNS
MTU

[Peer]
PublicKey
PresharedKey
AllowedIPs
Endpoint
PersistentKeepalive
```

Requirements:

- valid WireGuard keys;
- at least one usable IPv4 interface address;
- literal IPv4 DNS addresses only;
- exactly one `AllowedIPs` entry representing `0.0.0.0/0`;
- one hostname or IPv4 endpoint and UDP port;
- MTU from 576 through 9000 when present;
- keepalive from 0 through 65535 when present;
- no IPv6 values.

## Always rejected

- `PreUp`, `PostUp`, `PreDown`, or `PostDown`;
- `SaveConfig` or provider-supplied `Table`;
- shell commands or hooks;
- unknown or duplicate fields;
- multiple peers or sections;
- split-tunnel routes;
- symlinks, non-regular files, oversized files, or group/other-writable files;
- a file replaced while NFTFW reads it.

NFTFW writes a normalized root-only copy to
`/etc/wireguard/nftfw0.conf`, adds `Table = off`, and manages routing itself.
The source file is never edited.

Keys, preshared keys, and endpoint literals are never printed in errors or
stored in managed intent, status, the dashboard, setup journal, or release
evidence.
