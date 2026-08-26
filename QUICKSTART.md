# Quick Start

This path is for a clean Debian 13 amd64 or arm64 server with one IPv4 uplink,
local-console or directly connected private-LAN recovery, and one supported
WireGuard provider profile.

## 1. Install

```bash
sudo apt install "./nft-firewall-v2_2.1.0_$(dpkg --print-architecture).deb"
```

Installation is inert. It does not change the live firewall, VPN, routes,
resolver, IPv6 state, services, or exposure.

## 2. Inspect

```bash
sudo nftfw setup --vpn /path/to/working-vpn.conf --dry-run
```

Review the detected uplink, private LAN, management ports, resolver, and the
explicit statement that public exposure is empty.

## 3. Configure

```bash
sudo nftfw setup --vpn /path/to/working-vpn.conf
```

Keep the local console or a second LAN session available until setup reports
`Status: PROTECTED`.

## 4. Verify

```bash
sudo nftfw health
sudo nftfw tunnel status
sudo nftfw exposure list
sudo nftfw lan list
sudo nftfw config show --effective
```

Expected initial state:

```text
Status: PROTECTED
VPN: HEALTHY
IPv4 Internet: VPN ONLY
IPv6: DISABLED
Public exposure: NONE
LAN management: PRESERVED
Boot protection: READY
Rollback: VERIFIED
```

## Later changes

```bash
sudo nftfw expose add tcp 80 443
sudo nftfw lan allow tcp 8096
```

Preview either change with `--dry-run`. Use `--yes --json` for controlled
automation.

If setup stops, run:

```bash
sudo nftfw setup status
sudo nftfw setup rollback
```

Then follow `docs/RECOVERY.md`. Do not flush nftables or delete NFTFW state.
If a later `expose` or `lan` change is interrupted,
`nftfw-managed-rollback.timer` finishes a proved commit or restores the exact
prior files and pending generation.
