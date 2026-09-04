# Quick Start

**2.1.0 is awaiting stable validation.** Read
[`docs/RELEASE-2.1.0.md`](docs/RELEASE-2.1.0.md) before using these packages.
Version 2.0.3 remains the stable advanced-mode release.

This path is for a clean Debian 13 amd64 or arm64 server with one IPv4 uplink,
local-console or directly connected private-LAN recovery, and one supported
WireGuard provider profile.

If NFTFW state already exists, do not use this clean-host procedure. After a
supported inert 2.0.3-to-2.1.0 package upgrade, inspect a future conversion
without changing the host:

```bash
sudo nftfw setup adopt --vpn /path/to/working-vpn.conf --dry-run
```

That command only prints a redacted local worksheet. Omitting `--dry-run`
refuses; managed-mode conversion requires a separately approved live plan.

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
explicit statement that public exposure is empty. Also review the detected
network-producer count and `readiness-gated` ownership. If Docker is installed,
also review every adopted bridge network, `Docker IPv4 forwarding: NFTFW
OWNED`, and whether one Docker restart is required. Clean-host setup accepts
eligible empty bridge networks but refuses every running or retained
container; stop and use a separately reviewed existing-host plan instead of
allowing setup to assume ownership of an application workload.

## 3. Configure

```bash
sudo nftfw setup --vpn /path/to/working-vpn.conf
```

Keep the local console or a second LAN session available until setup reports
`Status: PROTECTED`. Setup asks again immediately before restarting Docker
when its daemon ownership settings changed. `--yes` accepts both confirmations
for controlled automation.

The first successful invocation stops at:

```text
Boot preparation: VERIFIED
Status: reboot_required
```

At that point NFTFW has changed only its exact backed-up GRUB/initramfs boot
preparation, the root-only direct-producer setup marker, and journal. The
generated boot transaction holds supported direct network services and
templates before they can configure a non-loopback interface. It has not
changed Docker ownership or forwarding, started the VPN, applied the firewall,
or exposed a service. Reboot explicitly:

```bash
sudo reboot
```

After the server returns, check the redacted state and rerun the same command:

```bash
sudo nftfw setup status
sudo nftfw setup --vpn /path/to/working-vpn.conf
```

Status may report `resume_ready` after the new kernel identity is verified.
The second invocation verifies exactly one `ipv6.disable=1`, no IPv6 address
state, the unchanged GRUB/initramfs transaction, and the same prepared profile
identity before it changes Docker, forwarding, firewall, routing, or VPN
state. LAN management returns under a narrow temporary resume guard; ordinary
physical Internet egress remains denied, DNS is not needed because the
prepared endpoint set is cached privately, and Docker is intentionally held
inactive until NFTFW's ownership files and restart confirmation are complete.
Keep console/LAN recovery until the second invocation reports
`Status: PROTECTED`. NFTFW never performs the reboot itself.

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
Docker: DISABLED
Public exposure: NONE
LAN management: PRESERVED
Boot protection: READY
Network producers: PROTECTED (N readiness-gated)
Rollback: VERIFIED
```

On a host with eligible Docker networks, the Docker line is:

```text
Docker: PROTECTED (N networks, IPv4 forwarding NFTFW-owned)
```

Containers remain private by default. Their IPv4 DNS, TCP, UDP, and ICMP
egress is allowed only through the managed VPN; published ports do not become
NFTFW public exposure.

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
Profile, discovery, Docker, or route-preflight refusals occur before a setup
journal or protected mutation exists and require no rollback. After a journal
exists, use only the status and rollback commands above; the independent timer
also handles an interrupted transaction.

When status is exactly `rolled_back`, rerun the dry-run. A terminal retry is
accepted only after NFTFW proves the captured operator files and runtime state
were restored, all managed services and routing are inactive, every retained
generation is rolled back, and the endpoint/provenance evidence is intact.
Do not delete the journal, backups, generation database, or provenance ledger;
the retry archives the old journal and advances generation numbers normally.
If a later `expose` or `lan` change is interrupted,
`nftfw-managed-rollback.timer` finishes a proved commit or restores the exact
prior files and pending generation.
