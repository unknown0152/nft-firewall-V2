# CLI

## Managed setup

```bash
nftfw setup --vpn PATH [--dry-run] [--yes] [--json]
nftfw setup status [--json]
nftfw setup rollback [--expired]
```

`setup` is single-writer locked. A healthy repeat with the same profile is a
no-op. A different profile or unhealthy prior managed state is refused.

## Tunnel

```bash
nftfw tunnel status [--json]
sudo nftfw tunnel restart
```

Tunnel loss keeps public IPv4 fail-closed while loopback and declared LAN
management remain available.

## Exposure

```bash
nftfw exposure list [--json]
sudo nftfw expose add tcp 80 443 [--dry-run] [--yes] [--json]
sudo nftfw expose remove tcp 80 443 [--dry-run] [--yes] [--json]
```

Public exposure applies only on the managed VPN interface.
The daemon reloads and compiles the exact protected intent/config files for
each change. A root-only transaction journal and independent timer restore the
prior files and exact pending generation if the CLI exits before commit.

## LAN services

```bash
nftfw lan list [--json]
sudo nftfw lan allow tcp 8096 [--dry-run] [--yes] [--json]
sudo nftfw lan deny tcp 8096 [--dry-run] [--yes] [--json]
```

The proved SSH management ports are separate from optional LAN allowances.
LAN mutations use the same checked, journaled safe-apply transaction as public
exposure changes.

## Inspection

```bash
nftfw health [--json]
nftfw status [--json]
nftfw config show --effective [--json]
nftfw version [--json]
```

## Backup

```bash
sudo nftfw backup create [DIRECTORY] [--json]
sudo nftfw backup verify DIRECTORY [--json]
```

The managed bundle includes generated configuration, non-secret intent,
root-only VPN profile, sysctl state file, generation database, provenance
ledger, enforcement pointer, and immutable generation artifacts. The
manifest contains only checksums, sizes, modes, and timestamps.

Advanced-mode commands (`config validate`, `doctor`, `plan`, `apply`,
`commit`, `rollback`, claims, and state operations) remain supported.

`nftfw managed-recover [--expired]` is an internal root-only recovery command
owned by `nftfw-managed-rollback.service`. Ordinary operation should use
`expose`, `lan`, `status`, and the documented recovery procedure instead.
