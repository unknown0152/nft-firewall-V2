# CLI

## Managed setup

```bash
nftfw setup --vpn PATH [--dry-run] [--yes] [--json]
nftfw setup adopt --vpn PATH --dry-run [--json]
nftfw setup status [--json]
nftfw setup rollback [--expired]
```

`setup` is single-writer locked. A healthy repeat with the same profile is a
no-op. A different profile or unhealthy prior managed state is refused. The
dry-run lists adopted Docker networks, NFTFW IPv4-forwarding ownership, and
whether one Docker restart is required. Interactive setup asks again
immediately before that restart; `--yes` accepts both confirmations. This
clean-host path refuses every running or retained Docker container while
retaining eligible empty built-in and custom bridge networks.

`setup adopt` is a separate, root-only, non-mutating reader for a compatible
existing 2.0.3 advanced-mode installation. It does not use the setup mutation
lock, create state, import a profile, or execute conversion. It reads the
protected profile/config/state/provenance and current host observation twice,
then emits a deterministic redacted worksheet. Invocation without
`--dry-run` returns `ADOPTION_EXECUTION_REQUIRES_SEPARATE_LIVE_PLAN` before
inspection or mutation. The JSON schema is `nftfw.adoption-plan.v1`.

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
manifest contains only checksums, sizes, modes, and timestamps. When managed
Docker is enabled, it also includes the exact managed `daemon.json` and
Docker-socket drop-in.

Advanced-mode commands (`config validate`, `doctor`, `plan`, `apply`,
`commit`, `rollback`, claims, and state operations) remain supported.

`nftfw managed-recover [--expired]` is an internal root-only recovery command
owned by `nftfw-managed-rollback.service`. Ordinary operation should use
`expose`, `lan`, `status`, and the documented recovery procedure instead.
