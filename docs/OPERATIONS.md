# Operations

The current 2.0.2 source is a non-deployable Stage R candidate. These commands
describe future operation after final acceptance; none was run on the NUC as
part of Stage R.

## Command reference

| Command | Purpose |
| --- | --- |
| `nftfw version [--json]` | Build version, commit, and date |
| `nftfw config validate [path]` | Strict decode, filesystem, and semantic validation |
| `nftfw doctor` | Live topology, ownership, fwmark, rollback guard, and kernel check |
| `nftfw plan [--json] [--show-nft]` | Semantic diff and exact checked candidate without apply |
| `nftfw apply [--safe|--unsafe]` | Apply candidate; safe is the default |
| `nftfw commit <generation>` | Commit an unexpired, untampered pending generation |
| `nftfw rollback <generation>` | Roll back the currently eligible pending generation |
| `nftfw reconcile` | Inspect and repair committed owned drift |
| `nftfw status [--json]` | Read status snapshot |
| `nftfw health [--json]` | Status plus nonzero exit when degraded |
| `nftfw explain ...` | Explain effective allow/deny from the compiler model |
| `nftfw audit` | Recent durable audit records; root control access required |
| `nftfw blocks list [--limit N] [--offset N]` | Paginated active claims |
| `nftfw block add/remove` | Manual block claim operations |
| `nftfw allow add/remove` | Expiring trusted access operations |
| `nftfw wg status/refresh` | Handshake status or endpoint refresh |
| `nftfw state backup/verify` | Consistent SQLite backup and integrity check |

The CLI uses `/run/nftfw/status.sock` and `/run/nftfw/control.sock`. For an
explicit root recovery operation only, `NFTFW_LOCAL=1` bypasses an unavailable
daemon while retaining the same controller/backend checks. Socket failure
never silently escalates to local mutation.

## Safe policy change

```bash
sudo nftfw config validate
sudo nftfw doctor
sudo nftfw plan
sudo nftfw apply --safe
sudo nftfw status
sudo nftfw commit <generation>
```

`plan` shows policy/NAT additions and removals, runtime set counts, explicit
security invariants, and `nft --check` status. Management reachability is
reported as not proven because it depends on declared policy and topology;
V2 does not insert a hidden SSH exception.

After apply, test management, DNS, intended VPN egress, intended inbound
services, and container traffic before commit. An uncommitted candidate is
rolled back at its configured deadline.

## Explain a decision

```bash
sudo nftfw explain --from 192.168.1.50 --to host --protocol tcp --port 22
sudo nftfw explain --from lan --to any --protocol udp --port 53
```

Explanation loads current non-expired claims and reports the source zone,
matched policy, reason, and compiled object identity. Precedence includes IPv6
mode, active blocks, temporary trusted access, explicit policy, and final
default deny. It does not packet-trace arbitrary third-party nftables chains.

## Dynamic claims

```bash
sudo nftfw block add 203.0.113.20/32 --ttl 24h scanner
sudo nftfw block add 203.0.113.20/32 repeated-scanner
sudo nftfw allow add 198.51.100.8/32 --ttl 15m maintenance
sudo nftfw blocks list
sudo nftfw block remove <claim-id>
sudo nftfw allow remove <claim-id>
```

Manual blocks are permanent when `--ttl` is omitted (`0`). Temporary access
defaults to 15 minutes and cannot be permanent. Addresses are canonicalized.
Operator removal is typed: it cannot delete integration-owned claims or cross
between block and allow ownership.

## Status and audit

```bash
sudo nftfw status --json | jq .
sudo nftfw health
sudo nftfw audit
journalctl -u nftfw-early -u nftfw-enforcement-ready -u nftfwd -u nftfw-rollback.service -u nftfw-web
```

Status includes active/pending generation, checksum, kill-switch state,
WireGuard health, endpoint count, claim counts by provenance, drift, database
health, integration state, and recent audit events. It contains no keys or
peer identifiers. The machine-readable contract and fail-closed consumer
rules are defined in `STATUS-API.md`.

The read-only dashboard is available locally at `http://127.0.0.1:8787/`.
Use SSH port forwarding for remote viewing rather than changing its bind:

```bash
ssh -L 8787:127.0.0.1:8787 <host>
```

## Backup

```bash
sudo install -d -m 0700 /var/lib/nftfw/backups
sudo nftfw state backup /var/lib/nftfw/backups/state-$(date -u +%Y%m%dT%H%M%SZ).db \
  --database /var/lib/nftfw/generation-state/state.db
sudo nftfw state verify --database /var/lib/nftfw/generation-state/state.db
```

The backup destination must be absolute, new, and beneath a protected
root-owned directory. The online generation-database backup is transactionally
consistent. It does not back up or authorize replacement of the separate
monotonic `/var/lib/nftfw/provenance-ledger.db`.

## Drift policy

Every 30 seconds the daemon checks the committed owned fingerprint. Deleted
or structurally modified owned rules/tables are audited and auto-repaired;
runtime sets are then restored. Failure to restore all mutable security state
installs the owned emergency deny policy. Third-party tables are ignored and
preserved.

Integration failures are degraded/alerting events that retain known-good
claims. A malformed desired policy is rejected and never replaces committed
kernel state.
