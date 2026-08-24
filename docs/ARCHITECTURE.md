# Architecture

This describes the 2.0.2 candidate design. The candidate is not deployable and
its privileged runtime behavior remains unproved until Stage R2.

## Process and privilege model

```text
desired TOML ----> pure policy model ----> deterministic compiler
                                                |
nftfw CLI ---- control.sock ----+               v
integrations -- typed calls ----+--> nftfwd --> nft backend --> nftables
reconciler ---------------------+

nftfw CLI ---- status.sock -----+
nftfw-web --- status.sock ------+--> read-only health projection
```

`nftfwd` runs as root with `CAP_NET_ADMIN` bounded by systemd and is the normal
long-running process that reaches nftables. `internal/nft` is the sole
code-level boundary that invokes the `nft` executable for checks, inspection,
or mutation. The control socket authorizes only UID 0. The status socket is
group-readable by the unprivileged dashboard. No TCP management listener
exists.

The CLI normally calls the daemon. An explicit `NFTFW_LOCAL=1` recovery mode
can instantiate the same controller locally as root when the daemon is
unavailable; packaged static recovery modes do the same. These explicit paths
remain inside the sole `internal/nft` backend boundary and are never implicit
fallbacks.

## State model

Desired state consists of validated TOML and durable administrator/integration
claims. Loading it has no operating-system side effects.

Observed state consists of nftables JSON, owned object fingerprints,
WireGuard handshakes/endpoints, Docker network observations, active claims,
and integration metadata.

Effective state is a pure combination of desired policy and explicit observed
inputs: active block prefixes, endpoint sets, and Docker networks matching the
configured stable name/driver/bridge/subnet/gateway tuple. Compilation returns
an artifact without applying it.

The high conntrack-mark byte is reserved for immutable ingress provenance.
Original-direction input and forward flows receive a configured interface ID
only while that byte is zero; lower mark bits are preserved. Reply accepts
require the same interface's provenance on the selected egress path. Permanent
name-to-ID assignments and retired tombstones live in a separate monotonic
ledger that generation rollback cannot rewind.

Reconciliation compares the committed generation fingerprint with canonical
owned nftables JSON. Rule handles, counters, and runtime set elements are
treated as volatile; table/chain/rule structure and verdicts are not. Missing
or modified owned objects are repaired from the committed artifact. An
unrelated table is never part of the comparison or repair transaction.

## Owned nftables objects

| Family/table | Purpose |
| --- | --- |
| `inet nftfw_filter` | Input, output, forward policy and runtime sets |
| `ip nftfw_nat` | Explicit IPv4 DNAT and VPN-only container masquerade |
| `ip6 nftfw_filter6` | IPv6 mode marker or early disabled-mode drop hooks |

An apply transaction deletes only owned tables that currently exist, then
creates the complete candidate in one atomic nftables batch. The backend
validates both its internal allowlist and `nft --check --file` before running
`nft --file`. A global ruleset flush is rejected even if a caller attempts to
supply one.

Runtime claim, endpoint, and Docker sets are updated atomically without
rebuilding unrelated policy. Temporary trusted sets use nftables kernel
timeouts and are reconstructed from still-valid SQLite leases after daemon
restart. Trusted elements are intentionally absent from committed snapshots,
preventing expired access from replaying at boot.

Generation restoration and mutable runtime-set restoration are deliberately
separate operations. They run under the same shared NFTFW mutation lock, but
are not one kernel transaction. If mutable runtime security state cannot be
restored after a generation install, that recovery path replaces the owned
tables with the emergency-deny policy and returns an error.

## Foreign-writer audit boundary

The conntrack-provenance collision audit reports scope
`NETFILTER_RULES_ONLY`. It inspects foreign rules in the nftables JSON ruleset;
it does **not** inspect existing conntrack entries, tc, OVS, BPF, other network
namespaces, or privileged userspace writers. The shared mutation lock
serializes NFTFW processes only. Repeated audits narrow races around sensitive
operations, but an independent privileged writer can still race or replace
state and therefore remains inside the explicit trusted-root boundary.

## Safe apply lifecycle

```text
compile -> reserve/validate provenance -> internal validation -> nft --check
   -> verify rollback guard -> persist immutable script/snapshot
   -> persist durable pending database row and deadline
   -> atomic generation apply -> health/fingerprint
   -> pending
        | commit before deadline: record commit_prepared in the database
          -> prepare and fsync temporary generation/checksum pointer
          -> final persisted-deadline read -> atomic pointer rename
             (publication linearization point) -> finalize committed DB state
        | timeout/failure: atomically restore previous committed generation
          -> separately restore mutable runtime sets under the shared lock
```

The CLI is not the rollback clock. `nftfwd` checks every five seconds and
`nftfw-rollback.timer` starts an independent one-shot check every 15 seconds.
Pending/prepared metadata survives process death. A root-owned immutable
snapshot and generation/checksum pointer allow `nftfw-early.service` to
resolve interrupted publication, reconstruct committed enforcement before
normal networking, and remain active. The nonmutating readiness unit verifies
the result before final network consumers may proceed.

If the database cannot be opened, the independent path cannot authenticate its
deadline metadata. It restores only when scoped foreign-rules audits pass, the
authoritative pointer and immutable snapshot (including provenance) verify,
the atomic apply succeeds, and owned-table integrity passes. The caller still
returns nonzero and readiness remains blocked until database recovery. A
healthy database still requires an expired pending generation, so an unrelated
configuration error cannot repeatedly clobber runtime sets. Missing, corrupt,
symlinked, oversized, or checksum-invalid recovery evidence fails before
mutation; it does not trigger emergency deny.

## WireGuard

The policy permits physical bootstrap only to validated host addresses in
`wg_bootstrap_v4` and `wg_bootstrap_v6`. The resolver stores a bounded,
root-only cache and keeps a configurable number of recently seen addresses
during rollover. DNS is refreshed at a fixed 60-second daemon cadence because
the standard resolver does not expose authoritative TTLs. A stale or invalid
cache is rejected; failure never creates a broad uplink exception.

The controller can update the endpoint of exactly one observed peer using
`wg set <interface> peer <key> endpoint <address>`. It rejects ambiguous
multi-peer updates and never logs the peer key. Tunnel creation, keys, and
routing remain external responsibilities.

## Persistence

The replaceable generation SQLite database uses WAL mode, foreign keys, busy
timeout, transactional migrations, constraints, and online backup. It stores
generations, pending/prepared publication state, claims, endpoint history,
audit events, reconciliation, health/recovery events, and integration
metadata. The separate synchronous provenance ledger stores insert-only
interface allocations and permanent retired-ID tombstones. It uses SQLite
DELETE journaling, so its canonical files are the main database and an
optional `-journal`; unexpected `-wal` or `-shm` files are preserved only as
forensic/defensive evidence. Immutable generation scripts are outside both
databases under the root-only state directory and are verified by checksum
before use.

Package responsibilities are listed in `PACKAGES.md`; important tradeoffs are
recorded in `DECISIONS.md`.
