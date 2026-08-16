# Architecture

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

`nftfwd` runs as root with `CAP_NET_ADMIN` bounded by systemd. It owns the
only production calls that check, inspect, or mutate nftables. The control
socket authorizes only UID 0. The status socket is group-readable by the
unprivileged dashboard. No TCP management listener exists.

The CLI normally calls the daemon. An explicit `NFTFW_LOCAL=1` recovery mode
can instantiate the same controller locally as root when the daemon is
unavailable; this remains inside the same backend boundary and is never an
implicit fallback.

## State model

Desired state consists of validated TOML and durable administrator/integration
claims. Loading it has no operating-system side effects.

Observed state consists of nftables JSON, owned object fingerprints,
WireGuard handshakes/endpoints, Docker network observations, active claims,
and integration metadata.

Effective state is a pure combination of desired policy and explicit observed
inputs: active block prefixes, endpoint sets, and observed container networks.
Compilation returns an artifact without applying it.

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
creates the complete candidate. The backend validates both its internal
allowlist and `nft --check --file` before running `nft --file`. A global
ruleset flush is rejected even if a caller attempts to supply one.

Runtime claim, endpoint, and Docker sets are updated atomically without
rebuilding unrelated policy. Temporary trusted sets use nftables kernel
timeouts and are reconstructed from still-valid SQLite leases after daemon
restart. Trusted elements are intentionally absent from committed snapshots,
preventing expired access from replaying at boot.

## Safe apply lifecycle

```text
compile -> internal validation -> nft --check -> verify rollback guard
   -> persist candidate and deadline -> atomic apply -> health/fingerprint
   -> pending
        | commit before deadline: committed snapshot + enforcement marker
        | timeout/failure: restore previous committed generation
```

The CLI is not the rollback clock. `nftfwd` checks every five seconds and
`nftfw-rollback.timer` starts an independent one-shot check every 15 seconds.
Pending metadata survives process death. A root-owned active snapshot and
checksum allow `nftfw-early.service` to reconstruct committed enforcement
before normal networking, even before SQLite opens.

If the database is corrupt during an expired rollback, the independent path
restores the committed snapshot. If persistent enforcement is marked but the
snapshot is corrupt, a minimal default-deny owned policy is installed.

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

SQLite uses WAL mode, foreign keys, busy timeout, transactional migrations,
constraints, and online backup. It stores generations, pending rollback
state, claim provenance, endpoint history, audit events, reconciliation,
health/recovery events, and integration metadata. Immutable generation
scripts are stored outside the database under the root-only state directory
and verified by checksum before use.

Package responsibilities are listed in `PACKAGES.md`; important tradeoffs are
recorded in `DECISIONS.md`.
