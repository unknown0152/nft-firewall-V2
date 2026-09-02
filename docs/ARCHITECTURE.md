# Architecture

This describes the 2.1.0 design, which preserves the accepted 2.0.3
enforcement core and adds managed setup, import, routing, and intent. Its
source invariants and unprivileged package contracts, including the August 29
managed-Docker reopening, are Stage E-R scope. Privileged runtime, package
lifecycle, reboot recovery, Docker integration, and real-provider tunnel
behavior still require the separately approved 2.1.0 R2 matrix described in
`TEST_RESULTS.md`.

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

Every status request is fresh. The daemon reloads and validates the protected
configuration and managed intent, recompiles desired policy, and re-observes
the schema-6 database, committed generation, provenance ledger, claims,
integrations, WireGuard, forwarding, Docker, and nftables state. The nftables
backend executes one bounded `nft -j list ruleset` and derives owned-table
presence, structural integrity, the canonical generation fingerprint, and the
foreign-provenance collision audit from that same immutable JSON document.
Docker uses one bounded list followed by one batched inspect of every
authorized immutable network ID, then verifies each expected Linux bridge.
The dashboard adds real HTTP/Unix transport but never caches or weakens the
daemon result; it independently derives `protected` from the typed v2 schema.

## State model

Desired state consists of validated TOML and durable administrator/integration
claims. Loading it has no operating-system side effects.

Observed state consists of nftables JSON, owned object fingerprints,
WireGuard handshakes/endpoints, Docker network observations, active claims,
and integration metadata.

Effective state is a pure combination of desired policy and explicit observed
inputs: active block prefixes, endpoint sets, and Docker networks matching the
configured stable name/driver/subnet/gateway identity plus the current
race-consistent bridge binding. Compilation returns an artifact without
applying it.

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

Runtime claim, endpoint, and unchanged Docker subnet sets are updated
atomically without rebuilding unrelated policy. A stable Docker tuple that is
recreated on a new Linux bridge requires a new committed generation because
the interface-and-prefix guard and provenance rules are bridge-bound. Only a
managed `dynamic_bridge = true` entry with exact `docker:<network>` provenance
may take that path. A legacy static advanced entry instead requires the exact
configured bridge and tuple, preserves its historical interface-name
provenance and ledger ID without rewriting configuration, and refuses bridge
recreation. The two projection branches cannot fall back to each other.
Managed mode persists a verified rebind and records the integration healthy
only after both steps succeed. Temporary trusted sets
use nftables kernel timeouts and are reconstructed from still-valid SQLite
leases after daemon restart. Trusted elements are intentionally absent from
committed snapshots, preventing expired access from replaying at boot.

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

Managed `expose` and `lan` changes add a separate file-publication
transaction. The CLI writes checksummed old-file backups and a durable journal
before replacing `intent.toml` and `nftfw.toml`. Artifact and status paths
reload those protected files instead of trusting stale daemon configuration.
The journal records the safe-applied generation before commit.
`nftfw-managed-rollback.timer` then distinguishes committed from
pending/applied/prepared/rolled-back state through the root-only control
socket. It either verifies and keeps the new files or rolls back the exact
generation and restores the exact old bytes. This timer does not replace the
daemon-independent pending-generation timer; the two recover different
durable resources.

## Managed setup and Docker ownership

Managed setup has a read-only preparation boundary followed by a
phase-recorded transaction:

```text
profile/discovery/plan (no journal, no mutation)
  -> durable journal containing the prepared summary
  -> checksum backup -> native initramfs + fixed GRUB fragment
  -> verify generated entries -> reboot_required -> explicit operator reboot
  -> initramfs deny guard -> checksum-bound LAN/endpoint resume guard
  -> Docker service/socket hold + same-profile identity verification
  -> temporary guard -> install/check candidate
  -> durable Docker/forwarding ownership -> confirmation -> release/restart
  -> daemon start without final Requisite -> safe apply -> tunnel
  -> validation -> commit -> early restore/readiness
  -> verify initramfs guard -> publish final Requisite -> boot
```

The explicit `handoff` phase is after the commit linearization point. It first
starts `nftfw-early` and the independent enforcement verifier while the
temporary setup guard and already-running daemon remain active. It then
publishes the managed initramfs marker, rebuilds and inspects every installed
initramfs, and finally writes the daemon/rollback `Requisite=` drop-ins. A
handoff interruption recovers forward from the committed generation; it never
rolls committed state back to make the dependency graph easier to satisfy.

The initial boot-policy preflight accepts only one locally installed Debian
GRUB family and a protected, writable local boot filesystem. Setup backs up
the absent fixed fragment plus generated configuration, publishes exactly one
root-only fragment using no-replace rename and file/parent fsync, runs the
package-owned `update-grub` under a deadline, and proves every generated Linux
entry contains exactly one `ipv6.disable=1`. Systemd-boot, UKI, extlinux,
alternate/multiple GRUB families, foreign fragments or arguments, unsafe
links/modes/ownership, remote/read-only storage, and changing identities are
refused before runtime ownership.

The initramfs hook patches only the staged Debian 13 initramfs-tools udev
prerequisite declaration. Its loader verifies the exact kernel command line
and module-disable proof before udev, confirms no IPv6 address state,
checksums and applies the all-interface deny guard, then records readiness in
the initramfs `/run`. It never tries to re-enable loopback while kernel-wide
disablement is active. The kernel argument prevents built-in or early-probed
NIC MLD/DAD; the nft guard remains a second independent boundary.
After root switch, the generated `network-pre.target` dependency validates the
pending journal and boot identity, then atomically replaces that deny table
with the protected resume guard. The guard exposes no public service and
admits only DHCP, reviewed LAN management replies/flows, and marked UDP to the
checksum-bound cached provider endpoint. Separate generated dependencies hold
both `docker.service` and `docker.socket` until managed daemon ownership and
kernel forwarding are durable. Process death on either side of the nftables
swap is restart-safe; neither/both-table contradictions are refused.
After root switch, `nftfw-enforcement-ready` verifies committed enforcement
and its post-start handoff removes only the exact marker/comment/chain shape
of `inet nftfw_initramfs_guard` under the global mutation lock. A colliding or
extended table is left untouched and blocks readiness.

Clean-host discovery treats pre-existing NFTFW state as requiring recovery or
adoption, with one narrow terminal retry exception. The engine still completes
ordinary preparation before publishing its own journal. A preparation or
initial journal-write failure returns without rollback because no
mutation-capable phase ran. An interrupted `inspect` or incomplete `backup`
journal with no durable backup is terminalized without stopping services;
every guard-or-later phase requires a valid prepared summary and recorded
backup before it uses exact rollback or proved committed recovery.

The retry classifier opens retained state strictly read-only. It requires an
exact canonical `rolled_back`/`failed` uncommitted journal, a verified restored
backup for every protected transaction, no enforcement pointer or owned table,
clean reserved route/rule/interface identities, inactive managed units, only
rolled-back first-generation history, verified immutable scripts/snapshots,
a valid endpoint cache, and one exact active monotonic provenance inventory.
No artifact is deleted or renumbered. Before a retry crosses its mutation
boundary, `Begin` checksum-verifies the current terminal journal, atomically
archives its exact bytes under `setup/history`, fsyncs the file and directory,
and only then publishes the new initial journal. That lineage also makes a
second failure or process death during terminal retry unambiguous.

Discovery queries only the local Docker socket and stores no generated Docker
network ID as durable authorization. Managed intent contains the network name,
bridge driver, canonical IPv4 subnet/gateway pairs, dynamic bridge binding,
and exact stable provenance name `docker:<network>`. Runtime projection treats
that managed identity separately from compatible v2.0.3 advanced entries:
static entries retain the configured bridge, tuple, historical interface-name
identity, and provenance ID byte-for-byte, while any mismatch refuses before
policy mutation.

Clean-host discovery sandwiches strict network observation between two
running/all-container observations. Eligible empty built-in and custom bridges
can be authorized, but any running or retained container is classified as an
existing workload and refused. Setup repeats the clean workload and exact
network-tuple check immediately before publishing ownership files.

Routing ownership is inspected with one bounded `ip -j -N -4 route show table
all` query. Numeric output gives non-main routes an explicit table identity;
an absent reserved table is therefore an empty selection, while malformed
identities, command failure, or any route in the reserved table fail closed.
The implementation never interprets localized stderr or special-cases the
iproute2 missing-table exit status.

The transaction strictly merges `/etc/docker/daemon.json`, preserving
unrelated keys while setting Docker's five firewall/forwarding/masquerade/
proxy mutation controls to false. NFTFW separately owns persistent and runtime
`net.ipv4.ip_forward = 1`, the forwarding policy, VPN-only NAT, and the exact
daemon socket sandbox exception. The setup guard drops forwarded traffic that
does not leave through the managed VPN, so the forwarding sysctl and Docker
restart cannot create a physical-uplink window before the committed policy.
Both prefix-bearing guard sets use nftables interval semantics. VPN bootstrap
elements are still validated and rendered only as canonical IPv4 `/32`
prefixes; interval syntax makes those exact hosts parser-valid and does not
authorize a broader network. The exact generated guard passes `nft --check`
before NFTFW applies its single owned `inet nftfw_setup_guard` table. It never
flushes the ruleset or mutates an unrelated table.

Setup backup payloads are checksummed. Rollback restores exact files, sysctls,
unit state, Docker state, and the prior firewall generation before removing
the guard. An unchanged compliant daemon configuration is an idempotent
no-restart path.

Exact package rollback is a separate protected transaction. Its parent keeps
the canonical mutation lock while exact 2.0.3 maintainer scripts see a fresh
lock inode only inside the dpkg mount namespace. Before boot handoff and again
before dpkg, the manifest-bound exact old binary validates the current
configuration with redacted output. The temporary bridge accepts a schema-6
database only as a UID-0, mode-0600, single-link file owned by either the
legacy root group or the exact v2.1 dashboard-service group.

## Existing-host adoption planner

The adoption planner is structurally separate from the managed setup engine.
It has no writer, setup journal, mutation lock, service-control API, nftables
backend, routing manager, or Docker mutation method. The CLI accepts only:

```text
setup adopt --vpn PATH --dry-run [--json]
```

The system inspector uses strict profile/config readers, immutable read-only
schema-6 SQLite, the verified enforcement pointer/snapshot, read-only
provenance, bounded nftables/discovery commands, the explicit local Docker
socket, `systemctl show`, `ip -j ... show`, and `sysctl -n`. It reduces raw
addresses, endpoint data, interface/network identities, and Docker details to
counts or fixed classifications plus private digests. It repeats the entire
observation and requires both sanitized facts and private digests to match.

The pure planner validates the supported adoption boundary and emits
`nftfw.adoption-plan.v1`. Actual ownership transfer has no code path from this
component and remains a separately reviewed Stage E-L transaction.

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
