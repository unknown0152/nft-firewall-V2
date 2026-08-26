# Architecture Decisions

The 2.1.0 design preserves the 2.0.3 decisions validated in source and
privileged environments. A new host still requires the topology audit,
recovery preparation, and guarded activation described in `HOST-HANDOFF.md`.

Each decision records a maintenance constraint, not merely the implementation
selected for v2.0.0.

## Strict typed TOML

Problem: V1 string values and implicit defaults could hide unsafe topology
mistakes.

Options: permissive INI, YAML with custom coercion, or strict TOML.

Decision: decode TOML into concrete Go types, reject unknown fields, then run
a separate semantic validator. Parsing remains side-effect free.

Security implications: malformed, duplicate, contradictory, or unsupported
policy cannot reach the compiler. Existing config paths must be protected,
root-owned regular files reached without symlinks.

## Strict VPN mode only

Problem: optional output filtering creates two substantially different safety
models and makes a declared kill switch easy to misunderstand.

Options: support permissive mode, infer mode from routes, or require strict
mode.

Decision: v2.0.0 rejects `strict_vpn = false`.

Security implications: all public host/container egress is explicitly pinned
to the VPN; no downgrade is accepted silently. A future permissive mode would
require a separate threat model and acceptance suite.

## Owned tables instead of a host-wide flush

Problem: `flush ruleset` destroys policy managed by unrelated software.

Options: own the whole host ruleset, coexist by convention, or enforce a
small named ownership domain.

Decision: V2 addresses only three fixed tables and fingerprints only their
objects.

Security implications: third-party tables survive apply, rollback, drift
repair, and uninstall. Operators remain responsible for interactions caused
by other base chains at different priorities.

## nft command JSON backend

Problem: a native netlink backend reduces process execution but raises initial
complexity and library risk; text parsing is unstable.

Decision: use the official `nft` executable with argument arrays, structured
JSON inspection, bounded output, candidate files, `--check`, and atomic
transactions. `internal/nft` is the sole code-level boundary that invokes the
executable. The normal daemon, explicit root-local CLI recovery, and static
recovery modes all reuse that backend rather than creating another mutation
implementation.

Future consequence: a netlink backend can replace the implementation without
changing policy or reconciliation contracts.

## Generation SQLite plus monotonic provenance ledger

Problem: ownership-less JSON sets cannot represent independent reasons for one
address and are vulnerable to partial updates.

Decision: the replaceable generation SQLite database stores claims,
publication state, and immutable firewall-generation identities. A separate
synchronous, insert-only ledger permanently binds interface names to ingress
provenance IDs and retains retired tombstones. Generation backup/rollback may
not replace or rewind that ledger.

Security implications: removing one producer's claim cannot remove another;
surviving conntrack marks retain one interpretation across generation rollback;
and constraints/checksums make malformed durable state fail closed.

## Unix control and status sockets

Problem: a network management port expands exposure, and a username supplied
inside JSON is not authentication.

Decision: use separate local sockets. Kernel peer credentials authorize root
control; filesystem groups authorize read-only status.

Future consequence: remote administration must be built as an optional,
separately authenticated adapter to the typed API.

## Durable safe apply and boot snapshot

Problem: a CLI confirmation loop dies with SSH or the process and cannot
restore policy early during boot.

Decision: persist pending state before apply, require an active independent
timer, and publish commits through prepared database state, an immutable
checksum-protected snapshot, a generation/checksum enforcement pointer, and a
final database transition. Early recovery is idempotent across each boundary;
`network-pre.target` independently pulls the early restorer and requires a
nonmutating readiness verifier. Readiness orders after early without a
`Requisite=` or activating dependency. Final network consumers retain
nonactivating `Requisite=`/`After=` edges to the already-active verifier.

Security implications: CLI/daemon death and database corruption do not imply
allow-all. Missing or corrupt immutable recovery evidence stops before any
nftables mutation and makes the verifier fail, which blocks
`network-pre.target` and consumers. Manually starting readiness or a consumer
cannot activate snapshot restoration. Emergency default deny is reserved for
a later failure to reconstruct mutable runtime security state after a
generation installation has succeeded.

## Fixed endpoint refresh cadence

Problem: the Go standard resolver returns addresses but not DNS TTLs.

Options: add a DNS protocol dependency, implement DNS directly, or use a
bounded fixed refresh interval.

Decision: refresh every 60 seconds, retain only bounded recent valid endpoint
addresses, and expire cache history by age.

Future consequence: authoritative TTL support can be added behind the
resolver interface. Documentation must not claim TTL-aware behavior today.

## Docker CLI observer

Problem: container addresses change, but the Docker socket is effectively
root-equivalent and must not reach the dashboard.

Decision: only the privileged daemon may run the Docker CLI, explicitly pinned
to `unix:///var/run/docker.sock`, and only when Docker's own iptables,
ip6tables, forwarding, masquerade, and userland proxy mutation are disabled.
Authorization requires the exact configured network name, `bridge` driver,
explicit stable Linux bridge name, subnet, and gateway. The generated network
ID only keeps one observation race-consistent and may not authorize traffic.
The packaged service hides the socket by default; enabling observation also
requires an explicit administrator-installed systemd drop-in.

Security implications: Docker observation remains privileged and
root-equivalent when explicitly granted, but is separated from HTTP and
cannot be enabled through TOML alone. The firewall core receives only exact
validated stable network tuples.

## Static web dashboard

Problem: a management framework or mutable web UI adds dependencies, CSRF,
and privilege pressure.

Decision: embed a small read-only page and same-origin assets in a separate
unprivileged process. It can call only `status.sock`.

Future consequence: mutations remain CLI/control-socket operations. Adding web
control would be a new security boundary, not a small feature toggle.
