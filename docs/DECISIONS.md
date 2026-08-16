# Architecture Decisions

## Typed TOML configuration

**Problem:** V1's ConfigParser values were stringly typed and allowed defaults
to hide unsafe topology mistakes.

**Decision:** Decode a strict TOML document into typed Go structs, reject
unknown fields, then run a separate semantic validator. Parsing has no OS or
nftables side effects.

**Security implications:** malformed or contradictory policy cannot reach the
compiler; configuration path ownership is checked before reading.

## Owned tables instead of a host-wide flush

**Problem:** `flush ruleset` destroys rules managed by unrelated software.

**Decision:** V2 owns only named tables. A transaction destroys/recreates those
tables and never addresses external tables.

**Future consequence:** external routing/NAT managers remain compatible; drift
inspection must account for handles and object comments.

## SQLite claims and generations

**Problem:** V1 JSON sets cannot represent two independent reasons for one
address and are vulnerable to lost updates.

**Decision:** SQLite stores migrations, generations, pending rollback metadata,
claims, endpoint history, and audit events. Effective sets are the union of
active claims.

**Security implications:** deletion is source-scoped and transactional; a
corrupt database fails closed and does not overwrite a known-good generation.

## Unix control/status sockets

**Problem:** a network management port expands the attack surface and claimed
usernames are not trustworthy.

**Decision:** `nftfwd` exposes read-only status and mutation control over
separate Unix sockets. Peer credentials and filesystem permissions authorize
requests.

## Durable safe apply

**Problem:** a CLI waiting for typed confirmation cannot recover after process
death or SSH loss.

**Decision:** apply records a pending generation, prior generation, deadline,
and rollback state before mutation. `nftfwd` and an independent systemd unit
roll back expired candidates.
