# Recovery

NFT Firewall V2 2.1.0 retains the 2.0.3 generation, boot, package, and
rollback architecture and adds separate managed-setup and managed-policy
file-publication journals and watchdogs. Recovery still depends on
local-console or independent LAN access and the actual deployed generation.

## Adoption-planner interruption

`nftfw setup adopt --vpn PATH --dry-run` has no recovery transaction. It does
not acquire the setup mutation lock or create a journal, backup, intent,
generated policy, VPN copy, route, nftables object, sysctl, systemd change, or
Docker change. Killing it at any point requires no rollback. Run the same
command again; if the two race-consistent observations differ, it refuses with
`ADOPTION_OBSERVATION_CHANGED`.

Every planner error confirms `live state changed: NO` and `rollback required:
NO`. The detailed-log pointer is the existing root-only daemon journal; the
planner itself writes no log.

## Managed setup interruption

Inspect the root-only setup journal:

```bash
sudo nftfw setup status
sudo systemctl status nftfw-setup-rollback.timer
sudo journalctl -u nftfw-setup-rollback.service -u nftfwd
```

An expired pre-commit transaction is rolled back from its verified setup
bundle:

```bash
sudo nftfw setup rollback
```

Rollback first stops the managed tunnel when it may exist, rolls back only the
exact pending generation, restores files, sysctls, unit state, routes, DNS,
and resolver ownership, then removes the temporary guard. It never flushes the
ruleset.

When Docker was adopted, the setup backup also contains a SHA-256 for the
exact prior `daemon.json`, the Docker socket drop-in state, the previous
`net.ipv4.ip_forward` value, and Docker enabled/active state. A failure before,
during, or after the confirmed Docker restart restores those exact resources
while the temporary setup guard still blocks physical container forwarding.
Checksum failure stops restoration with
`SETUP_BACKUP_RESTORE_CHECKSUM_FAILED`.

If the firewall generation committed but the process died before recording
that fact in the setup journal, recovery verifies the active committed
generation and continues forward to boot readiness. If commit state cannot be
proved, it reports `SETUP_COMMIT_STATE_UNKNOWN` and does not perform a
destructive rollback.

Docker-specific setup failures are actionable and remain pre-commit:

- `SETUP_POLICY_CHECK_FAILED`: the generated nftables candidate did not pass
  before Docker ownership change;
- `SETUP_DOCKER_CONFIG_CHANGED_AFTER_PLAN`: `daemon.json` changed after the
  reviewed plan;
- `SETUP_DOCKER_RESTART_FAILED`: the one confirmed Docker restart failed;
- `SETUP_DOCKER_IPV4_FORWARDING_FAILED`: kernel forwarding is not exactly
  `1`;
- `SETUP_DOCKER_TOPOLOGY_CHANGED` or
  `SETUP_DOCKER_VALIDATION_FAILED`: an authorized network tuple or bridge
  changed.

Do not retry by enabling Docker iptables or adding a broad forwarding rule.
Let rollback complete, inspect Docker through `docs/DOCKER.md`, and run a new
dry-run.

## Docker runtime rebind

The daemon checks Docker topology on its regular refresh loop. A network
recreation with the same authorized name, driver, canonical subnet/gateway
tuple, and a new race-consistent full ID may produce a new Linux bridge name.
NFTFW marks Docker degraded, compiles and commits a new generation for the new
bridge, atomically persists the generated binding, republishes mutable claims,
and then records Docker healthy.

The firewall generation is committed before the generated binding is
published. If the daemon dies or the file write fails in between, the old
generated binding causes the next refresh to repeat the safe rebind; the
already-active generation remains fail-closed. A semantic tuple change,
undeclared bridge, missing bridge, or invalid daemon ownership never enters
the rebind path.

```bash
sudo nftfw health
sudo nftfw config show --effective
sudo journalctl -u nftfwd -u docker
```

Look for the `docker_bridge_rebound` audit event and a healthy Docker
integration state. Do not edit `bridge_interface` manually.

## Managed exposure or LAN change interruption

Managed `expose` and `lan` mutations first save exact checksummed copies of
`intent.toml` and `nftfw.toml` under
`/var/lib/nftfw/managed-change/`. The daemon reloads those protected files,
compiles them, safe-applies the resulting generation, and commits only after
tunnel validation. The journal records the returned generation before the
commit request.

`nftfw-managed-rollback.timer` checks every 15 seconds. Recovery asks the
privileged daemon for the exact journaled generation state:

- `committed`: verify the new file hashes and finish forward;
- `pending`, `applied`, or `commit_prepared`: roll back that exact generation
  and restore the exact prior file bytes;
- `rolled_back` or no generation recorded: restore the exact prior file bytes;
- unavailable, malformed, or unknown generation state: leave the journal in
  place and fail closed for another timer/operator attempt.

The ordinary generation timer remains independent, so a crash after kernel
apply but before the CLI records the generation still expires and rolls back
the pending firewall while the managed-change timer restores the old files.

```bash
sudo systemctl status nftfw-managed-rollback.timer
sudo journalctl -u nftfw-managed-rollback.service -u nftfwd
sudo nftfw managed-recover
sudo nftfw health
sudo nftfw config show --effective
```

Do not delete `/var/lib/nftfw/managed-change/` during recovery. The journal
contains hashes and non-secret policy data, not VPN keys.

## Uncommitted apply

Pending safe applies are checked every five seconds by `nftfwd` and every 15
seconds by `nftfw-rollback.timer`. The configured deadline is 30 through 600
seconds. On expiry, the previous committed generation is installed as one
atomic nftables transaction. Mutable runtime sets are then reconstructed as a
separate step while the same shared NFTFW mutation lock is held. If that
runtime-state restoration fails, the recovery path installs the owned
emergency-deny policy and reports an error. A confirmed safe-applied
first-generation rollback removes only V2-owned tables and clears boot
enforcement.

```bash
sudo nftfw status
sudo nftfw rollback <pending-generation>
sudo systemctl start nftfw-rollback.service
sudo journalctl -u nftfw-rollback.service -u nftfwd
```

Rollback is idempotent. Commit rejects an expired safe-applied generation and
initiates its rollback; the daemon and independent timer likewise roll it back
at expiry. Rollback rejects tampered, historical, or otherwise inapplicable
generation identifiers, but expiry itself is the reason an eligible rollback
must remain permitted.

### Ambiguous first apply

If `nft --file` reports an error, the kernel transaction may still have
completed before userspace observed a timeout, cancellation, or output-limit
failure. With no earlier committed generation, product-named tables in that
state are not enough to prove ownership. V2 therefore retains the pending
record and refuses automatic deletion. The corrupt-database fallback also
refuses to mutate product-named tables when no verified enforcement pointer
exists.

Preserve the generation database and journal, immutable snapshots, enforcement
pointer, and monotonic provenance ledger. Inspect live rules from a trusted
console and establish ownership before any manual removal. Do not use `nft
flush ruleset`. When no product-named table exists, the pending failure can be
finalized without a kernel mutation.

## Daemon or CLI failure

The CLI process is not needed after apply. If `nftfwd` exits or is killed,
systemd restarts it. Pending metadata survives. If the daemon cannot recover,
the independent timer invokes `nftfwd --rollback-expired` directly.

```bash
sudo systemctl restart nftfwd
sudo systemctl is-active nftfwd nftfw-rollback.timer
sudo nftfw health
```

## Database failure

Do not initialize a blank database over known enforcement state. The
root-owned generation/checksum `enforcement-enabled` pointer prevents that
downgrade. When SQLite cannot be opened, the independent path cannot safely
trust its deadline state. It attempts a restore only after the scoped foreign
netfilter-rules audit succeeds and the pointer, immutable snapshot, policy
checksum, and monotonic provenance assignments all verify. It repeats the
foreign audit immediately before the atomic nftables apply and then requires
owned-table integrity to pass. Even after a successful defensive restore, the
command returns nonzero and readiness remains blocked because no database
recovery transition was authorized. With a healthy database, configuration
failure alone never authorizes a restore: an actually expired pending
generation is still required. A missing pointer never authorizes deletion of
product-named tables.

Do not copy a backup over live state without a reviewed offline recovery
procedure. Preserve, under unique names, at least:

```text
/var/lib/nftfw/generation-state/state.db{,-wal,-shm}
/var/lib/nftfw/provenance-ledger.db
/var/lib/nftfw/provenance-ledger.db-journal  # optional DELETE-mode rollback journal
/var/lib/nftfw/generations/
/var/lib/nftfw/managed-change/  # only while a managed policy transaction is unresolved
/var/lib/nftfw/active.snapshot.json  # legacy evidence only; never published by 2.0.3
/var/lib/nftfw/enforcement-enabled
```

Generation backup restore must validate the generation/checksum pointer and
must never overwrite or rewind the ledger. Ledger restoration is merge-only
and rejects changed mappings, removed tombstones, ID reuse, or regression. Use
a unique recovery directory if prior failed files already exist, and preserve
failed generation-database WAL/SHM files and the ledger's optional DELETE-mode
`-journal` for diagnosis. Ledger `-wal` or `-shm` files are not canonical 2.0.3
state; if encountered, preserve them separately as unexpected forensic or
defensive evidence rather than treating them as normal restore inputs. Never
use `nft flush ruleset`; it can remove unrelated protections.

## Boot enforcement

When a generation is committed, V2 writes an immutable checked snapshot and a
generation/checksum enforcement pointer. At boot, `nftfw-early.service`
resolves durable prepared/pending state, restores the uniquely selected
snapshot before `network-pre.target`, and remains active. The nonmutating
`nftfw-enforcement-ready.service` must verify that enforcement before audited
network consumers start. Runtime trusted leases are excluded so expired access
cannot replay.

`network-pre.target` pulls early and readiness independently. Readiness orders
after early but has no `Wants=`, `Requires=`, or `Requisite=` edge to it, so
the common boot transaction can run early first while a manual readiness start
cannot activate snapshot restoration. The verifier, required by
`network-pre.target`, is the fail-closed success dependency. Final consumer
drop-ins retain `Requisite=` plus `After=` on readiness so a routine consumer
restart cannot activate either readiness or early restore.

If a required pointer or snapshot is missing, corrupt, symlinked, oversized,
or has an invalid checksum, recovery fails before an nftables mutation and
readiness remains blocked. It does not select the emergency-deny policy merely
because immutable recovery evidence is unusable. Emergency deny is reserved
for a failure to restore separate mutable runtime security state after a
generation installation path has already run.

```bash
sudo systemctl status nftfw-early nftfw-enforcement-ready
sudo journalctl -b -u nftfw-early -u nftfw-enforcement-ready
sudo nftfw reconcile
```

## Managed WireGuard failure

An absent or unhealthy tunnel is a degraded status, not a reason to open the
uplink. Host public traffic remains blocked. Bootstrap endpoint UDP remains
narrowly permitted so NFTFW can recover the tunnel.

```bash
sudo nftfw tunnel status
sudo nftfw tunnel restart
sudo nftfw health
```

Managed mode owns `nftfw0`, its DNS handoff, route table, policy rules, and
WireGuard lifecycle. Advanced 2.0.3-compatible configurations continue to use
their separately managed WireGuard path.

## Emergency host access

Use console/provider recovery if both declared management policy and rollback
paths were administratively disabled. The product deliberately has no hidden
SSH allow rule. Any manual nftables recovery should address only the three
V2-owned tables and preserve unrelated host policy.
