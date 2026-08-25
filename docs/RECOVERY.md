# Recovery

The current 2.0.3 source is a **RELEASE CANDIDATE - NOT DEPLOYABLE**. Recovery
commands must not be exercised on the NUC until the disposable Stage R2 crash,
boot, package, and rollback matrix has passed and the deployment plan is
separately approved.

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

Do not copy a backup over live state from this candidate's documentation. A
final offline recovery procedure must first pass R2 and preserve, under unique
names, at least:

```text
/var/lib/nftfw/generation-state/state.db{,-wal,-shm}
/var/lib/nftfw/provenance-ledger.db
/var/lib/nftfw/provenance-ledger.db-journal  # optional DELETE-mode rollback journal
/var/lib/nftfw/generations/
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

## WireGuard failure

An absent or unhealthy tunnel is a degraded status, not a reason to open the
uplink. Host and container public traffic remains blocked. Bootstrap endpoint
UDP remains narrowly permitted so an external WireGuard manager can recover
the tunnel.

```bash
sudo nftfw wg status
sudo nftfw wg refresh
sudo systemctl restart wg-quick@wg0
sudo nftfw health
```

Replace `wg0` with the declared interface. V2 may update a changed endpoint
for a single peer but does not start the interface or import private keys.

## Emergency host access

Use console/provider recovery if both declared management policy and rollback
paths were administratively disabled. The product deliberately has no hidden
SSH allow rule. Any manual nftables recovery should address only the three
V2-owned tables and preserve unrelated host policy.
