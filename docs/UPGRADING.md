# Upgrading

The current 2.0.2 source is a **RELEASE CANDIDATE - NOT DEPLOYABLE**. No
upgrade may be attempted until Stage R2 and final tagged-package acceptance
are complete. Passing those release gates still does not authorize a server
upgrade; the completed deployment plan requires separate explicit approval.

## Supported package path

The corrected package supports only an established 2.0.2-family state layout:

```text
/var/lib/nftfw/generation-state/state.db
/var/lib/nftfw/provenance-ledger.db
```

An in-place upgrade from a version older than `2.0.2~`, an unknown installed
version, or legacy `/var/lib/nftfw/state.db` is refused. That stop occurs before
dpkg can invoke the legacy package's removal script. A separately implemented,
reviewed, and tested offline migration is required; deleting or renaming state
to evade the guard is prohibited.

For a future supported 2.0.2-to-2.0.2 upgrade, first record unit
enabled/disabled and active/inactive state, then validate and back up the
generation database with the currently installed binary:

```bash
sudo nftfw config validate
sudo nftfw state verify --database /var/lib/nftfw/generation-state/state.db
sudo nftfw state backup /var/lib/nftfw/backups/pre-upgrade.db \
  --database /var/lib/nftfw/generation-state/state.db
```

The Debian `preinst` creates an additional timestamped verified backup when a
nonempty compatible generation database exists. The source installer follows
the same fail-closed sequence. `sqlite3` is used only for an immutable,
read-only check that the migration history is exactly schema 6. The protected,
currently installed `nftfw` binary then performs a nonmigrating online backup
while holding the canonical NFTFW mutation lock, and that binary verifies the
backup through its read-only state path. There is no unlocked `sqlite3` backup
fallback. Either installation path aborts if the lock, installed backup
command, schema check, backup, or verification cannot be proven safe.

The monotonic provenance ledger has a different lifecycle. A generation-state
backup never replaces or rewinds it. Preserve a protected copy as evidence;
restoration requires the separately reviewed merge-only compatibility path
that rejects changed mappings, deletion, ID reuse, or regression. The ledger
uses DELETE journaling: preserve its canonical main file and any optional
`-journal`. Unexpected ledger `-wal` or `-shm` files are defensive/forensic
evidence, not ordinary restore inputs.

## Lifecycle preservation

Package and source upgrades may run `systemctl daemon-reload`, but do not
enable, disable, start, stop, or restart NFTFW units. An inactive installation
remains inactive. An active daemon continues running its previous process image
until an administrator performs the separately reviewed migration/readiness
checks and explicitly restarts it.

After a future approved upgrade, verify without claiming the new executable is
active merely because files were replaced:

```bash
sudo nftfw version
sudo nftfw config validate
sudo nftfw doctor
systemctl is-enabled nftfw-early nftfw-enforcement-ready nftfwd nftfw-rollback.timer nftfw-web
systemctl is-active nftfw-early nftfw-enforcement-ready nftfwd nftfw-rollback.timer nftfw-web
```

Any restart, migration, early restore, or policy reconciliation is a separate
deployment action with rollback and readiness checks. Keep the prior package,
configuration, generation backup, provenance-ledger evidence, and release
checksums until post-upgrade validation completes.
