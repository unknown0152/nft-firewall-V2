# Upgrading

Read release notes and validate the existing configuration with the currently
installed binary first.

```bash
sudo nftfw config validate
sudo nftfw state verify --database /var/lib/nftfw/state.db
sudo nftfw state backup /var/lib/nftfw/backups/pre-upgrade.db
```

The Debian `preinst` creates an additional timestamped online backup before
unpack. The source installer does the same using the installed binary, with a
verified SQLite fallback. Upgrade aborts rather than proceeding without a
safe backup of an existing database.

SQLite migrations run transactionally when the new daemon opens state. A
failed migration leaves the live kernel generation untouched. Newer unknown
schema versions are rejected; do not downgrade across a schema version unless
you restore the database backup made by that version.

After upgrade:

```bash
sudo systemctl is-active nftfwd nftfw-rollback.timer nftfw-web
sudo nftfw version
sudo nftfw config validate
sudo nftfw doctor
sudo nftfw status
```

Package installation does not apply a newly compiled candidate. Existing
committed state may be reconciled if owned kernel objects were missing while
services restarted.

Keep the last known-good package, configuration backup, database backup, and
release checksums until post-upgrade health is established.
