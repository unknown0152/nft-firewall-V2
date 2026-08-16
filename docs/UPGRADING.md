# Upgrading

Back up `/etc/nftfw` and `/var/lib/nftfw` before replacing binaries. Stop
`nftfwd`, install the new version, start it, then run config validation and
status checks. SQLite migrations run transactionally on open. A failed
migration leaves the installed kernel generation untouched.

Do not downgrade across an unknown schema version without restoring a database
backup made by that version.
