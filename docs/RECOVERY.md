# Recovery

## Uncommitted apply

Pending safe applies are checked every five seconds by `nftfwd` and every 15
seconds by `nftfw-rollback.timer`. The configured deadline is 30 through 600
seconds. On expiry, the previous committed generation and its runtime sets are
restored atomically. A first-generation rollback removes only V2-owned tables
and clears boot enforcement.

```bash
sudo nftfw status
sudo nftfw rollback <pending-generation>
sudo systemctl start nftfw-rollback.service
sudo journalctl -u nftfw-rollback.service -u nftfwd
```

Rollback is idempotent. Commit and rollback reject expired, tampered,
historical, or inapplicable generation identifiers.

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
root-owned `enforcement-enabled` marker prevents that downgrade. During
rollback, an unavailable/corrupt database causes the independent path to use
the checksum-protected committed snapshot.

Verify and restore an operator backup offline:

```bash
sudo systemctl stop nftfwd nftfw-rollback.timer
sudo nftfw state verify --database /var/lib/nftfw/backups/<backup>.db
sudo install -d -o root -g root -m 0700 /var/lib/nftfw/recovery
sudo mv /var/lib/nftfw/state.db /var/lib/nftfw/recovery/state.db.failed
sudo test ! -e /var/lib/nftfw/state.db-wal || sudo mv /var/lib/nftfw/state.db-wal /var/lib/nftfw/recovery/state.db.failed-wal
sudo test ! -e /var/lib/nftfw/state.db-shm || sudo mv /var/lib/nftfw/state.db-shm /var/lib/nftfw/recovery/state.db.failed-shm
sudo install -o root -g root -m 0600 /var/lib/nftfw/backups/<backup>.db /var/lib/nftfw/state.db
sudo systemctl start nftfw-rollback.timer nftfwd
sudo nftfw health
```

Use a unique recovery directory if prior failed files already exist. Preserve
the failed database and WAL/SHM files for diagnosis. Never use `nft flush
ruleset`; it can remove unrelated protections.

## Boot enforcement

When a generation is committed, V2 writes an immutable checked snapshot and
enforcement marker. `nftfw-early.service` runs before `network-pre.target` and
restores it before `nftfwd`. Runtime trusted leases are excluded so expired
access cannot replay.

If a required snapshot is missing, corrupt, symlinked, oversized, or has an
invalid checksum, the early process installs a minimal owned default-deny
policy and exits with an error for systemd/journal visibility.

```bash
sudo systemctl status nftfw-early
sudo journalctl -b -u nftfw-early
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
