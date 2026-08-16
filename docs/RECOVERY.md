# Recovery

Pending safe applies are checked every five seconds by `nftfwd` and every 15
seconds by `nftfw-rollback.timer`. On expiry, the prior committed generation is
loaded atomically; if no prior generation exists, only V2-owned tables are
removed.

Manual recovery:

```bash
sudo nftfw rollback <generation>
sudo systemctl start nftfw-rollback.service
sudo journalctl -u nftfwd -u nftfw-rollback.service
```

If SQLite is unavailable, do not replace the live policy. Restore the database
from an operator backup, validate it with `sqlite3 state.db 'pragma
integrity_check'`, then restart `nftfwd`. Never use `nft flush ruleset` as a
recovery shortcut; it can remove unrelated protections.
