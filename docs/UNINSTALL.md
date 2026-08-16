# Uninstall

```bash
sudo ./scripts/uninstall.sh
```

Configuration and state are preserved by default. Add `--purge-state` only
after backing them up. Uninstall does not flush nftables and does not remove
third-party tables. Explicitly remove V2-owned tables only after another
firewall is ready.
