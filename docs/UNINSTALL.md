# Uninstall

Prepare another firewall before removing V2. Stopping the services does not
flush the active V2-owned kernel tables; this intentional fail-closed behavior
avoids silently opening the host.

From a source installation:

```bash
sudo ./scripts/uninstall.sh
```

Configuration and operational state remain under `/etc/nftfw` and
`/var/lib/nftfw`. `--purge-state` is an explicit destructive request and
should be used only after a verified backup.

For a Debian package:

```bash
sudo apt remove nft-firewall-v2
```

Package removal preserves state. `apt purge` removes the conffile according to
Debian semantics but still leaves `/var/lib/nftfw` for explicit operator
disposition.

After a replacement firewall is active, remove only V2-owned tables if they
remain:

```bash
sudo nft delete table inet nftfw_filter
sudo nft delete table ip nftfw_nat
sudo nft delete table ip6 nftfw_filter6
```

Commands return an error for tables already absent. Never use `flush ruleset`
as an uninstall shortcut.
