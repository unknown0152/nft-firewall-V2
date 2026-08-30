# Uninstall

Prepare another firewall before removing V2. Stopping the services does not
flush the active V2-owned kernel tables; this intentional fail-closed behavior
avoids silently opening the host.

From a source installation:

```bash
sudo ./scripts/uninstall.sh
```

On a managed host, removal first runs the initramfs `disable` transaction.
It removes the protected activation marker, regenerates every installed
initramfs, and proves the pre-udev loader and deny guard are absent before the
handoff binary or systemd unit is removed. If regeneration or verification
fails, it restores the marker, attempts to rebuild and verify the guarded
images, and aborts uninstall. Do not reboot after that failure until
`/usr/lib/nftfw/initramfs/nftfw-initramfs-manage verify-enabled` succeeds.
This prevents package or source removal from silently retaining a deny guard
without its verified root-filesystem handoff.

Configuration and operational state remain under `/etc/nftfw` and
`/var/lib/nftfw`. `--purge-state` is an explicit destructive request and
should be used only after a verified backup.

When managed Docker was enabled, uninstall removes the Docker socket systemd
drop-in only when its bytes still exactly match NFTFW's managed content. A
modified file or symlink is preserved for manual review. The Docker daemon
settings and managed sysctl remain deliberately fail-closed, and the script
writes:

```text
/var/lib/nftfw/setup/UNINSTALL_HANDOFF
```

That record points to the setup journal/backup containing the exact prior
ownership state. Establish and verify a replacement firewall before restoring
Docker defaults or changing `net.ipv4.ip_forward`.

For a Debian package:

```bash
sudo apt remove nft-firewall-v2
```

Package removal preserves state. `apt purge` removes the conffile according to
Debian semantics but still leaves `/var/lib/nftfw` for explicit operator
disposition. Package removal uses the same exact-content Docker drop-in, the
same transactional initramfs handoff, and preserves daemon/sysctl ownership.

After a replacement firewall is active, remove only V2-owned tables if they
remain:

```bash
sudo nft delete table inet nftfw_filter
sudo nft delete table ip nftfw_nat
sudo nft delete table ip6 nftfw_filter6
```

Commands return an error for tables already absent. Never use `flush ruleset`
as an uninstall shortcut.
