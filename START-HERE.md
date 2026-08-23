# Start Here

Do not apply the example policy unchanged. It uses documentation networks and
placeholder interface names.

1. Read `SECURITY.md`, `docs/THREAT-MODEL.md`, and `docs/CONFIGURATION.md`.
2. Install with the release package or the source-tree installer.
3. Create the WireGuard interface and routing policy independently; keep its
   private configuration root-owned and mode `0600`.
4. Edit `/etc/nftfw/nftfw.toml` to declare the real uplink, VPN, management
   source network, services, and policies.
5. Run `sudo nftfw config validate`, `sudo nftfw doctor`, and
   `sudo nftfw plan`.
6. Confirm `nftfw-rollback.timer` is enabled and active.
7. Run `sudo nftfw apply --safe`; verify SSH and intended traffic through a
   second session.
8. Commit the returned generation before its deadline with
   `sudo nftfw commit <generation>`.

Useful checks:

```bash
sudo nftfw status
sudo nftfw health
sudo nftfw audit
systemctl status nftfw-early nftfwd nftfw-rollback.timer nftfw-web
```

If the candidate is not committed, the daemon and independent timer both
attempt rollback. The early service restores the committed enforcement
snapshot before normal networking on subsequent boots.
