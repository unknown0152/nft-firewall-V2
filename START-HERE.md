# Start Here

> **2.0.3 is currently a non-deployable Stage R release candidate.** Do not
> execute installation, activation, or apply steps from this checkout.
> Privileged Stage R2 evidence has not been executed. A later R2 pass or final
> release would still not authorize this server's installation: the completed
> deployment plan must receive separate explicit approval.

Do not apply the example policy unchanged. It uses documentation networks and
placeholder interface names.

1. Read `SECURITY.md`, `docs/THREAT-MODEL.md`, and `docs/CONFIGURATION.md`.
2. After a final tagged release is accepted, install with its verified package
   or source-tree installer; installation deliberately leaves all units
   inactive.
3. Create the WireGuard interface and routing policy independently; keep its
   private configuration root-owned and mode `0600`.
4. Edit `/etc/nftfw/nftfw.toml` to declare the real uplink, VPN, management
   source network, services, and policies.
5. Run `sudo nftfw config validate`, `sudo nftfw doctor`, and
   `sudo nftfw plan`.
6. Only after the completed server deployment plan is separately approved,
   follow its guarded activation/handoff procedure and confirm
   `nftfw-rollback.timer` is enabled and active.
7. Run `sudo nftfw apply --safe`; verify SSH and intended traffic through a
   second session.
8. Commit the returned safe-applied generation before its deadline with
   `sudo nftfw commit <generation>`.

Useful checks:

```bash
sudo nftfw status
sudo nftfw health
sudo nftfw audit
systemctl status nftfw-early nftfw-enforcement-ready nftfwd nftfw-rollback.timer nftfw-web
```

If the safe-applied generation is not committed, the daemon and independent
timer both attempt rollback at expiry. The early service restores the
committed enforcement snapshot before normal networking on subsequent boots.
