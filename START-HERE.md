# Start Here

NFT Firewall V2 `2.0.3` is an accepted release. The validated source boundary
is annotated tag `v2.0.3`, commit
`e2b3fa0a20fa6e36325792397564966b21045120`.

Do not apply the example policy unchanged. It uses documentation networks and
placeholder interface names. A wrong uplink, VPN interface, management
network, Docker bridge, or IPv6 choice can disconnect the host.

1. Read `SECURITY.md`, `docs/THREAT-MODEL.md`, and
   `docs/HOST-HANDOFF.md`.
2. Confirm local-console or independent LAN recovery access.
3. Run `sudo ./scripts/host-preflight.sh` from the default branch, then check
   out `v2.0.3` and verify the exact commit. The publication-only preflight
   intentionally postdates the immutable release tag.
4. Audit competing firewall managers, the default route, WireGuard routing,
   Docker ownership settings, IPv4 forwarding, IPv6, listening services, and
   systemd consumers.
5. Install a verified release package. Installation leaves every NFTFW unit
   inactive and does not apply a firewall.
6. Create the WireGuard interface and routing policy independently. Keep its
   private configuration root-owned and mode `0600`.
7. Edit `/etc/nftfw/nftfw.toml` with the real host topology and policy.
8. Run `sudo nftfw config validate`, `sudo nftfw doctor`, and
   `sudo nftfw plan`.
9. Install only the systemd dependency drop-ins required by the reviewed host
   handoff, then enable/start the selected NFTFW units.
10. Run `sudo nftfw apply --safe`; verify management and intended traffic
    through a second session.
11. Commit the returned generation before its deadline with
    `sudo nftfw commit <generation>`.
12. Reboot only after the committed generation, early restore, readiness
    verifier, rollback timer, VPN recovery, and operator rollback bundle have
    all been checked.

Useful checks:

```bash
sudo nftfw status
sudo nftfw health
sudo nftfw audit
systemctl status \
  nftfw-early nftfw-enforcement-ready nftfwd \
  nftfw-rollback.timer nftfw-web
```

If a safe-applied generation is not committed, the daemon and independent
timer both attempt rollback at expiry. The early service restores the
committed enforcement snapshot before normal networking on subsequent boots.
