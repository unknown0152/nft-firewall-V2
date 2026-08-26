# Troubleshooting

## Setup refused before mutation

Run the dry-run again and record the bounded error code:

```bash
sudo nftfw setup --vpn /path/to/profile.conf --dry-run
```

Do not disable a firewall manager, delete state, flush nftables, or remove
routes to bypass a refusal. Confirm the host is in `SUPPORTED-PLATFORMS.md`.

## Interrupted setup

```bash
sudo nftfw setup status
sudo nftfw setup rollback
sudo journalctl -u nftfw-setup-rollback.service -u nftfwd
```

The independent setup timer rolls back an expired pre-commit transaction.
After a durable commit, recovery proceeds forward to the verified boot state.
An unknown commit state fails closed and requires inspection.

## Interrupted exposure or LAN change

```bash
sudo systemctl status nftfw-managed-rollback.timer
sudo journalctl -u nftfw-managed-rollback.service -u nftfwd
sudo nftfw managed-recover
sudo nftfw health
sudo nftfw config show --effective
```

Do not remove the managed-change journal manually. Recovery uses its exact
generation ID and old/new file hashes to decide whether to finish a committed
change or restore the prior policy.

## Tunnel unhealthy

```bash
sudo nftfw tunnel status
sudo nftfw health
sudo journalctl -u nftfw-vpn.service -u nftfwd
sudo nftfw tunnel restart
```

Public IPv4 must remain blocked on the physical uplink during tunnel failure.

## Managed profile mismatch

`SETUP_ALREADY_MANAGED_PROFILE_MISMATCH` means the supplied profile is not
byte-equivalent to the installed normalized profile. Setup does not replace
VPN identity in place. Use a separately reviewed profile migration.

## Existing-host refusal

`DISCOVERY_EXISTING_NFTFW_REQUIRES_ADOPT` or
`DISCOVERY_EXISTING_DOCKER_REQUIRES_ADOPT` protects an existing deployment.
Use the upgrade/adoption workflow; do not erase evidence.
