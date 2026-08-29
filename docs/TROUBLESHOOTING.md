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

## Docker setup refused

Common pre-mutation codes include:

- `DISCOVERY_DOCKER_SOCKET_UNREADABLE`: Docker is installed but the local
  daemon socket cannot be inspected;
- `DOCKER_DAEMON_CONFIG_*`: `daemon.json` is malformed, duplicated,
  oversized, symlinked, unsafe, or changed during read;
- `DOCKER_NETWORK_DRIVER_UNSUPPORTED_*` or
  `DOCKER_NETWORK_MODE_UNSUPPORTED_*`: an undeclared driver, internal
  network, or IPv6 network is present;
- `INTENT_DOCKER_SUBNET_OVERLAPS_*`: Docker IPAM collides with LAN, VPN,
  bootstrap, reserved, or another Docker range;
- `DOCKER_NETWORK_BRIDGE_MISSING_*`: Docker reports a bridge that is absent
  from the host.

Do not edit the generated bridge name, enable Docker iptables, or remove a
network merely to bypass the code. Correct the Docker topology, then repeat
`nftfw setup --dry-run`.

## Docker degraded after setup

```bash
sudo nftfw health
sudo nftfw config show --effective
sudo sysctl net.ipv4.ip_forward
sudo journalctl -u nftfwd -u docker
```

Healthy managed Docker requires the exact five false daemon settings, the
exact socket drop-in, `net.ipv4.ip_forward = 1`, every authorized network, and
its current Linux bridge. A stable network recreation is rebound
automatically. Name, driver, subnet, gateway, mode, multiplicity, or unknown
bridge changes stay degraded and fail-closed until a new semantic setup plan
is confirmed.

## Managed profile mismatch

`SETUP_ALREADY_MANAGED_PROFILE_MISMATCH` means the supplied profile is not
byte-equivalent to the installed normalized profile. Setup does not replace
VPN identity in place. Use a separately reviewed profile migration.

## Existing-host refusal

`DISCOVERY_EXISTING_NFTFW_REQUIRES_ADOPT` protects an existing NFTFW
deployment. Use the upgrade/adoption workflow; do not erase evidence. Docker
alone is not an existing-host refusal: eligible IPv4 bridge networks are
included in the generated plan, while unsupported topology returns a specific
Docker refusal code.
