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
- `DISCOVERY_DOCKER_WORKLOADS_REQUIRE_ADOPT`: at least one running or retained
  container makes this a non-clean host; preserve the workload and use a
  separately reviewed migration plan, or intentionally stop and remove only
  disposable containers before retrying clean-host setup;
- `DISCOVERY_DOCKER_STATE_CHANGED`: the running/retained container observation
  changed while Docker topology was being inspected; let Docker settle and
  retry;
- `SETUP_DOCKER_STATE_CHANGED_AFTER_PLAN`: workloads or authorized bridge
  topology changed after confirmation but before ownership-file publication;
  inspect the host and generate a fresh plan;
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

## Route-table preflight refused

`TUNNEL_ROUTE_TABLE_INSPECTION_FAILED` means the bounded numeric all-table
route query itself failed or returned malformed/ambiguous data. A normally
absent reserved table is clean and does not produce this error. Do not create
table 51820 manually; investigate `ip -j -N -4 route show table all`, command
permissions, timeout, and JSON support.

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
deployment. After a supported inert upgrade, run:

```bash
sudo nftfw setup adopt --vpn /path/to/profile.conf --dry-run
```

Do not erase evidence. The 2.1.0 command produces a worksheet only and refuses
execution without `--dry-run`.

Common adoption refusals are:

- `ADOPTION_USAGE_INVALID`: rerun the exact dry-run command shown in the
  refusal; unknown/conflicting options are never echoed;
- `ADOPTION_ALREADY_MANAGED` or `ADOPTION_CLEAN_HOST_USE_SETUP`: use the
  matching ordinary setup/idempotent workflow;
- `ADOPTION_STATE_INVALID`, `ADOPTION_PENDING_GENERATION`, or
  `ADOPTION_PROVENANCE_INVALID`: verify and recover the existing advanced
  deployment before planning conversion;
- `ADOPTION_POLICY_IDENTITY_MISMATCH`: the live owned-table fingerprint does
  not match the committed generation; recover the advanced firewall before
  retrying;
- `ADOPTION_FIREWALL_OWNERSHIP_AMBIGUOUS` or
  `ADOPTION_ROUTING_AMBIGUOUS`: retain advanced mode and investigate ownership;
- `ADOPTION_EXPOSURE_UNSUPPORTED`: advanced policy or DNAT exposes the host
  through a non-VPN ingress; keep advanced mode until a topology-specific
  Stage E-L plan accounts for that service;
- `ADOPTION_DOCKER_TOPOLOGY_UNSUPPORTED`: an existing authorized tuple drifted
  or Docker returned unsupported/ambiguous topology;
- `ADOPTION_OBSERVATION_CHANGED`: protected state or topology changed between
  the two read-only observations; retry after it becomes stable; and
- `ADOPTION_EXECUTION_REQUIRES_SEPARATE_LIVE_PLAN`: actual conversion is Stage
  E-L and is not implemented as a generic 2.1.0 action.

All planner refusals occur without mutation or rollback.
