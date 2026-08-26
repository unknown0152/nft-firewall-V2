# Docker

Managed setup does not silently take over an active Docker host.

- Docker absent: normal clean-host setup.
- Docker installed with no containers and no custom networks: setup may
  continue, but Docker integration remains disabled.
- Any running or retained workload, custom network, published-port
  dependency, Cosmos installation, or uncertain state: automatic setup
  refuses before mutation.

Docker firewall ownership requires a separately reviewed handoff that
preserves unrelated `daemon.json` keys, disables Docker's nftables/iptables
ownership settings, proves persistent forwarding, restarts Docker only with
explicit disruption approval, and validates container recreation and
rollback.

Do not disable Docker firewall management on a live host merely to make the
clean-host check pass.
