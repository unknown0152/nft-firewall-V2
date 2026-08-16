# NFT Firewall V2

NFT Firewall V2 is a declarative Linux firewall controller for nftables and
WireGuard. It compiles a strict typed policy, applies only product-owned
tables, records generations and dynamic claim provenance in SQLite, and
reconciles drift through a small privileged daemon.

V2 is an independent Go implementation. V1 was studied only as a behavioral
and security reference; see `docs/V1_FEATURE_PARITY.md`.

## Operator workflow

```bash
sudo ./scripts/install.sh
sudoedit /etc/nftfw/nftfw.toml
sudo nftfw config validate
sudo nftfw plan
sudo nftfw apply
sudo nftfw status
sudo nftfw commit <generation>
```

The installer never applies a firewall policy. Apply is safe by default and
`--unsafe` must be supplied explicitly to disable its rollback lease. Safe apply persists a rollback
deadline before calling nftables. `nftfwd` and `nftfw-rollback.timer` both
enforce expiration independently of the CLI session.

## Security boundaries

- `nftfwd` is the only nftables mutation boundary.
- `/run/nftfw/control.sock` accepts root peers only.
- `/run/nftfw/status.sock` is read-only.
- `nftfw-web` binds to `127.0.0.1:8787` and has no control or Docker socket.
- Owned tables are `inet nftfw_filter`, `ip nftfw_nat`, and
  `ip6 nftfw_filter6`; normal operation never uses `flush ruleset`.

Build and test with `make check`. Privileged behavior tests are under
`tests/namespaces`; they require a host with `CAP_NET_ADMIN`, WireGuard,
nftables, ping, and tcpdump.
