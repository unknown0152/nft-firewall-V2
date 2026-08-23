# NFT Firewall V2

NFT Firewall V2 is a declarative Linux firewall controller for nftables,
WireGuard, systemd, and SQLite. An operator describes zones, services,
policies, NAT, and runtime integrations in strict TOML. The controller compiles
that intent into deterministic, default-deny nftables transactions and
continuously checks that the owned kernel state still matches.

V2 is an independent Go implementation. V1 was used only as a read-only
behavioral and security reference. See `docs/V1_FEATURE_PARITY.md` and
`docs/V1_SECURITY_INVARIANTS.md`.

## Implemented capabilities

- Default-deny input and forwarding, plus strict VPN-pinned output.
- Atomic `nft --check` and apply without `flush ruleset`.
- Ownership limited to `inet nftfw_filter`, `ip nftfw_nat`, and
  `ip6 nftfw_filter6`.
- WireGuard bootstrap constrained by uplink, endpoint address set, UDP port,
  and fwmark.
- Explicit IPv6 `disabled`, `vpn`, and `native` modes.
- Persistent safe apply with commit, timeout rollback, boot snapshot, and an
  independent systemd rollback timer.
- SQLite generations, audit records, endpoint history, integration state, and
  provenance-aware block and temporary-access claims.
- Drift detection and scoped repair of owned tables.
- Optional bounded HTTPS threat feeds, operator-supplied GeoIP CIDR sets, and
  Docker network observation.
- Root-only control socket, read-only status socket, and a local read-only web
  dashboard.
- Static amd64 and arm64 binaries and Debian packages.

## First workflow

```bash
sudo ./scripts/install.sh
sudoedit /etc/nftfw/nftfw.toml
sudo nftfw config validate
sudo nftfw doctor
sudo nftfw plan
sudo nftfw apply --safe
sudo nftfw status
sudo nftfw commit <generation>
```

The installer validates prerequisites, files, units, and checksums but never
applies a candidate firewall. Safe apply is the default. Disabling rollback
requires the explicit `--unsafe` flag.

## Security boundaries

`nftfwd` is the only production nftables mutation boundary. It listens on
local Unix sockets, authenticates peers with kernel credentials, and accepts
strict size-limited JSON. The dashboard has the status socket only, binds to
`127.0.0.1:8787`, and has neither nftables nor Docker privileges.

The controller expects the declared WireGuard interface and routing policy to
be managed by the operator or `wg-quick`. It refreshes validated peer
endpoints and firewall endpoint sets but does not import keys or construct the
tunnel.

## Build and test

Go 1.25.13 or newer in the Go 1.25 line is required for the audited release.

```bash
make check
make static vuln security
make release VERSION=2.0.0
sudo ./tests/namespaces/run.sh
```

Privileged acceptance tests require nftables, WireGuard, iproute2, tcpdump,
network namespace support, and `CAP_NET_ADMIN`. Test status and deliberate
limitations are recorded in `TEST_RESULTS.md` and
`FINAL_ACCEPTANCE_REPORT.md`.
