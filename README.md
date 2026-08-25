# NFT Firewall V2

> **Current 2.0.2 status: RELEASE CANDIDATE - NOT DEPLOYABLE.** Only
> source-only Stage R work is approved. R2 privileged package, boot, network,
> Docker, and real-OVPN evidence has not been executed for this source
> revision; a prior commit's boot hard stop is not transferable evidence. Do
> not install or deploy this checkout or untagged candidate output.

NFT Firewall V2 is a declarative Linux firewall controller for nftables,
WireGuard, systemd, and SQLite. An operator describes zones, services,
policies, NAT, and runtime integrations in strict TOML. The controller compiles
that intent into deterministic, default-deny nftables transactions and
continuously checks that the owned kernel state still matches.

V2 is an independent Go implementation. V1 was used only as a read-only
behavioral and security reference. See `docs/V1_FEATURE_PARITY.md` and
`docs/V1_SECURITY_INVARIANTS.md`.

External dashboards must consume the fail-closed, versioned status contract
documented in `docs/STATUS-API.md`.

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
- Explicit offline schema 1-5 migration with a byte-identical source backup,
  no-overwrite publication, and read-only schema-6 verification.
- Drift detection and scoped repair of owned tables.
- Optional bounded HTTPS threat feeds, operator-supplied GeoIP CIDR sets, and
  Docker network observation.
- Root-only control socket, read-only status socket, and a local read-only web
  dashboard.
- Static amd64 and arm64 binaries and Debian packages.

## Future tagged-release workflow

The following workflow is documentation for a future accepted tagged release;
it is blocked for the present candidate. Use the prebuilt package whose
checksums and exact bytes were covered by final external approval; do not
rebuild an extracted source tree and silently substitute different bytes.

```bash
unzip nft-firewall-v2-2.0.2.zip
cd nft-firewall-v2
sha256sum -c SHA256SUMS
sudo apt install ./packages/nft-firewall-v2_2.0.2_$(dpkg --print-architecture).deb
sudoedit /etc/nftfw/nftfw.toml
sudo nftfw config validate
sudo nftfw doctor
sudo nftfw plan
sudo nftfw apply --safe
sudo nftfw status
sudo nftfw commit <generation>
```

The installer validates prerequisites, files, checksums, and staged systemd
units before changing host paths. It may reload systemd metadata but does not
enable, start, stop, or restart NFTFW units and never applies a candidate
firewall. Activation and first safe apply are separate guarded deployment
steps. Disabling rollback requires the explicit `--unsafe` flag.

## Security boundaries

`internal/nft` is the sole code-level boundary that invokes the `nft`
executable. `nftfwd` is the normal long-running process that reaches that
backend; explicit root-local CLI recovery and packaged static recovery modes
reuse the same boundary rather than implementing separate nftables mutation.
The daemon listens on local Unix sockets, authenticates peers with kernel
credentials, and accepts strict size-limited JSON. The dashboard has the
status socket only, binds to `127.0.0.1:8787`, and has neither nftables nor
Docker privileges.

The controller expects the declared WireGuard interface and routing policy to
be managed by the operator or `wg-quick`. It refreshes validated peer
endpoints and firewall endpoint sets but does not import keys or construct the
tunnel.

## Build and test

Final release gates require exactly Go 1.25.13, as pinned by `go.mod`. The
source-only pinned matrix passes; post-freeze artifact evidence and every
privileged R2 gate remain outstanding.

```bash
make check
make static vuln security
make release VERSION=2.0.2+ci DISPOSITION=ci
sudo ./tests/namespaces/run.sh
```

The privileged command above is an R2-only example and was not run under Stage
R. Privileged acceptance requires the separately approved disposable test
environment plus nftables, WireGuard, iproute2, tcpdump, network namespaces,
and `CAP_NET_ADMIN`. Exact status is recorded in `TEST_RESULTS.md` and
`FINAL_ACCEPTANCE_REPORT.md`.
