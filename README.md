# NFT Firewall V2

> **Current release: 2.0.3.** The immutable annotated tag `v2.0.3` points to
> source commit `e2b3fa0a20fa6e36325792397564966b21045120`. Stage R, privileged
> R2, post-tag validation, package/archive inspection, reproducibility,
> secret scanning, and final release approval passed on 2026-08-25.

NFT Firewall V2 is a declarative Linux firewall controller for nftables,
WireGuard, systemd, Docker, and SQLite. An operator describes zones, services,
policies, NAT, and runtime integrations in strict TOML. The controller compiles
that intent into deterministic, default-deny nftables transactions and
continuously checks that the owned kernel state still matches.

This is security-sensitive host software, not a universal one-click firewall.
Every target machine must be audited for its interfaces, management path, VPN
routing, existing firewall managers, container networking, IPv6 mode, and
recovery access before installation or activation. Start with
`docs/HOST-HANDOFF.md` and the read-only `scripts/host-preflight.sh`.

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

## Before installation

Use a local console or a proven second LAN management session. Do not perform
the first activation over the same route that the new firewall or VPN will
replace.

```bash
sudo ./scripts/host-preflight.sh
git checkout v2.0.3
test "$(git rev-parse HEAD)" = \
  e2b3fa0a20fa6e36325792397564966b21045120
```

The preflight lives on the default branch because it was added after the
immutable release tag. It is read-only. A PASS does not prove that the example
policy matches the host. Review its warnings and complete
`docs/HOST-HANDOFF.md` before checking out the release source.

## Build from the validated tag

The release toolchain is Go 1.25.13 as pinned by `go.mod`.

Prebuilt amd64 and arm64 packages, binaries, and the approved checksum
manifest are attached to the GitHub `v2.0.3` release. The commands below
reproduce those bytes from the exact tag.

```bash
test -z "$(git status --porcelain)"
export NFTFW_COMMIT="$(git rev-parse HEAD)"
export NFTFW_BUILD_DATE="$(
  date -u -d "$(git show -s --format=%cI HEAD)" +%Y-%m-%dT%H:%M:%SZ
)"
make check
make deb \
  VERSION=2.0.3 \
  COMMIT="$NFTFW_COMMIT" \
  BUILD_DATE="$NFTFW_BUILD_DATE" \
  DISPOSITION=release
sha256sum -c dist/SHA256SUMS
```

Install only the package matching the target architecture:

```bash
sudo apt install \
  "./dist/nft-firewall-v2_2.0.3_$(dpkg --print-architecture).deb"
```

Installation is deliberately inert. It does not start the VPN, enable NFTFW
units, apply a firewall, or select a policy. Continue with `INSTALL.md` and the
host-specific handoff plan.

## First safe apply

After replacing every example interface, address, service, and network with
audited host values:

```bash
sudo nftfw config validate
sudo nftfw doctor
sudo nftfw plan
sudo nftfw apply --safe
sudo nftfw status
sudo nftfw commit <generation>
```

Verify management access, VPN egress, intended inbound services, container
traffic, and IPv6 behavior before committing. If the generation is not
committed before its deadline, the daemon and independent systemd timer
attempt rollback.

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

The release currently provides checksum integrity and reproducible-build
evidence, but no publisher signature. Verify the exact tag and commit through
an independently trusted channel before using artifacts from a mirror.

## Documentation

- `START-HERE.md`: shortest safe path through the project.
- `INSTALL.md`: package, source, activation, and installed-state behavior.
- `docs/HOST-HANDOFF.md`: adapting the release to another host.
- `docs/CONFIGURATION.md`: complete strict TOML reference.
- `docs/OPERATIONS.md`: routine commands, monitoring, and backup.
- `docs/RECOVERY.md`: rollback, boot, database, and emergency procedures.
- `TEST_RESULTS.md`: consolidated release validation.
- `SECURITY_AUDIT.md`: repaired findings and accepted residual risks.
