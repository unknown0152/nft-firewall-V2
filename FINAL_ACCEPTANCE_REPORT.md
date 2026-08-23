# NFT Firewall V2 Final Acceptance Report

| Item | Value |
| --- | --- |
| Version | `@RELEASE_VERSION@` |
| Git commit | `@GIT_COMMIT@` |
| Git tag | `@GIT_TAG@` |
| Build date | `@BUILD_DATE@` |
| Release source | `source/` inside the release bundle |
| Detailed test record | `TEST_RESULTS.md` |

The packaging process replaces the metadata tokens in the copy placed in a
release bundle. The tracked source retains tokens because a commit cannot
contain its own final hash.

## Acceptance status

`2.0.1` is a security-hardening release candidate. Its complete unprivileged
source gate passes: unit/package and full race tests, vet, formatting, module
integrity, pinned analyzers, fuzzing, shell analysis, staged systemd-unit
verification, and worktree/history secret scanning. Committed/tagged
cross-architecture builds, package/archive inspection, extracted-archive
secret scanning, and two-build reproducibility remain release gates until
they are recorded against the exact final commit.

Privileged/live acceptance has not been executed for `2.0.1`. This report does
not assert that the firewall is installed, enabled, or validated on the
current NUC/server. Installation and host/network mutation require a separate
approved deployment plan and the documented safety controls.

## Architecture and hardening review

The candidate remains an independent Go implementation with deterministic
policy compilation, SQLite generations, bounded runtime state, and a single
privileged nftables mutation boundary. Normal operation is limited to the
owned `inet nftfw_filter`, `ip nftfw_nat`, and `ip6 nftfw_filter6` tables; the
backend rejects global flushes and unsupported or foreign management commands.

The `2.0.1` remediation set adds or strengthens:

- canonical interface-to-zone ownership;
- bounded public-only threat feeds with cross-feed aggregate limits,
  protected topology/WireGuard endpoints, rollback compensation, and safe
  rule ordering for management recovery and VPN bootstrap;
- first-use collision refusal for product-named nftables tables;
- fail-closed peer credentials and independent status/control quotas;
- bounded audit retention and recoverable rollback accounting;
- cross-process claim publication serialization, compensating mutations, and
  durable desired/applied revision health;
- bounded lock and request waits with independently timed emergency deny;
- the typed `nftfw.status.v1` health contract and fail-closed consumers;
- explicit administrator opt-in for root-equivalent Docker socket access; and
- deterministic manifests plus unsigned in-toto/SLSA provenance generation;
  and
- mutation-free source-install preflight against staged systemd executables.

See `SECURITY_AUDIT.md`, `SECURITY.md`, and `CHANGELOG.md` for the detailed
findings, operating assumptions, and release delta.

## Gate summary

| Gate | `2.0.1` result |
| --- | --- |
| Unit/package tests | PASS |
| Changed-path race tests | PASS |
| Vet, formatting, module integrity | PASS |
| Shell analysis | PASS |
| systemd staged static verification | PASS; units not installed or started |
| Full race suite | PASS |
| Staticcheck, govulncheck, and gosec | PASS |
| Fuzz/property suite | PASS; all eight targets, 10 seconds each |
| Worktree and Git-history secret scans | PASS |
| Final extracted-archive secret scan | PENDING FINAL BUILD |
| amd64/arm64 static binaries | PENDING FINAL BUILD |
| Debian amd64/arm64 packages | PENDING FINAL BUILD/INSPECTION |
| Release manifests and provenance | PENDING FINAL BUILD/INSPECTION |
| ZIP/tar integrity and reproducibility | PENDING TWO FINAL BUILDS |
| Namespace firewall/WireGuard | NOT EXECUTED FOR `2.0.1` |
| Real provider and Docker lifecycle | NOT EXECUTED FOR `2.0.1` |
| Guarded host safe apply/rollback | NOT EXECUTED FOR `2.0.1` |
| Actual NUC/server installation | NOT EXECUTED |
| Full host reboot | NOT EXECUTED |

Passing privileged acceptance recorded for `v2.0.0` is historical evidence,
not a substitute for rerunning changed `2.0.1` code. See `TEST_RESULTS.md` for
the exact separation.

## Deployment prerequisites

Before any production installation, an operator must:

1. review and validate the machine-specific configuration and paths;
2. back up existing firewall, service, database, and network configuration;
3. confirm the management recovery path and arm an independent rollback;
4. decide whether access is LAN-only, VPN-only, or public with an approved
   authentication/TLS design;
5. verify WireGuard ownership, endpoint bootstrap, DNS, IPv4/IPv6 modes, and
   any container topology; and
6. explicitly approve the exact installation and any disruptive validation.

Docker integration is disabled by default. Enabling it requires both the safe
Docker daemon settings documented in `docs/CONFIGURATION.md` and installation
of the separate systemd socket-access drop-in, acknowledging that Docker
socket access is effectively host-root trust.

## Limitations and residual risk

1. Checksums and generated provenance are not cryptographically signed. A
   release operator must add a signature using an independently controlled
   identity if authenticated distribution is required.
2. No full-machine reboot has been run for this candidate.
3. A privileged competing firewall manager can install higher-priority rules;
   this product detects and repairs only its owned objects.
4. WireGuard tunnel creation, private keys, policy routing, and provider
   availability remain operator responsibilities.
5. Docker integration, when explicitly enabled, expands the daemon trust
   boundary to the root-equivalent Docker API.
6. The loopback dashboard has no application login and must not be exposed
   publicly without a separately approved authentication/TLS layer.

No pending gate should be represented as PASS. A final release handoff should
update this report and `TEST_RESULTS.md` with only evidence collected against
the exact tagged commit.

## Release artifacts

Expected artifact names in the enclosing release directory are:

```text
nft-firewall-v2-@RELEASE_VERSION@.zip
nft-firewall-v2-@RELEASE_VERSION@.tar.gz
SHA256SUMS
```

The release builder appends binary and package checksums to the embedded copy
of this report before manifest generation. It appends the enclosing ZIP and
tar checksum to the external copy after archive creation, because an archive
cannot contain its own checksum.
