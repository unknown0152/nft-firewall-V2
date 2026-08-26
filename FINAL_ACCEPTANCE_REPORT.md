# NFT Firewall V2 2.0.3 Final Acceptance

Release approval status: **FINAL_RELEASE_APPROVED**

| Item | Value |
| --- | --- |
| Version | `2.0.3` |
| Git commit | `e2b3fa0a20fa6e36325792397564966b21045120` |
| Annotated tag | `v2.0.3` |
| Tag object | `9038ff5f6ecd32d707cb8f6fffcd9e6dc9f3b20d` |
| Final validation time | `2026-08-25T23:35:37Z` |
| Source-only Stage R | PASS |
| Privileged Stage R2 | PASS |
| Post-tag validation | PASS |
| Final decision | `FINAL_RELEASE_APPROVED` |

## Acceptance decision

NFT Firewall V2 `2.0.3` is accepted for release. The exact source commit,
annotated tag object, build evidence, artifact checksum set, R2 attestation,
post-tag validation manifest, and final approval were bound through external
SHA-256 records.

The immutable tag was not moved or rewritten after promotion. The tracked
reports at the tag intentionally describe the earlier source-only freeze
because they cannot truthfully attest to evidence created after their own
commit. The default branch contains this later publication record and
host-handoff documentation.

## Accepted gates

- Complete pinned Go 1.25.13 quality and security matrix.
- Deterministic source, package, archive, and manifest construction.
- Independent protected-parent byte-for-byte reproducibility.
- Source tree, reachable history, and extracted-tree secret scans.
- Static amd64 and arm64 binaries and Debian packages.
- Package install, supported upgrade, removal, and inactive lifecycle.
- Early boot restore, nonmutating readiness verification, rollback timer, and
  reboot recovery.
- nftables ownership, atomic apply, provenance, reply-path, drift, and
  unrelated-table survival.
- Safe apply, commit, timeout rollback, database failure, and emergency-deny
  behavior.
- IPv4 and IPv6 tunnel-loss capture with zero direct physical Internet leak.
- Docker stable bridge identity, recreation, and VPN recovery.
- Real-provider WireGuard/OVPN validation.
- Fail-closed dashboard consumption of `nftfw.status.v2`.

See `TEST_RESULTS.md` and `SECURITY_AUDIT.md` for the public consolidated
evidence.

## Release limitations

- Checksums and provenance are not cryptographically signed by a publisher.
- The local dashboard has no application login and must remain loopback-only
  unless a separately authenticated and TLS-protected boundary is added.
- WireGuard keys, tunnel creation, provider routing, and DNS ownership remain
  external operator responsibilities.
- Docker socket access is root-equivalent and remains an explicit opt-in.
- NFTFW owns only its three documented tables and cannot prevent a different
  privileged firewall manager from installing higher-priority policy.
- A validated release cannot infer another host's topology. The example
  configuration is never safe to apply unchanged.

## Deployment boundary

Release acceptance authorizes use of the validated software; it does not make
host-specific choices. Before activation on each machine, the operator must:

1. Establish console or independent LAN recovery access.
2. Back up existing firewall, service, VPN, and NFTFW configuration.
3. Run `scripts/host-preflight.sh` and resolve its failures.
4. Document the actual uplink, management network, VPN, routes, ports, Docker
   networks, IPv6 mode, and competing firewall managers.
5. Install without activation.
6. Validate and plan the real configuration.
7. Use safe apply with a second management session and independent rollback.
8. Commit only after connectivity and leak checks pass.
9. Perform a controlled reboot validation before declaring that host ready.

The complete generic procedure is in `docs/HOST-HANDOFF.md`.
