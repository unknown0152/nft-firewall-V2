# Security Policy and Guarantees

NFT Firewall V2 `2.0.3` is an accepted release. The guarantees below passed
the source, privileged R2, and post-tag validation described in
`TEST_RESULTS.md`. They apply to the exact validated source and declared
operating assumptions, not to an unaudited host configuration.

Report vulnerabilities privately to the repository owner. Do not include live
keys, tokens, public address inventories, production packet captures, or an
operational state database in a report.

## Enforced guarantees

- Input and forwarding are default deny. Strict VPN mode also makes output
  default deny and is the only supported mode in V2.
- Internet-bound host and container policy is pinned to the declared
  WireGuard interface.
- Physical WireGuard bootstrap requires the declared uplink, validated
  endpoint host address, UDP destination port, and nonzero WireGuard fwmark.
- Container-to-uplink drops precede forward conntrack acceptance. Output has
  no blanket established/related accept that could become an egress bypass.
- Original-direction ingress reserves only the high conntrack-mark byte,
  preserves lower bits, and writes provenance once. Reply accepts require the
  exact matching provenance and egress interface. Interface IDs are permanent
  in a monotonic ledger and retired IDs are never reused.
- IPv6 behavior is mandatory and explicit. Disabled mode installs early
  IPv6 drop hooks; VPN and native modes use equivalent typed inet policy.
- Normal operation never invokes `flush ruleset` and never deletes a table it
  does not own.
- Every candidate passes internal validation and `nft --check` before one
  atomic apply transaction.
- Safe apply records a pending generation before kernel mutation and requires
  a verified independent rollback timer. After successful application, that
  safe-applied generation remains uncommitted until explicit commit or
  rollback at expiry. Prepared commit publication, immutable snapshots, and a
  generation/checksum pointer are recoverable across crash boundaries. Early
  boot restore remains active and a nonmutating readiness verifier gates final
  network consumers.
- Dynamic block removal is claim-specific. Manual, feed, GeoIP, automated,
  and temporary reasons cannot erase each other.
- Temporary access always expires in both SQLite and the kernel set; permanent
  allow claims are rejected.
- Configuration and sensitive state reject unsafe ownership, permissions,
  symlinks, ambiguous topology, unknown fields, malformed addresses, and
  unsafe broad prefixes.
- Privileged API authorization comes from Unix peer credentials, not request
  content. Request and response bodies are bounded and schemas reject unknown
  or operation-inapplicable fields.
- Child processes receive validated argument arrays. Production Go code does
  not invoke a command through a shell string.
- Threat-feed downloads require HTTPS, public destinations, bounded redirects,
  time, bytes, entries, individual prefixes, and cross-feed aggregate
  coverage. Public topology and resolved WireGuard endpoints are protected,
  persisted feed claims are revalidated, and failed publication restores
  prior claims and live sets.
- The web process is read-only, local by default, emits restrictive headers,
  and has no control or Docker socket.

## Trust assumptions

The Linux kernel, nft executable, systemd, root account, installed binaries,
configured DNS resolver, and package verification path are trusted. A root or
kernel compromise can bypass this controller. WireGuard routing is assumed to
be configured consistently with the declared interface and fwmark; `doctor`
checks the live values it can observe.

The product retains the last known good kernel state on policy/configuration
errors where possible. Missing, corrupt, symlinked, oversized, or
checksum-invalid immutable recovery evidence causes an error before any
nftables mutation and leaves readiness blocked. Emergency deny is used only
after an owned generation installation succeeds but restoration of its
separate mutable runtime security state fails.

See `docs/THREAT-MODEL.md` for the full model and `SECURITY_AUDIT.md` for the
release review.

Release validation does not determine a target host's interfaces, management
policy, VPN routing, Docker topology, or public exposure. Complete
`docs/HOST-HANDOFF.md`, preserve an independent recovery path, and use a
safe apply before activating the release on each host.
