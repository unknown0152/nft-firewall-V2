# Changelog

## 2.0.2 — Stage R release candidate (not deployable)

This entry describes source-only remediation whose pre-freeze Stage R matrix
passes. It is not a final release announcement. Stage R2 privileged package, boot, network, Docker, and
real-OVPN acceptance has **not been executed**; no 2.0.2 tag or final artifact
exists.

- Reserve the high conntrack-mark byte for immutable ingress provenance while
  preserving the lower 24 bits, tag original-direction input/forward flows
  only once, and require matching provenance on reply accepts.
- Add explicit interface provenance IDs and a separate monotonic provenance
  ledger with permanent retired-ID tombstones.
- Authorize routed Docker bridges by stable configured name, bridge driver,
  explicit Linux interface, subnet, and gateway rather than a generated
  Docker network ID.
- Add generation publication/recovery state for prepared commits, durable
  enforcement pointers, crash-boundary recovery, and read-only enforcement
  verification.
- Add a locked, nonactivating offline database migration for exact schema 1
  through 5. It creates a byte-identical protected backup, leaves the source
  unchanged, refuses unsafe/active/ambiguous inputs and existing outputs, and
  verifies the separate schema-6 destination.
- Make package and source installation nonactivating: installation may reload
  systemd metadata but does not enable, start, stop, or restart NFTFW units.
- Keep the base daemon and rollback timer/service independent of early restore
  before first commit. Add the remain-active early unit, nonactivating
  readiness verifier, and inert final `Requisite=`/`After=` templates.
- Add unprivileged Stage R contracts and immutable v2.0.1 expected-red proofs
  for provenance, package lifecycle, and dependency-graph defects.
- Quarantine untagged candidate output with an explicit
  `RELEASE CANDIDATE - NOT DEPLOYABLE` disposition, commit-bound pre-release
  version, composite binary identity, runtime refusal, and non-installable
  package guard.
- Bind exact Git export contents, source/history and both extracted-tree secret
  scans, protected build parents, deterministic double builds, R2 evidence,
  annotated tag object, post-tag validation, and final approval through
  external checksummed records without rewriting the frozen source report.

## 2.0.1 — Security and release hardening

- Reject contradictory interface-to-zone assignments across both supported
  declaration styles.
- Restrict threat feeds to bounded public prefixes, cap aggregate coverage
  across feeds, protect topology and resolved WireGuard endpoints, sanitize
  HTTP failures, and compensate both database and live-set updates on failure.
- Keep established management replies, explicit temporary recovery access,
  and narrow WireGuard bootstrap ahead of untrusted dynamic feed blocks.
- Reject obfuscated global flushes, unsupported nft management commands,
  plural reset operations against foreign objects, table-rename escapes,
  quote/comment tricks, and command continuations.
- Refuse first-use adoption or deletion of pre-existing product-named tables,
  re-arm the guard after failed first attempts, and preserve ambiguous pending
  tables instead of guessing ownership.
- Preserve recoverable generation state and report both sides when a
  post-apply rollback or state transition fails. Treat an `nft --file` error
  as potentially applied until restoration is confirmed.
- Fail closed on inner `SO_PEERCRED` errors and isolate status/control
  connection quotas.
- Bound the durable SQLite audit log to 10,000 rows with schema migration 4.
- Add the typed `nftfw.status.v1` contract, validated SHA-256 policy identity,
  and fail-closed CLI/web consumers.
- Persist runtime claim-set publication health so manual claim changes cannot
  leave a falsely healthy DB/kernel mismatch after an nftables error. Serialize
  publication across processes, track desired/applied revisions, and compensate
  all failed manual claim mutations.
- Bound API, controller, and backend lock waits, and preserve an independently
  timed emergency-deny path when ordinary recovery exhausts its deadline.
- Hide the root-equivalent Docker socket in the packaged service unless an
  administrator installs the explicit opt-in drop-in.
- Include complete upgrade/uninstall/status documentation in Debian packages,
  enforce Go 1.25.13 release builds, and emit deterministic manifests plus an
  unsigned in-toto/SLSA build-provenance statement. Scope enclosing checksums
  to the exact release, normalize locale/timezone inputs, and disable ambient
  VCS auto-discovery so an enclosing unrelated repository cannot alter output.
- Verify source-install systemd units against isolated staged executables before
  making any host change.

## 2.0.0 — Initial independent Go release

- Declarative default-deny nftables compiler with VPN-pinned output.
- Durable safe apply, commit, rollback, boot recovery, drift reconciliation,
  dynamic claims, optional integrations, local APIs, dashboard, static
  binaries, and Debian packages.
