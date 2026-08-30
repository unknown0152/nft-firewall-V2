# Changelog

## 2.1.0 - One-file managed setup

- Require exact Go 1.27.0 for builds, validation, and release identity.
- Add `nftfw setup --vpn PATH` for a supported clean Debian 13 server,
  including strict secret-safe profile import, host discovery, deterministic
  managed intent and advanced policy generation, WireGuard interface
  lifecycle, DNS, policy routing, IPv6 disablement, safe apply, validation,
  commit, boot integration, and automatic rollback.
- Default to VPN-only IPv4 egress, preserved private-LAN SSH management, and
  zero public inbound exposure.
- Add managed tunnel, exposure, LAN allowance, effective-config, setup status,
  and setup rollback commands with human and JSON output.
- Make managed exposure/LAN mutations reload the exact protected on-disk
  intent and generated policy inside the daemon before compilation. Add a
  checksummed root-only file-publication journal, exact generation-status
  recovery, and an independent managed-change rollback timer so CLI death
  cannot leave new files paired with an old committed policy.
- Add `nftfw-vpn.service` and an independent managed-setup rollback
  service/timer plus a separate managed-change rollback service/timer while
  preserving the nonactivating package lifecycle.
- Extend the additive status-v2 and read-only dashboard views with managed
  mode, public exposure, and LAN policy.
- Preserve 2.0.3 advanced TOML, schema-6 state, generations, snapshots,
  provenance, systemd, and package-upgrade behavior.
- Add `nftfw setup adopt --vpn PATH --dry-run` as a deterministic, redacted,
  double-observed worksheet for compatible existing 2.0.3 advanced-mode
  state. It is structurally read-only; actual conversion remains a separately
  approved Stage E-L operation and invocation without `--dry-run` refuses.
- Adopt every eligible built-in or Compose-style Docker IPv4 bridge from the
  local socket only when no running or retained container exists; preserve
  unrelated daemon JSON keys, disable Docker firewall/forwarding/masquerade/
  proxy mutation, make NFTFW own persistent kernel IPv4 forwarding, validate
  the nftables candidate before one confirmed Docker restart, and roll back
  exact daemon/sysctl/drop-in/unit state on failure.
- Preserve stable Docker network provenance across a full-ID/bridge
  recreation, automatically commit the verified bridge rebind, and keep
  containers VPN-only with no physical-uplink or implicit published-port
  exposure.
- Preserve v2.0.3 static advanced Docker bridge bindings, interface-name
  provenance, and ledger IDs without rewriting them, while restricting
  automatic bridge rebinding to managed dynamic entries with exact
  `docker:<network>` provenance.
- Refuse unsupported profiles, competing firewall owners, unsupported or
  ambiguous Docker topology, prior NFTFW state, and conflicting route/rule/
  interface ownership before setup mutation.
- Inspect the reserved policy-routing table through bounded numeric all-table
  JSON so a normally absent clean-host table is accepted without weakening
  populated-table or malformed/failed-inspection refusal.
- Render every setup-guard prefix set with nftables interval semantics while
  retaining strict canonical IPv4 `/32` VPN-endpoint authorization, exact
  table ownership, pre-apply parser validation, and deterministic output.
- Accept canonical systemd absence only for the three 2.1-only units on an
  exact 2.0.3 adoption worksheet while rejecting aliases, shadows,
  contradictory states, malformed output, and changed observations.
- Defer final early-service `Requisite=` drop-ins until runtime policy is
  committed and early enforcement is independently ready; add a distinct,
  recover-forward setup handoff phase.
- Add a managed-only checksum-verified initramfs deny guard. Its explicit
  pre-udev prerequisite disables IPv6 defaults before interface creation,
  blocks all early packets until committed enforcement is verified, preserves
  final loopback IPv6 after handoff, and fails closed on regeneration or
  archive verification errors.
- Add `nftfw-package-rollback`, which prepares a protected checksummed bundle
  and an exact-payload lower-version package-manager bridge before upgrade so
  the unmodified exact 2.0.3 package can be restored without dpkg-state edits,
  retained-state deletion, or maintainer-script bypass.
- Bind that bridge to Debian 13's exact three-argument `iHR` pre-install
  transition, the generated bridge version, architecture, package and binary
  hashes, schema history, protected metadata, and verified bundle identity;
  reject configured and every neighboring package state at that boundary.
- Retain the canonical global mutation lock across exact-package rollback
  while giving only dpkg descendants a private mount-namespace lock inode for
  the historical 2.0.3 pre-install backup; reject aliasing or unsafe metadata.
- Add setup, importer, routing, discovery, intent, rollback, benchmark,
  packaging, and reproducible-candidate validation.

## 2.0.3 - Dashboard status contract patch

- Align the read-only dashboard and its fail-closed health projection with the
  daemon's `nftfw.status.v2` schema.
- Add regression coverage that rejects the obsolete v1 status schema and
  accepts only a complete protected v2 snapshot.
- Preserve the 2.0.2 policy compiler, privileged daemon, state schema,
  nftables ownership, WireGuard enforcement, and systemd boot contracts
  unchanged.

## 2.0.2 - Provenance and boot-safety release

This release introduced the production provenance, boot-readiness, package,
Docker-ownership, and recovery architecture used by the first live deployment.

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
  before first commit. Independently pull the remain-active early restore and
  nonmutating readiness verifier into `network-pre.target`, order readiness
  after early without a readiness `Requisite=`, and retain inert final
  `Requisite=`/`After=` templates for consumers, the daemon, and rollback.
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
- Pin Git archive permission normalization so the protected build is
  independent of ambient `tar.umask` defaults and all exported regular files
  match their required `0644`/`0755` modes.

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
- Add the typed `nftfw.status.v2` contract, validated SHA-256 policy identity,
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
