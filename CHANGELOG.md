# Changelog

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
  to the exact release and normalize locale/timezone inputs.
- Verify source-install systemd units against isolated staged executables before
  making any host change.

## 2.0.0 — Initial independent Go release

- Declarative default-deny nftables compiler with VPN-pinned output.
- Durable safe apply, commit, rollback, boot recovery, drift reconciliation,
  dynamic claims, optional integrations, local APIs, dashboard, static
  binaries, and Debian packages.
