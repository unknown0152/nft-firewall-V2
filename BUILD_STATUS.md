# NFT Firewall V2 Build Status

Status values are `NOT STARTED`, `ACTIVE`, `BLOCKED`, `PASS`, and `FAIL`.

| Phase | Status | Evidence / note |
| --- | --- | --- |
| P0 host baseline | PASS | `../HOST_BASELINE.md`, sanitized raw results under `../test-results/host-baseline/` |
| P1 V1 inventory | PASS | Frozen commit, source manifest, SHA256 manifest, tests/comments index under `../test-results/v1-inventory/` |
| P2 V1 invariant extraction | PASS | `docs/V1_FEATURE_PARITY.md`, `docs/V1_SECURITY_INVARIANTS.md` |
| P3 architecture | PASS | `docs/ARCHITECTURE.md`, `docs/DECISIONS.md`, `docs/PACKAGES.md` |
| P4 Go foundation | PASS | Three static command binaries, pinned modules, strict local API |
| P5 policy/compiler | PASS | Typed deterministic policy, plan/explain, IPv4/IPv6 default-deny tests |
| P6 nft backend | PASS | JSON inspection, owned-only atomic check/apply, runtime sets, fingerprint tests |
| P7 state/reconciliation | PASS | SQLite migrations/backup, generations, safe rollback, drift auto-repair |
| P8 WireGuard | PASS | Bounded endpoints, health/control, simulated and external provider acceptance |
| P9 dynamic blocks | PASS | Provenance union, source-scoped removal, expiry and kernel lease tests |
| P10 Docker/integrations | PASS | Hardened observer, feed/GeoIP bounds, lifecycle and real Docker VPN tests |
| P11 CLI/API/web | PASS | Required commands, strict peer/schema limits, read-only dashboard, chaos tests |
| P12 packaging | PASS | Source installer, both Debian architectures, manifest/archive integrity, and byte-reproducibility pass |
| P13 namespace acceptance | PASS | Full IPv4/IPv6 kill-switch, active-flow, drift, boot snapshot, DNAT suite; zero leaks |
| P14 host acceptance | PASS | Independent emergency timer, SSH-preserving safe apply, commit/crash/timeout rollback, zero leaks |
| P15 security audit | PASS | Findings repaired; exact-candidate static, vulnerability, history/worktree/archive secret scans pass |
| P16 release | PASS | All release gates pass; deterministic tagged packaging is the final automated handoff step |
