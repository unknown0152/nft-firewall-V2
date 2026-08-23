# NFT Firewall V2 Build Status

Status values are `NOT STARTED`, `ACTIVE`, `BLOCKED`, `PASS`, and `FAIL`.
Results below describe the current `2.0.1` candidate. Privileged acceptance
recorded for `v2.0.0` is historical context and is not silently promoted to a
pass for changed code.

| Phase | Status | Current evidence / remaining gate |
| --- | --- | --- |
| P0 host baseline | PASS | Read-only server audit exists outside this release source; no live firewall changes were made |
| P1 V1 inventory | PASS | Existing parity and invariant documents remain in `docs/` |
| P2 V1 invariant extraction | PASS | `docs/V1_FEATURE_PARITY.md`, `docs/V1_SECURITY_INVARIANTS.md` |
| P3 architecture | PASS | `docs/ARCHITECTURE.md`, `docs/DECISIONS.md`, `docs/PACKAGES.md` |
| P4 Go foundation | PASS | Current unit/package suite, vet, formatting, and module integrity pass |
| P5 policy/compiler | PASS | Current regressions cover deterministic policy, default deny, zone conflicts, and dynamic-feed rule ordering |
| P6 nft backend | PASS | Current regressions cover owned-only validation, obfuscated-command rejection, collision guard, and fingerprints |
| P7 state/reconciliation | PASS | Current regressions cover migrations 4/5, bounded audit, durable claim revisions, generation recovery, rollback errors, cross-process serialization, and drift paths |
| P8 WireGuard | ACTIVE | Unprivileged endpoint/bootstrap tests pass; `2.0.1` namespace and real-provider acceptance remain pending approval |
| P9 dynamic blocks | PASS | Current feed/provenance tests cover public-prefix bounds, global coverage caps, protected prefixes, restoration, and compensation |
| P10 Docker/integrations | ACTIVE | Observer/feed unit paths pass; live Docker lifecycle is not executed and Docker socket access remains explicit opt-in |
| P11 CLI/API/web | PASS | Current contract tests enforce `nftfw.status.v1`, typed protected-state fields, fail-closed peer credentials, and separate quotas |
| P12 packaging | ACTIVE | Release/deb scripts and mutation-free staged systemd preflight pass; clean tagged cross-build, package inspection, archive validation, and reproducibility remain pending |
| P13 namespace acceptance | NOT STARTED | Not executed for `2.0.1`; `v2.0.0` results are historical only |
| P14 host acceptance | NOT STARTED | No `2.0.1` host firewall mutation, service installation, reboot, or live NUC validation performed |
| P15 security audit | ACTIVE | Source findings are repaired; tests, race, pinned analyzers, fuzzing, and history/worktree secret scans pass; final extracted-archive scan remains pending |
| P16 release | ACTIVE | Commit, tag, final artifacts, checksums, provenance inspection, and two-build comparison remain pending |

The candidate must not be described as a completed production release until
all required unprivileged release gates pass against the exact tagged commit.
Privileged deployment and live-host gates additionally require explicit
operator approval under the installation safety plan.
