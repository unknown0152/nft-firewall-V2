# NFT Firewall V2 Build Status

Release disposition: **RELEASE CANDIDATE - NOT DEPLOYABLE**

Snapshot: 2026-08-25

Target version: `2.0.3`

This is the reopened, pre-freeze Stage R status after a prior source commit
hard-stopped in the R2 systemd boot transaction. It authorizes neither
installation nor deployment. No 2.0.3 release tag or final release has been
created. Candidate construction and the two-build comparison occur only after
the corrected source commit is frozen and are recorded in external evidence,
because a tracked report cannot attest to its own later enclosing build.

Status values are `NOT STARTED`, `PASS`, and `BLOCKED`.

| Phase | Status | Evidence boundary |
| --- | --- | --- |
| Source isolation and baseline | PASS | Work is confined to the isolated 2.0.3 RC worktree; immutable `v2.0.1` lifecycle/systemd/provenance defects remain expected-red baseline proofs |
| Configuration/compiler/provenance | PASS | Pinned unit/race/static/security analysis and source contracts pass for strict provenance IDs, write-once connection marking, reply binding, and foreign-mask collision refusal |
| Generation state and recovery | PASS | Source-only tests pass for immutable snapshots, exact schema history, locked/no-overwrite offline schema 1-5 migration, byte-identical backup, crash-safe publication, ambiguity retention, rollback verification, and read-only recovery refusal; privileged migration and live boot remain R2 |
| Docker stable identity | PASS | Exact ID/name/driver/bridge/subnet/gateway unit paths pass; no live Docker daemon or bridge lifecycle was accessed |
| Package lifecycle/systemd graph | PASS | Static lifecycle, metadata, candidate-quarantine, staged unit, and dependency-graph contracts pass; readiness is independently required by `network-pre.target`, ordered after early without a readiness `Requisite=`, and no package was installed or service changed |
| Unprivileged quality/security | PASS | Go 1.25.13 test/race/vet/module/fmt, staticcheck, govulncheck, gosec, nine bounded fuzz targets, ShellCheck, Stage R contracts, and current-tree secret scan pass |
| Candidate package/archive build | NOT STARTED | Must be generated twice from the frozen commit into separate protected parents; results belong only in external build/comparison evidence |
| Stage R2 privileged acceptance | NOT STARTED | **R2 NOT EXECUTED FOR THIS SOURCE REVISION**: the prior commit's boot hard stop and other evidence do not transfer |
| Final release | BLOCKED | Requires separately approved R2/deployment plan, exact R2 attestation, immutable annotated tag, post-tag validation manifest, and external final approval bound to exact hashes |

The source is ready to freeze as an untagged Stage R candidate. Candidate-mode
output is intrinsically non-installable and non-startable, uses the Debian
version `2.0.3~stage.r.<commit12>`, and remains test input only. A successful
candidate build does not promote this status to final release or deployment.
