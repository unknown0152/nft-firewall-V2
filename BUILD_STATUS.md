# NFT Firewall V2 2.1.0 Build Status

Source disposition: **AMENDMENT AA SOURCE VALIDATED; CANDIDATES PENDING**

Validation date: 2026-09-02

Target version: `2.1.0`

Reopened source baseline:
`01d559e884277a9b819aa712dec5620fed2d796a`

The E-R2 run for the baseline above passed seventeen disposable subjects, then
hard-stopped because installed dashboard p95 was 65.231 ms against the
exclusive 50 ms budget. Amendment AA consolidates nine sequential nftables
reads into one immutable ruleset observation and batches all authorized Docker
network inspections by immutable ID. Fresh disposable source profiling now
passes the unchanged CLI, dashboard, memory, and idle-CPU budgets. The
replacement clean commit and two quarantined candidate parents remain the
final Stage E-R outputs before a complete renewed E-R2 run.

| Phase | Status | Evidence boundary |
| --- | --- | --- |
| Go 1.27 migration and release identity | PASS | Exact `go1.27.0` source/toolchain contract |
| Managed one-file setup/import/routing | PASS | Unit, race, source-contract, and failure-path tests |
| Managed setup transaction boundary | PASS | Real Engine/System proof completes read-only preparation before the initial prepared-summary journal; pre-mutation failures do not invoke rollback or system mutation; guard-or-later rollback remains backup-bound |
| Terminal first-setup retry | PASS | One strict read-only classifier verifies exact rollback, terminal journal lineage, rolled-back generation history, endpoint cache, and monotonic provenance; ambiguous state retains the adoption refusal |
| Durable setup-journal lineage | PASS | Exact prior terminal bytes are checksum-bound, atomically archived under a root-only history directory, file/directory synced, collision-refused, and retry-safe across both archive/publication crash windows |
| Inverse-boot generation lineage | PASS | Finalization preserves the exact nonzero uncommitted first-setup generation, keeps pre-generation rollback at zero, clears committed package-only handoff, and refuses finalizer/write failure without false terminal publication |
| Setup-guard nftables validity | PASS | Endpoint and LAN prefix sets use interval semantics; endpoint inputs remain exact IPv4 `/32`; deterministic unit/source contracts and a separately gated real-parser disposable regression |
| Clean-host route-table preflight | PASS | Numeric all-table JSON accepts absent table 51820 and refuses populated, malformed, oversized, timeout, permission, or command-failed observations |
| Managed Docker forwarding/adoption | PASS | Eligible empty local topology only; running/retained/changing workload refusal; post-plan revalidation; semantic ownership, VPN-only policy, rebind, status, handoff, and exact rollback tests |
| Fresh daemon/dashboard status | PASS | Each request reloads protected config/intent and freshly checks schema-6 state, provenance, one immutable nftables ruleset snapshot, batched immutable-ID Docker topology, forwarding, WireGuard, claims, and integrations; adjacent observation changes degrade the next response |
| Legacy advanced Docker provenance | PASS | Static bridge/tuple/configuration and historical interface-name ID remain unchanged; only exact managed `docker:<network>` identities can dynamically rebind |
| Existing-host adoption planner | PASS | Explicit dry-run grammar, exact schema-6/provenance readers, double observation, redaction, and no-mutation fixture |
| Exact-2.0.3 unit compatibility | PASS | One strict six-property systemd snapshot per unit; only three enumerated 2.1-only units accept the canonical exact-2.0.3 absent tuple; aliases, shadows, contradictions, malformed output, and newer-version absence refuse |
| First-setup committed handoff | PASS | Runtime starts under the temporary guard before commit; early/readiness and verified initramfs protection precede durable final dependency publication and boot activation; every post-commit failure recovers forward |
| Pre-driver disabled-IPv6 boot boundary | PASS | Strict Debian GRUB ownership, explicit reboot/resume/rollback, running-kernel proof, native guard compatibility, both process-death sides, package handoff, two consecutive zero-pre-readiness managed boots, post-readiness traffic, and contradictory-identity zero-guest capture pass in disposable guests |
| Exact 2.0.3 package rollback source | PASS | Protected bundle, exact-old configuration preflight before mutation, strict `iHR` bridge, both legitimate mode-0600 database group histories, exact three-mode dpkg transaction, parent-held canonical lock with private dpkg lock view, external contention, no residue, and package/policy/provenance/Docker/unit/initramfs restoration pass in a disposable guest; complete renewed E-R2 remains separate |
| Privileged-umask security fixtures | PASS | Explicit and verified mode-0644/mode-0750 unsafe fixtures, authenticated control-status fixture with non-status refusal, isolated restrictive-umask regression, and complete disposable-root `umask 0077` suite |
| Managed policy mutation/recovery | PASS | Protected reload, exact generation query, checksummed file journal, and independent watchdog tests |
| Configuration/compiler/provenance | PASS | Unit, fuzz, vet, staticcheck, gosec, and source contracts |
| Coverage | PASS | 79.0% overall and 90.0% `internal/setup`; all other documented core-package floors remain satisfied |
| Dependencies | PASS | `go mod verify`, tidy diff, and govulncheck with no reachable vulnerabilities |
| Package/systemd source | PASS | Nonactivating lifecycle contracts, staged unit verification, and sandbox review |
| Shell and secret handling | PASS | ShellCheck and deterministic source/history scan contracts |
| Benchmarks | PASS | Disposable installed path: CLI p95 36.367 ms and persistent-HTTP dashboard p95 32.658 ms versus unchanged exclusive 75/50 ms budgets; three-network Docker projection 16.463-17.807 us/op, 6436-6438 B/op, 74 allocs/op in the complete ten-count sweep; full Go sweep remains within retained thresholds |
| Protected Amendment W disposable retry | PASS | W6 proves a coherent Docker baseline; two validate-phase process deaths; exact rollback; nonmutating retry; durable lineage; generations 1/2 rolled back and 3 committed; stable provenance; host/container VPN egress; idempotence; tunnel-loss/Docker-restart zero leak; recovery; two managed boots; zero residual QEMU process/listener |
| Protected Amendment Z disposable retry | PASS | Fresh source-only run preserves generations 1/2 across inverse boot and strict nonmutating retry, commits generation 3, and repeats the retained Docker/VPN/leak/recovery/two-boot lifecycle with clean overlays and zero residual QEMU process/listener |
| Disposable native initramfs lifecycle | PASS | W7 proves inert package install, foreign-source refusal, enable/verify idempotence, native source order, tamper refusal, exact disable restoration, purge cleanup, and a clean overlay |
| Amendment X disposable boot/package preflight | PASS | Failed update, pre/post-reboot death, rollback finalization, package removal plus restored next boot, exact 2.0.3 downgrade, and clean stopped overlays all pass |
| Amendment AA disposable status profile | PASS for timing/resources | 100 measurements after 10 warmups: CLI median/p95/max 33.997/36.367/38.995 ms; dashboard 30.617/32.658/35.712 ms; RSS, cgroup memory, and 60-second idle CPU all pass. The guest lacked an independent provider assignment, so this is not protected-status or E-R2 acceptance; the shipped E-R2 harness now requires healthy protection on every sample |
| Quarantined candidate builds | NOT EXECUTED | Replacement builds follow the clean Amendment AA source freeze |
| Candidate comparison | NOT EXECUTED | Requires both replacement protected-parent candidates |
| Privileged R2 | NOT AUTHORIZED | Amendment AA authorizes source-stage disposable validation only; a new frozen commit/comparison-bound E-R2 approval is required later |
| Release tag/publication/deployment | NOT AUTHORIZED | Explicitly outside Stage E-R |

No package was installed on the live host, and no live firewall, VPN, route,
resolver, systemd, Docker, Cosmos, boot, or host service state was changed by
this source validation.
