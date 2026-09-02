# NFT Firewall V2 2.1.0 Build Status

Source disposition: **AMENDMENT Z SOURCE VALIDATED; CANDIDATES PENDING**

Validation date: 2026-09-02

Target version: `2.1.0`

Reopened source baseline:
`e4953a52384b351cc57849068759e27fadc95ec2`

Amendment X passed, froze as the reopened baseline above, and produced two
identical quarantined candidates. Its E-R2 run then stopped before private
package construction when both independent build guests reproduced two
ambient-umask directory fixtures and one deliberately impossible control-API
fixture. Amendment Y corrected those tests and froze as the reopened baseline.
The following recovery run exposed inverse-boot generation loss. Amendment Z
preserves that identity only for an uncommitted first setup; direct, full,
restrictive-umask, and fresh disposable retry/lifecycle regressions pass. The
replacement clean commit and two quarantined candidate parents are the
remaining Stage E-R outputs.

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
| Legacy advanced Docker provenance | PASS | Static bridge/tuple/configuration and historical interface-name ID remain unchanged; only exact managed `docker:<network>` identities can dynamically rebind |
| Existing-host adoption planner | PASS | Explicit dry-run grammar, exact schema-6/provenance readers, double observation, redaction, and no-mutation fixture |
| Exact-2.0.3 unit compatibility | PASS | One strict six-property systemd snapshot per unit; only three enumerated 2.1-only units accept the canonical exact-2.0.3 absent tuple; aliases, shadows, contradictions, malformed output, and newer-version absence refuse |
| First-setup committed handoff | PASS | Runtime starts under the temporary guard before commit; early/readiness and verified initramfs protection precede durable final dependency publication and boot activation; every post-commit failure recovers forward |
| Pre-driver disabled-IPv6 boot boundary | PASS | Strict Debian GRUB ownership, explicit reboot/resume/rollback, running-kernel proof, native guard compatibility, both process-death sides, package handoff, two consecutive zero-pre-readiness managed boots, post-readiness traffic, and contradictory-identity zero-guest capture pass in disposable guests |
| Exact 2.0.3 package rollback source | PASS | Protected bundle, exact-old configuration preflight before mutation, strict `iHR` bridge, both legitimate mode-0600 database group histories, exact three-mode dpkg transaction, parent-held canonical lock with private dpkg lock view, external contention, no residue, and package/policy/provenance/Docker/unit/initramfs restoration pass in a disposable guest; complete renewed E-R2 remains separate |
| Privileged-umask security fixtures | PASS | Explicit and verified mode-0644/mode-0750 unsafe fixtures, authenticated control-status fixture with non-status refusal, isolated restrictive-umask regression, and complete disposable-root `umask 0077` suite |
| Managed policy mutation/recovery | PASS | Protected reload, exact generation query, checksummed file journal, and independent watchdog tests |
| Configuration/compiler/provenance | PASS | Unit, fuzz, vet, staticcheck, gosec, and source contracts |
| Coverage | PASS | 78.8% overall and 90.0% `internal/setup`; all other documented core-package floors remain satisfied |
| Dependencies | PASS | `go mod verify`, tidy diff, and govulncheck with no reachable vulnerabilities |
| Package/systemd source | PASS | Nonactivating lifecycle contracts, staged unit verification, and sandbox review |
| Shell and secret handling | PASS | ShellCheck and deterministic source/history scan contracts |
| Benchmarks | PASS | Ten-sample terminal classifier: 1.328-1.390 ms/op, 231082-232286 B/op, 1040-1042 allocs/op; full benchmark sweep remains inside Amendment E budgets |
| Protected Amendment W disposable retry | PASS | W6 proves a coherent Docker baseline; two validate-phase process deaths; exact rollback; nonmutating retry; durable lineage; generations 1/2 rolled back and 3 committed; stable provenance; host/container VPN egress; idempotence; tunnel-loss/Docker-restart zero leak; recovery; two managed boots; zero residual QEMU process/listener |
| Protected Amendment Z disposable retry | PASS | Fresh source-only run preserves generations 1/2 across inverse boot and strict nonmutating retry, commits generation 3, and repeats the retained Docker/VPN/leak/recovery/two-boot lifecycle with clean overlays and zero residual QEMU process/listener |
| Disposable native initramfs lifecycle | PASS | W7 proves inert package install, foreign-source refusal, enable/verify idempotence, native source order, tamper refusal, exact disable restoration, purge cleanup, and a clean overlay |
| Amendment X disposable boot/package preflight | PASS | Failed update, pre/post-reboot death, rollback finalization, package removal plus restored next boot, exact 2.0.3 downgrade, and clean stopped overlays all pass |
| Quarantined candidate builds | NOT EXECUTED | Replacement builds follow the clean Amendment Z source freeze |
| Candidate comparison | NOT EXECUTED | Requires both replacement protected-parent candidates |
| Privileged R2 | NOT AUTHORIZED | Amendment Z authorizes source-stage disposable validation only; a new frozen commit/comparison-bound E-R2 approval is required later |
| Release tag/publication/deployment | NOT AUTHORIZED | Explicitly outside Stage E-R |

No package was installed on the live host, and no live firewall, VPN, route,
resolver, systemd, Docker, Cosmos, boot, or host service state was changed by
this source validation.
