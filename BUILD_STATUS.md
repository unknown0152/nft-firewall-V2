# NFT Firewall V2 2.1.0 Build Status

Source disposition: **STAGE E-R SOURCE VALIDATED**

Validation date: 2026-08-30

Target version: `2.1.0`

Reopened source baseline:
`4ed1f0c55ec2fe20ae9292480f4e425aad90f287`

The frozen source commit, independent candidate parents, and comparison digest
are created after this source report and are therefore recorded only in the
external candidate evidence. This file must not claim evidence created after
its own commit.

| Phase | Status | Evidence boundary |
| --- | --- | --- |
| Go 1.27 migration and release identity | PASS | Exact `go1.27.0` source/toolchain contract |
| Managed one-file setup/import/routing | PASS | Unit, race, source-contract, and failure-path tests |
| Managed setup transaction boundary | PASS | Real Engine/System proof completes read-only preparation before the initial prepared-summary journal; pre-mutation failures do not invoke rollback or system mutation; guard-or-later rollback remains backup-bound |
| Setup-guard nftables validity | PASS | Endpoint and LAN prefix sets use interval semantics; endpoint inputs remain exact IPv4 `/32`; deterministic unit/source contracts and a separately gated real-parser disposable regression |
| Clean-host route-table preflight | PASS | Numeric all-table JSON accepts absent table 51820 and refuses populated, malformed, oversized, timeout, permission, or command-failed observations |
| Managed Docker forwarding/adoption | PASS | Eligible empty local topology only; running/retained/changing workload refusal; post-plan revalidation; semantic ownership, VPN-only policy, rebind, status, handoff, and exact rollback tests |
| Legacy advanced Docker provenance | PASS | Static bridge/tuple/configuration and historical interface-name ID remain unchanged; only exact managed `docker:<network>` identities can dynamically rebind |
| Existing-host adoption planner | PASS | Explicit dry-run grammar, exact schema-6/provenance readers, double observation, redaction, and no-mutation fixture |
| Privileged-umask security fixtures | PASS | Explicit unsafe modes plus isolated `umask 0077` acceptance/refusal regression and full-suite rerun |
| Managed policy mutation/recovery | PASS | Protected reload, exact generation query, checksummed file journal, and independent watchdog tests |
| Configuration/compiler/provenance | PASS | Unit, fuzz, vet, staticcheck, gosec, and source contracts |
| Coverage | PASS | Overall 76.6%; setup 90.6%; import 90.6%; intent 92.6%; routing 90.5%; adoption 91.1% |
| Dependencies | PASS | `go mod verify`, tidy diff, and govulncheck with no reachable vulnerabilities |
| Package/systemd source | PASS | Nonactivating lifecycle contracts, staged unit verification, and sandbox review |
| Shell and secret handling | PASS | ShellCheck and deterministic source/history scan contracts |
| Benchmarks | PASS | Ten-sample comparison against exact `4ed1f0c`; no significant runtime/allocation regression and all reference operations remain inside Amendment E budgets |
| Quarantined candidate builds | NOT EXECUTED | Must be built twice from the later frozen clean commit |
| Candidate comparison | NOT EXECUTED | Requires both independent protected-parent candidates |
| Privileged R2 | FAIL, HARD STOPPED | The latest approved run proved the transaction-ordering correction, then real Debian nftables rejected the temporary guard's non-interval endpoint prefix set before apply. Amendment L corrects the source; a complete renewed run is NOT EXECUTED and requires new identity-bound approval |
| Release tag/publication/deployment | NOT AUTHORIZED | Explicitly outside Stage E-R |

No package was installed and no live firewall, VPN, route, resolver, systemd,
Docker, Cosmos, or host service state was changed by this source validation.
