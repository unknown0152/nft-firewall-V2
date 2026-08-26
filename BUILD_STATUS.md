# NFT Firewall V2 2.1.0 Build Status

Source disposition: **STAGE E-R SOURCE VALIDATED**

Validation date: 2026-08-26

Target version: `2.1.0`

Approved source base:
`da9c611f378d3988c4011dbec7cbba210ab274c5`

The frozen source commit, independent candidate parents, and comparison digest
are created after this source report and are therefore recorded only in the
external candidate evidence. This file must not claim evidence created after
its own commit.

| Phase | Status | Evidence boundary |
| --- | --- | --- |
| Go 1.27 migration and release identity | PASS | Exact `go1.27.0` source/toolchain contract |
| Managed one-file setup/import/routing | PASS | Unit, race, source-contract, and failure-path tests |
| Managed policy mutation/recovery | PASS | Protected reload, exact generation query, checksummed file journal, and independent watchdog tests |
| Configuration/compiler/provenance | PASS | Unit, fuzz, vet, staticcheck, gosec, and source contracts |
| Coverage | PASS | Overall statement coverage at least 75%; setup/import/intent/routing packages at least 90% |
| Dependencies | PASS | `go mod verify`, tidy diff, and govulncheck with no reachable vulnerabilities |
| Package/systemd source | PASS | Nonactivating lifecycle contracts, staged unit verification, and sandbox review |
| Shell and secret handling | PASS | ShellCheck and deterministic source/history scan contracts |
| Benchmarks | PASS | Source benchmark matrix collected; reference operations remain inside Amendment E budgets |
| Quarantined candidate builds | NOT EXECUTED | Must be built twice from the later frozen clean commit |
| Candidate comparison | NOT EXECUTED | Requires both independent protected-parent candidates |
| Privileged R2 | NOT EXECUTED | Requires separate E-R2 approval |
| Release tag/publication/deployment | NOT AUTHORIZED | Explicitly outside Stage E-R |

No package was installed and no live firewall, VPN, route, resolver, systemd,
Docker, Cosmos, or host service state was changed by this source validation.
