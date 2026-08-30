# NFT Firewall V2 2.1.0 Build Status

Source disposition: **STAGE E-R SOURCE VALIDATED**

Validation date: 2026-08-30

Target version: `2.1.0`

Reopened source baseline:
`02a7ea711a72725a27b25decb9b36a277b37d7b8`

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
| Exact-2.0.3 unit compatibility | PASS | One strict six-property systemd snapshot per unit; only three enumerated 2.1-only units accept the canonical exact-2.0.3 absent tuple; aliases, shadows, contradictions, malformed output, and newer-version absence refuse |
| First-setup committed handoff | PASS | Runtime starts under the temporary guard before commit; early/readiness and verified initramfs protection precede durable final dependency publication and boot activation; every post-commit failure recovers forward |
| Zero-packet initramfs source boundary | PASS | Inert marker-gated pre-udev loader, reversible non-loopback IPv6 defaults, retained loopback, checksum-bound exact nft guard, strict locked handoff, archive verification, transactional removal, and disposable namespace proof; boot capture remains R2 |
| Exact 2.0.3 package rollback source | IN PROGRESS | Protected bundle and strict `iHR` bridge are retained; the parent-held canonical lock/private dpkg lock-view correction for the legacy backup now requires full disposable regression and complete source-gate rerun |
| Privileged-umask security fixtures | PASS | Explicit unsafe modes plus isolated `umask 0077` acceptance/refusal regression and full-suite rerun |
| Managed policy mutation/recovery | PASS | Protected reload, exact generation query, checksummed file journal, and independent watchdog tests |
| Configuration/compiler/provenance | PASS | Unit, fuzz, vet, staticcheck, gosec, and source contracts |
| Coverage | PASS | Overall 76.7%; setup 90.6%; bootguard 91.8%; import 90.6%; intent 92.6%; routing 90.5%; adoption 91.0% |
| Dependencies | PASS | `go mod verify`, tidy diff, and govulncheck with no reachable vulnerabilities |
| Package/systemd source | PASS | Nonactivating lifecycle contracts, staged unit verification, and sandbox review |
| Shell and secret handling | PASS | ShellCheck and deterministic source/history scan contracts |
| Benchmarks | PASS | Fresh ten-sample run remains inside Amendment E budgets; Amendment N changes shell recovery only and exact `02a7ea7` Go sources are unchanged |
| Quarantined candidate builds | NOT EXECUTED | Earlier Amendment N candidates were invalidated by NFV2-060; build twice from the later frozen clean commit |
| Candidate comparison | NOT EXECUTED | Requires both replacement protected-parent candidates |
| Privileged R2 | FAIL, HARD STOPPED | The latest approved run passed the corrected Amendment M boundaries, then found the impossible configured-state assertion at Debian's real `iHR` rollback transition. This source corrects it; the complete E–N matrix is NOT EXECUTED and requires new identity-bound approval |
| Release tag/publication/deployment | NOT AUTHORIZED | Explicitly outside Stage E-R |

No package was installed and no live firewall, VPN, route, resolver, systemd,
Docker, Cosmos, or host service state was changed by this source validation.
