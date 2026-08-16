# NFT Firewall V2 Build Status

Status values: `NOT STARTED`, `ACTIVE`, `BLOCKED`, `PASS`, `FAIL`.

| Phase | Status | Evidence / note |
| --- | --- | --- |
| P0 host baseline | PASS | `../test-results/host-baseline/`; Debian 13, kernel 6.12.94, initial tools were absent. |
| P1 V1 inventory | PASS | Frozen checkout, commit, source and SHA256 manifests under `../test-results/v1-inventory/`. |
| P2 V1 invariant extraction | PASS | `docs/V1_FEATURE_PARITY.md`, `docs/V1_SECURITY_INVARIANTS.md`. |
| P3 architecture | ACTIVE | `docs/ARCHITECTURE.md`, `docs/DECISIONS.md`. |
| P4 Go foundation | NOT STARTED | |
| P5 policy/compiler | NOT STARTED | |
| P6 nft backend | NOT STARTED | Host netlink is sandbox-restricted; syntax tests remain possible. |
| P7 state/reconciliation | NOT STARTED | |
| P8 WireGuard | NOT STARTED | No real config present. |
| P9 dynamic blocks | NOT STARTED | |
| P10 Docker/integrations | NOT STARTED | Docker absent. |
| P11 CLI/API/web | NOT STARTED | |
| P12 packaging | NOT STARTED | |
| P13 namespace acceptance | NOT STARTED | Capability availability must be tested before claiming PASS. |
| P14 host acceptance | NOT STARTED | Must not mutate management path without independent rollback. |
| P15 security audit | NOT STARTED | |
| P16 release | NOT STARTED | |
