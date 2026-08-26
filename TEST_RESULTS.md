# NFT Firewall V2 2.1.0 Source Test Results

Source disposition: **STAGE_R_CANDIDATE_ONLY**

Validation date: 2026-08-26

Source base:
`da9c611f378d3988c4011dbec7cbba210ab274c5`

This tracked report is the pre-build source snapshot. The later frozen commit,
candidate build evidence, candidate comparison, R2 evidence, tag, and any
publication decision must remain external and checksummed.

## Source and quality gates

| Gate | Result |
| --- | --- |
| Exact Go toolchain | PASS, `go1.27.0 linux/amd64` |
| Formatting and diff checks | PASS |
| Module verification and tidy diff | PASS |
| Full unit/regression suite | PASS |
| Race suite | PASS |
| Vet | PASS |
| Staticcheck v0.8.1 | PASS |
| govulncheck v1.7.0 | PASS, no reachable vulnerabilities |
| gosec v2.29.0 reviewed profile | PASS |
| Nine bounded fuzz targets | PASS |
| ShellCheck | PASS |
| Stage R source/package/systemd contracts | PASS |
| Staged systemd verification | PASS |
| Overall statement coverage | PASS, at least 75% |
| `internal/setup` coverage | PASS, at least 90% |
| `internal/wgconfig` coverage | PASS, at least 90% |
| `internal/intent` coverage | PASS, at least 90% |
| `internal/routing` coverage | PASS, at least 90% |

## Functional source coverage

- Strict single-peer IPv4 WireGuard import and redacted error handling.
- Debian 13 clean-host discovery and refusal of ambiguous/competing ownership.
- Deterministic managed intent, advanced TOML, DNS, route, rule, and IPv6
  ownership planning.
- Setup journaling, verified backup, temporary guard, safe apply, commit,
  boot activation, idempotent rerun, and rollback/recovery boundaries.
- Managed `expose` and `lan` changes compiled from the newly published
  protected files rather than stale daemon memory.
- Checksummed managed-change journal recovery for pre-apply, applied,
  prepared, rolled-back, and uncertain committed states.
- Structured operator backup including state, provenance, intent, VPN,
  enforcement pointer, and immutable generation artifacts.
- Managed status/dashboard projection and fail-closed status-v2 consumers.
- Package nonactivation, unit ownership, candidate quarantine, and release
  evidence separation.

## Performance source results

The 10-sample report is generated outside this tracked snapshot. Smoke results
on the reference NUC were inside the Amendment E budgets, including standard
profile/config/compile paths, 10,000-policy compilation, canonical
fingerprinting, SQLite status/backup, no-op reconciliation, status projection,
and dashboard serving. Performance evidence is not privileged network proof.

## Not executed under Stage E-R

| Gate | Result |
| --- | --- |
| Two protected-parent candidate builds | NOT EXECUTED in this source snapshot |
| External byte-for-byte candidate comparison | NOT EXECUTED |
| Debian install/upgrade/remove in disposable VMs | NOT EXECUTED |
| Privileged namespace/network/leak matrix | NOT EXECUTED |
| Clean-server setup and reboot matrix | NOT EXECUTED |
| Docker ownership handoff | NOT EXECUTED |
| Real-provider VPN test | NOT EXECUTED |
| Local release tag | NOT CREATED |
| GitHub publication | NOT AUTHORIZED |
| Current-server installation/adoption | NOT AUTHORIZED |

Privileged scripts mutate disposable network, package, Docker, or boot state.
They require the separately identity-bound Stage E-R2 approval.
