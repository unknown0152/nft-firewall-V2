# NFT Firewall V2 2.1.0 Source Test Results

Source disposition: **STAGE_R_CANDIDATE_ONLY**

Validation date: 2026-08-29

Reopened source baseline:
`34b6d413f467b6d0f01d7c1626c025ea03298f0e`

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
| Eleven bounded fuzz targets | PASS |
| ShellCheck | PASS |
| Stage R source/package/systemd contracts | PASS |
| Staged systemd verification | PASS |
| Overall statement coverage | PASS, 76.4% |
| `internal/setup` coverage | PASS, 90.0% |
| `internal/wgconfig` coverage | PASS, 90.6% |
| `internal/intent` coverage | PASS, 92.3% |
| `internal/routing` coverage | PASS, 90.2% |
| `internal/adoption` coverage | PASS, 91.1% |

## Functional source coverage

- Strict single-peer IPv4 WireGuard import and redacted error handling.
- Debian 13 clean-host discovery and refusal of ambiguous/competing ownership.
- Deterministic managed intent, advanced TOML, DNS, route, rule, and IPv6
  ownership planning.
- Setup journaling, verified backup, temporary guard, safe apply, commit,
  boot activation, idempotent rerun, and rollback/recovery boundaries.
- Strict local Docker bridge discovery; semantic daemon JSON ownership;
  container-zone/VPN-only policy; NFTFW-owned IPv4 forwarding; confirmed
  restart only when required; topology/route revalidation; and exact rollback.
- Stable Docker authorization provenance across a race-consistent full-ID and
  Linux-bridge rebind, including transactional generation publication.
- Explicit dry-run-only existing-host adoption planning with exact schema-6
  state/pointer/snapshot/provenance and live-policy fingerprint verification,
  double observation,
  deterministic redacted output, actionable refusals, and byte-identical
  no-mutation fixture proof.
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

The 10-sample source matrix remained inside the Amendment E budgets on the
reference NUC. Observed maxima included 0.006 ms provider parsing, 0.016 ms
managed Docker config generation, 0.032 ms strict daemon merge, 0.014 ms
Docker topology projection, 0.078 ms standard compilation, 34.7 ms
10,000-policy compilation, 0.022 ms canonical fingerprinting, 0.361 ms no-op
reconciliation, 0.001 ms dashboard status projection, and 0.046 ms adoption
worksheet generation. Performance evidence is not privileged network proof.

## Not executed under Stage E-R

| Gate | Result |
| --- | --- |
| Two protected-parent candidate builds | NOT EXECUTED in this source snapshot |
| External byte-for-byte candidate comparison | NOT EXECUTED |
| Debian install/upgrade/remove in disposable VMs | NOT EXECUTED |
| Privileged namespace/network/leak matrix | NOT EXECUTED |
| Clean-server setup and reboot matrix | NOT EXECUTED |
| Privileged Docker ownership/traffic/rollback matrix | NOT EXECUTED |
| Disposable exact-2.0.3 adoption-planner no-mutation matrix | NOT EXECUTED |
| Real-provider VPN test | NOT EXECUTED |
| Local release tag | NOT CREATED |
| GitHub publication | NOT AUTHORIZED |
| Current-server installation/adoption | NOT AUTHORIZED |

Privileged scripts mutate disposable network, package, Docker, or boot state.
They require the separately identity-bound Stage E-R2 approval.
