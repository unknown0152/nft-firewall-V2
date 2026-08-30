# NFT Firewall V2 2.1.0 Source Test Results

Source disposition: **STAGE_R_CANDIDATE_ONLY**

Validation date: 2026-08-30

Reopened source baseline:
`4ed1f0c55ec2fe20ae9292480f4e425aad90f287`

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
| Full unit/regression suite with `umask 0077` | PASS, disposable unprivileged environment |
| Race suite | PASS |
| Vet | PASS |
| Staticcheck v0.8.1 | PASS |
| govulncheck v1.7.0 | PASS, no reachable vulnerabilities |
| gosec v2.29.0 reviewed profile | PASS |
| Twelve bounded fuzz targets | PASS |
| ShellCheck | PASS |
| Stage R source/package/systemd contracts | PASS |
| Staged systemd verification | PASS |
| Disposable real-nft setup-guard regression | PASS, narrowly scoped source gate; not E-R2 |
| Static amd64/arm64 CI package build and inspection | PASS |
| Dependency/license inventory | PASS, 29 non-main modules |
| Overall statement coverage | PASS, 76.6% |
| `internal/setup` coverage | PASS, 90.6% |
| `internal/wgconfig` coverage | PASS, 90.6% |
| `internal/intent` coverage | PASS, 92.6% |
| `internal/routing` coverage | PASS, 90.5% |
| `internal/adoption` coverage | PASS, 91.1% |

## Functional source coverage

- Strict single-peer IPv4 WireGuard import and redacted error handling.
- Debian 13 clean-host discovery and refusal of ambiguous/competing ownership.
- Deterministic managed intent, advanced TOML, DNS, route, rule, and IPv6
  ownership planning.
- Bounded numeric all-table routing inspection that treats an absent reserved
  table as clean while refusing populated, malformed, oversized, timed-out,
  permission-denied, or command-failed observations.
- Read-only setup preparation before journal publication; prepared-summary
  journaling at the pre-mutation boundary; no-op preparation, initial-write,
  and incomplete-backup recovery; verified backup; temporary guard; safe
  apply; commit; boot activation; idempotent rerun; and exact later rollback.
- Deterministic setup-guard rendering with interval semantics for every prefix
  set, strict IPv4 `/32` endpoint refusal, no global flush, and an explicitly
  gated real nftables check/apply/list/exact-delete regression in a disposable
  Debian guest.
- Strict local Docker bridge discovery; semantic daemon JSON ownership;
  eligible empty custom-network support; running/retained/changing workload
  refusal; post-plan clean-state revalidation; container-zone/VPN-only policy;
  NFTFW-owned IPv4 forwarding; confirmed restart only when required;
  topology/route revalidation; and exact rollback.
- Stable Docker authorization provenance across a race-consistent full-ID and
  Linux-bridge rebind, including transactional generation publication.
- Exact v2.0.3 static advanced Docker compatibility: unchanged bridge/tuple,
  historical interface-name provenance, ledger ID, and configuration bytes;
  strict isolation from managed dynamic `docker:<network>` rebinding; mixed
  static/dynamic operation; and non-mutating mismatch refusal.
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
- Security-sensitive mode-refusal fixtures set and verify their intended mode;
  an isolated `umask 0077` regression proves mode-`0600` handling and explicit
  mode-`0644` refusal without changing the runtime helper.

## Performance source results

The repeated 10-sample source matrix remained inside the Amendment E budgets
on the reference NUC. Observed maxima included 0.004756 ms provider parsing,
0.015391 ms managed Docker config generation, 0.032293 ms strict daemon merge,
0.016723 ms Docker topology projection, 0.008432 ms managed route decoding,
0.001419 ms Docker workload-ID classification, 0.065686 ms standard
compilation, 42.184367 ms 10,000-policy compilation, 0.021105 ms canonical
fingerprinting, 0.376339 ms no-op reconciliation, 0.0003060 ms dashboard status
projection, and 0.002104 ms adoption worksheet generation. Ten-sample
`benchstat` comparison against exact `4ed1f0c` found no statistically
significant runtime or allocation regression; the only significant runtime
change was an 8.72% semantic-summary improvement, with two sub-0.1% allocation
decreases. Performance evidence is not privileged network proof.

## Not executed under Stage E-R

The latest approval-bound E-R2 attempt passed its preceding disposable gates,
proved the corrected journal/prepare boundary, and reached the managed
first-setup guard phase. It then hard-stopped because real Debian nftables
requires interval semantics for a set populated by `/32` prefixes, while the
generated endpoint set omitted that flag. The guard was rejected before
apply and rollback completed. That partial run is not complete privileged
acceptance evidence. A complete renewed E-R2 run has not been executed and
requires new approval bound to the replacement frozen source and candidate
comparison.

| Gate | Result |
| --- | --- |
| Two protected-parent candidate builds | NOT EXECUTED in this source snapshot |
| External byte-for-byte candidate comparison | NOT EXECUTED |
| Renewed Debian install/upgrade/remove in disposable VMs | NOT EXECUTED |
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
