# NFT Firewall V2 2.1.0 Source Test Results

Source disposition: **STAGE_R_CANDIDATE_ONLY**

Validation date: 2026-08-30

Reopened source baseline:
`02a7ea711a72725a27b25decb9b36a277b37d7b8`

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
| Disposable initramfs guard namespace regression | PASS; later interface inherits IPv6 disabled, loopback remains enabled, exact guard loads, unreadable archive refuses |
| Disposable exact-package rollback bundle regression | PASS; protected inputs, exact payload-equivalent bridge, generated-script exact `iHR` acceptance plus argument/state/identity/metadata refusal, tamper/path coverage, no host dpkg install |
| Disposable exact-package rollback transaction | PASS; complete, configured-bridge resume, and idempotent paths restore exact 2.0.3 and protected snapshots; external canonical-lock probe remains blocked while legacy backup succeeds through the private dpkg lock view; no lock residue |
| Static amd64/arm64 CI package build and inspection | PASS |
| Dependency/license inventory | PASS, 29 non-main modules |
| Overall statement coverage | PASS, 76.7% |
| `internal/setup` coverage | PASS, 90.6% |
| `internal/bootguard` coverage | PASS, 91.8% |
| `internal/wgconfig` coverage | PASS, 90.6% |
| `internal/intent` coverage | PASS, 92.6% |
| `internal/routing` coverage | PASS, 90.5% |
| `internal/adoption` coverage | PASS, 91.0% |

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
- Exact-2.0.3 planning accepts only the enumerated canonical absent systemd
  tuple for the three units not shipped by 2.0.3. One bounded six-property
  snapshot rejects aliases, shadows, contradictions, malformed output, races,
  and absence on 2.1.0.
- Managed first setup starts runtime enforcement under the temporary guard,
  validates and commits it, establishes committed early/readiness, builds and
  verifies the pre-udev guard in every installed initramfs, and only then
  publishes final dependency edges and enables boot consumers. Post-commit
  failures recover forward; pre-commit failures retain exact rollback.
- The marker-gated initramfs loader sets reversible non-loopback IPv6 defaults
  before udev, keeps loopback IPv6 enabled, checksum-verifies and applies an
  exact three-chain deny guard, and hands it off only after committed
  enforcement verification under the global mutation lock. Removal refuses
  unreadable archives and cannot strand the marker silently.
- The pre-upgrade exact-package rollback helper binds both release packages,
  architecture, helper, schema history, binary hashes, and canonical payload
  digest in a protected manifest. Its lower-version bridge carries exact
  2.0.3 data and accepts only Debian 13's exact three-argument `iHR 2.1.0`
  transition, generated bridge version, architecture, protected binary and
  database metadata, optional exact schema-6 history, and manifest transition
  identity. The controller retains the real canonical mutation lock while
  only dpkg descendants see a fresh protected lock inode in a private mount
  namespace, allowing the historical 2.0.3 backup without an unlocked handoff.
  It permits the unmodified 2.0.3 package to finish without dpkg-status edits,
  state deletion, or manual file copy. The complete disposable rerun passes
  after NFV2-060 exposed and the source corrected the previous same-lock
  self-deadlock.
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
on the reference NUC. Current medians included 0.004027 ms provider parsing,
0.01405 ms managed Docker config generation, 0.02952 ms strict daemon merge,
0.01236 ms Docker topology projection, 0.006285 ms managed route decoding,
0.001363 ms Docker workload-ID classification, 0.05728 ms standard
compilation, 32.35 ms 10,000-policy compilation, 0.01869 ms canonical
fingerprinting, 0.3329 ms no-op reconciliation, 0.0002975 ms dashboard status
projection, and 0.001781 ms adoption worksheet generation. Amendment N changes
shell recovery only, and the exact `02a7ea7` Go sources are unchanged. Every
reference operation remained inside budget; performance evidence is not
privileged network proof.

## Not executed under Stage E-R

The latest approval-bound E-R2 attempt passed the corrected Amendment M
boundaries and every preceding still-useful independent row, then reached the
real Debian rollback and hard-stopped without a tag because the generated
bridge required configured `ii` after dpkg had entered `iHR`. That partial run
is not complete privileged acceptance evidence. A complete renewed E–N R2 run
has not been executed and requires new approval bound to the replacement
frozen source and candidate comparison.

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
