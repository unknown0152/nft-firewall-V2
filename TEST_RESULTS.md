# NFT Firewall V2 2.1.0 Source Test Results

Source disposition: **AMENDMENT X SOURCE VALIDATED; CANDIDATES PENDING**

Validation date: 2026-09-01

Reopened source baseline:
`e59cacbf81cd1851cc52530074209c84eb1ac3d9`

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
| Thirteen bounded fuzz targets | PASS |
| ShellCheck | PASS |
| Stage R source/package/systemd contracts | PASS |
| Staged systemd verification | PASS |
| Disposable real-nft setup-guard regression | PASS, narrowly scoped source gate; not E-R2 |
| Disposable initramfs guard namespace regression | PASS; synthetic kernel-disable proof is required, the loader rewrites no loopback/per-interface sysctl, the exact guard loads, and unreadable archive refuses |
| Disposable exact-package rollback bundle regression | PASS; protected inputs, exact payload-equivalent bridge, exact-old configuration preflight, generated-script exact `iHR` acceptance, legacy-root/service-group database ownership, argument/state/identity/metadata refusal, deterministic tamper/path coverage, no host dpkg install |
| Disposable exact-package rollback transaction | PASS; v2.1-only config refuses before mutation without value disclosure; complete, configured-bridge resume, and idempotent paths restore exact 2.0.3 and protected snapshots; external canonical-lock probe remains blocked while legacy backup succeeds through the private dpkg lock view; no lock residue |
| Protected Amendment W managed transaction | PASS in W6; coherent Docker baseline, two validate-phase process deaths, exact rollback, nonmutating reentry, durable lineage, stable provenance, generation-3 success, all adopted Docker bridges through VPN, idempotence without Docker restart, zero-leak tunnel loss across Docker restart, recovery, and two managed boots |
| Disposable native initramfs package lifecycle | PASS in W7; inert install, exact native ownership/order, idempotence, tamper/foreign refusal, disabled restoration, and purge cleanup |
| Zero-pre-readiness-packet boot | **FAIL / HARD STOP in W11**; two guest-originated IPv6 MLD/DAD frames were captured before readiness although the post-boot sysctls were disabled. Init-top is not a sufficient pre-driver boundary |
| Amendment X direct GRUB transaction | PASS; strict BIOS/EFI identity, conflicting manager/mount/mode/link/race refusal, normalized mount identity, generated-entry argument parser, explicit two-pass resume, failed update, exact rollback, package handoff, and redacted status |
| Amendment X disposable GRUB/reboot/capture matrix | PASS; failed update, pre/post-reboot process death, rollback finalization, package removal/restored boot, two consecutive managed boots with zero packets before readiness and traffic after readiness, and contradictory identity with zero guest packets |
| Static amd64/arm64 CI package build and inspection | PASS |
| Dependency/license inventory | PASS, 29 non-main modules |
| Overall statement coverage | PASS, 78.7% |
| `internal/setup` coverage | PASS, 90.0% |
| `internal/bootguard` coverage | PASS, 91.2% |
| `internal/wgconfig` coverage | PASS, 90.6% |
| `internal/intent` coverage | PASS, 92.6% |
| `internal/routing` coverage | PASS, 90.6% |
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
- Strict retry after a terminal first-setup rollback only: exact backup and
  inactive runtime verification, rolled-back first-use generations, immutable
  snapshots, endpoint cache, stable monotonic provenance, and checksum-bound
  current/history journals must all agree. Two consecutive failures retain
  generation/provenance evidence and the third run commits monotonically.
- Durable journal lineage uses root-owned no-follow paths, bounded canonical
  JSON, checksum-addressed names, atomic no-replace publication, file and
  directory sync, collision refusal, and idempotent recovery when a process
  dies either before archive rename or between archive and new-current
  publication.
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
- Managed disabled setup owns one fixed Debian GRUB fragment, verifies every
  generated Linux entry, stops at `reboot_required`, and resumes only after an
  explicit reboot proves the prepared and running kernel identities. The
  native loader requires that kernel-wide contract, rewrites no loopback or
  interface sysctl, checksum-verifies an exact three-chain deny guard, and
  hands it off only after committed enforcement verification under the global
  mutation lock.
- Resumed-boot direct regressions prove atomic initramfs-to-resume guard
  replacement, restart-idempotent process-death recovery, contradictory-table
  refusal, DNS-free protected endpoint reuse, exact resume-payload metadata
  and checksum validation, separate Docker service/socket holds, confirmation
  before release, exact pre-release rollback restoration, and runtime-state
  cleanup. Managed sysctl generation and application keep loopback IPv6
  disabled under the kernel-wide policy.
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

The repeated source matrix remained inside the Amendment E budgets on the
reference NUC. Amendment X's GRUB generated-entry verifier measured
2.095-2.401 microseconds/op, 4672 B/op, and 22 allocations/op. The strict
retained-state classifier was measured in ten independent samples at
1.340-1.412 ms/op, 230852-231690 B/op, and 1040-1041 allocations/op. It
includes canonical journal/history reads, exact backup
verification, schema-6 generation inspection, immutable snapshot checks, and
read-only provenance validation. Performance evidence is not privileged
network proof.

## Not executed under Stage E-R

Successive approval-bound R2/source-disposable attempts hard-stopped safely
and led through NFV2-061. Amendment W's retry, managed-transaction, and native
initramfs lifecycle rows pass. The preserved W11 baseline reopened NFV2-057
when two IPv6 control frames left the guest before init-top readiness.
Amendment X is the separately approved source correction, and its complete
source-stage capture, boot/package, quality, coverage, fuzz, benchmark, and
scan-ready matrix now passes. This tracked snapshot still precedes the clean
freeze and independent quarantined candidate builds.

| Gate | Result |
| --- | --- |
| Two protected-parent candidate builds | NOT EXECUTED in this source snapshot |
| External byte-for-byte candidate comparison | NOT EXECUTED |
| Renewed Debian install/upgrade/remove in disposable VMs | Source-stage Amendment X package removal and exact 2.0.3 rollback PASS; complete E-R2 repeat NOT EXECUTED |
| Privileged namespace/network/leak matrix | NOT EXECUTED |
| Clean-server Amendment X setup and reboot matrix | Source-stage PASS; W11 remains the preserved failing pre-X baseline and complete E-R2 repeat is NOT EXECUTED |
| Privileged Docker ownership/traffic/rollback matrix | NOT EXECUTED |
| Protected Amendment W managed retry matrix | PASS in W6; source-only disposable scope, not complete E-R2 |
| Disposable exact-2.0.3 adoption-planner no-mutation matrix | NOT EXECUTED |
| Real-provider VPN test | NOT EXECUTED |
| Local release tag | NOT CREATED |
| GitHub publication | NOT AUTHORIZED |
| Current-server installation/adoption | NOT AUTHORIZED |

Privileged scripts mutate disposable network, package, Docker, or boot state.
They require the separately identity-bound Stage E-R2 approval.
