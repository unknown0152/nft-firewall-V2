# NFT Firewall V2 2.1.0 Source Test Results

Source disposition: **AMENDMENT AD SOURCE VALIDATED; CANDIDATES PENDING**

Validation date: 2026-09-04

Reopened source baseline:
`53e53f0dbce141df33d8f2120be5757ab789773b`

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
| Full unit/regression suite as root with `umask 0077` | PASS, fresh disposable Debian 13 guest; affected fixtures also passed independently first |
| Race suite | PASS |
| Vet | PASS |
| Staticcheck v0.8.1 | PASS |
| govulncheck v1.7.0 | PASS, no reachable vulnerabilities |
| gosec v2.29.0 reviewed profile | PASS |
| Fourteen bounded fuzz targets | PASS |
| ShellCheck | PASS |
| Stage R source/package/systemd contracts | PASS |
| Staged systemd verification | PASS |
| Disposable real-nft setup-guard regression | PASS, narrowly scoped source gate; not E-R2 |
| Disposable initramfs guard namespace regression | PASS; synthetic kernel-disable proof is required, the loader rewrites no loopback/per-interface sysctl, the exact guard loads, and unreadable archive refuses |
| Disposable exact-package rollback bundle regression | PASS; protected inputs, exact payload-equivalent bridge, exact-old configuration preflight, generated-script exact `iHR` acceptance, legacy-root/service-group database ownership, argument/state/identity/metadata refusal, deterministic tamper/path coverage, no host dpkg install |
| Disposable exact-package rollback transaction | PASS; v2.1-only config refuses before mutation without value disclosure; complete, configured-bridge resume, and idempotent paths restore exact 2.0.3 and protected snapshots; external canonical-lock probe remains blocked while legacy backup succeeds through the private dpkg lock view; no lock residue |
| Protected Amendment W managed transaction | PASS in W6; coherent Docker baseline, two validate-phase process deaths, exact rollback, nonmutating reentry, durable lineage, stable provenance, generation-3 success, all adopted Docker bridges through VPN, idempotence without Docker restart, zero-leak tunnel loss across Docker restart, recovery, and two managed boots |
| Protected Amendment Z inverse-boot retry | PASS in a fresh source-only disposable run; uncommitted generations 1/2 survive inverse-boot finalization, strict dry-run reentry remains nonmutating, and generation 3 commits before the retained Docker/VPN/leak/two-boot lifecycle completes; not E-R2 |
| Baseline E-R2 installed performance | **FAIL / HARD STOP**; CLI p95 67.224 ms passed, but persistent-HTTP dashboard p95 65.231 ms exceeded the exclusive 50 ms budget; no tag was created |
| Amendment AA source-only disposable performance | PASS for timing/resources; CLI median/p95/max 33.997/36.367/38.995 ms and dashboard 30.617/32.658/35.712 ms over 100 samples after 10 warmups; all RSS, cgroup-memory, and 60-second idle-CPU budgets pass. The guest had no independent provider assignment, so protected-status acceptance and complete E-R2 remain pending |
| Baseline E-R2 managed reboot/resume | **FAIL / HARD STOP** after eleven passed subjects; the guest booted with `ipv6.disable=1` but EFI identity validation refused and no tag was created |
| Amendment AB exact-source audit | PASS; the hard-stop file digest matches the frozen source object, which contains one active `BootCurrent` arm. The preserved failed guest shows regenerated PXE/HTTP firmware entries, so network-boot refusal—not a consumed `BootCurrent` line—caused the bounded error |
| Amendment AB EFI parser regression | PASS; exact singleton labels use a literal switch, one valid amd64 and arm64 Debian identity passes, and missing/duplicate/malformed/inactive/network/`BootNext`/wrong-order/wrong-loader/non-Debian/unsupported-architecture cases fail closed |
| Amendment AB direct disposable reboot/resume | PASS; after a real reboot with the virtual NIC option ROM disabled, status reaches `resume_ready`, the resume guard and Docker hold remain active until verification, and the same transaction completes protected setup |
| Baseline E-R2 repeated normal boot | **FAIL / HARD STOP** after fourteen passed subjects; two ROM-less boots passed, but the third reached readiness before `/run/nftfw` existed, exited `226/NAMESPACE`, and kept SSH blocked; no tag or live-host change occurred |
| Amendment AC systemd source contract | PASS; every independently activatable `/run/nftfw` writer owns the exact preserved `root:nftfw-web`, mode-`0750` directory; early/readiness are independent `sysinit.target` wants; the VPN remains a non-owner behind readiness `Requires=`/`After=` without giving readiness an activating edge to early restore |
| Amendment AC disposable runtime-directory regression | PASS; condition-skipped and injected-failed early enforcement remain blocked without namespace failure, 150 absent-directory service starts pass, and concurrent owners preserve the shared directory and peer state |
| Amendment AC repeated-boot source regression | PASS; twenty consecutive unique ROM-less boots retain exact installed readiness identity, early/readiness success, readiness-before-SSH timing, application verification, transient-guard cleanup, no namespace failure or NFTFW ordering cycle, zero frames before every initramfs marker, and post-readiness traffic; complete renewed E-R2 must repeat this candidate-bound |
| Baseline E-R2 adverse producer boot | **FAIL / HARD STOP** after the clean build/runtime and twenty-normal-boot rows passed; failed readiness kept SSH/application consumers stopped, but udev directly activated `ifup@enp0s1.service` and emitted DHCP/ARP bootstrap frames; no tag or host change occurred |
| Amendment AD producer inventory and lifecycle | PASS; closed supported set, one-primary/canonical-fragment validation, known alternate/custom/ambiguous refusal, pre-mutation target checks, exact setup marker/generated holds, post-commit readiness gates, topology drift, backup, committed recovery, exact rollback, package handoff, status, operator backup, and adoption contracts |
| Amendment AD direct systemd semantics | PASS in an offline marked Debian guest; ordinary and template direct activation waits for readiness, failed and condition-skipped readiness executes no producer payload, stopping readiness tears down the bound producer, and the effective `Requires=`/`BindsTo=`/`After=` graph is exact; complete capture-backed E-R2 remains pending |
| Disposable native initramfs package lifecycle | PASS in W7; inert install, exact native ownership/order, idempotence, tamper/foreign refusal, disabled restoration, and purge cleanup |
| Zero-pre-readiness-packet boot | **FAIL / HARD STOP in W11**; two guest-originated IPv6 MLD/DAD frames were captured before readiness although the post-boot sysctls were disabled. Init-top is not a sufficient pre-driver boundary |
| Amendment X direct GRUB transaction | PASS; strict BIOS/EFI identity, conflicting manager/mount/mode/link/race refusal, normalized mount identity, generated-entry argument parser, explicit two-pass resume, failed update, exact rollback, package handoff, and redacted status |
| Amendment X disposable GRUB/reboot/capture matrix | PASS; failed update, pre/post-reboot process death, rollback finalization, package removal/restored boot, two consecutive managed boots with zero packets before readiness and traffic after readiness, and contradictory identity with zero guest packets |
| Static amd64/arm64 CI package build and inspection | PASS; cross-binary composite identity is matched as an exact contiguous byte sequence and does not depend on tool-specific printable-run boundaries |
| Dependency/license inventory | PASS, 29 non-main modules |
| Overall statement coverage | PASS, 79.3% |
| `internal/setup` coverage | PASS, 90.0% |
| `internal/netgate` coverage | PASS, 92.3% |
| `internal/bootguard` coverage | PASS, 91.2% |
| `internal/wgconfig` coverage | PASS, 90.6% |
| `internal/intent` coverage | PASS, 92.6% |
| `internal/routing` coverage | PASS, 90.6% |
| `internal/adoption` coverage | PASS, 90.7% |

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
- Fresh daemon status on every request: current protected config/intent,
  schema-6 state and generation, provenance, one immutable full-ruleset
  nftables observation, one batched immutable-ID Docker inspection, Linux
  bridge presence, IPv4 forwarding, WireGuard, claims, and integrations.
  Adjacent-request, timeout, cancellation, saturation, concurrency, and HTTP
  over Unix-socket regressions prevent a stale `protected=true` projection.
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
  mode-`0644` refusal without changing the runtime helper. Amendment Y also
  explicitly sets and verifies both intended mode-`0750` unsafe directory
  fixtures and proves the root-only readiness fixture accepts authenticated
  control-socket status while refusing every non-status operation.
- Inverse-boot rollback preserves the exact nonzero generation only for an
  uncommitted first setup. Finalizer or terminal-journal publication failure
  cannot claim completion, and package-only or genuine pre-generation handoff
  cannot publish retry evidence. The strict classifier rejects a cleared or
  mismatched generation without changing the database or provenance ledger.

## Performance source results

The projection-only `BenchmarkDashboardProtected` remains a narrow boolean
microbenchmark and is not used as installed dashboard evidence. The Amendment
AA source adds a true HTTP-to-Unix transport benchmark and a disposable-only
installed-runtime harness. On a fresh managed-Docker KVM guest, 100 samples
after 10 warmups produced:

| Operation | Median | p95 | Maximum | Budget |
| --- | --- | --- | --- | --- |
| `nftfw status --json` | 33.997 ms | 36.367 ms | 38.995 ms | p95 under 75 ms |
| Persistent HTTP `/api/status` | 30.617 ms | 32.658 ms | 35.712 ms | p95 under 50 ms |

The same run measured `nftfwd` RSS 27,408 KiB, cgroup memory 19,509,248
bytes, `nftfw-web` RSS 14,364 KiB, and 60-second `nftfwd` idle CPU 0.15%; all
unchanged Amendment E budgets passed. Ten-count source benchmarks retain
median/p95/max plus B/op and allocations/op. In the complete ten-count sweep,
the new three-network batched Docker projection measured 16.084-17.299 us/op,
6436-6438 B/op, and 74 allocations/op. The timing guest had no independent
provider assignment and is not protected-status acceptance. The shipped
disposable-only harness requires CLI, daemon Unix-socket, and dashboard
samples to satisfy the complete healthy protected contract. It also times
both SQLite integrity reads and reports aggregate CLI/HTTP overhead relative
to the Unix path; E-R2 must run it with the authorized provider fixture.

## Not executed under Stage E-R

Successive approval-bound R2/source-disposable attempts hard-stopped safely
and led through NFV2-066. Amendment W's retry, managed-transaction, and native
initramfs lifecycle rows pass. The preserved W11 baseline reopened NFV2-057
when two IPv6 control frames left the guest before init-top readiness.
Amendment X passed its source-stage capture, boot/package, quality, coverage,
fuzz, benchmark, and scan-ready matrix, froze as
`e48d071783cd9a62ad3424c917957e4f0e6ea06a`, and produced two identical
quarantined candidates. The following E-R2 stopped before package construction
when both independent private-build guests exposed the same three privileged
test-fixture defects. Amendment Y explicitly corrects only those fixtures.
The affected tests and complete suite now pass both unprivileged and as root
under `umask 0077` in a fresh disposable guest. Amendment Z then corrects the
inverse-boot generation loss and repeats the exact two-failure, nonmutating
retry, generation-3 success, Docker/VPN/leak, and managed-boot lifecycle in a
fresh source-only disposable run. The next E-R2 passed seventeen independent
subjects, then hard-stopped when dashboard p95 exceeded 50 ms. Amendment AA's
freshness, transport, concurrency, and disposable installed-runtime source
proof now passes the unchanged budget. Its next E-R2 passed eleven subjects and
then stopped at EFI identity verification. Amendment AB preserves the strict
network-boot refusal, makes exact singleton dispatch structurally unique, and
passes the focused parser plus real-reboot resume regression using a fixture
whose virtual NIC cannot regenerate firmware network options. Amendment AC
then corrected the runtime-directory race and its source run passed twenty
normal boots. The following E-R2 repeated those normal boots but hard-stopped
when the adverse ambiguous-state boot let a directly activated ifupdown
template emit bootstrap frames after readiness failed. Amendment AD closes
that direct-producer boundary; its unit, restrictive-root, generator,
real-systemd semantic, full quality, coverage, fuzz, analyzer, benchmark, and
source-contract gates pass. This tracked snapshot precedes the replacement
clean freeze and independent quarantined candidate builds.

| Gate | Result |
| --- | --- |
| Two protected-parent candidate builds | NOT EXECUTED in this source snapshot |
| External byte-for-byte candidate comparison | NOT EXECUTED |
| Renewed Debian install/upgrade/remove in disposable VMs | Source-stage Amendment X package removal and exact 2.0.3 rollback PASS; complete E-R2 repeat NOT EXECUTED |
| Privileged namespace/network/leak matrix | NOT EXECUTED |
| Clean-server Amendment X setup and reboot matrix | Source-stage PASS; W11 remains the preserved failing pre-X baseline and complete E-R2 repeat is NOT EXECUTED |
| Privileged Docker ownership/traffic/rollback matrix | NOT EXECUTED |
| Protected Amendment W managed retry matrix | PASS in W6; source-only disposable scope, not complete E-R2 |
| Protected Amendment Z inverse-boot retry matrix | PASS; source-only disposable scope, not complete E-R2 |
| Amendment AA installed status/dashboard performance | Source-only timing/resource PASS without an independent provider assignment; strict healthy-protected E-R2 repeat NOT EXECUTED |
| Amendment AB EFI reboot/resume | Source-only direct disposable PASS; complete E-R2 repeat NOT EXECUTED |
| Amendment AC twenty consecutive boot handoffs | PASS in the source-only disposable run; 20 unique boot IDs, zero pre-marker packets on all 20, readiness-before-SSH, post-readiness traffic, stopped clean overlay; the complete candidate-bound E-R2 repeat remains NOT EXECUTED |
| Amendment AD direct network-producer gating | PASS in the source-only offline systemd guest; complete real-service, hotplug, adverse-boot, and capture-backed E-R2 repeat NOT EXECUTED |
| Disposable exact-2.0.3 adoption-planner no-mutation matrix | NOT EXECUTED |
| Real-provider VPN test | NOT EXECUTED |
| Local release tag | NOT CREATED |
| GitHub publication | NOT AUTHORIZED |
| Current-server installation/adoption | NOT AUTHORIZED |

Privileged scripts mutate disposable network, package, Docker, or boot state.
Except for the explicitly source-approved isolated fixtures reported above,
they require the separately identity-bound Stage E-R2 approval.
