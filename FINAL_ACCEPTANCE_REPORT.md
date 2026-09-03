# NFT Firewall V2 2.1.0 Source Acceptance

Release approval status: STAGE_R_CANDIDATE_ONLY

| Item | Value |
| --- | --- |
| Target version | `@RELEASE_VERSION@` |
| Artifact version | `@RELEASE_ARTIFACT_VERSION@` |
| Source commit | `@GIT_COMMIT@` |
| Git tag | `@GIT_TAG@` |
| Build date | `@BUILD_DATE@` |
| Build disposition | `@RELEASE_DISPOSITION@` |
| Artifact label | `@RELEASE_ARTIFACT_LABEL@` |
| Source-only Stage E-R | AMENDMENT AC SOURCE GATES PASS; CANDIDATES PENDING |
| Privileged Stage E-R2 | NOT AUTHORIZED for the Amendment AC working tree |
| Publication | NOT AUTHORIZED |
| Deployment | NOT AUTHORIZED |

## Source decision

The 2.1.0 working source has passed the Amendment AC gate set and is accepted
for a clean source freeze and the two intrinsically nondeployable candidate
builds. The retained Amendment E-through-Z source scope
includes Go 1.27, one-file managed setup, strict VPN import, managed routing,
strict managed Docker IPv4 bridge adoption and forwarding ownership,
the explicit dry-run-only existing-host adoption planner, CLI/dashboard
changes, the corrected managed first-setup transaction boundary, valid
interval-based setup-guard prefix sets with exact `/32` endpoint scope,
strict exact-2.0.3 absent-unit planning, the committed first-setup handoff,
the two-pass pre-driver Debian GRUB transaction and exact guard handoff, and the
protected exact-2.0.3 Debian rollback transaction. It also includes strict
terminal first-setup retry classification, monotonic retained-state reentry,
checksum-bound durable terminal-journal lineage, and the inverse-boot
generation correction: an uncommitted first setup retains its exact rolled-back
generation, while genuine pre-generation and package-only paths remain
non-retryable. Amendment AA also retains every fresh fail-closed status check
while deriving nftables ownership, integrity, fingerprint, and foreign
provenance from one immutable ruleset snapshot and inspecting all authorized
Docker networks in one immutable-ID batch. Package source, documentation,
benchmarks, tests, and local nondeployable candidate builds are included.
Amendment AB additionally makes each EFI singleton dispatch label a unique
literal switch arm, expands fail-closed `BootCurrent` coverage, and retains the
strict rejection of firmware network boot paths. Its direct disposable reboot
uses a virtual NIC without an option ROM, reaches `resume_ready` while both
pre-policy holds remain effective, and completes the protected transaction.
Amendment AC gives readiness and the independent rollback timers deterministic
ownership of the common runtime directory before systemd constructs their
mount namespaces. Early uses explicit early-boot dependencies; early and
readiness are independently scheduled by `sysinit.target`; protected consumers
require the verifier; and readiness still has no activating edge to early. The
disposable source fixtures prove condition-skipped and failed early enforcement
remain blocked, 150 absent-directory starts succeed, concurrent owners cannot
remove or chown-break shared state, and twenty consecutive ROM-less boots
release SSH only after verification with zero pre-marker packets.

The candidate binaries permit only their quarantine-safe behavior, candidate
daemon/web processes refuse startup, and candidate Debian packages refuse
installation. This report does not authorize a release tag, R2, publication,
live installation, firewall application, VPN interruption, or deployment.

## Source gates

- Full unit, race, vet, staticcheck, govulncheck, gosec, module, formatting,
  ShellCheck, fuzz, source-contract, systemd, coverage, and benchmark gates.
- Adjacent daemon requests re-observe config, intent, database/provenance,
  nftables, Docker, forwarding, WireGuard, claims, and integrations. Drift in
  any injectable observation degrades the next completed response. The true
  HTTP-to-Unix transport, concurrent saturation, timeout, cancellation, and
  allocation regressions pass without caching a protected result.
- The disposable installed managed-Docker source profile passes the unchanged
  budgets: CLI p95 36.367 ms and persistent-HTTP dashboard p95 32.658 ms over
  100 samples after 10 warmups, with RSS, cgroup memory, and 60-second idle CPU
  also passing. That guest lacked an independent provider assignment and is
  not protected-status acceptance. The shipped harness requires a healthy
  protected result on every sample; complete E-R2 must run that strict proof.
- Explicit mode fixtures and an isolated `umask 0077` regression preserve the
  mode-`0600`/root-ownership acceptance boundary and mode-`0644` refusal; the
  two intended unsafe directory fixtures explicitly establish and verify
  mode `0750`. The authenticated-control readiness fixture serves only status
  and directly refuses a non-status control operation. The complete suite
  passes with `umask 0077` both unprivileged and as root in a fresh disposable
  Debian 13 guest.
- Overall statement coverage at least 75%, with all five new core packages at
  or above 90%; the new bootguard package is also above 90%.
- Clean-host routing uses bounded numeric all-table JSON: an absent reserved
  table is clean, but failed, malformed, or populated observations refuse.
- Managed first setup completes all read-only preparation before publishing a
  journal containing the prepared summary. Preparation, initial publication,
  and incomplete-backup failures cannot invoke protected mutation or system
  rollback; guard-or-later rollback remains bound to a durable backup.
- A terminal first-setup retry is accepted only after exact backup restoration,
  no live managed ownership, only rolled-back first-setup generations, a valid
  endpoint cache, and unchanged monotonic provenance are all proven together.
  The prior terminal journal is durably archived before the next transaction
  can mutate; collisions, partial evidence, and changed lineage refuse.
- Inverse-boot rollback finalization preserves the exact nonzero generation
  only for an uncommitted first setup. It publishes no terminal state when the
  finalizer or journal write fails, keeps a genuine pre-generation rollback at
  zero, and clears committed package-only handoff so it cannot masquerade as a
  complete firewall rollback. A fresh disposable run repeats two failed
  generations, nonmutating retry, generation-3 success, Docker/VPN leak
  recovery, and two managed boots.
- The temporary setup guard renders every prefix-bearing set with interval
  semantics, keeps VPN bootstrap endpoints restricted to canonical IPv4
  `/32` values, passes the real nftables parser in a gated disposable guest,
  and never flushes the global ruleset.
- Managed Docker clean-host setup accepts eligible empty bridges only and
  revalidates that no running or retained workload appeared immediately before
  ownership-file publication.
- Exact v2.0.3 static advanced Docker entries preserve their bridge, tuple,
  configuration bytes, historical interface-name provenance, and ledger ID.
  Only managed dynamic entries with exact `docker:<network>` provenance may
  automatically rebind; neither mode can fall back to the other.
- Managed file publication and kernel generation recovery remain separate,
  independently timed, and exact-generation scoped.
- Existing-host adoption planning has no mutation path, repeats protected
  observation, and refuses actual conversion pending a separate Stage E-L
  plan.
- Exact 2.0.3 planning accepts only the three enumerated canonical absent
  units from one strict systemd property snapshot; aliases, shadows,
  contradictions, malformed output, and 2.1.0 absence refuse.
- Managed first setup publishes no final early dependency before runtime
  enforcement starts and commits. It establishes early/readiness and verifies
  every initramfs before publishing final edges or enabling boot consumers;
  every post-commit failure follows the recover-forward path.
- Managed disabled setup accepts one exact local Debian GRUB family, publishes
  one root-only `ipv6.disable=1` fragment, verifies every generated Linux
  entry, and stops before ordinary mutation. It resumes only after an explicit
  reboot proves a changed boot ID, the exact argument, kernel disablement,
  empty IPv6 state, and unchanged transaction. The native loader verifies that
  contract, never re-enables loopback, and keeps the exact nft guard as defense
  in depth. Rollback/package handoff restores the captured next boot exactly
  and reports when the running kernel still requires another reboot.
- The post-reboot generator replaces the initramfs deny table atomically with
  one checksum-bound DHCP/LAN/cached-endpoint resume guard and keeps both
  Docker consumers queued. The same-profile pass requires the exact private
  endpoint identity without DNS, writes Docker/forwarding ownership, confirms
  the restart before release, and restores the old Docker files first on
  rollback. Direct crash, tamper, contradiction, ordering, and cleanup tests
  pass. Disposable capture proves two consecutive managed boots emit zero
  packets before readiness and expected traffic only afterward; a
  contradictory boot identity emits zero guest packets.
- The package rollback bundle binds exact 2.0.3 and 2.1.0 release packages,
  helper, architecture, schema, binaries, bridge, payload, and transition
  identity. The payload-identical lower-version bridge accepts only Debian's
  exact three-argument `iHR 2.1.0` boundary plus protected metadata, then
  preflights the current configuration with the bound exact old parser before
  boot or package mutation, accepts only the two strict mode-0600 database
  ownership histories, and
  retains the parent canonical lock while giving only dpkg a protected private
  lock view for exact 2.0.3's historical backup. It then makes the unmodified
  2.0.3 install a supported transition; no configured/neighboring state,
  unlocked handoff, dpkg-status edit, or unverified copy is accepted.
- No VPN key, provider identity, public topology, token, or live secret is
  present in tracked source evidence.

## Later gates

After this report is frozen, Stage E-R must build two independent protected
candidate parents and emit an external
`STAGE_R_CANDIDATE_COMPARISON_PASS` record. Stage E-R2 then requires a new
approval bound to that frozen source commit and comparison SHA-256. Any local
tag, remote publication, or current-server deployment requires still later
identity-bound approval.

Successive approved R2/source-disposable attempts hard-stopped safely and led
through NFV2-066. Amendment W's W6 protected matrix passes exact retry,
generation-3 success, Docker VPN/leak recovery, and two managed boots; W7
passes the real native initramfs package lifecycle. W11 then failed the
mandatory zero-pre-readiness-packet gate: two IPv6 MLD/DAD frames left the
guest before init-top readiness. Amendment X implements the approved
pre-driver correction. Its complete source-stage disposable and source
validation passed and froze as
`e48d071783cd9a62ad3424c917957e4f0e6ea06a`. Its E-R2 private-build stage then
exposed three deterministic privileged fixture failures before package
construction. Amendment Y corrects only those fixtures; its focused and full
ordinary/restrictive/root-disposable suites pass. The following recovery run
exposed the inverse-boot generation loss; Amendment Z corrects it and its
direct, full, restrictive-umask, and source-only disposable lifecycle gates
pass. The next E-R2 passed seventeen disposable subjects, then hard-stopped on
dashboard p95 65.231 ms against the exclusive 50 ms budget. Amendment AA
corrects that demonstrated fan-out and passes the source-only disposable
installed benchmark without weakening freshness. The replacement clean freeze
then entered E-R2, where eleven subjects passed before the managed reboot guest
failed closed on EFI identity. Exact source and failed-guest inspection showed
that the frozen parser already had one active `BootCurrent` arm and that OVMF
had regenerated PXE/HTTP entries across reboot. Amendment AB preserves that
network refusal, makes singleton dispatch compile-time unique, and passes the
focused real-reboot source regression with firmware network option ROMs
disabled. Its E-R2 replacement passed fourteen subjects and then failed closed
on the intermittent readiness runtime-directory race. Amendment AC corrects
that shared systemd ownership and directly coupled boot-transaction ordering
boundary. Its source run passes twenty consecutive ROM-less boots. The
replacement clean freeze and two quarantined candidate builds may
proceed. E-R2, tagging, publication, installation, and deployment remain
outside this report.

R2 PRIVILEGED PACKAGE/BOOT/NETWORK/DOCKER/OVPN EVIDENCE: NOT EXECUTED FOR THE AMENDMENT AC CORRECTION
