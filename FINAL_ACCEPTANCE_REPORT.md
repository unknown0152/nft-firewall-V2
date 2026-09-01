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
| Source-only Stage E-R | AMENDMENT X SOURCE GATES PASS; CANDIDATES PENDING |
| Privileged Stage E-R2 | NOT AUTHORIZED for the Amendment X working tree |
| Publication | NOT AUTHORIZED |
| Deployment | NOT AUTHORIZED |

## Source decision

The 2.1.0 working source has passed the Amendment X gate set and is accepted
for a clean source freeze and the two intrinsically nondeployable candidate
builds. The approved Amendment X source scope
includes Go 1.27, one-file managed setup, strict VPN import, managed routing,
strict managed Docker IPv4 bridge adoption and forwarding ownership,
the explicit dry-run-only existing-host adoption planner, CLI/dashboard
changes, the corrected managed first-setup transaction boundary, valid
interval-based setup-guard prefix sets with exact `/32` endpoint scope,
strict exact-2.0.3 absent-unit planning, the committed first-setup handoff,
the two-pass pre-driver Debian GRUB transaction and exact guard handoff, and the
protected exact-2.0.3 Debian rollback transaction. It also includes strict
terminal first-setup retry classification, monotonic retained-state reentry,
and checksum-bound durable terminal-journal lineage, plus package source,
documentation, benchmarks, tests, and local nondeployable candidate builds.

The candidate binaries permit only their quarantine-safe behavior, candidate
daemon/web processes refuse startup, and candidate Debian packages refuse
installation. This report does not authorize a release tag, R2, publication,
live installation, firewall application, VPN interruption, or deployment.

## Source gates

- Full unit, race, vet, staticcheck, govulncheck, gosec, module, formatting,
  ShellCheck, fuzz, source-contract, systemd, coverage, and benchmark gates.
- Explicit mode fixtures and an isolated `umask 0077` regression preserve the
  mode-`0600`/root-ownership acceptance boundary and mode-`0644` refusal; the
  complete suite also passes with `umask 0077` in an unprivileged environment.
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
through NFV2-061. Amendment W's W6 protected matrix passes exact retry,
generation-3 success, Docker VPN/leak recovery, and two managed boots; W7
passes the real native initramfs package lifecycle. W11 then failed the
mandatory zero-pre-readiness-packet gate: two IPv6 MLD/DAD frames left the
guest before init-top readiness. Amendment X implements the approved
pre-driver correction. Its complete source-stage disposable and source
validation now passes, so the clean freeze and two quarantined candidate
builds may proceed. E-R2, tagging, publication, installation, and deployment
remain outside this report.

R2 PRIVILEGED PACKAGE/BOOT/NETWORK/DOCKER/OVPN EVIDENCE: NOT EXECUTED
