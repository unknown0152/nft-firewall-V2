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
| Source-only Stage E-R | PASS |
| Privileged Stage E-R2 | FAIL, HARD STOPPED; renewed run NOT EXECUTED |
| Publication | NOT AUTHORIZED |
| Deployment | NOT AUTHORIZED |

## Source decision

The 2.1.0 source is accepted only for intrinsically quarantined Stage R
candidate construction and independent comparison. The approved source scope
includes Go 1.27, one-file managed setup, strict VPN import, managed routing,
strict managed Docker IPv4 bridge adoption and forwarding ownership,
the explicit dry-run-only existing-host adoption planner, CLI/dashboard
changes, package source, documentation, benchmarks, tests, and local
nondeployable candidate builds.

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
  or above 90%.
- Managed file publication and kernel generation recovery remain separate,
  independently timed, and exact-generation scoped.
- Existing-host adoption planning has no mutation path, repeats protected
  observation, and refuses actual conversion pending a separate Stage E-L
  plan.
- No VPN key, provider identity, public topology, token, or live secret is
  present in tracked source evidence.

## Later gates

After this report is frozen, Stage E-R must build two independent protected
candidate parents and emit an external
`STAGE_R_CANDIDATE_COMPARISON_PASS` record. Stage E-R2 then requires a new
approval bound to that frozen source commit and comparison SHA-256. Any local
tag, remote publication, or current-server deployment requires still later
identity-bound approval.

The first approved R2 attempt hard-stopped before private package construction
when its privileged source rerun exposed an ambient-umask-dependent test
fixture. It is not acceptance evidence. The corrected source requires a new
identity-bound E-R2 approval and complete renewed run.

R2 PRIVILEGED PACKAGE/BOOT/NETWORK/DOCKER/OVPN EVIDENCE: NOT EXECUTED
