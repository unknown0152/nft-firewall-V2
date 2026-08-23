# NFT Firewall V2 Test Results

This file separates evidence collected for the current `2.0.1` source
candidate from privileged acceptance that belongs to the tagged `2.0.0`
baseline. Results are not carried forward across code changes unless the same
gate was rerun against the current candidate.

## 2.0.1 candidate evidence

Unprivileged checks were run on 2026-08-23 with Go 1.25.13. They did not
install services, load an nftables ruleset, alter networking, access Docker,
start WireGuard, or exercise the current machine as a live firewall.

| Gate | Current result | Evidence / scope |
| --- | --- | --- |
| Unit and package tests | PASS | `GOTOOLCHAIN=go1.25.13 go test -count=1 ./...` |
| Targeted race tests | PASS | Compiler and application/runtime race tests covering the changed paths |
| Full race suite | PASS | `GOTOOLCHAIN=go1.25.13 go test -race -count=1 ./...` |
| Vet | PASS | `GOTOOLCHAIN=go1.25.13 go vet ./...` |
| Formatting | PASS | All tracked Go files pass `gofmt` comparison |
| Module integrity | PASS | `go mod verify` and `go mod tidy -diff` |
| Shell syntax and analysis | PASS | `bash -n` and ShellCheck 0.10.0 over the production and packaging scripts |
| systemd static verification | PASS | Units were verified against isolated staged executables; the fresh-host wrapper regression proved no final-path executable was required. No units were installed or started |
| Staticcheck | PASS | staticcheck v0.7.0 with Go 1.25.13 |
| Vulnerability scan | PASS | govulncheck v1.7.0 reported no vulnerabilities |
| Go security scan | PASS | gosec v2.28.0 focused scan reported no findings |
| Worktree and Git-history secret scan | PASS | Gitleaks 8.16.0 with redaction over the complete history and current worktree |
| Final extracted-archive secret scan | PENDING | Requires final ZIP and tar.gz artifacts |
| Fuzz/property suite | PASS | All eight documented targets ran independently for 10 seconds with one worker each |
| amd64/arm64 release build | PENDING | Requires the clean committed/tagged release candidate |
| Debian package inspection | PENDING | Requires final amd64 and arm64 packages |
| Archive integrity and manifests | PENDING | Requires final ZIP and tar.gz artifacts |
| Reproducibility | PENDING | Requires two builds from the same final commit and tag |
| Signature | NOT PROVIDED | Checksums and generated provenance are unsigned; an external release identity must sign them if required |

### Remediation regressions covered

The passing `2.0.1` unit/package suite covers the release-hardening changes,
including:

- rejecting contradictory interface-to-zone declarations;
- ordering established management replies, temporary recovery access, and
  WireGuard bootstrap ahead of untrusted dynamic-feed drops;
- constraining threat feeds to bounded public prefixes, enforcing aggregate
  limits and protected-prefix exclusions, validating persisted claims, and
  compensating database/live-set publication failures;
- rejecting obfuscated global flushes and unsupported or foreign nftables
  management commands;
- refusing first-use collisions with pre-existing product-named tables;
- preserving rollback errors and recoverable generation state;
- serializing claim publication across processes, compensating every manual
  claim mutation failure, and exposing durable desired/applied revisions;
- bounding API, controller, and backend lock waits while retaining an
  independent emergency-deny recovery context;
- failing closed on `SO_PEERCRED` failures and separating control/status
  connection quotas;
- pruning the durable audit log to 10,000 rows through schema migration 4;
- enforcing the typed `nftfw.status.v1` health contract in the CLI and bundled
  web consumer; and
- keeping Docker socket access disabled unless an administrator explicitly
  installs the documented opt-in systemd drop-in; and
- validating systemd units against staged executables before a source
  installer makes any host change.

## Privileged and live `2.0.1` gates

The following gates have not been run for `2.0.1` and remain pending explicit
approval because they require root privileges, network namespace or host
firewall mutation, a real provider profile, Docker access, service
installation, or disruption:

- namespace nftables/WireGuard IPv4 and IPv6 kill-switch acceptance;
- active TCP/UDP host and container failure tests and packet capture;
- guarded host safe-apply, commit, crash, timeout rollback, and drift repair;
- real-provider WireGuard, DNS, endpoint refresh, loss, and recovery;
- Docker lifecycle and container VPN isolation;
- systemd installation, service crash/restart, early restore, and reboot;
- source installer and Debian package installation/upgrade/removal; and
- validation on the actual NUC/server topology.

No result in this document means that `2.0.1` is installed, enabled, or active
on the current machine.

## Inherited `2.0.0` historical evidence

The `v2.0.0` release documentation records successful namespace, real
WireGuard provider, Docker, guarded host rollback, database, service-chaos,
package, archive, secret-scan, and reproducibility exercises. It also records
that a full VPS reboot was not executed. That evidence is useful architectural
history, but it is not a pass result for the changed `2.0.1` candidate.

In particular, the following historical observations are not restated as
current results:

- zero IPv4/IPv6 leak packet counts;
- real-provider handshake and public-route changes;
- Docker container loss/recovery;
- host SSH-preserving safe apply and independent timeout rollback; and
- byte-identical release archives.

Those claims apply only to the exact `v2.0.0` code and environment on which
they were collected. Current source evidence must be completed and recorded
above before `2.0.1` is called accepted.

## Fuzz targets required before release

| Package | Target | Current result |
| --- | --- | --- |
| Config | `FuzzDecode` | PASS — 10 seconds |
| API | `FuzzDecodeRequest` | PASS — 10 seconds |
| Policy | `FuzzExplainAlwaysReturnsAVerdict` | PASS — 10 seconds |
| Compiler | `FuzzCompileRuntimePrefix` | PASS — 10 seconds |
| nft | `FuzzValidateScript` | PASS — 10 seconds |
| nft | `FuzzCanonicalOwnedJSON` | PASS — 10 seconds |
| State | `FuzzValidateClaim` | PASS — 10 seconds |
| Threat feed | `FuzzParse` | PASS — 10 seconds |

## Release evidence rules

Final evidence must identify the exact commit and tag, retain sanitized logs
outside the release archives, and avoid recording provider keys, credentials,
public addresses, domains, usernames, device identifiers, or private topology.
Any privileged validation report derived from a real host must be redacted
before publication.
