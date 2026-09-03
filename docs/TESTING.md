# Testing

Current disposition: **2.1.0 AMENDMENT AC STAGE E-R SOURCE VALIDATION**.
Source-only results are consolidated in `TEST_RESULTS.md`. The narrowly
approved source-stage disposable GRUB/boot, native-initramfs, setup-guard, and
exact-package rollback preflights have run. The complete namespace, Docker,
provider, and E-R2 matrix below has not run for this frozen-candidate cycle and
still requires the separately approved disposable lab with independent
recovery.

Test outcomes use only `PASS`, `FAIL`, `BLOCKED`, `NOT APPLICABLE`, or
`NOT EXECUTED`. A namespace simulation and an external provider tunnel are
reported separately.

## Unprivileged gates

```bash
make fmt-check
go mod verify
go mod tidy -diff
go test ./...
(umask 0077; go test ./...)
go test -race ./...
go vet ./...
staticcheck ./...
govulncheck ./...
gosec -quiet -exclude-generated -exclude=G104,G204,G304,G302 ./...
./tests/packaging/systemd_preflight.sh amd64
bash ./tests/packaging/docker_handoff.sh
bash ./tests/stage-r/run.sh
```

Amendment M adds two root-only, disposable source regressions. Neither
installs a package or changes the host network namespace:

```bash
sudo ./tests/initramfs-guard-namespace.sh
sudo ./tests/package-rollback-bundle.sh
```

The first creates private mount/network namespaces, supplies a synthetic exact
kernel-disable proof, applies the exact initramfs guard, and proves the loader
does not try to rewrite loopback or per-interface IPv6 sysctls while the
kernel-wide contract is active. The second builds disposable minimal Debian
packages, proves the rollback bridge payload is identical to exact 2.0.3,
executes the generated `preinst` inside a minimal chroot, and accepts only the
real three-argument Debian 13 call with `iHR 2.1.0`. It rejects configured and
neighboring package states, malformed arguments, identity/schema/architecture
drift, unsafe metadata, symlinks, hard links, and manifest/package tampering
without invoking dpkg installation on the host.

The native source-order and boot-hold generator fixtures are also direct,
temporary-tree tests:

```bash
sudo ./tests/packaging/initramfs_native_sources.sh
./tests/packaging/setup_boot_hold_generator.sh
```

The full package-manager regression is deliberately unusable on an operator
host. In a disposable Debian 13 guest already carrying the exact 2.0.3
advanced-mode fixture, create the same protected marker used by other
destructive guest tests, copy both exact release-form test packages into a
root-only directory, and run:

```bash
sudo ./tests/package-rollback-disposable.sh \
  /absolute/guest/path/nft-firewall-v2_2.0.3_amd64.deb \
  /absolute/guest/path/nft-firewall-v2_2.1.0_amd64.deb \
  OLD_SHA256 NEW_SHA256
```

It performs the complete 2.1.0-to-bridge-to-2.0.3 transaction, separately
resumes from the configured bridge, repeats from already restored 2.0.3, and
compares package payload, schema, policy, provenance/state, Docker, unit,
route/rule, configuration, and initramfs identities. It also races an external
canonical-lock probe against exact 2.0.3's historical backup: the probe must
remain blocked while the backup succeeds through dpkg's private lock view, and
no transaction-local lock file may remain. Timestamped audit/backup material,
SQLite WAL files, and the restart-regenerated WireGuard endpoint observation
cache are excluded from byte identity. Audit, integration-health, and runtime
claim-publication rows are normalized only in a temporary database copy
because daemon restart necessarily refreshes them; schema, generations,
claims, provenance, and committed policy remain byte/logically covered. The root-owned regular
mode-`0600` marker and disposable guest are mandatory; this script must never
run on an operator host.

Before the complete transaction, the fixture injects a private v2.1-only
configuration value and requires a content-free refusal while 2.1.0 remains
configured. It then restores the compatible file and proves both real
mode-0600 database ownership histories (`root:root` and
`root:nftfw-web`) without accepting any other group.

The systemd preflight uses temporary unit copies and staged executables, so it
can validate a fresh-host source installation before final paths exist and
without installing or starting anything.

The isolated `umask 0077` regression creates a mode-`0600` secret under the
restrictive mask. Root execution requires acceptance; unprivileged execution
requires the separate root-ownership refusal. Both paths then explicitly set
and verify mode `0644` before asserting refusal. The full unprivileged suite is
also rerun under `umask 0077`; no security refusal fixture may depend on the
invoking shell's ambient mask.

Amendment Y adds a required fresh-disposable-guest root pass. The two
directory refusal fixtures explicitly `chmod` and verify mode `0750` before
calling the production validators. The root-only daemon-readiness fixture
serves a healthy status through both API sockets and proves a non-status
control operation still returns its fixed refusal. Run the affected tests
first and then the complete suite, both under the restrictive mask:

```bash
(umask 0077; go test -count=1 \
  -run 'TestBackupEvidenceHelpersFailClosed|TestJournalHistoryHelpersFailClosed|TestRuntimeAPIReadinessUsesStatusAndAuthenticatedControl' \
  -v ./internal/setup)
(umask 0077; go test -count=1 ./...)
```

This root pass belongs only in a disposable Debian 13 guest. It must not run
on an operator host or be replaced by a changed umask, skipped test, filtered
exit status, or external handler workaround.

Managed setup transaction tests use both a phase-injectable executor and the
real setup `Engine` plus `System`. They prove direct first setup and dry-run
followed by first setup discover the clean host before a journal exists, the
initial journal contains the prepared summary, and preparation or initial
journal publication failures execute no mutation or rollback. An expired
pre-mutation journal is terminalized without invoking system rollback, while
backup-complete guard through commit failures retain exact rollback and
post-commit failures retain forward recovery. The disposable R2 matrix repeats
the real process-death, timeout, idempotent-rerun, Docker, and reboot cases.

Amendment W adds the terminal retry matrix. Unit and protected disposable
tests require exact restored backup verification, strict current/history
journal parsing, atomic checksum-bound archive publication, fail-closed
collision/symlink/mode/change handling, retained endpoint and provenance
validation, stable provenance reuse, monotonic generation allocation, two
consecutive failed retries, and eventual success. The Docker process-death
fixture starts from coherent live/on-disk firewall ownership values and uses
only a prior `userland-proxy=true` value to require the setup restart. Exact
operator/runtime restoration and monotonic retained-state advancement are
asserted separately. The protected W6 source-stage run passed both failed
generations, eventual generation-3 success, host/container VPN egress,
idempotence, tunnel-loss/Docker-restart zero-leak recovery, and two managed
boots, then returned both overlays clean with zero QEMU process or listener.
W7 passed the real native initramfs lifecycle. W11 then hard-stopped because
the first normal capture contained two IPv6 MLD/DAD frames before readiness;
Amendment X replaces that boundary with a strict Debian GRUB transaction.
Direct tests cover BIOS/EFI identity, competing managers, mount/mode/link/race
refusals, generated-entry parsing, duplicate/quoted/conflicting arguments,
bounded update failure, exact pre-reboot rollback, same-boot reentry, explicit
reboot/resume, post-reboot rollback disposition, package handoff, and output
redaction. The disposable X matrix passed failed update, both
process-death sides, rollback finalization, package removal, two consecutive
managed boots with zero packets before readiness, expected traffic after
readiness, and a contradictory boot identity with zero guest packets. The
complete X source gate rerun passed and froze as
`e48d071783cd9a62ad3424c917957e4f0e6ea06a`. Its E-R2 build stage then stopped
before package construction when two independent guests reproduced the three
fixture defects corrected by Amendment Y. The Amendment Y focused and full
root restrictive-umask regression now passes; replacement candidate
construction follows only from the new clean frozen commit.

Amendment Z adds the inverse-boot terminal-lineage regression. The CLI test
proves that finalization preserves a nonzero generation only for an
uncommitted first setup, leaves a genuine pre-generation rollback at zero,
and prevents finalizer or journal-write failure from publishing a false
terminal state. Package-only boot handoff remains non-retryable. The strict
classifier test rejects a cleared/mismatched current generation, accepts the
preserved exact generation without mutation, and binds the terminal checksum.
The fresh disposable source transaction repeated and passed two validate-phase
deaths, reboot/resume/inverse-reboot rollback, nonmutating retry, generation-3
success, stable provenance, Docker VPN-only traffic, tunnel-loss zero leak,
and repeated managed boots before the replacement source freeze.

Amendment AA adds three deliberately separate performance scopes:

- `BenchmarkDashboardProtected` measures only the final fail-closed boolean
  projection and is not dashboard latency evidence;
- `BenchmarkDashboardStatusTransportEndToEnd` uses real HTTP framing and the
  real Unix protocol against a controlled full-status fixture; and
- `scripts/benchmark-status-e2e.py` measures the installed CLI and persistent
  loopback HTTP paths in a complete managed-Docker disposable guest.

The installed harness refuses non-VM execution, requires completed managed
setup, validates the full typed/protected contract on every CLI, Unix-socket,
and HTTP sample, emits no command payloads or secrets, and records component
timing only in aggregate. Its bounded component profile times the daemon Unix
status path, config validation, one whole-ruleset nftables read, Docker list
plus batched inspect, WireGuard reads, and read-only SQLite `quick_check` for
both generation and provenance databases. Derived median deltas isolate the
CLI and HTTP framing overhead from the daemon Unix path.
It must be run only inside the approved disposable guest:

```bash
sudo ./scripts/benchmark-status-e2e.py --disposable-vm \
  --samples 100 --warmups 10 --component-samples 20 --idle-seconds 60 \
  --baseline-cli-p95-ms 67.224 \
  --baseline-dashboard-p95-ms 65.231
```

The source-only diagnostic run reports CLI median/p95/max
33.997/36.367/38.995 ms and dashboard 30.617/32.658/35.712 ms. It also checks
the unchanged RSS, cgroup-memory, and idle-CPU budgets. That diagnostic guest
had no independent provider assignment, so it is timing evidence rather than
protected-status acceptance. The shipped harness additionally requires every
CLI, daemon Unix-socket, and dashboard sample to satisfy the complete healthy
protected contract. Unit and transport
regressions change nftables, forwarding, WireGuard, database/provenance, and
Docker observations between adjacent requests and require the next completed
response to degrade. Concurrent HTTP saturation, cancellation, recovery, and
the race suite ensure the optimization does not reuse mutable status or leak
goroutines/file descriptors. Complete E-R2 must repeat the installed proof.

Amendment AB directly binds the EFI parser regression to the stopped reboot
case. `TestManagedGRUBEFIIdentityMatrix` proves one exact amd64 and arm64
Debian identity passes while missing, duplicate, malformed, inactive, network,
`BootNext`, wrong-order, wrong-loader, non-Debian, and unsupported-architecture
evidence refuses. The source contract also requires exactly one literal switch
arm for each singleton label, making a repeated `BootCurrent` arm a compile-time
error. Exact frozen-source and preserved-guest inspection are separate inputs:
the former had one active arm, while the latter showed OVMF-regenerated
PXE/HTTP entries after reboot.

The direct source-stage guest therefore performs a real first pass and reboot
with the virtual NIC option ROM disabled before the second boot. It does not
edit the journal, synthesize `resume_ready`, or bypass EFI verification. The
post-boot action must observe `resume_ready`, the exact resume guard, inactive
Docker service, active socket queue, and activating Docker hold before the same
profile completes protected setup. This is focused source-stage evidence, not
the complete E-R2 matrix.

Amendment AC adds a destructive-guest-only systemd runtime-directory fixture.
It requires a clean disposable guest, exact installed unit hashes, inactive
NFTFW services/timers, no committed enforcement, and the standard root-owned
mode-`0600` guest marker:

```bash
sudo ./tests/packaging/runtime_directory_disposable.sh \
  READY_UNIT_SHA256 MANAGED_ROLLBACK_UNIT_SHA256 SETUP_ROLLBACK_UNIT_SHA256
```

The fixture accepts only an absent runtime path or the verified exact empty
package-created directory and removes the latter before testing. It then proves
a condition-skipped early unit and an injected early failure both
keep readiness fail closed without `226/NAMESPACE`. It performs 50 fresh
absent-directory starts for each of readiness, managed rollback, and setup
rollback, followed by concurrent-owner stop/lifetime checks. It restores the
empty package directory before exit and must never run on an operator host.

The external boot controller invokes
`tests/packaging/runtime_directory_boot_disposable.sh` after each of twenty
independent ROM-less boots. Each invocation binds the installed readiness-unit
hash, records one unique kernel boot ID, requires early and readiness success,
proves readiness became active before SSH, reruns the application verifier,
requires every transient guard to be absent, and rejects a namespace-failure
journal or NFTFW ordering-cycle diagnostic. Packet capture and
marker-before-packet assertions remain controller responsibilities. The
Amendment AC source run completed all twenty consecutive boots with unique
boot IDs and zero captured frames before every initramfs marker; renewed E-R2
must repeat the sequence from its own candidate-bound guest.
No harness may pre-create `/run/nftfw`.

The setup-guard unit regression covers one and multiple endpoint `/32`
elements, exact interval flags, deterministic order, malformed/broader-prefix
refusal, and absence of global flush or unrelated-table mutation. Its real
nftables companion refuses to run unless it is root, the opt-in value is exact,
and `/run/nftfw-disposable-test-guest` is a root-owned regular mode-`0600`
marker. Only inside a disposable Debian guest, run:

```bash
install -o root -g root -m 0600 /dev/null /run/nftfw-disposable-test-guest
NFTFW_PRIVILEGED_NFT_TEST=disposable-approved \
  go test ./internal/setup -run '^TestGuardPassesRealNftablesParserInDisposableGuest$' -count=1
rm -f /run/nftfw-disposable-test-guest
```

The regression checks the exact rendered file, applies only its owned table,
lists it, deletes that exact table, and verifies cleanup. It must never be run
on an operator host or counted as the complete E-R2 matrix.

The Stage R runner checks package nonactivation, the early/ready/rollback
dependency graph, packaged CLI contracts, release-candidate metadata, and
immutable v2.0.1 expected-red defects without installing or starting anything.

Unit tests cover strict config, compiler invariants, owned transaction
validation, JSON fingerprints, API size/schema/peer rules, state migrations,
backup/corruption, provenance union, endpoint rollover/failure, Docker
daemon merge/ownership, eligible empty topology adoption, running/retained
workload refusal, changing workload observation, post-plan revalidation,
forwarding, bridge recreation, uninstall handoff, numeric all-table routing
preflight for absent/populated/malformed/failed observations, adoption-planner
command grammar, exact schema-6 read-only inspection, deterministic/redacted
worksheet generation, no-mutation tree comparison, feed parsing, explanation,
safe apply, and rollback. Docker projection regressions additionally prove
that an exact v2.0.3 static advanced configuration retains its bridge,
interface-name provenance, ledger ID, and bytes; managed dynamic entries alone
may rebind with exact `docker:<network>` provenance; mixed configurations keep
both identity models isolated; and every tuple/observation mismatch is
non-mutating.

Fourteen fuzz targets cover config decoding, API decoding, policy explanation, runtime
prefix compilation, nft transaction validation/fingerprinting, claim
validation, strict Docker daemon JSON, managed route-table JSON, adoption error
redaction, managed GRUB token parsing, full-ruleset status projection, and feed
parsing. The adoption target proves untrusted provider/path/error strings
reduce to one bounded operator code without echoing input. Example bounded run:

```bash
go test ./internal/config -run '^$' -fuzz FuzzDecode -fuzztime 5s
```

## Namespace lab

**Privileged and destructive to the test topology. NOT EXECUTED for 2.1.0.**

```bash
sudo ./tests/namespaces/run.sh
```

The script creates isolated host, Internet, VPN server, LAN, and container
topology with veth links and a real in-kernel WireGuard tunnel. It applies the
actual compiler/backend output and tests:

- repeated atomic apply and boot snapshot restoration;
- no trusted-lease replay and kernel timeout expiry;
- corrupt authoritative generation snapshot rejection with zero nft mutation
  and readiness blocked;
- rule modification/deletion, table deletion, and unrelated-table survival;
- typed IPv4 DNAT;
- healthy host/container IPv4 and IPv6 traffic through WireGuard;
- tunnel removal with physical-link packet capture;
- already-established TCP and UDP traffic after tunnel removal;
- host/container IPv6 tunnel loss and active-flow capture.

The Amendment F extension additionally requires disposable-VM proof for
Docker daemon ownership transfer, built-in and multiple Compose bridges,
equal host/container VPN exit identity, Docker/network recreation, forwarding
sysctl loss, Docker restart with the VPN down, and exact rollback at every
Docker handoff phase.

The Amendment I extension additionally requires a clean Debian 13 guest to
prove that the initially absent table 51820 reaches the dry-run plan through
numeric all-table JSON, while populated/malformed/oversized/failed queries
still refuse. Docker cases must prove empty built-in and eligible empty custom
bridges are accepted, running and retained containers are refused without
identity leakage, and a changing observation stops before ownership mutation.

The Amendment J extension reruns the bundled lifecycle with an exact
v2.0.3-style static advanced Docker fixture. Its first plan must leave the
configuration hash unchanged, while managed dynamic recreation, mixed
static/dynamic networks, tuple mismatch, provenance mismatch, and ledger
preservation retain their separate fail-closed contracts.

Success includes exactly:

```text
LEAKED INTERNET PACKETS: 0
LEAKED IPV6 INTERNET PACKETS: 0
```

Missing prerequisites exit 77 and print `BLOCKED`; they do not produce PASS.

## Real WireGuard acceptance

**Privileged and provider-connected. NOT EXECUTED for 2.1.0.**

Place a root-owned mode `0600` profile at the path below. The harness parses
only the fields it needs and never prints or archives the private key.

```text
../test-data/wg-test.conf
```

```bash
sudo ./tests/acceptance/real_wireguard.sh
```

The profile is used inside an isolated namespace while the real provider is
reached through a physical veth/uplink. Tests cover handshake, changed public
IPv4, DNS, IPv6, namespace container, actual Docker container, endpoint set
refresh, daemon restart, tunnel loss, physical packet capture, tunnel
recovery, and Docker recovery. Synthetic traffic only is captured.

## Other privileged suites

**Privileged. NOT EXECUTED for 2.1.0.**

```bash
sudo ./tests/acceptance/database.sh
sudo ./tests/acceptance/docker_lifecycle.sh
sudo ./tests/acceptance/host_safe_apply.sh
sudo ./tests/chaos/services.sh
```

The host safe-apply script first proves a transient independent emergency
rollback, installs a short-lived test policy that preserves the observed SSH
flow, captures physical IPv4/IPv6 egress, commits/rolls back, kills the test
daemon, and waits for independent timeout rollback. Cleanup is scoped to
owned test objects and verifies the unrelated proof table survives.

Renewed E-R2 must repeat the source-stage boot preflight in fresh Debian 13
QEMU guests with capture active before execution. It covers failed
`update-grub`, pre-reboot process
death, explicit reboot/resume, post-reboot process death,
`rollback_reboot_required`, uninstall/downgrade handoff, and two consecutive
managed boots. Every failure or contradictory boot identity must remain at
zero physical packets. Normal boot must remain at zero before readiness and
emit expected traffic only afterward; kernel-wide disabled mode has no IPv6
loopback address. The upgrade guest prepares the release rollback bundle
before 2.1.0, then exercises both interruption-resume states and ends with the
unmodified exact 2.0.3 package configured and all approved state/unit/network
snapshots preserved.

The resumed-boot matrix also proves the atomic initramfs-to-resume guard swap,
process death immediately after that swap, strict one-table identity, private
endpoint-cache reuse with DNS unavailable, LAN-only management recovery, and
Docker service/socket inactivity. It confirms that Docker restart consent
precedes hold release, rollback restores the exact daemon/drop-in before
release, runtime markers are cleaned, and a second boot contains no generator
hold after setup completion.

## Endpoint and DNS failure coverage

The resolver test simulates endpoint A changing to B, retains bounded recent
addresses, then injects DNS failure. Other tests reject stale, symlinked,
oversized, future-dated, private, loopback, multicast, and unspecified data.
Controller tests verify a changed single-peer endpoint and reject ambiguous
multi-peer mutation. Real acceptance verifies a live endpoint set refresh.

This composition tests the resolver/controller transaction without changing
the operator's real provider DNS record.

## Evidence

Sanitized raw results remain outside Git and release archives because provider
and topology diagnostics are not public release material. The consolidated,
non-secret result is recorded in `TEST_RESULTS.md`; no absent raw log should be
treated as evidence for a new run.
