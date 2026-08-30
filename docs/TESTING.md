# Testing

Current disposition: **2.1.0 STAGE E-R SOURCE VALIDATED**. Source-only results
are consolidated in `TEST_RESULTS.md`. Except for the narrowly scoped
setup-guard parser regression described below, the privileged commands below
have not been executed for this corrected source and require a separately
approved disposable lab with independent recovery.

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

The first creates private mount/network namespaces, applies the exact
initramfs guard, and proves a later-created interface inherits IPv6 disabled
while loopback remains enabled. The second builds disposable minimal Debian
packages, proves the rollback bridge payload is identical to exact 2.0.3, and
rejects manifest/package tampering without invoking dpkg installation.

The systemd preflight uses temporary unit copies and staged executables, so it
can validate a fresh-host source installation before final paths exist and
without installing or starting anything.

The isolated `umask 0077` regression creates a mode-`0600` secret under the
restrictive mask. Root execution requires acceptance; unprivileged execution
requires the separate root-ownership refusal. Both paths then explicitly set
and verify mode `0644` before asserting refusal. The full unprivileged suite is
also rerun under `umask 0077`; no security refusal fixture may depend on the
invoking shell's ambient mask.

Managed setup transaction tests use both a phase-injectable executor and the
real setup `Engine` plus `System`. They prove direct first setup and dry-run
followed by first setup discover the clean host before a journal exists, the
initial journal contains the prepared summary, and preparation or initial
journal publication failures execute no mutation or rollback. An expired
pre-mutation journal is terminalized without invoking system rollback, while
backup-complete guard through commit failures retain exact rollback and
post-commit failures retain forward recovery. The disposable R2 matrix repeats
the real process-death, timeout, idempotent-rerun, Docker, and reboot cases.

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

Twelve fuzz targets cover config decoding, API decoding, policy explanation, runtime
prefix compilation, nft transaction validation/fingerprinting, claim
validation, strict Docker daemon JSON, managed route-table JSON, adoption error
redaction, and feed parsing. The adoption target proves untrusted provider/path/error strings
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

Renewed E-R2 additionally boots two fresh QEMU guests with capture active
before execution. It requires zero guest-originated IPv4 and IPv6 frames when
the initramfs readiness marker is first observed, classifies any frame rather
than moving the marker, completes two consecutive boots, and proves final
`::1`. The upgrade guest prepares the release rollback bundle before 2.1.0,
then exercises both interruption-resume states and ends with the unmodified
exact 2.0.3 package configured and all state/unit/network snapshots preserved.

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
