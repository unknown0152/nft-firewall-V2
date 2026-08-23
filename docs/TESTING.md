# Testing

Test outcomes use only `PASS`, `FAIL`, `BLOCKED`, `NOT APPLICABLE`, or
`NOT EXECUTED`. A namespace simulation and an external provider tunnel are
reported separately.

## Unprivileged gates

```bash
make fmt-check
go mod verify
go mod tidy -diff
go test ./...
go test -race ./...
go vet ./...
staticcheck ./...
govulncheck ./...
gosec -quiet -exclude-generated -exclude=G104,G204,G304,G302 ./...
```

Unit tests cover strict config, compiler invariants, owned transaction
validation, JSON fingerprints, API size/schema/peer rules, state migrations,
backup/corruption, provenance union, endpoint rollover/failure, Docker
observation, feed parsing, explanation, safe apply, and rollback.

Fuzz targets cover config decoding, API decoding, policy explanation, runtime
prefix compilation, nft transaction validation/fingerprinting, claim
validation, and feed parsing. Example bounded run:

```bash
go test ./internal/config -run '^$' -fuzz FuzzDecode -fuzztime 5s
```

## Namespace lab

```bash
sudo ./tests/namespaces/run.sh
```

The script creates isolated host, Internet, VPN server, LAN, and container
topology with veth links and a real in-kernel WireGuard tunnel. It applies the
actual compiler/backend output and tests:

- repeated atomic apply and boot snapshot restoration;
- no trusted-lease replay and kernel timeout expiry;
- corrupt snapshot emergency deny;
- rule modification/deletion, table deletion, and unrelated-table survival;
- typed IPv4 DNAT;
- healthy host/container IPv4 and IPv6 traffic through WireGuard;
- tunnel removal with physical-link packet capture;
- already-established TCP and UDP traffic after tunnel removal;
- host/container IPv6 tunnel loss and active-flow capture.

Success includes exactly:

```text
LEAKED INTERNET PACKETS: 0
LEAKED IPV6 INTERNET PACKETS: 0
```

Missing prerequisites exit 77 and print `BLOCKED`; they do not produce PASS.

## Real WireGuard acceptance

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

## Endpoint and DNS failure coverage

The resolver test simulates endpoint A changing to B, retains bounded recent
addresses, then injects DNS failure. Other tests reject stale, symlinked,
oversized, future-dated, private, loopback, multicast, and unspecified data.
Controller tests verify a changed single-peer endpoint and reject ambiguous
multi-peer mutation. Real acceptance verifies a live endpoint set refresh.

This composition tests the resolver/controller transaction without changing
the operator's real provider DNS record.

## Evidence

Sanitized raw results live outside Git under
`/root/nft-firewall-work/test-results/`. They are intentionally excluded from
release archives because provider endpoint and host topology diagnostics are
not public release material. The consolidated, non-secret result is
`TEST_RESULTS.md`.
