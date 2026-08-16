# NFT Firewall V2 Test Results

Executed on 2026-08-16 UTC. Sanitized raw evidence is retained outside Git at
`/root/nft-firewall-work/test-results/`. Provider key material and private
topology details are excluded.

## Release gates

| Gate | Status | Executed evidence |
| --- | --- | --- |
| amd64/arm64 static build | PASS | Six CGO-free binaries built; embedded metadata and SHA256 checked |
| Unit tests | PASS | `go test ./...` across command and internal packages |
| Race tests | PASS | `go test -race ./...` |
| Vet | PASS | `go vet ./...` |
| Formatting/module integrity | PASS | gofmt, `go mod verify`, and `go mod tidy -diff` |
| Staticcheck | PASS | staticcheck v0.7.0, zero findings after fixes |
| Vulnerability scan | PASS | govulncheck v1.7.0 with Go 1.25.13; no reachable vulnerabilities |
| Go security scan | PASS | gosec v2.28.0 focused scan, zero untriaged findings |
| Shell analysis | PASS | ShellCheck 0.10.0 over install/package/acceptance scripts |
| Fuzz/property | PASS | Eight parser/policy/nft/state targets, five seconds each |
| Namespace firewall | PASS | Actual nftables/WireGuard traffic suite |
| Simulated VPN kill switch | PASS | Healthy and removed tunnel, host and container |
| Active connection failure | PASS | TCP/UDP, IPv4/IPv6, host/container |
| Provenance | PASS | Manual plus feed/GeoIP source union and typed removal |
| Safe apply/rollback | PASS | Unit plus real host independent timer, crash and timeout |
| Drift | PASS | Deleted/modified rule and deleted table repaired; unrelated table retained |
| IPv6 | PASS | Native host capability, namespace disabled/VPN leak capture, real VPN IPv6 |
| Docker | PASS | Lifecycle observation and actual Docker container through real VPN/loss/recovery |
| Real WireGuard | PASS | Operator profile used in isolated real-provider acceptance |
| Database | PASS | Create, migrations, constraints, concurrent WAL, backup/restore, corruption |
| Service crash | PASS | SIGTERM, SIGKILL, repeated restart, sockets, malformed/oversized API |
| systemd verify/hardening | PASS | Unit verification and exposure analysis |
| Full VPS reboot | NOT EXECUTED | Preserved live SSH; real early-boot unit ordering/snapshot paths tested without reboot |
| Optional live threat/GeoIP source | NOT APPLICABLE | Integrations disabled; parsers/refresh failure/atomic state tested locally |

## Namespace result

The isolated lab executed repeated atomic apply, early active snapshot restore,
trust replay prevention, corrupt snapshot fail-closed, kernel lease expiry,
three drift classes, unrelated-table survival, typed DNAT, healthy VPN traffic,
tunnel removal, and active-flow traffic.

```text
VPN HEALTHY HOST: PASS
VPN HEALTHY CONTAINER: PASS
VPN HEALTHY IPV6 HOST: PASS
VPN HEALTHY IPV6 CONTAINER: PASS
WIREGUARD REMOVED HOST: PASS
WIREGUARD REMOVED CONTAINER: PASS
ACTIVE TCP HOST/CONTAINER: PASS
ACTIVE UDP HOST/CONTAINER: PASS
ACTIVE IPV6 TCP/UDP HOST/CONTAINER: PASS
LEAKED INTERNET PACKETS: 0
LEAKED IPV6 INTERNET PACKETS: 0
```

## Real provider result

The supplied root-owned mode `0600` profile was used without logging its
private key. The provider tunnel ran inside an isolated namespace over the
real host uplink. An actual Docker container joined the protected topology.

```text
REAL WIREGUARD HANDSHAKE: PASS
REAL VPN PUBLIC IPV4 CHANGE: PASS
REAL VPN DNS: PASS
REAL VPN CONTAINER EGRESS: PASS
REAL DOCKER CONTAINER VPN EGRESS: PASS
REAL VPN IPV6 EGRESS: PASS
REAL ENDPOINT SET REFRESH: PASS
REAL DAEMON RESTART: PASS
REAL VPN LOSS HOST: PASS
REAL VPN LOSS CONTAINER: PASS
REAL DOCKER CONTAINER VPN LOSS: PASS
REAL LEAKED PHYSICAL PACKETS: 0
REAL WIREGUARD RESTART/RECOVERY: PASS
REAL DOCKER CONTAINER RECOVERY: PASS
REAL WIREGUARD ACCEPTANCE: PASS
```

The packet capture excluded provider endpoint bootstrap traffic and looked for
synthetic non-endpoint Internet traffic on the physical test link.

## Host safe-apply result

Before touching host-owned test tables, the suite armed and proved a separate
transient systemd emergency rollback. The candidate retained the observed SSH
management connection and used an absent test VPN to prove physical denial.

```text
INDEPENDENT EMERGENCY ROLLBACK PROOF: PASS
UNRELATED TABLE PRESERVATION PROOF: PASS
HOST EMERGENCY ROLLBACK ARMED: PASS
HOST CANDIDATE NFT CHECK: PASS
DECLARED SSH MANAGEMENT PATH RETAINED: PASS
HOST IPV4 LEAKED INTERNET PACKETS: 0
HOST IPV6 LEAKED INTERNET PACKETS: 0
HOST SAFE APPLY COMMIT: PASS
HOST EXPLICIT ROLLBACK: PASS
HOST DAEMON SIGKILL AFTER APPLY: PASS
HOST TIMEOUT ROLLBACK AFTER DAEMON CRASH: PASS
HOST SAFE-APPLY ACCEPTANCE: PASS
```

Cleanup left the host NFT Firewall ruleset empty and preserved SSH.

## Fuzz targets

| Target | Status |
| --- | --- |
| Config `FuzzDecode` | PASS |
| API `FuzzDecodeRequest` | PASS |
| Policy `FuzzExplainAlwaysReturnsAVerdict` | PASS |
| Compiler `FuzzCompileRuntimePrefix` | PASS |
| nft `FuzzValidateScript` | PASS |
| nft `FuzzCanonicalOwnedJSON` | PASS |
| State `FuzzValidateClaim` | PASS |
| Threat feed `FuzzParse` | PASS |

## Scope notes

Endpoint A-to-B rollover, bounded recent retention, DNS failure, stale cache,
unusable answers, and single-peer endpoint update are deterministic injected
tests. Live acceptance separately confirms real DNS, endpoint set refresh,
handshake, restart, and recovery. The operator's provider DNS record was not
modified.

A full host reboot was deliberately not executed on the only SSH management
host. Boot persistence is supported and was exercised through the real
`nftfw-early.service`, systemd dependency verification, committed snapshot
restore, missing/corrupt snapshot emergency deny, and pending restart paths.
