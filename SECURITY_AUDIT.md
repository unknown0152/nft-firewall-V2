# NFT Firewall V2 Security Audit

Audit date: 2026-08-16 and 2026-08-17 UTC. Scope: production Go, configuration/compiler,
nftables ownership, Unix APIs, persistence/rollback, systemd, integrations,
web, installers, tests, dependencies, Git history, and release contents.

Status at release: no unresolved `CRITICAL` or `HIGH` finding.

## Findings repaired

| ID | Finding | Severity | Impact | Fix | Verification | Status |
| --- | --- | --- | --- | --- | --- | --- |
| NFV2-001 | Rule-marker-only drift could miss a changed verdict | HIGH | A modified owned allow/drop rule might appear healthy | Canonicalized bounded `nft -j` owned structure and persisted fingerprint | Modified rule with marker retained is detected/repaired in unit and namespace suites | CLOSED |
| NFV2-002 | Restoring a generation did not guarantee runtime sets were restored | HIGH | Blocks/endpoints/container isolation could be absent after rollback/drift | Central runtime restore callback; emergency deny on any restore failure | Rollback/reconcile tests plus namespace drift and boot restore | CLOSED |
| NFV2-003 | Corrupt SQLite could prevent independent expired rollback | HIGH | Pending unsafe candidate might outlive its deadline | Checksum-protected active snapshot fallback; first-generation destroy; emergency deny | Database corruption, rollback fallback, corrupt boot snapshot tests | CLOSED |
| NFV2-004 | Persisted allow provenance/expiry validation was incomplete | HIGH | Forged or permanent trusted access could enter effective state | Reserved source checks, mandatory expiry, typed removal, kernel timeout | State/blocks/app unit tests and namespace expiry/replay tests | CLOSED |
| NFV2-005 | Signed previous-generation references could convert to large unsigned IDs | HIGH | Corrupt state could address an unintended generation | Reject negative references before conversion | State corruption regression test and gosec rerun | CLOSED |
| NFV2-006 | API string fields had request-body limits but insufficient field-specific limits | MEDIUM | Root/local malformed clients could amplify memory/audit content | Operation-specific schema and bounded address/source/reason fields | API unit/fuzz and malformed/oversized socket chaos | CLOSED |
| NFV2-007 | Some sensitive reads relied on pre-open path checks | MEDIUM | Symlink swap/oversized-file risk at config/cache boundaries | `O_NOFOLLOW`, post-open regular/mode/owner/size checks, bounded reads | Config, endpoint, state, GeoIP, Docker path tests | CLOSED |
| NFV2-008 | Endpoint cache accepted unusable or future-dated data | HIGH | Bootstrap exception could contain invalid/stale attacker-selected state | Unicast validation, future-time rejection, age and count bounds | Resolver rollover/failure/cache regression tests | CLOSED |
| NFV2-009 | Docker binary could inherit an alternate daemon target | HIGH | Privileged observer might query a remote/attacker-selected Docker API | Explicit `--host unix:///var/run/docker.sock` and validated network names | Fake CLI assertion and real Docker lifecycle | CLOSED |
| NFV2-010 | Docker integration checked only iptables ownership | HIGH | Docker forwarding, masquerade, or proxy behavior could fall outside policy model | Require five explicit false daemon settings | Unit regression, daemon JSON gate, lifecycle and real Docker VPN tests | CLOSED |
| NFV2-011 | A vulnerable indirect `x/sys` version remained in the module graph | MEDIUM | Platform-specific dependency vulnerability, unreachable on tested Linux path | Upgrade to `golang.org/x/sys v0.47.0` | `go mod verify`, full tests, govulncheck no reachable findings | CLOSED |
| NFV2-012 | Debian staging root inherited mode `0700`; package output was published directly | HIGH | Package metadata could carry unsafe root mode and readers could see partial output | Force stage root `0755`, build to temporary, inspect fully, atomically rename | `dpkg-deb --contents/info` for amd64 and arm64 | CLOSED |
| NFV2-013 | Malformed privileged frames were rejected but not audited | MEDIUM | Repeated parse abuse could lack durable security evidence | Emit bounded content-free rejection events for frame, size, JSON, and missing-op failures | Root-peer API regression plus malformed/oversized socket chaos | CLOSED |
| NFV2-014 | Release staging copied ignored Python bytecode from the working tree | MEDIUM | Local cache artifacts could disclose build paths or enter an otherwise clean release | Populate duplicate release trees only from `git archive`; reject cache, runtime, secret, and symlink entries before manifesting | Dirty-cache regression build plus extracted final archive inspection | CLOSED |

## Adversarial review areas

| Area | Result |
| --- | --- |
| Shell/argument injection | Go invokes fixed binaries with argument arrays; interfaces/names/addresses validated; no Go shell string execution |
| nft ownership | Global flush rejected; only fixed family/table tuples may be deleted; unrelated-table tests pass |
| Hidden allows | Compiler review found only loopback, protocol bootstrap, endpoint bootstrap, reply-only, trusted lease, stateful input/forward, and declared policies |
| Conntrack bypass | Output has no broad state accept; physical forward drops precede state accept; active TCP/UDP leak tests pass |
| IPv6 bypass | Three explicit modes, early disabled hooks, dual-stack sets, host/namespace/real VPN capture pass |
| Unsafe temp/path use | Go uses secure temp APIs; protected state/config/cache paths reject symlinks and unsafe parents; package temp paths are fixed templates |
| Socket permissions | Control mode/root peer authorization; status is deliberately dashboard-group readable; unsafe existing socket objects rejected |
| Request/resource bounds | API, nft output, config, Docker output, feeds, Geo files, set counts, and audit fields bounded |
| Database injection/races | Parameterized SQL, foreign keys, WAL, busy timeout, transactions, constraints, race/concurrent-open tests |
| Rollback | Persistent deadline, exact guard validation, checksummed artifacts, independent timer, crash/timeout tests |
| Web XSS/CSRF/file access | No mutable endpoint, no templated user HTML, DOM uses `textContent`, fixed routes/assets, strict CSP/headers |
| HTTP resource limits | Loopback default, read/header/write/idle timeouts, 16 KiB headers, status-only upstream response limit |
| Secret logging | Status omits keys/peer IDs; controller observation is aggregate; test config excluded; release/history scan required |
| Capabilities/systemd | Root daemon bounded to `CAP_NET_ADMIN`; web has no capabilities; strict filesystem/kernel/namespace protections verified |

## Accepted residual risks

1. Root, kernel, nft executable, systemd, Docker daemon, and installed binary
   compromise are outside the enforcement boundary.
2. A malicious but publicly valid DNS answer can redirect bootstrap UDP to a
   different public address on the declared port; WireGuard cryptographic peer
   authentication still protects tunnel establishment.
3. The fixed resolver cadence does not honor authoritative TTL because the Go
   standard resolver does not expose it.
4. Another privileged nftables manager can install a higher-priority chain or
   repeatedly fight reconciliation. V2 detects/repairs its own objects only.
5. The local dashboard has no application authentication. Its loopback bind,
   service sandbox, and status-only socket are required controls.
6. Full-machine reboot was not executed on the SSH-only VPS; the real early
   service and every boot state branch were tested without reboot.

These are documented operating assumptions or low/medium residual risks, not
unresolved high/critical implementation findings.

## Final scan evidence

- staticcheck v0.7.0: PASS, zero findings.
- govulncheck v1.7.0 with Go 1.25.13: PASS, no vulnerabilities found.
- gosec v2.28.0 focused scan: PASS, zero untriaged findings.
- Go race detector: PASS across all packages.
- ShellCheck 0.10.0: PASS across production packaging and privileged tests.
- Gitleaks 8.16.0 complete V2 Git history: PASS, no leaks found.
- Gitleaks current worktree and extracted release: PASS, no leaks found.
- Sensitive filename/content pattern checks: PASS.
- Archive contains no `.git`, build cache, real WireGuard fixture, database,
  WAL, log, symlink, or credential file: PASS.
