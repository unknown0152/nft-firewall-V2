# NFT Firewall V2 Security Audit

Audit date: 2026-08-16, 2026-08-17, and 2026-08-23 UTC. Scope: production Go, configuration/compiler,
nftables ownership, Unix APIs, persistence/rollback, systemd, integrations,
web, installers, tests, dependencies, Git history, and release contents.

Current source disposition: the tagged `2.0.1` release passes its unprivileged
source, artifact, archive-scan, and reproducibility gates. Privileged/live
acceptance remains separately gated in `TEST_RESULTS.md`; this document must
not be read as approval to install or mutate a live host.

## Findings repaired

| ID | Finding | Severity | Impact | Fix | Verification | Status |
| --- | --- | --- | --- | --- | --- | --- |
| NFV2-001 | Rule-marker-only drift could miss a changed verdict | HIGH | A modified owned allow/drop rule might appear healthy | Canonicalized bounded `nft -j` owned structure and persisted fingerprint | Modified rule with marker retained is detected/repaired in unit and namespace suites | CLOSED |
| NFV2-002 | Restoring a generation did not guarantee runtime sets were restored | HIGH | Blocks/endpoints/container isolation could be absent after rollback/drift | Central runtime restore callback; emergency deny on any restore failure | Rollback/reconcile tests plus namespace drift and boot restore | CLOSED |
| NFV2-003 | Corrupt SQLite could prevent independent expired rollback | HIGH | Pending unsafe candidate might outlive its deadline | Checksum-protected committed fallback, ownership-conservative first-generation handling, and emergency deny | Database corruption, rollback fallback, corrupt boot snapshot tests | CLOSED |
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
| NFV2-015 | One interface could be assigned to contradictory zones through separate declaration styles | HIGH | An uplink could inherit a LAN selector and bypass intended zone isolation | Build one canonical interface-to-zone map and reject cross-zone assignments | Config and compiler uplink/LAN regression tests | CLOSED |
| NFV2-016 | Threat feeds accepted overly broad or protected prefixes and could terminate recovery traffic | HIGH | A compromised feed could approximate default deny, block management, or break VPN bootstrap | Public-only `/24`/`/48` minimums, global aggregate caps, protected topology/resolved endpoints, and recovery-rule ordering | Parser, multi-feed, resolved-endpoint, compiler-order, and persisted-claim tests | CLOSED |
| NFV2-017 | Integration claims were committed before live-set publication without complete compensation | HIGH | Kernel failure could leave database intent different from the known-good live sets | Snapshot prior sources, restore every changed source, and republish prior sets on failure | Synthetic kernel-failure rollback test | CLOSED |
| NFV2-018 | Obfuscated/unsupported nft commands could escape the owned-object validator | HIGH | A malformed internal transaction could address an unrelated table or bypass global-flush detection | Quote/escape-aware comment removal, quoted-content masking, continuation rejection, token-normalized global-flush detection, and deny-by-default command/object validation | Whitespace/case/semicolon, quote/comment, continuation, rename, plural-reset, and foreign-table regressions | CLOSED |
| NFV2-019 | Post-apply state failures discarded restore/rollback-record errors | HIGH | An active candidate could be forgotten after an unconfirmed rollback | Join all errors and mark rolled back only after kernel restoration succeeds | Injected mark/fingerprint/restore/state failure matrix | CLOSED |
| NFV2-020 | An inner `SO_PEERCRED` failure could be mistaken for UID 0 | HIGH | A local control connection could be misclassified as root in an error path | Require successful raw control, successful credential lookup, and non-nil credentials | Injected inner/outer credential failure tests | CLOSED |
| NFV2-021 | Status clients shared the control quota and status saturation generated durable audit rows | MEDIUM | Read-only load could starve root control and amplify database growth | Separate 64-status/16-control quotas; audit privileged saturation only | Independent-quota saturation tests | CLOSED |
| NFV2-022 | Audit records had no retention bound | MEDIUM | Repeated events could grow SQLite without limit | Schema migration 4 prunes and caps audit at 10,000 rows | Oversized pre-migration and post-insert retention tests | CLOSED |
| NFV2-023 | First apply silently destroyed pre-existing product-named tables | HIGH | An unrelated administrator table could be adopted and erased | Re-arm a race-resistant first-use guard while no committed/pending generation exists; preserve ambiguous first-pending tables instead of deleting them | Existing/raced/re-armed collision, failed apply, crash-window, fallback, and composition-root tests | CLOSED |
| NFV2-024 | Status consumers could coerce missing/string fields into a false Protected state | HIGH | A degraded or incompatible daemon could appear healthy in dashboards | Versioned typed status schema; strict booleans; validated lowercase SHA-256 aliases; independently derived web-proxy decision | Healthy/degraded/missing/wrong-type/falsey-hash/mismatched-hash/wrong-schema contract tests across CLI, built-in UI, and Control Center | CLOSED |
| NFV2-025 | Enabling Docker observation silently restored a root-equivalent socket into the daemon sandbox | MEDIUM | Daemon compromise could pivot through Docker despite capability bounding | Packaged unit hides the socket; access requires a separate explicit administrator drop-in | Unit verification, package inspection, and disabled-default documentation | CLOSED |
| NFV2-026 | An `nft --file` error and an unmarked fallback were treated as if kernel mutation outcome/ownership were known | HIGH | A possibly active candidate could be forgotten, or an unrelated product-named table could be deleted | Type execution-attempt errors, require confirmed restoration, retain ambiguous pending state, and refuse no-marker fallback mutation | Prior-generation restore success/failure, first-generation ambiguous/empty, post-save collision, and corrupt/absent fallback regressions | CLOSED |
| NFV2-027 | Durable claim mutations and runtime-set publication could diverge or interleave across processes | HIGH | Status could report healthy while a DB block/allow change was absent from the kernel, or a stale writer could overwrite newer sets | Atomic desired/applied publication revisions, cross-process serialization, fail-closed health, and add/remove compensation | Direct failure, same-count swap, interleaving, health, compensation, full race, and adversarial-review regressions | CLOSED |
| NFV2-028 | Enclosing checksum generation included unrelated stale release-directory files | MEDIUM | `SHA256SUMS` could describe a mixed release set and make publication non-reproducible | Hash an explicit sorted artifact list for the requested version; normalize locale/timezone; isolate the captured commit; stage a complete versioned release before atomic publication | Shell analysis, unrelated-parent sentinel regression, exact checksum scope, and cross-parent two-build comparison | CLOSED |
| NFV2-029 | Fresh source installation verified units before final-path binaries existed | MEDIUM | Installation aborted on a clean host before making changes | Verify rewritten temporary unit copies against isolated staged executables before any host mutation | ShellCheck, direct clean-host reproduction, and wrapper-enforced staged-preflight regression | CLOSED |
| NFV2-030 | Go auto-discovered an unrelated enclosing Git repository for an isolated source export | MEDIUM | Otherwise identical builds in a workspace and `/tmp` embedded different ambient VCS metadata and produced different binaries | Pass `-buildvcs=false`, reject any ambient VCS build setting in every release binary, and rely on the explicit signed-off commit fields and provenance | Original cross-parent reproduction, metadata-absence assertions for all binaries, and corrected byte-identical cross-parent builds | CLOSED |

Verification labels in this table describe regression coverage. Any
namespace, real-provider, Docker, host, reboot, or other privileged evidence
is historical `v2.0.0` evidence unless `TEST_RESULTS.md` explicitly records a
current `2.0.1` rerun.

## Adversarial review areas

| Area | Result |
| --- | --- |
| Shell/argument injection | Go invokes fixed binaries with argument arrays; interfaces/names/addresses validated; no Go shell string execution |
| nft ownership | Global flush rejected; only fixed family/table tuples may be deleted; unrelated-table tests pass |
| Hidden allows | Compiler review found only loopback, protocol bootstrap, endpoint bootstrap, reply-only, trusted lease, stateful input/forward, and declared policies |
| Conntrack bypass | Output has no broad state accept and physical-forward drops precede state accept; current compiler/order regressions pass, while active `2.0.1` TCP/UDP leak tests remain gated |
| IPv6 bypass | Three explicit modes, early disabled hooks, and dual-stack sets pass current compiler/unit review; `2.0.1` namespace/real-VPN capture remains gated |
| Unsafe temp/path use | Go uses secure temp APIs; protected state/config/cache paths reject symlinks and unsafe parents; package temp paths are fixed templates |
| Socket permissions | Control mode/root peer authorization; status is deliberately dashboard-group readable; unsafe existing socket objects rejected |
| Request/resource bounds | API, nft output, config, Docker output, feeds, Geo files, set counts, and audit fields bounded |
| Database injection/races | Parameterized SQL, foreign keys, WAL, busy timeout, transactions, constraints, race/concurrent-open tests |
| Rollback | Persistent deadline, exact guard validation, checksummed artifacts, independent timer, and current unprivileged crash/ambiguity/timeout regressions; live-host execution remains gated |
| Web XSS/CSRF/file access | No mutable endpoint, no templated user HTML, DOM uses `textContent`, fixed routes/assets, strict CSP/headers |
| HTTP resource limits | Loopback default, read/header/write/idle timeouts, 16 KiB headers, status-only upstream response limit |
| Secret logging | Status omits keys/peer IDs; controller observation is aggregate; test config excluded; worktree/history scans pass and final extracted archives remain gated |
| Capabilities/systemd | Static units bind the root daemon to `CAP_NET_ADMIN`; web has no capabilities; isolated staged verification passes and installation/runtime verification remains gated |

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
6. No `2.0.1` full-machine reboot or live-host acceptance has been executed.
   Historical `v2.0.0` service/boot-branch evidence is not promoted to this
   candidate.
7. Release checksums and provenance are not cryptographically signed. A
   release operator must add a signature using an independently controlled
   identity; the build does not fabricate one.

These are documented operating assumptions or low/medium residual risks, not
unresolved high/critical implementation findings.

## Final scan evidence

The `2.0.1` staticcheck, govulncheck, gosec, full race, ShellCheck, fuzz,
Gitleaks history/worktree/extracted-release, package/archive inspection, and
two-build reproducibility gates pass against the tagged release. Historical
`2.0.0` privileged evidence is retained in that tag's reports and is not
promoted to this release.
