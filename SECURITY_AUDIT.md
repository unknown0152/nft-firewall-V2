# NFT Firewall V2 Security Audit

Audit date: 2026-08-16, 2026-08-17, 2026-08-23, 2026-08-24,
2026-08-25, 2026-08-26, 2026-08-29, 2026-08-30, 2026-08-31, and
2026-09-01, 2026-09-02, 2026-09-03, and 2026-09-04 UTC. Scope: production Go, configuration/compiler,
nftables ownership, Unix APIs, persistence/rollback, systemd, integrations,
web, installers, tests, dependencies, Git history, and release contents.

Current source disposition: **2.1.0 AMENDMENT AD SOURCE VALIDATED; CANDIDATES
PENDING**.
The Amendment W retry and native-lifecycle rows pass, but the mandatory W11
boot capture reopened NFV2-057 before source freeze. Amendment X now supplies
the approved pre-driver Debian GRUB transaction. Its direct regressions,
disposable boot/capture/package preflights, and complete source gates now pass.
Successive privileged R2 runs
hard-stopped safely on NFV2-049, NFV2-050/NFV2-051, NFV2-052, and then
NFV2-053/NFV2-054. The latest run completed every still-useful independent
row and found NFV2-055 through NFV2-058: exact-2.0.3 absent-unit planning,
first-setup final-edge ordering, pre-readiness IPv6 MLD/DAD, and exact package
rollback refusal. The next run passed those corrected boundaries and reached
the real rollback, then found NFV2-059 at dpkg's `iHR` bridge transition. The
source-only disposable regression exposed NFV2-060 in the following exact
package step. Later recovery runs corrected transaction ordering and durable
recovery, then exposed NFV2-061: an exact first-setup rollback retained its
required audit/provenance evidence but could not re-enter clean setup. The
Amendment W retry correction and direct regressions pass. W11 then captured
two IPv6 MLD/DAD frames before the first init-top readiness marker even though
the native manager was enabled and post-boot sysctls were disabled. Amendment
X's kernel-wide boundary then produced zero pre-readiness packets on two
consecutive managed boots and zero guest packets for a contradictory boot.
Exact rollback preflight also exposed and corrected NFV2-062 and NFV2-063
before freeze. Amendment X froze as
`e48d071783cd9a62ad3424c917957e4f0e6ea06a`; both independent E-R2 private
build guests then stopped before package construction on the same two
ambient-umask directory fixtures and one deliberately impossible control API
fixture, recorded as NFV2-064. Amendment Y explicitly establishes the unsafe
directory modes, serves authenticated control status, refuses non-status
control, and passes the focused plus complete suite as disposable guest root
under `umask 0077`. The next E-R2 recovery path exposed NFV2-065: inverse-boot
finalization cleared the exact uncommitted generation while its rolled-back
database row, immutable snapshot, backup, and provenance correctly remained.
Amendment Z preserves that identity only for an uncommitted first setup and
keeps pre-generation and package-only handoff paths non-retryable. Its direct,
restrictive-umask, complete source, and disposable two-failure/eventual-success
regressions pass. The following E-R2 completed seventeen disposable subjects
and then exposed NFV2-066: the status path spawned nine sequential nftables
reads and one Docker inspect per network, causing dashboard p95 to miss its
mandatory budget. Amendment AA derives all nftables status results from one
fresh immutable ruleset snapshot and batches Docker inspection by immutable
IDs. Freshness/fail-closed, adjacent-request, concurrency, cancellation,
saturation, allocation, and disposable installed-runtime timing regressions
pass the unchanged latency and resource budgets. The timing guest lacked an
independent provider assignment; the strict shipped harness requires healthy
protection on every sample for renewed E-R2. That E-R2 passed eleven subjects
before a managed reboot stopped at strict EFI identity verification. Exact
digest-bound source review disproved the initial duplicate-arm diagnosis: the
frozen object had one active `BootCurrent` arm. The preserved guest instead
showed OVMF had regenerated PXE and HTTP entries, which must remain forbidden.
Amendment AB makes singleton labels unique literal switch cases, adds explicit
missing/duplicate/malformed and retained refusal coverage, and passes a real
reboot/resume with the virtual NIC option ROM disabled while the network and
Docker holds remain effective. That replacement then passed fourteen E-R2
subjects before repeated normal boot exposed NFV2-068: readiness could reach
mount namespace construction before `/run/nftfw` existed. The service failed
with `226/NAMESPACE` and SSH remained blocked. Amendment AC gives readiness
and every independently timer-activated rollback path the same preserved
`root:nftfw-web`, mode-`0750` runtime-directory identity. The required
repeated-boot audit then exposed NFV2-069: consumer `Requisite=` ordering and
the early unit's implicit basic-target dependency could respectively skip the
boot transaction or form a socket/readiness ordering cycle. Early now has
explicit early-boot dependencies, early/readiness are independent
`sysinit.target` wants, and protected consumers require the nonmutating
verifier without giving it an activating edge to early restore. Source
contracts, condition-skip and early-failure cases, 150 absent-directory
starts, concurrent lifecycle proof, and twenty consecutive unique ROM-less
boots with zero pre-marker packets cover the correction. That replacement
then passed twenty normal boots, but its adverse ambiguous-state boot exposed
NFV2-070: Debian udev started `ifup@` directly without pulling the passive
`network-pre.target`, and DHCP/ARP bootstrap frames escaped after readiness
failed. Amendment AD adds closed-set direct-producer inventory, transient
setup-boot holds, post-commit `Requires=`/`BindsTo=`/`After=` readiness gates,
strict topology revalidation, and exact lifecycle ownership. Replacement
candidate builds, renewed E-R2, tag validation, publication, and deployment
have not been executed. The findings
below through NFV2-030 record the tagged 2.0.1 audit history; NFV2-031 through
NFV2-041 record the accepted 2.0.2/2.0.3 release work; NFV2-042 onward records
2.1.0 source work.
Consolidated current results are listed in `TEST_RESULTS.md`. This document
does not select or authorize a target host's policy or topology.

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

Verification labels in this table describe regression coverage. Current 2.0.3
namespace, real-provider, Docker, package, boot, reboot, and other privileged
evidence is consolidated in `TEST_RESULTS.md`.

## 2.0.3 source baseline

These repairs passed the pinned source matrix and the applicable privileged R2
and post-tag gates.

| ID | Finding | Severity | Source repair | Current status |
| --- | --- | --- | --- | --- |
| NFV2-031 | Broad established/reply acceptance did not prove the original ingress/egress path | HIGH | Reserve the high connection-mark byte for write-once interface provenance and require exact marked reply paths | CLOSED; privileged packet proof PASS |
| NFV2-032 | Configuration-only provenance IDs could be reused after an interface disappeared | HIGH | Add a separate monotonic allocation ledger with retired tombstones and a digest bound into generation evidence | CLOSED; persistence and reboot proof PASS |
| NFV2-033 | A foreign nftables rule could already use the reserved mark mask | HIGH | Audit the complete bounded nft JSON ruleset before mutation and refuse any foreign mask collision | CLOSED; collision proof PASS |
| NFV2-034 | Mutable/stale generation evidence could make recovery ambiguous after a crash | HIGH | Publish immutable script/snapshot pairs with exact checksums, fsync ordering, commit protocol, and conservative ambiguity retention | CLOSED; crash and boot proof PASS |
| NFV2-035 | Apply, reconcile, claim publication, and recovery could interleave across processes | HIGH | Use one global mutation lock plus the canonical claim-publication lock and verified rollback paths | CLOSED; concurrency and recovery proof PASS |
| NFV2-036 | Docker name-only observation could accept a recreated or drifted bridge | HIGH | Bind the stable ID/name/driver/bridge/subnet/gateway tuple and revalidate immutable observation ID | CLOSED; live Docker proof PASS |
| NFV2-037 | Package/systemd dependency edges could activate too early or imply readiness | HIGH | Keep install inert, separate early restore from nonactivating readiness, and ship final dependency edges only as administrator-selected examples | CLOSED; package, VM, and reboot proof PASS |
| NFV2-038 | An outer RC filename alone did not prevent an extracted payload from running or installing | HIGH | Embed a commit-bound Stage R version/disposition/composite identity; quarantine CLI/daemon/web and refuse candidate package/source installation | CLOSED; package and archive inspection PASS |
| NFV2-039 | Release approval and scan claims could become circular or stale | HIGH | Keep frozen reports pre-build; emit exact external build/comparison/secret evidence; bind R2, tag object, post-tag validation, and final approval by SHA-256 | CLOSED; external evidence chain PASS |
| NFV2-040 | The R2 contract required v1-to-v6 state migration, but the frozen CLI only rejected legacy schemas and supplied no reviewed offline path | HIGH | Add an explicit globally locked migration that accepts only exact schema 1-5, refuses active/sidecar/unknown/weakened/ambiguous inputs, creates a byte-identical no-overwrite backup, leaves the source unchanged, migrates a separate bounded work copy, and publishes only a read-only-verified schema-6 destination | CLOSED; privileged package/database proof PASS |
| NFV2-041 | Release source archives inherited Git's ambient `tar.umask`, so a clean clone could export `0664` files and fail or diverge from the reviewed mode inventory | MEDIUM | Force `tar.umask=0022` on the exact-commit archive command and retain independent extracted mode/blob verification | CLOSED; two-parent artifact proof PASS |

## 2.1.0 source candidate findings

| ID | Finding | Severity | Source repair | Current status |
| --- | --- | --- | --- | --- |
| NFV2-042 | Managed `expose`/`lan` wrote new files but ordinary daemon apply compiled stale in-memory configuration | HIGH | Reload and strictly validate the protected config and managed intent at artifact, reconcile, and status boundaries | CLOSED; unit/race/source-contract proof PASS, privileged R2 NOT EXECUTED |
| NFV2-043 | CLI death during managed file publication could leave intent/config bytes inconsistent with the pending or committed generation | HIGH | Add exact old/new file hashes, a root-only durable managed-change journal, an exact generation-status control query, deterministic restore/finish-forward logic, and a separate 15-second watchdog | CLOSED; pre-apply/applied/committed crash regressions PASS, privileged R2 NOT EXECUTED |
| NFV2-044 | The initial managed-change recovery unit omitted `CapabilityBoundingSet`, leaving root capabilities available despite no capability need | MEDIUM | Clear bounding and ambient capabilities; restrict the service to AF_UNIX and exact writable paths | CLOSED; systemd source contract and offline security analysis PASS |
| NFV2-045 | Managed setup detected Docker but then removed every Docker network and omitted kernel IPv4 forwarding ownership | HIGH | Adopt only strict local IPv4 bridge tuples, generate container-zone/VPN-only policy, and persist/apply/verify/restore `net.ipv4.ip_forward=1` while Docker's own forwarding mutation remains disabled | CLOSED; unit/race/source-contract/coverage proof PASS, privileged R2 NOT EXECUTED |
| NFV2-046 | A recreated Docker network changes its full ID and Linux bridge, so a static binding could silently become stale or tempt name-only authorization | HIGH | Authorize the stable name/driver/subnet/gateway tuple, race-bind one observation by full ID, and transactionally compile/commit/persist the newly observed bridge before restoring claims | CLOSED; end-to-end recreation and idempotence regressions PASS, privileged R2 NOT EXECUTED |
| NFV2-047 | Managed Docker ownership introduces root-sensitive daemon JSON, socket-access, forwarding, and uninstall handoff boundaries | HIGH | Strict no-follow/owner/mode/size/duplicate-key reads, semantic merge, checksummed exact rollback, narrow socket drop-in, and fail-closed uninstall handoff that removes only exact managed content | CLOSED; tamper/failure/rollback/package lifecycle tests PASS, privileged R2 NOT EXECUTED |
| NFV2-048 | The frozen 2.1.0 CLI documented `setup adopt` for existing hosts but implemented no such action | HIGH | Add an explicit dry-run-only planner structurally separate from setup mutation; verify exact schema-6 state/pointer/snapshot/provenance, the committed live-policy fingerprint, and bounded host topology twice; emit only a deterministic redacted worksheet; refuse execution pending a separate Stage E-L plan | CLOSED; command/refusal/redaction/race/exact-fixture/no-mutation source proof PASS, privileged R2 NOT EXECUTED |
| NFV2-049 | A security test created its intended mode-`0644` refusal fixture with `os.WriteFile` and therefore inherited the privileged runner's `umask 0077` as mode `0600` | MEDIUM | Explicitly set and verify the unsafe fixture mode; add an isolated `umask 0077` regression covering protected-mode handling, root ownership, and explicit world-readable refusal without changing the runtime helper | CLOSED; targeted and full-suite normal/`umask 0077` source proof PASS, renewed privileged R2 NOT EXECUTED |
| NFV2-050 | Clean Debian 13 returns valid empty JSON plus status 2 when the reserved route table does not yet exist, and preflight discarded the JSON before classification | MEDIUM | Query bounded numeric all-table JSON, select only exact table 51820 entries, and reject malformed identities, command failures, or populated ownership without interpreting stderr | CLOSED; absent/empty/populated/malformed/oversized/timeout/permission/command source proof PASS, renewed privileged R2 NOT EXECUTED |
| NFV2-051 | Discovery recorded non-clean Docker state but clean-host validation and intent generation ignored it, allowing automatic ownership planning around retained workloads | HIGH | Observe running/all containers around topology discovery, refuse every stable non-empty or changing observation, retain eligible empty custom bridges, and repeat clean/topology validation immediately before ownership publication | CLOSED; empty/custom/running/retained/race/redaction/post-plan source proof PASS, renewed privileged R2 NOT EXECUTED |
| NFV2-052 | The managed dynamic bridge projector required `docker:<network>` provenance for legacy v2.0.3 static advanced Docker entries, rejecting a valid unchanged historical interface-name identity | HIGH | Split projection into non-crossing modes: static entries require an unchanged bridge and exact tuple while retaining their historical identity/ID; dynamic entries require exact `docker:<network>` provenance and alone may rebind | CLOSED; unit/runtime/bundled-fixture source proof PASS, renewed privileged R2 NOT EXECUTED |
| NFV2-053 | Managed first setup published its transaction journal before clean-host discovery, so discovery classified the transaction's own journal as pre-existing NFTFW state and rollback then lacked a prepared plan | HIGH | Complete read-only preparation before journal publication; write the prepared summary at the durable pre-mutation boundary; return preparation/initial-write failures without rollback; terminalize inspect/incomplete-backup interruption without touching services; require a valid prepared summary and durable backup before guard-or-later rollback can touch services | CLOSED; engine plus real-system ordering, refusal, redaction, initial-write, backup-boundary, expiry, phase-failure, and exact-rollback source proof PASS; renewed privileged R2 NOT EXECUTED |
| NFV2-054 | The temporary setup guard declared an ordinary IPv4 address set but populated it with `/32` prefixes, which Debian nftables rejects without interval semantics | HIGH | Emit interval semantics for the endpoint set while retaining strict canonical IPv4 `/32` validation, deterministic ordering, exact table ownership, and pre-apply `nft --check` | CLOSED; unit/source-contract and gated disposable real-parser/apply/exact-delete proof PASS; complete renewed privileged R2 NOT EXECUTED |
| NFV2-055 | Exact-2.0.3 adoption planning rejected three 2.1-only units that systemd correctly reported as absent | HIGH | Read one strict six-property snapshot per unit and accept only the enumerated exact-2.0.3 `not-found`/inactive/empty-state/empty-fragment tuple; reject aliases, shadows, contradictions, malformed output, and newer-version absence | CLOSED; unit/source-contract proof PASS; complete renewed privileged R2 NOT EXECUTED |
| NFV2-056 | Managed first setup installed final `Requisite=nftfw-early` edges before starting the daemon, making the runtime phase unstartable | HIGH | Defer final dependency publication to a post-commit handoff: start and validate runtime under the temporary guard, commit, establish early/readiness and initramfs protection, then atomically publish final edges and activate boot consumers | CLOSED; Engine/System ordering, failure, recovery-forward, and rollback source proof PASS; complete renewed privileged R2 NOT EXECUTED |
| NFV2-057 | The initramfs design allows guest-originated IPv6 MLD and DAD frames before readiness when the NIC is built in or probed before init-top | HIGH | For managed disabled mode, accept only one exact local Debian GRUB family, own one fixed root-only `ipv6.disable=1` fragment, verify all generated Linux entries, stop before ordinary setup mutation, and resume only after an explicit reboot proves the prepared and running identities. Retain the native nft guard as defense in depth and restore exact boot ownership on every rollback/package path | CLOSED at source boundary; direct parser/identity/transaction/rollback tests, two consecutive zero-pre-readiness managed boot captures, post-readiness traffic, contradictory-identity zero-guest capture, and complete source gates PASS; complete renewed E-R2 repeat NOT EXECUTED |
| NFV2-058 | Exact 2.0.3 package rollback was refused by its historical downgrade guard after dpkg recorded 2.1.0 | HIGH | Prepare and verify a protected bundle before upgrade; use a lower-version fail-closed Debian bridge with exact-2.0.3 data payload, then install the unmodified exact 2.0.3 package; validate package state, schema, hashes, payload, resumable states, and initramfs cleanup without editing dpkg status | CLOSED at source boundary; bundle/tamper/path/payload proof plus full disposable exact-package transaction PASS; complete renewed E-R2 repeat NOT EXECUTED |
| NFV2-059 | The generated rollback bridge required configured `ii  2.1.0`, but Debian 13 invokes its `preinst` only after entering the `iHR 2.1.0` transition | HIGH | Accept only the exact observed three-argument downgrade call and `iHR` state; bind bridge version, architecture, package/binary hashes, protected metadata, optional exact schema history, and manifest transition identity; reject configured and every neighboring state | CLOSED at source boundary; direct generated-script acceptance/refusal and full disposable transaction PASS; complete renewed E-R2 repeat NOT EXECUTED |
| NFV2-060 | The rollback parent held the canonical mutation lock across dpkg while exact 2.0.3's historical pre-install backup tried to acquire the same pathname, causing a self-deadlock | HIGH | Keep the parent-held canonical lock and run only the exact-package dpkg descendant tree in a private mount namespace whose lock pathname is bound to a fresh protected non-alias inode; fail closed on namespace, binding, metadata, alias, or cleanup failure | CLOSED at source boundary; canonical-lock contention, cleanup, complete/resume/idempotent transaction, and restoration proof PASS; complete renewed E-R2 repeat NOT EXECUTED |
| NFV2-061 | Exact first-setup rollback retained the generation database, immutable snapshots, endpoint cache, provenance ledger, backup, and terminal journal as required, but clean-host discovery then permanently refused a retry | HIGH | Add one strict read-only terminal retry classifier; verify exact restored files/runtime state and every retained artifact; require only rolled-back first-setup generations and stable provenance; checksum-bind and durably archive the prior terminal journal before a new mutation; keep every ambiguity on the adoption refusal path | CLOSED at source boundary; terminal predicate, backup, endpoint, provenance, monotonic generation, repeated-failure, journal-lineage, coherent Docker rollback, and protected disposable generation-1/2 rollback plus generation-3 success proof PASS; complete renewed E–W R2 NOT EXECUTED |
| NFV2-062 | Exact downgrade could restore boot ownership before discovering that exact 2.0.3 rejects a v2.1-only configuration | HIGH | Extract and authenticate the bundle-bound exact old binary; run its parser with output suppressed before boot handoff and again immediately before dpkg; keep incompatible configuration on a fixed redacted refusal path | CLOSED at source boundary; ordering contracts, private-value non-disclosure, unchanged-package refusal, and compatible full disposable rollback PASS; complete renewed E-R2 repeat NOT EXECUTED |
| NFV2-063 | The generated bridge accepted only the v2.1 systemd `root:nftfw-web` database group, refusing a genuine legacy root-CLI `root:root` schema-6 database | MEDIUM | Accept only the two real ownership histories while retaining UID 0, mode 0600, one link, protected parents, exact runtime GID, and exact schema history; reject every other group | CLOSED at source boundary; both positive histories and malformed/root-runtime/unrecognized-group/symlink/hard-link/mode/owner refusals PASS; genuine legacy-to-new-to-exact-old guest rollback PASS |
| NFV2-064 | Two directory refusal tests inherited privileged `umask 0077` and therefore created safe mode-0700 fixtures, while the root-only readiness fixture required control status from a handler that rejected every control request | MEDIUM | Explicitly set and verify both intended mode-0750 unsafe directories; return the healthy snapshot only for control status; directly refuse a non-status control operation; retain all production validators, peer credentials, request validation, and readiness logic unchanged | CLOSED at source boundary; focused ordinary-user proof and focused plus complete disposable-root `umask 0077` suite PASS; renewed E-R2 NOT EXECUTED |
| NFV2-065 | Inverse-boot rollback finalization cleared an uncommitted first-setup generation even though the rolled-back database row, immutable snapshot, backup, terminal journal lineage, and provenance remained bound to it | HIGH | Preserve the exact generation when finalizing only an uncommitted first-setup rollback; retain zero for genuine pre-generation rollback and clear package-only committed handoff so it cannot masquerade as complete retry evidence | CLOSED at source boundary; direct finalizer/write-failure/package-handoff/classifier proof plus disposable generations 1/2 exact rollback, nonmutating retry, and generation-3 success PASS; renewed E-R2 NOT EXECUTED |
| NFV2-066 | Status independently reread the same nftables state for ownership, integrity, fingerprint, and provenance and inspected Docker networks one at a time, exceeding the mandatory dashboard budget while widening cross-read race windows | HIGH | Derive all nftables results from one fresh immutable full-ruleset JSON snapshot and batch all authorized Docker inspections by immutable ID; preserve fresh config, state, forwarding, WireGuard, claim, and integration checks with no cache or skipped security gate | CLOSED at source boundary; one-read/batch, drift, adjacent-request, HTTP-to-Unix, cancellation, saturation, race, allocation, and no-provider disposable timing/resource proof PASS; strict healthy-protected E-R2 NOT EXECUTED |
| NFV2-067 | The E-R2 hard stop attributed EFI refusal to a duplicate parser arm, but the exact frozen source digest contained one arm; the disposable firmware had regenerated forbidden PXE/HTTP entries after reboot | MEDIUM | A false root cause could invite weakening network-boot refusal or leave singleton dispatch vulnerable to a repeated empty arm | Parse `BootCurrent`, `BootOrder`, and `BootNext` through unique literal switch cases; explicitly test valid, missing, duplicate, malformed, inactive, network, one-shot, order, loader, distribution, and architecture identities; disable the disposable NIC option ROM before the mandatory reboot instead of relaxing verification | Exact source/guest audit, focused unit/source-contract proof, and direct disposable reboot to `resume_ready` plus protected completion PASS | CLOSED at source boundary; complete renewed E-R2 NOT EXECUTED |
| NFV2-068 | Independently scheduled readiness declared `/run/nftfw` writable but relied on the conditionally scheduled early unit to create it | HIGH | An intermittent boot ordering path failed systemd mount namespace construction with `226/NAMESPACE` and kept all dependent network consumers unavailable | Make readiness and independently timer-activated rollback paths identical preserved owners of the shared `root:nftfw-web`, mode-`0750` runtime directory; retain nonactivating ordering and application-level verification | Source graph/sandbox contracts, condition-skipped and failed-early refusal, 150 absent-directory starts, concurrent-owner lifetime, disposable root/umask suite, and repeated-boot fixture | CLOSED at source boundary; complete renewed E-R2 NOT EXECUTED |
| NFV2-069 | A protected consumer's nonactivating `Requisite=readiness` could be evaluated before it caused `network-pre.target` to schedule readiness; naively adding early to sysinit retained an implicit `After=basic.target` and formed a cycle through protected sockets | HIGH | Depending on transaction construction, networking/SSH remained inactive or systemd deleted early's job; readiness then failed closed because final enforcement was absent | Give early explicit `DefaultDependencies=no` plus `After=local-fs.target`; schedule early and readiness independently as sysinit wants; make consumers require the nonmutating verifier while readiness retains no activating edge to early | Source graph and systemd verification, preserved failed cycle/skip boots, twenty consecutive unique ROM-less boots, readiness-before-SSH, zero pre-marker packets, post-readiness traffic, and clean overlay | CLOSED at source boundary; complete renewed E-R2 NOT EXECUTED |
| NFV2-070 | Debian ifupdown udev hotplug could start `ifup@<interface>.service` without pulling the passive `network-pre.target` or enforcement readiness | HIGH | A failed adverse boot kept SSH/application consumers stopped but the independent producer emitted DHCP and ARP frames through the narrow bootstrap exception | Inventory a closed set of Debian network producer services/templates before mutation; transiently gate all direct entry points on the setup boot hold; after commit publish and verify exact `Requires=`/`BindsTo=`/`After=` readiness edges; bind marker, files, topology, backup, watchdog recovery, rollback, uninstall, status, and adoption | Go/source/generator tests and bounded disposable direct-activation semantic fixture; full capture-backed E-R2 remains required | CLOSED in source; complete renewed E-R2 NOT EXECUTED |

## Adversarial review areas

| Area | Result |
| --- | --- |
| Shell/argument injection | Go invokes fixed binaries with argument arrays; interfaces/names/addresses validated; no Go shell string execution |
| nft ownership | Global flush rejected; only fixed family/table tuples may be deleted; unrelated-table tests pass |
| Hidden allows | Compiler review found only loopback, protocol bootstrap, endpoint bootstrap, reply-only, trusted lease, stateful input/forward, and declared policies |
| Conntrack bypass | Write-once ingress provenance and removal of broad established accepts passed direct TCP/UDP alternate-ingress and leak packet proof |
| IPv6 bypass | Three explicit modes and disabled-mode hooks passed unit, namespace, and real-VPN release coverage |
| Unsafe temp/path use | Go uses secure temp APIs; protected state/config/cache paths reject symlinks and unsafe parents; package temp paths are fixed templates |
| Socket permissions | Control mode/root peer authorization; status is deliberately dashboard-group readable; unsafe existing socket objects rejected |
| Request/resource bounds | API, nft output, config, Docker output, feeds, Geo files, set counts, and audit fields bounded |
| Database injection/races | Parameterized SQL, foreign keys, WAL, busy timeout, transactions, constraints, race/concurrent-open tests, and engine-level offline-migration constraint probes |
| Rollback | Persistent deadline, exact guard validation, checksummed artifacts, independent timer, crash/ambiguity/timeout regressions, and live execution passed |
| Web XSS/CSRF/file access | No mutable endpoint, no templated user HTML, DOM uses `textContent`, fixed routes/assets, strict CSP/headers |
| HTTP resource limits | Loopback default, read/header/write/idle timeouts, 16 KiB headers, status-only upstream response limit |
| Secret logging | Status omits keys/peer IDs; controller observation is aggregate; test config excluded; secret-rule and redaction contracts pass while exact frozen-history and extracted-archive scans remain post-freeze gates |
| Capabilities/systemd | Static units bind the root daemon to `CAP_NET_ADMIN`; web has no capabilities; staged, package, runtime, and reboot verification passed |
| Managed routing | Numeric all-table JSON makes an absent reserved table clean without accepting command failure, malformed identity, or populated ownership |
| Managed Docker | Clean-host setup refuses running or retained workloads; Docker keeps all five packet-mutation settings false; NFTFW alone owns IPv4 forwarding, container policy/NAT, dynamic bridge binding, and the narrow local socket handoff |
| Status freshness | Every request reloads protected config/intent and observes schema-6 state, provenance, one immutable nftables snapshot, one immutable-ID Docker batch, forwarding, WireGuard, claims, and integrations; no cache can preserve `protected=true` across adjacent drift |
| Legacy Docker compatibility | Static advanced entries retain their exact bridge, tuple, historical interface-name provenance, and ledger ID; they never enter the managed rebind branch |
| Adoption planner | Dry-run-only component has no writer/mutation backend; double observation, exact state/provenance verification, bounded fixed output, and untrusted-error redaction are source-tested |
| Managed setup boundary | Profile/discovery/plan complete before journal creation; initial journal contains the prepared summary; pre-backup interruption changes no protected state; guard-or-later recovery requires a valid prepared summary, durable backup, and exact phase record before touching services |
| Temporary setup guard | Every prefix-bearing generated set uses nftables interval semantics; bootstrap endpoints remain canonical IPv4 `/32`; the guard is checked before apply and owns/deletes only `inet nftfw_setup_guard` |
| Managed disabled boot boundary | A strict Debian GRUB transaction adds exactly one kernel-wide disable token, records `reboot_required`, and resumes only after changed-boot and running-kernel proof. The native loader verifies that contract and never re-enables loopback. A pre-network transaction atomically replaces its deny table with one checksum-bound DHCP/LAN/cached-endpoint guard, holds Docker service/socket activation until ownership and forwarding are durable, and makes exact rollback release Docker only after restoring its prior files; exact rollback records when another reboot is required |
| Exact package rollback | Both release packages, helper, bridge, architecture, schema, canonical payload digest, protected metadata, exact `iHR` transition, and resumable outer-controller states are bound in a protected manifest; the exact old parser preflights configuration before mutation; the database permits only its two strict ownership histories; the parent retains the canonical lock while only dpkg receives a protected private lock view; neighboring states, unsafe paths, tampering, unlocked handoff, direct dpkg-status edits, and manual payload replacement are refused |
| Direct network producers | Only canonical closed-set Debian 13 services/templates are accepted; the setup reboot holds every entry point and final managed state verifies exact readiness require/bind/order edges. Unsupported, custom, ambiguous, changed, condition-skipped, failed, and stopped-verifier states fail closed, while exact backup/handoff restores prior files or absence |

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
6. The source-stage Debian guest evidence does not validate an arbitrary 2.1.0
   deployment host. Different kernels, interfaces, firewall managers, VPN
   providers, Docker networks, and management paths remain host-specific until
   the complete R2 and per-host deployment preflight.
7. Release checksums and provenance are not cryptographically signed. A
   release operator must add a signature using an independently controlled
   identity; the build does not fabricate one.

These are documented operating assumptions or low/medium residual risks, not
unresolved high/critical implementation findings.

## Final scan evidence

The amended 2.1.0 source passed Go 1.27.0 unit/race/vet/module/fmt, staticcheck
v0.8.1, govulncheck v1.7.0, gosec v2.29.0, fourteen bounded fuzz targets,
complete shell analysis, Stage R source/guard/comparator contracts, staged
systemd/package verification, the full suite under `umask 0077`, the retained
Amendment M disposable root source regressions, the protected Amendment W
two-failure/eventual-success transaction, Amendment X zero-pre-readiness boot,
contradictory-boot, boot-handoff, and exact-package rollback preflights, and
the coverage/benchmark gates. Amendment Y's two exact directory-mode fixtures,
authenticated control-status/non-status-refusal regression, and complete fresh
disposable-root `umask 0077` suite also pass without production runtime source
changes.
Amendment Z's inverse-boot finalizer and strict retry-classifier regressions
also pass. A fresh disposable transaction preserves generations 1 and 2
through reboot, process death, inverse reboot, exact rollback, and dry-run
reentry before committing generation 3; the existing Docker/VPN/leak/reboot
lifecycle remains green. Amendment AA adds one-snapshot nftables status,
batched Docker observation, adjacent-request fail-closed coverage, real
HTTP-to-Unix transport tests, and a disposable installed-runtime benchmark;
the source-only reference run passes every unchanged latency and resource
budget. Amendment AB additionally passes the exact singleton-dispatch and
expanded EFI refusal matrix plus a real reboot/resume with the virtual
firmware network option-ROM path disabled; strict network-boot refusal remains
unchanged. Amendment AC additionally establishes deterministic runtime-directory
ownership and an acyclic independent boot schedule without changing firewall
policy or allowing readiness to activate early restoration. Its
direct disposable regression proves missing and failed early enforcement
remain blocked while systemd reaches the application verifier rather than
`226/NAMESPACE`; 150 absent-directory starts and concurrent owner stops retain
the exact shared identity. Twenty consecutive ROM-less source-stage boots also
retain zero pre-marker packets and readiness-before-SSH ordering. Candidate
source/history/extracted-tree scans and two-parent comparison are generated
only after the clean source freeze. Privileged R2, tagged package/archive
inspection, post-tag validation, publication, and deployment are not current
2.1.0 evidence.
