# Threat Model

The 2.1.0 boundary preserves the accepted 2.0.3 enforcement model and adds
provider-profile parsing, discovery, managed routing, setup transactions, and
their independent rollback owner. The prior Stage R2 packet, package, boot,
Docker, and real-provider evidence passed. A new host still needs its own
topology review and guarded handoff because those choices are not release
properties.

## Assets and goals

Assets are management reachability, the confidentiality of traffic that must
use a VPN, firewall integrity, WireGuard key material, administrator intent,
operational state, and trustworthy audit evidence.

Primary goals are default deny, zero direct physical egress when the declared
VPN fails, no IPv6 bypass, no cross-provenance unblock, atomic known-good
updates, and recovery that does not erase unrelated firewall state.

## Adversaries and controls

| Threat | Boundary and control | Residual risk |
| --- | --- | --- |
| Remote network attacker | Default-deny input/forward; no network control API; local dashboard | A deliberately allowed service remains in scope of that service's security |
| Compromised container | Exact stable bridge tuple, immutable ingress provenance, physical-forward deny, and VPN-only NAT | Rootful Docker itself remains privileged and can alter host state |
| Malicious local user | Root peer credentials; protected config/state/runtime dirs; bounded schemas | A user granted root or Docker socket access is outside this boundary |
| Compromised dashboard | Separate UID, status socket only, no capabilities, control or Docker socket | Status data is visible to the dashboard group by design |
| Malformed config | Strict unknown-key rejection, limits, typed references, topology validation, `nft --check` | Semantically valid policy can still deny operator traffic; safe apply mitigates |
| Malicious threat feed | HTTPS public-only dial; no proxy env; redirect/time/byte/entry limits; public `/24` and `/48` minimums; cross-feed aggregate caps; topology/WireGuard exclusions; persisted-state validation and rollback; established/trusted recovery paths precede feed blocks | HTTPS/DNS trust can still supply bounded valid but unwanted public prefixes |
| DNS manipulation | Valid unicast results only, bounded history/age, endpoint-only bootstrap | A compromised resolver can redirect the VPN endpoint to another public host on the same port/mark path |
| WireGuard endpoint change | Fixed-cadence resolution, atomic endpoint sets, narrow single-peer update | Authoritative TTL is unavailable; convergence can take up to refresh cadence |
| Kernel/firewall drift | Canonical owned JSON fingerprint, 30-second repair, runtime set restore | A competing privileged manager can cause repeated churn or preempt via another base chain |
| Operator mistake | Plan, doctor, candidate check, persistent deadline, independent timer, explicit commit | Hidden topology outside declared policy cannot be proven automatically |
| Supply-chain compromise | Small direct dependency set, pinned sums, vulnerability/static scans, manifests, checksums, reproducible archives, unsigned in-toto provenance | CI action tags and upstream Go/module/tool distribution remain trust roots; release signing is operator-owned |
| Symlink/permission attack | `lstat`, `O_NOFOLLOW`, parent ownership/mode checks, secure temp files | Root can deliberately replace protected files |
| Command injection | No shell strings in Go; validated fixed argument arrays; Docker `--` separator | Shell acceptance scripts are privileged test tooling, not runtime input APIs |
| API/socket abuse | Kernel peer credentials, separate sockets, mode checks, request limits, operation field allowlists | Root control clients can intentionally change policy |
| Stale state | Expiry validation, integration timestamps, cache maximum age, reconciliation | Retained failed-feed claims can over-block until operator repair |
| Database corruption | Separate monotonic provenance ledger, generation pointer/snapshot checks, transactional migration, online generation backup, and a conditional independently verified restore that still blocks readiness | Unusable immutable evidence stops before nft mutation; audit events written only to a destroyed DB require external journal/backup recovery; ledger recovery is merge-only |
| IPv6 bypass | Explicit modes; early disabled hooks; dual-stack policy and leak tests | Third-party higher-priority rules remain an operator integration concern |
| Conntrack bypass | Write-once original-ingress provenance, exact masked reply accepts, no blanket forward/output established accept, and unconditional physical-forward deny | Kernel conntrack/nft implementation is trusted; privileged active-flow/retag packet proof passed for the release test topologies |
| Docker privilege exposure | Socket hidden by packaged unit unless an explicit drop-in grants it; local host pinned; dashboard isolation; hardened daemon config | An operator-enabled Docker socket remains effectively host-root trust |
| Unsafe rollback | Generation checksums, eligibility checks, prior generation, independent fallback | Disabling both systemd and daemon rollback removes this protection |
| Secret disclosure | Keys never stored in SQLite/audit/status; config mode checks; release secret scan | Operators can still expose secrets through external logging or shell history |
| Web attacks | GET/HEAD only, no mutation, textContent rendering, same-origin assets, CSP, size/time limits | Binding beyond loopback exposes operational metadata without application authentication |

## Failure policy

Invalid desired input, ambiguous topology, unsafe files, malformed integration
data, or failed kernel validation never replace known-good policy. Integrations
retain their prior source claims and become degraded. Missing or invalid
immutable boot evidence returns an error before nft mutation and blocks
readiness. Emergency deny is reserved for the distinct case in which an owned
generation installation succeeds but restoration of separate mutable runtime
security state fails.

Fail closed does not mean destroying working state. V2 prefers retaining the
last known good generation plus an auditable health error.

## Assumptions

- The Linux kernel, nftables, systemd, root, and installed executables are
  trusted.
- One declared physical uplink and one declared WireGuard interface represent
  the protected topology.
- WireGuard keys and initial tunnel/routing setup are managed outside V2.
- System time is sufficiently correct for deadlines and lease expiry.
- Operators review interactions with other nftables base chains.
- A provider or local console is available for recovery from deliberate
  administrative disablement of every rollback path.

## Non-goals

V2 is not a host intrusion prevention system, VPN key manager, DNSSEC
validator, Docker authorization proxy, remote ChatOps service, kernel security
module, or replacement for application authentication. It does not guarantee
availability against root/kernel compromise or upstream VPN outage.
