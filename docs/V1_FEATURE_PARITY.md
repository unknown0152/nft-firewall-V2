# V1 Feature Parity and V2 Decisions

> This comparison records design decisions for the accepted 2.0.3 release.
> It is not a substitute for the target-host audit and guarded handoff in
> `HOST-HANDOFF.md`.

The reference checkout is
`unknown0152/nft-firewall-public@b607738bf917fd5a198be5a24ae92c8ba523a076`
on branch `main`. It was frozen read-only with a source list and SHA256
manifest under the work root. Source, tests, setup/install scripts, systemd
units, migration notes, and historical Git metadata were reviewed. V2 is an
independent repository and imports no V1 implementation module.

Disposition means:

- `KEEP`: preserve the useful behavior, with a new implementation.
- `REDESIGN`: preserve the product requirement through a safer contract.
- `PLUGIN`: keep outside the privileged core; may or may not ship in v2.0.0.
- `REPLACE`: solve the same operational need with a different mechanism.
- `DROP`: intentionally absent for a documented security/maintenance reason.

| V1 capability | Decision | V2 implementation/status |
| --- | --- | --- |
| Pure ruleset generation | REDESIGN | Typed policy plus deterministic compiler; compilation has no OS side effects |
| INI/ConfigParser configuration | REPLACE | Strict typed TOML, unknown-field rejection, filesystem and semantic checks |
| Named deployment profiles | PLUGIN | Generic zones/services/policies ship; application-specific presets do not |
| Cosmos/application defaults | PLUGIN | No application/country names in core; operators can publish separate presets |
| Default-drop input/forward | KEEP | Explicit base chains with drop policy and final counters |
| Output VPN kill switch | REDESIGN | Strict-only output drop with VPN-pinned public policy and narrow bootstrap |
| Broad established/related handling | REDESIGN | Physical forward denial before state accept; no blanket output state accept |
| IPv6 hard-drop option | REDESIGN | Explicit `disabled`, `vpn`, and `native` modes with dual-stack policy |
| WireGuard bootstrap allow | REDESIGN | Uplink + fwmark + endpoint set + UDP port; no broad temporary uplink allow |
| Endpoint hostname refresh | KEEP | Validated fixed-cadence resolver, bounded cache/history, atomic v4/v6 sets |
| WireGuard watchdog/recovery levels | REDESIGN | Health/reconcile loop and narrow single-peer endpoint repair; interface manager remains external |
| Firewall backup/restore | REDESIGN | Immutable checksummed generations, authoritative generation/checksum pointer, database backup |
| Interactive safe apply | REPLACE | Durable pending-before-mutation state, uncommitted safe-applied generation, deadline, explicit commit, daemon plus systemd rollback |
| Boot firewall persistence | REDESIGN | Early pre-network committed-generation restore; unusable immutable evidence fails before nft mutation and blocks readiness |
| Whole-ruleset flush | DROP | Backend rejects `flush ruleset`; only three fixed V2 tables are addressed |
| Text/regex nft inspection | REPLACE | Bounded `nft -j` JSON inspection and canonical owned fingerprints |
| Marker comments | KEEP | Deterministic ownership/rule comments, backed by structural JSON fingerprint |
| Dynamic block set | REDESIGN | SQLite claims with address, family, source, reason, actor, creation, expiry |
| Dynamic trusted set | REDESIGN | Expiring `allow` claims restricted to declared services and kernel timeouts |
| Protected/never-block entries | REPLACE | Typed ownership prevents integration deletion; admin policy remains declarative |
| JSON dynamic-state files | REPLACE | Transactional SQLite migrations and bounded root-only state files |
| Audit JSONL | REPLACE | Durable structured SQLite audit plus systemd journal process events |
| Threat-feed updater | PLUGIN (SHIPPED) | Bounded public HTTPS client, strict parser, atomic provenance source, stale retain |
| GeoIP country blocks | PLUGIN (SHIPPED) | Operator-supplied licensed CIDR exports become `geo/<name>` claims |
| Docker network discovery | REDESIGN | Privileged local CLI observer, validated networks, atomic runtime sets |
| Docker iptables disabling | REDESIGN | Integration requires five explicit false daemon ownership/proxy settings |
| Container VPN egress | KEEP | Pre-conntrack physical drop, VPN-only NAT, IPv4/IPv6 observed network sets |
| Container port exposure/DNAT | REDESIGN | Typed IPv4 DNAT plus independently required forward policy and observed target |
| Container IP/network recreation | KEEP | Re-observation and atomic network set refresh; lifecycle acceptance test |
| Keybase notifications | PLUGIN (NOT SHIPPED) | Audit adapter boundary documented; core never depends on messaging |
| Keybase remote command listener | DROP from product core | No remote management listener; any future adapter must be typed/authenticated |
| Arbitrary ChatOps commands | DROP | Remote text-to-command and shell execution are incompatible with privilege boundary |
| SSH/fail2ban event blocking | PLUGIN (NOT SHIPPED) | Future adapter may create bounded typed claims; core has manual claim API |
| Raw packet port knocking | DROP | Privileged packet parser/per-rule mutation replaced by explicit expiring access |
| Port manager/menu actions | REPLACE | Strict CLI commands and declarative service/policy edits |
| Interactive `fw` wrapper/menu | REPLACE | Non-interactive professional CLI with useful errors and JSON modes |
| Doctor/simulation commands | REDESIGN | Live `doctor`, checked semantic `plan`, shared-model `explain`, status/health |
| Raw rules/debug display | REDESIGN | `plan --show-nft`; no key/config disclosure and raw output is opt-in |
| Traffic counters/analytics | PLUGIN (NOT SHIPPED) | nft counters inform inspection; top-talker analytics is outside v2.0.0 core |
| Prometheus textfile output | PLUGIN (NOT SHIPPED) | Structured status socket is the supported observability boundary |
| Daily/weekly text reports | PLUGIN (NOT SHIPPED) | Durable audit/status data is available to an unprivileged report adapter |
| Generated report images | DROP from core | Image rendering and third-party delivery add dependencies without enforcement value |
| Read-only web UI | KEEP/REDESIGN | Separate sandboxed local process, status socket only, embedded same-origin assets |
| Mutable web actions | DROP | Dashboard is deliberately GET/HEAD-only with no CSRF-relevant control path |
| Multi-user installer roles | REDESIGN | Root control and dedicated `nftfw-web` read identity; no broad sudo wrappers |
| Generated privileged shell wrappers | REPLACE | Strict Unix API, peer credentials, operation schemas, single mutation backend |
| Monolithic setup logic | REPLACE | Small installer, Go product logic, Debian maintainer scripts, systemd units |
| Docker/Keybase auto-install | DROP | Package manager/operator owns optional external services and credentials |
| systemd watchdog/timers | REDESIGN | Hardened daemon, early restore, rollback timer, and read-only web units |
| Periodic doctor service | REPLACE | Continuous health/reconciliation and operator `doctor` |
| Migration/zero-downtime notes | KEEP/REDESIGN | Transactional SQLite migrations, pre-upgrade backup, `UPGRADING.md` |
| Local change tracking guidance | KEEP | Git history plus architecture `DECISIONS.md` and clean release source |
| Public-source secret exclusions | KEEP/STRENGTHEN | No credential fixtures; config outside repo; history and archive secret scans |
| Backup helper | REDESIGN | `nftfw state backup`, package/source pre-upgrade backup, checksum manifests |
| Uninstaller | REDESIGN | Preserves config/state and active fail-closed kernel state unless explicit action |
| Unit/security/chaos tests | REPLACE | Go unit/race/fuzz plus namespace, real VPN, Docker, host rollback, DB, service chaos |

## Explicit DROP rationale

`flush ruleset` is incompatible with coexistence and can erase an unrelated
security control. Remote free-form ChatOps and generated shell/sudo wrappers
expand a root command surface that is unnecessary when a strict Unix API
exists. Raw port knocking adds a privileged packet parser and timing state;
expiring typed access leases solve the intended workflow more visibly.

Mutable web actions are absent so compromise of the dashboard cannot mutate
policy. Report image generation and bundled external-service installers do not
contribute to enforcement and introduce large dependency/credential surfaces.
Prometheus, analytics, notification, report, intrusion-event, and preset
adapters are classified rather than represented as implemented in v2.0.0.
