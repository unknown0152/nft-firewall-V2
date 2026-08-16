# V1 Feature Parity and V2 Decisions

V1 was frozen from `unknown0152/nft-firewall-public` at commit
`b607738bf917fd5a198be5a24ae92c8ba523a076`. The checkout and SHA256 manifest
are under `../reference/nft-firewall-v1` and `../test-results/v1-inventory` in
the work root. V2 is a new repository; no V1 implementation modules are
imported.

| V1 capability | V2 disposition | V2 treatment |
| --- | --- | --- |
| Pure nftables ruleset generation | REDESIGN | Typed policy compiler returns deterministic owned-table transactions. It never mutates the kernel. |
| Default-drop input/forward/output | KEEP | Explicit base chains with drop policy and interface-pinned exceptions. |
| WireGuard full-tunnel killswitch | REDESIGN | Runtime endpoint sets, fwmark/endpoint/port constrained bootstrap, VPN-only NAT, and no output established shortcut. |
| IPv6 hard-drop table | REDESIGN | Explicit `disabled`, `vpn`, and `native` modes; disabled mode has an owned early-priority IPv6 drop table. |
| Dynamic blocked/trusted/GeoIP sets | REDESIGN | SQLite claim records with provenance, expiry, audit actor, and effective-set compilation. |
| Persistent JSON dynamic sets | REPLACE | SQLite migrations and transactions replace ownership-less JSON. Legacy JSON can be imported by a future migration tool. |
| `flush ruleset` apply | DROP | V2 destroys/replaces only its named tables. Unrelated nftables tables are never touched. |
| Regex parsing of `nft list` text | REDESIGN | Backend prefers `nft -j`; text is retained only as a bounded diagnostic fallback. |
| Backup/restore | REDESIGN | Generation records, owned-table snapshots, durable pending state, and an independent rollback timer. |
| Watchdog with four WireGuard recovery levels | REDESIGN | Narrow reconciler/health loop; recovery uses validated interface/config arguments and endpoint cache. Notifications are outside the core. |
| Endpoint hostname re-resolution/cache | KEEP | Bounded resolver, validated IPv4/IPv6 results, TTL/history, bounded runtime sets, and fail-closed rollover. |
| Docker iptables=false hardening | REDESIGN | Optional observer validates daemon settings and bridge networks; only the privileged backend mutates nftables. |
| Docker expose registry/DNAT | REDESIGN | Typed, validated integration input; policy compiler owns DNAT rules and rejects destinations outside observed bridge networks. |
| Threat-feed synchronization | PLUGIN | Separate bounded HTTPS integration producing `threatfeed/<name>` claims. Core remains usable without it. |
| GeoIP country blocking | PLUGIN | Optional data source producing `geo/<country>` claims; no country codes in firewall core. |
| Keybase/ChatOps commands | DROP from core / PLUGIN boundary | V1's remote command path is disabled by default in V2. Any future adapter must call typed local APIs, never a shell. |
| Keybase notifications | PLUGIN | Optional notifier; failures cannot affect apply/reconciliation. |
| SSH intrusion alert/auto-block | PLUGIN | Optional event adapter creating audited temporary claims through the control API. |
| Port knocking | DROP | V1's raw packet daemon and per-rule mutation add complexity and a privileged parser. Use declared temporary leases instead. |
| Read-only web UI | KEEP / REDESIGN | Separate unprivileged process, local bind, status socket only, strict headers, bounded JSON, no Docker socket. |
| Metrics/report images | PLUGIN | Status JSON and optional text metrics are available; report rendering and external APIs are not a core dependency. |
| Prometheus textfile | KEEP (optional) | Health package can emit bounded textfile metrics without changing policy. |
| CLI `doctor`, `status`, `health`, `rules` | KEEP / REDESIGN | `nftfw` provides typed JSON/human output and explains desired/observed/effective state. |
| ConfigParser INI config | REPLACE | Strict TOML schema with unknown-field rejection, path/permission checks, and pure validation. |
| Systemd templates | KEEP / REDESIGN | Hardened `nftfwd` and read-only web units plus independent rollback unit. |
| Installer/uninstaller | REDESIGN | Versioned package scripts install binaries and units; uninstaller preserves config/state unless explicitly requested. |
| 251+ V1 unit tests | REPLACE | Go unit, race, fuzz/property, API, state, and namespace acceptance tests target V2 contracts and behavior. |

## Deliberate drops

V2 does not carry over raw port knocking, ownership-less JSON state, blanket
ChatOps control, or the V1 installer behavior that could flush a whole host
ruleset. These features either create a privileged parsing surface or weaken
the single mutation boundary. They can be implemented as separately audited
adapters later.
