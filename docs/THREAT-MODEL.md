# Threat Model

## Assets

Management reachability, confidentiality of non-VPN traffic, firewall policy,
WireGuard configuration, operational state, and auditable administrator intent.

## Threats and controls

| Threat | Control |
| --- | --- |
| Remote attacker | Default deny; no network control port; local-only dashboard |
| Compromised container | Physical-uplink hard drop before conntrack; VPN-only NAT |
| Local unprivileged user | Root peer credentials and socket modes; strict config/state ownership |
| Compromised dashboard | Status socket only; no nft/Docker/control capability |
| Malformed config | Strict decode, unknown-field rejection, typed semantic validation |
| Malicious feed | HTTPS, timeout, byte/entry limits, CIDR parser, provenance claims |
| DNS manipulation | Address validation, bounded cached history, no temporary broad egress |
| Endpoint rollover | Separate v4/v6 bootstrap sets and bounded recent addresses |
| nft drift | Owned-table JSON/marker inspection and scoped repair |
| Operator error | Plan, kernel check, pending deadline, independent rollback timer |
| Supply-chain compromise | Pinned Go modules, checksums, reproducible source manifest, CI |
| Symlink/path attack | Config symlink rejection, fixed state paths, secure temp files |
| Command injection | `exec.CommandContext` argument arrays; no shell strings in Go |
| SQLite corruption | Open/migration failure retains kernel last-known-good state |
| IPv6 bypass | Explicit modes and early disabled-mode drop |
| Conntrack bypass | No output established shortcut; container physical drop precedes state |

Assumptions: the kernel/nft executable, root account, systemd, and installed
binaries are trusted. Real provider behavior requires an operator-supplied
WireGuard test configuration and cannot be simulated by unit tests.
