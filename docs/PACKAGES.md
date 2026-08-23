# Package Map

| Package | Responsibility |
| --- | --- |
| `config` | Strict TOML decoding, filesystem checks, and semantic validation |
| `policy` | Pure effective model and shared explanation decisions |
| `compiler` | Deterministic owned-table transaction generation and plan summaries |
| `nft` | Sole nft command boundary, JSON inspection, fingerprints, atomic set updates |
| `state` | SQLite migrations, generations, claims, audit, snapshots, backup |
| `reconcile` | Safe apply, commit, rollback, health verification, drift repair |
| `wireguard` | Bounded endpoint resolution/cache and narrow peer endpoint control |
| `blocks` | Typed, provenance-aware block and temporary-access operations |
| `containers` | Optional read-only Docker CLI observation through a pinned local socket |
| `threatintel` | Bounded HTTPS retrieval and strict address-list parsing |
| `geo` | Secure parsing of operator-supplied country CIDR exports |
| `recovery` | Exact systemd rollback guard verification |
| `api` | Strict bounded Unix-socket protocol and peer credential authorization |
| `health` | Read-only effective/observed status projection |
| `app` | Composition root and scheduled runtime reconciliation operations |
| `audit` | Audit event constants/helpers |
| `version` | Build-injected immutable version metadata |

Command packages contain only process wiring and operator presentation. Policy
decisions do not live in the dashboard or HTTP handlers.
