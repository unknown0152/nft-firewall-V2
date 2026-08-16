# Package Map

| Package | Responsibility |
| --- | --- |
| `config` | Strict TOML decode and semantic validation |
| `policy` | Pure effective model and explanation engine |
| `compiler` | Deterministic nft script generation |
| `nft` | Sole nftables command/mutation boundary |
| `state` | SQLite migrations, generations, claims, audit |
| `reconcile` | Safe apply, commit, rollback, drift repair |
| `wireguard` | Bounded DNS endpoint cache/rollover data |
| `blocks` | Provenance-aware block/trust claim service |
| `containers` | Optional read-only Docker observation |
| `threatintel`, `geo` | Bounded optional claim sources |
| `api` | Strict Unix-socket protocol and peer credentials |
| `health` | Read-only status projection |
