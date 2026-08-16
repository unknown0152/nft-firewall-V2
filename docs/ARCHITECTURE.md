# Architecture

```text
nftfw CLI ----------- control.sock --+
integrations -------- typed request --+--> nftfwd --> nft backend --> nftables
reconciler ---------------------------+

nftfw-web ----------- status.sock ----> read-only status
```

Desired state is the validated TOML plus durable administrator claims.
Observed state is nftables JSON, interfaces/endpoints, and optional integration
observations. Effective state is a pure compiler input containing desired
policy plus active, non-expired runtime claims and endpoint sets.

The compiler emits deterministic definitions for three owned tables. The nft
backend checks the candidate and applies one transaction that replaces only
owned tables. SQLite stores migrations, generations, pending deadlines,
provenance claims, and audit records. Reconciliation verifies owned-table
structural markers and can restore the committed generation without touching
third-party tables.

Package ownership is summarized in `docs/PACKAGES.md`.
