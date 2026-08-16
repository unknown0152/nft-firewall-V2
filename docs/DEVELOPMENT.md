# Development

Go 1.24 or newer is used. Dependencies are pinned in `go.mod`/`go.sum`:
BurntSushi TOML provides strict metadata-aware decoding; modernc SQLite avoids
CGO and supports static cross builds. The remaining production code uses the
standard library.

```bash
make fmt-check
make test
make race
make vet
make release VERSION=2.0.0-dev
```

No package outside `internal/nft` may invoke `nft`. Parsing and compilation
must remain deterministic and side-effect-free. Tests use temporary paths and
injected runners.
