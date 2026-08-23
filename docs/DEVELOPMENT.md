# Development

The audited release uses Go 1.25.13. `go.mod` pins the language/toolchain and
all module versions. Production has two direct third-party dependencies:

| Dependency | Reason |
| --- | --- |
| `github.com/BurntSushi/toml` | Small strict TOML decoder with unknown-key metadata |
| `modernc.org/sqlite` | Pure-Go SQLite, enabling CGO-free static cross-builds |

Everything else in production is the Go standard library or a transitive
dependency of pure-Go SQLite. No framework, native database library, metrics
server, or message broker is required.

## Quality commands

```bash
make fmt-check
go mod verify
go mod tidy -diff
make test
make race
make vet
make static
make vuln
make security
shellcheck scripts/*.sh tests/acceptance/*.sh tests/chaos/*.sh tests/namespaces/*.sh tests/packaging/*.sh packaging/deb/*inst packaging/deb/prerm
```

The audited analyzer versions are staticcheck v0.7.0, govulncheck v1.7.0,
and gosec v2.28.0. The gosec target excludes four heuristic classes only after
manual review: ignored cleanup errors, command execution, file paths, and a
deliberately group-readable status socket. Argument arrays, fixed/validated
paths, and socket purpose are reviewed in `SECURITY_AUDIT.md`.

## Build

```bash
make build
make release VERSION=2.0.1 COMMIT=$(git rev-parse HEAD) \
  BUILD_DATE=$(git show -s --format=%cI HEAD)
make deb VERSION=2.0.1
./tests/packaging/systemd_preflight.sh amd64
```

Release builds set `CGO_ENABLED=0`, `GOOS=linux`, use `-trimpath`, omit the Go
build ID, and embed version, commit, and a controlled build date. amd64 and
arm64 are produced. `SOURCE_DATE_EPOCH` is honored by final package tooling.

Final packaging requires a clean tree and matching `v<version>` tag:

```bash
GOTOOLCHAIN=go1.25.13 ./scripts/package-release.sh 2.0.1
```

The release script refuses any Go toolchain other than the pinned Go 1.25.13
and records that toolchain in the manifest and unsigned in-toto provenance
statement. SHA256 manifests provide integrity; release signing requires an
operator-controlled signing identity and is intentionally not fabricated by
the build.

The script builds from an immutable export of the captured Git commit, verifies
the complete artifact set in a temporary directory, and atomically publishes it
as `../releases/nft-firewall-v2-<version>/`. It serializes release builds and
refuses to replace an existing version directory.

For a two-build reproducibility check, set `NFTFW_RELEASE_PARENT` to a different
empty absolute directory for each invocation, then compare the two published
version directories. The output-parent path is not embedded in the artifacts.

`--allow-untagged` exists only to exercise packaging before release. It marks
the embedded manifest `unreleased`.

## Code boundaries

- Only `internal/nft` may invoke `nft`.
- Configuration loading and policy compilation must remain side-effect free.
- Runtime observations enter compilation as explicit inputs.
- UI and API presentation must not duplicate policy decisions.
- Child processes use argument arrays and bounded output.
- Unit tests use temporary directories and injected runners/backends.
- New persistent state requires a forward-only migration and corruption test.
- New privileged operations require an operation-specific API schema and peer
  authorization test.

Some cohesive transactional modules exceed the normal 500-line guideline;
new work should split along real ownership boundaries rather than adding to
command or state monoliths.

## CI

`.github/workflows/ci.yml` runs formatting, module verification, tidy diff,
unit/race/vet, staticcheck, govulncheck, gosec, ShellCheck, static cross-builds,
Debian package inspection, and artifact upload.

Third-party actions are pinned to full reviewed commit IDs. Self-hosted runners
must be GitHub Actions Runner 2.327.1 or newer for the pinned setup-go runtime.

The namespace suite needs a self-hosted Linux runner labeled
`nftfw-privileged` and repository variable
`NFTFW_PRIVILEGED_RUNNER=enabled`. Hosted GitHub runners do not provide the
required durable `CAP_NET_ADMIN` lab environment, so absence of this opt-in is
not represented as a pass.
