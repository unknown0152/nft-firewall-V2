# Development

The 2.1.0 release line uses exact Go 1.27.0. `go.mod` pins the language and
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
shellcheck scripts/*.sh packaging/initramfs/nftfw-ipv6-early \
  packaging/initramfs/nftfw-udev-gate \
  packaging/initramfs/nftfw-early-guard-hook \
  packaging/initramfs/nftfw-initramfs-manage \
  packaging/systemd/nftfw-setup-boot-hold-generator \
  tests/*.sh tests/acceptance/*.sh tests/chaos/*.sh tests/namespaces/*.sh \
  tests/packaging/*.sh packaging/deb/*inst packaging/deb/prerm
```

The audited analyzer versions are staticcheck v0.8.1, govulncheck v1.7.0,
and gosec v2.29.0. The gosec target excludes four heuristic classes only after
manual review: ignored cleanup errors, command execution, file paths, and a
deliberately group-readable status socket. Argument arrays, fixed/validated
paths, and socket purpose are reviewed in `SECURITY_AUDIT.md`.

## Build

```bash
make build
make release VERSION=2.1.0+ci COMMIT=$(git rev-parse HEAD) \
  BUILD_DATE=$(git show -s --format=%cI HEAD) DISPOSITION=ci
make deb VERSION=2.1.0+ci COMMIT=$(git rev-parse HEAD) DISPOSITION=ci
./tests/packaging/systemd_preflight.sh amd64
```

Release builds set `CGO_ENABLED=0`, `GOOS=linux`, use `-trimpath`, disable
ambient VCS auto-discovery, omit the Go build ID, and embed version, commit,
and a controlled build date. amd64 and arm64 are produced.
`SOURCE_DATE_EPOCH` is honored by final package tooling.

Source-only Stage R may exercise candidate packaging only from a clean tree:

```bash
GOTOOLCHAIN=go1.27.0 ./scripts/package-release.sh 2.1.0 --allow-untagged
```

That mode derives the quarantine label
`2.1.0-RELEASE-CANDIDATE-NOT-DEPLOYABLE-<commit12>`. The output directory,
both archive filenames, and both standalone package filenames contain that
full label. Every standalone binary filename contains
`RELEASE-CANDIDATE-NOT-DEPLOYABLE-<commit12>`. The external directory also
contains the standalone `RELEASE-CANDIDATE-NOT-DEPLOYABLE.txt` warning, and
the copied report metadata and console output repeat the disposition. Candidate
binaries and the packages enclosed by the archives use the non-final artifact
version `2.1.0~stage.r.<commit12>`. Quarantine is enforced at runtime too:
candidate `nftfw` permits only `version`, candidate `nftfwd` and `nftfw-web`
refuse startup, and candidate Debian `preinst` refuses installation. These are
test inputs, not installable or publishable release artifacts. Tagged final
validation packaging requires an annotated tag and an external, protected R2
attestation bound to the exact version and commit. The frozen report at the
release tag remains `STAGE_R_CANDIDATE_ONLY`; later publication documentation
must not rewrite the commit it attests to.

The release script refuses any Go toolchain other than exact Go 1.27.0
and records that toolchain in the manifest and unsigned in-toto provenance
statement. SHA256 manifests provide integrity; release signing requires an
operator-controlled signing identity and is intentionally not fabricated by
the build.

The script builds from an immutable export of the captured Git commit, verifies
the complete artifact set in a temporary directory, and atomically publishes
with no-replace semantics into the pre-created protected default parent as
`../releases/nft-firewall-v2-2.1.0-RELEASE-CANDIDATE-NOT-DEPLOYABLE-<commit12>/`.
That directory contains two quarantined archives, six visibly quarantined
standalone binaries, two visibly quarantined standalone Debian packages,
`FINAL_ACCEPTANCE_REPORT.md`, `SOURCE_SECURITY_AUDIT.md`,
`SOURCE_TEST_RESULTS.md`, `SOURCE_HISTORY_SECRET_SCAN.json`,
`EXTRACTED_TREE_SECRET_SCAN.json`,
`CANDIDATE_BUILD_EVIDENCE-NOT-DEPLOYABLE.json`, the standalone warning, and
the enclosing `SHA256SUMS`. The extracted-tree record is emitted only after
both ZIP and tar extractions pass and their deterministic scan evidence is
byte-identical. The archives contain their
own warning and integrity inventory; any generic internal binary/package names
remain enclosed `2.1.0~stage.r.<commit12>` test inputs and must not be extracted
for installation during Stage R. The script serializes release builds and
refuses to replace an existing artifact-label directory.

For the required two-build reproducibility check, pre-create a different empty
directory for each invocation and a separate evidence directory. Each must be
owned by the invoking user, must not be writable by group/other, and must have
no unsafe or symlinked ancestor (a root-owned sticky `/tmp` ancestor is
allowed). The builder never creates or relaxes these trust roots.

```bash
install -d -m 0700 /absolute/parent-a /absolute/parent-b /absolute/evidence
NFTFW_RELEASE_PARENT=/absolute/parent-a GOTOOLCHAIN=go1.27.0 \
  ./scripts/package-release.sh 2.1.0 --allow-untagged
NFTFW_RELEASE_PARENT=/absolute/parent-b GOTOOLCHAIN=go1.27.0 \
  ./scripts/package-release.sh 2.1.0 --allow-untagged
```

Then generate the external comparison record:

```bash
python3 ./scripts/compare-candidate-builds.py \
  --left /absolute/parent-a/nft-firewall-v2-2.1.0-RELEASE-CANDIDATE-NOT-DEPLOYABLE-<commit12> \
  --right /absolute/parent-b/nft-firewall-v2-2.1.0-RELEASE-CANDIDATE-NOT-DEPLOYABLE-<commit12> \
  --output /absolute/evidence/STAGE_R_CANDIDATE_COMPARISON.json
```

The comparison verifies the complete enclosing checksum sets and byte-for-byte
tree equality. Its external JSON is the temporally correct evidence for a
comparison that cannot be claimed inside either earlier build.

`--allow-untagged` exists only to exercise packaging before release. It always
sets the embedded manifest tag to `unreleased` and refuses to run on a commit
already carrying the matching release tag. Omitting it requires a matching
annotated `v<version>` tag plus `NFTFW_R2_ATTESTATION=/absolute/protected.json`.
That attestation must use schema `nftfw.r2-attestation.v1`, status
`R2_PASSED_TAG_BUILD_AUTHORIZED`, identify the exact target version/commit and
Stage R comparison digest, record the complete privileged R2 family as
`PASS`, bind the sanitized privileged-evidence manifest SHA-256, and keep both
`publication_authorized` and `deployment_authorized` false. The resulting tagged bytes and
their generated evidence remain publication/deployment pending. Only a later
external `FINAL_RELEASE_APPROVED` record referencing their exact hashes may
authorize publication. That approval must also bind the exact annotated tag
object and the SHA-256 of a `nftfw.post-tag-validation.v1` manifest containing
the named package, boot, network/leak, Docker, OVPN, reproducibility,
inspection, and secret-scan results. A tag is never moved and the frozen source
is never amended merely to insert later results.

The post-R2 tagged build uses the canonical `2.1.0` archive, binary, and
package filenames inside a protected non-public parent. Its notice and build
evidence state that external final approval is still required. Approval may
therefore authorize the already checksummed canonical path set without
renaming files or changing bytes.

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
unit/race/vet, staticcheck, govulncheck, gosec, ShellCheck, unprivileged Stage R
source contracts, static cross-builds, Debian package inspection, and artifact
upload. It does not describe the hosted source-contract job as R2 evidence.

Third-party actions are pinned to full reviewed commit IDs. Self-hosted runners
must be GitHub Actions Runner 2.327.1 or newer for the pinned setup-go runtime.

The namespace suite needs a self-hosted Linux runner labeled
`nftfw-privileged` and repository variable
`NFTFW_PRIVILEGED_RUNNER=enabled`. It is additionally gated by
`NFTFW_STAGE_R2_APPROVED=enabled`; Stage R approval alone must not satisfy that
condition. Hosted GitHub runners do not provide the required durable
`CAP_NET_ADMIN` lab environment, so absence of either opt-in is not represented
as a pass.

Amendment M also has two narrowly scoped root source regressions. They use
disposable mount/network namespaces or disposable package construction and do
not install NFTFW or touch the host package database:

```bash
sudo ./tests/initramfs-guard-namespace.sh
sudo ./tests/package-rollback-bundle.sh
```

The first verifies that the native initramfs loader accepts only an exact
kernel-level IPv6-disable proof, applies the checksum-bound nftables guard, and
fails closed during archive inspection. The second verifies the protected rollback
bundle, exact 2.0.3 payload-equivalent bridge, exact `iHR` transition, and
argument/state/identity/metadata/tamper/path refusals. The disposable package
test additionally proves the parent canonical lock remains externally held
while dpkg's private mount namespace satisfies the legacy pre-install backup.
Full boot packet capture and the complete Amendment E through X privileged
matrix must be repeated as E-R2 guest gates. The source-stage Amendment X
preflight has already passed its two-boot zero-pre-readiness capture,
contradictory-identity zero-guest capture, boot rollback/handoff cases, and
exact-package rollback guest transaction; those results do not substitute for
the later complete E-R2 run.
