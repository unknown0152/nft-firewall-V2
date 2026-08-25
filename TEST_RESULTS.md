# NFT Firewall V2 2.0.3 RC Test Results

Release disposition: **RELEASE CANDIDATE - NOT DEPLOYABLE**

Evidence snapshot: 2026-08-25

Approval scope: source-only Stage R

This tracked record covers the reviewed source immediately before its renewed
freeze after a prior commit hard-stopped in the R2 systemd boot transaction.
It does not authorize installation, privileged testing, publication, or
deployment. Candidate build, extracted-archive, and cross-parent comparison
results are necessarily generated later and live in external evidence bound to
the corrected frozen commit and artifact hashes.

## Source-only gates executed

All commands below passed with Go `go1.25.13 linux/amd64` unless another tool
is named explicitly.

| Gate | Result | Command / exact scope |
| --- | --- | --- |
| Formatting | PASS | `make fmt-check` |
| Module integrity | PASS | `go mod verify` and `go mod tidy -diff` |
| Full unit/regression suite | PASS | `go test ./...` |
| Race suite | PASS | `go test -race ./...` |
| Vet | PASS | `go vet ./...` |
| Staticcheck | PASS | staticcheck 2026.1 / v0.7.0: `staticcheck ./...` |
| Vulnerability reachability | PASS | govulncheck module v1.1.4; database updated 2026-08-25: `govulncheck ./...`; no vulnerabilities found |
| Go security analysis | PASS | gosec module v2.28.0: `gosec -quiet -exclude-generated -exclude=G104,G204,G304,G302 ./...`; zero reported issues |
| Offline migration contract | PASS | Exact schema 1-5 fixtures reach ordered schema 6 only through `state migrate`; source and byte-identical backup match; weakened/unknown/active/sidecar/current/future/ambiguous/overwrite cases refuse |
| Stage R contracts | PASS | `bash ./tests/stage-r/run.sh`: source/package/systemd contracts including the independently scheduled early/readiness boot graph, eight release guards, immutable v2.0.1 expected-red proofs, provenance source shape, twelve comparator tests, and nine scanner tests |
| Staged systemd verification | PASS | `./tests/packaging/systemd_preflight.sh amd64`; temporary units and staged executables only |
| Shell quality | PASS | `bash -n`/`dash -n` and ShellCheck 0.10.0 across every changed installer, package, acceptance, namespace, and Stage R shell script |
| Current filesystem secret scan | PASS | `python3 scripts/secret-scan.py tree --root . --output -`; deterministic rules `nftfw.secret-rules/2026-08-24.1`, zero findings |
| Diff integrity | PASS | `git diff --check` |

Nine fuzz targets each passed a bounded five-second run with two workers:

- config decoding;
- Unix API request decoding;
- policy explanation;
- runtime-prefix compilation;
- nft transaction validation;
- canonical owned-ruleset JSON;
- foreign provenance-mask ruleset parsing;
- claim validation; and
- threat-feed parsing.

## Post-freeze Stage R artifact evidence

The tracked report deliberately does not claim these future enclosing results.
The candidate builder must independently produce and checksum:

- exact-commit plus reachable-history secret-scan evidence;
- six amd64/arm64 binaries with composite artifact identity;
- two intrinsically non-installable candidate Debian packages;
- ZIP and tar archives whose extracted path/type/mode/size/content trees match;
- byte-identical extracted-tree secret-scan evidence from both archive formats;
- a complete external candidate-build evidence record; and
- a second build in a different protected parent plus external byte-for-byte
  comparison evidence.

Those gates are PASS only if the generated external JSON records say so and
their SHA-256 subjects verify. They cannot be promoted by editing this frozen
source report.

## Privileged evidence boundary

**R2 PRIVILEGED PACKAGE/BOOT/NETWORK/DOCKER/OVPN EVIDENCE: NOT EXECUTED FOR
THIS SOURCE REVISION.**

A prior commit reached an R2 systemd boot hard stop. Its results do not transfer
to this corrected source revision. This revision performed none of the
following:

- nftables or network-namespace mutation;
- tunnel-loss packet capture or zero-physical-leak validation;
- package install, upgrade, removal, service activation, or reboot;
- database crash testing in a disposable Debian 13 environment;
- live Docker bridge recreation;
- real-provider OVPN validation; or
- installation, service changes, firewall mutation, or validation on the NUC.

Historical 2.0.1 and 2.0.0 results do not apply to the changed 2.0.3
provenance, persistence, Docker identity, package lifecycle, or boot graph.
Stage R2 requires a separately approved completed plan and approved disposable
environments. Deployment to the server remains a later, separate approval even
after R2.

Provider keys, tokens, public addresses, domains, usernames, device IDs, and
private topology must remain absent from every release evidence record.
