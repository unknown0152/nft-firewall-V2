# NFT Firewall V2 Acceptance Report Template

Release approval status: STAGE_R_CANDIDATE_ONLY

| Item | Value |
| --- | --- |
| Disposition | `@RELEASE_DISPOSITION@` |
| Version | `@RELEASE_VERSION@` |
| Artifact version | `@RELEASE_ARTIFACT_VERSION@` |
| Git commit | `@GIT_COMMIT@` |
| Git tag | `@GIT_TAG@` |
| Build date | `@BUILD_DATE@` |
| External artifact label | `@RELEASE_ARTIFACT_LABEL@` |
| Release source | `source/` inside the candidate bundle |
| Frozen source test record | `TEST_RESULTS.md` |

The release builder replaces the `@...@` tokens only in its copied report.
The tracked template cannot truthfully claim the result of a later enclosing
build. It therefore remains `STAGE_R_CANDIDATE_ONLY`; candidate-build,
two-parent comparison, R2, tagged-build, and final-publication evidence are
separate immutable records bound to exact hashes.

## Acceptance status

**NOT ACCEPTED FOR RELEASE OR DEPLOYMENT.**

The current 2.0.2 work is an untagged source-only Stage R candidate. No final
package, archive, checksum set, provenance statement, or `v2.0.2` tag has been
created. Candidate-mode output, if later built under the existing Stage R
scope, must say `RELEASE CANDIDATE - NOT DEPLOYABLE` and is test input only.

The passing pre-freeze pinned-toolchain and independent-review evidence is
recorded in `TEST_RESULTS.md`. Deterministic candidate construction and the
external two-parent comparison remain post-freeze Stage R gates.

## Privileged evidence boundary

**R2 PRIVILEGED PACKAGE/BOOT/NETWORK/DOCKER/OVPN EVIDENCE: NOT EXECUTED.**

No namespace firewall mutation, package installation, service activation,
reboot, Docker-daemon access, real OVPN use, host-network test, or NUC
deployment was performed for 2.0.2. Older release evidence is historical and
is not a substitute for rerunning changed code.

| Gate | 2.0.2 status |
| --- | --- |
| Source-only Stage R contracts | See the frozen `TEST_RESULTS.md`; exact tests are identified by command rather than a brittle count |
| Full pinned Go 1.25.13 quality/security matrix | See the frozen `TEST_RESULTS.md` |
| Enclosing candidate package/archive build and inspection | Recorded only by generated external `CANDIDATE_BUILD_EVIDENCE-NOT-DEPLOYABLE.json` |
| Two-parent deterministic candidate comparison | Recorded only by external `STAGE_R_CANDIDATE_COMPARISON.json` |
| Privileged namespace provenance/retag/leak tests | R2 NOT EXECUTED |
| Disposable-VM package lifecycle and boot recovery | R2 NOT EXECUTED |
| Docker bridge recreation and real OVPN | R2 NOT EXECUTED |
| Tagged final package rerun | NOT EXECUTED |
| Actual NUC/server installation | NOT EXECUTED |

## External final-release promotion gate

This frozen template is not changed merely to insert evidence produced after
its commit. Promotion requires separate immutable records in this order:

1. Stage R passes against one frozen, reviewed, clean commit.
2. The completed deployment/R2 plan receives separate approval.
3. All required privileged R2 package, boot, database, network, Docker, and
   real-OVPN gates pass against that exact commit in approved disposable test
   environments.
4. An external `nftfw.r2-attestation.v1` record authorizes only tagged
   validation and keeps deployment unauthorized.
5. The immutable annotated `v2.0.2` tag points to that commit.
6. Post-tag final packages are built and the required package lifecycle,
   boot, leak, reproducibility, inspection, and secret-scan gates pass again.
7. A `nftfw.post-tag-validation.v1` manifest binds every named PASS gate to the
   exact commit, annotated tag object, tagged-build evidence, and artifact
   checksum set.
8. An external `nftfw.final-release-approval.v1` record says
   `FINAL_RELEASE_APPROVED` and identifies the exact tagged-build evidence,
   checksums, tag object, and post-tag validation manifest SHA-256. Deployment
   still requires the separately approved deployment plan.

A failure after tagging quarantines that tag and its unpublished artifacts; it
does not permit moving the tag, rewriting the frozen report, or silently
replacing the source.

## Candidate limitations

- Checksums and generated provenance are unsigned and do not authenticate an
  artifact publisher.
- Hardware, kernel, nftables, systemd, Docker, WireGuard, provider, and actual
  topology behavior remains unproved until R2.
- Candidate quarantine is intrinsic: `nftfw` permits only `version`, the daemon
  and web binary refuse startup, and candidate Debian packages refuse
  installation before unpack.
- The dashboard is loopback-only and has no application login; it must never be
  exposed without a separately approved authentication/TLS boundary.
- Installation and deployment remain prohibited under the Stage R approval.

## Expected enclosing candidate artifact inventory

Candidate mode uses the visibly quarantined label below rather than a
final-looking output directory, archive, binary, or package name. In a copied
candidate report, `@RELEASE_ARTIFACT_LABEL@` expands to
`2.0.2-RELEASE-CANDIDATE-NOT-DEPLOYABLE-<commit12>`; `<commit12>` below is the
first 12 hexadecimal characters of `@GIT_COMMIT@`. Its non-final embedded and
Debian artifact version is `2.0.2~stage.r.<commit12>`.

```text
nft-firewall-v2-@RELEASE_ARTIFACT_LABEL@/
nft-firewall-v2-@RELEASE_ARTIFACT_LABEL@.zip
nft-firewall-v2-@RELEASE_ARTIFACT_LABEL@.tar.gz
nftfw-linux-amd64-RELEASE-CANDIDATE-NOT-DEPLOYABLE-<commit12>
nftfw-linux-arm64-RELEASE-CANDIDATE-NOT-DEPLOYABLE-<commit12>
nftfwd-linux-amd64-RELEASE-CANDIDATE-NOT-DEPLOYABLE-<commit12>
nftfwd-linux-arm64-RELEASE-CANDIDATE-NOT-DEPLOYABLE-<commit12>
nftfw-web-linux-amd64-RELEASE-CANDIDATE-NOT-DEPLOYABLE-<commit12>
nftfw-web-linux-arm64-RELEASE-CANDIDATE-NOT-DEPLOYABLE-<commit12>
nft-firewall-v2_@RELEASE_ARTIFACT_LABEL@_amd64.deb
nft-firewall-v2_@RELEASE_ARTIFACT_LABEL@_arm64.deb
RELEASE-CANDIDATE-NOT-DEPLOYABLE.txt
FINAL_ACCEPTANCE_REPORT.md
SOURCE_SECURITY_AUDIT.md
SOURCE_TEST_RESULTS.md
SOURCE_HISTORY_SECRET_SCAN.json
EXTRACTED_TREE_SECRET_SCAN.json
CANDIDATE_BUILD_EVIDENCE-NOT-DEPLOYABLE.json
SHA256SUMS
```

The directory line is the container for the remaining listed files, not an
entry in its own `SHA256SUMS`. The builder appends embedded binary/package
checksums to its copied report and adds enclosing archive checksums only to the
external copy. Each archive also embeds the standalone warning and its own
integrity inventory. `SOURCE_HISTORY_SECRET_SCAN.json` binds the exact commit
and its reachable history; `EXTRACTED_TREE_SECRET_SCAN.json` is published only
when independent ZIP and tar extractions produce byte-identical PASS evidence.
Generic binary/package names found only inside a
quarantined archive contain the non-final artifact version and remain
candidate test inputs. The build-evidence JSON inventories every enclosing
candidate artifact except itself and `SHA256SUMS`; the enclosing checksum file
then covers the evidence JSON as well. None of these integrity records changes
this report's acceptance disposition.
