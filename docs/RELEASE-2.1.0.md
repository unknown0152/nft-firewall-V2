# Version 2.1.0 publication audit

Date: 2026-09-04

Status: **STABLE VALIDATION INCOMPLETE**

Version 2.1.0 was published on GitHub on 2026-09-04. Its downloadable files
are internally consistent, but the available evidence does not support final
stable approval. Version 2.0.3 remains the stable advanced-mode line.

## Verified downloads and source

- Source commit: `3851db45ed7e2f0c2935d20b6034595a6fc05bb0`.
- [Hosted CI](https://github.com/unknown0152/nft-firewall-V2/actions/runs/33909980990)
  passed quality, source contracts, and CI package checks. Its privileged R2
  job was skipped; hosted CI is not the runtime acceptance matrix.
- All four files downloaded from GitHub match their advertised SHA-256 hashes.
- The tar and ZIP archives contain the same 350 files. All 349 internal
  checksum entries and all 348 manifest hash/size/mode entries verify.
- Both standalone Debian packages match their archive copies byte for byte
  and identify version `2.1.0` with build disposition `release`.
- The private-build records report reproducibility and source scans. They do
  not establish complete boot, network, Docker, or provider acceptance.

The release provides `NFTFW-2.1.0-SHA256SUMS` for its four original downloads.
Run `sha256sum -c --ignore-missing NFTFW-2.1.0-SHA256SUMS` in the download
directory. A matching checksum does not resolve the acceptance gaps below.

## Evidence gaps

The attestation consumed by the tagged build has SHA-256
`02afb0c4155dffe23f03277e1e98ab51db2d3f5ebc9f793d5205dab0d8abc6a6`.
It asserts `R2_PASSED_TAG_BUILD_AUTHORIZED`, but both its candidate-comparison
and privileged-evidence-manifest digests are 64 zeroes. These are placeholders,
not links to verified evidence. No complete R2 runtime matrix, post-tag
validation, or final approval for this source was found in the inspected
release and protected evidence locations.

The packaging check at the published commit accepted those placeholders
because it checked only the hexadecimal shape. The subsequent source fix
rejects zero digests and malformed attestation inputs. This fix cannot
retroactively validate existing artifacts, and nonzero hashes alone still
require verification against actual evidence.

## Annotated tag discrepancy

| Identity | Object SHA |
| --- | --- |
| Tag object embedded in the archives' build provenance | `5f4e1333aeedd0dab9286f29a54faec531fd835d` |
| Published `v2.1.0` tag object | `674478be474ddb6067e405554f4c795f95a1f8e7` |
| Source commit reached by both objects | `3851db45ed7e2f0c2935d20b6034595a6fc05bb0` |

The two annotated tag objects differ only in tagger timestamp, by 693 seconds.
Source and package identities agree, but the exact tag-object provenance does
not. Existing tags and downloadable bytes are preserved for traceability.

## Requirements for stable completion

1. Run and retain the complete source-bound disposable R2 matrix, including
   failed-readiness packet captures and supported direct network producers.
   Verify each evidence reference against the actual protected records.
2. Resolve release identity without moving the published tag or silently
   replacing published downloads. Any corrected build needs its own verified
   provenance and an explicit publication path.
3. Verify two independent tagged builds and the required post-tag package,
   boot, network/leak, Docker, and real-provider checks. Preserve the distinction
   between amd64 runtime validation and arm64 artifact inspection.
4. Publish the final approval and sanitized evidence bound to the exact
   source, annotated tag, artifact checksums, and post-tag validation.

Any provider test that stops the development server's active VPN requires an
immediate downtime decision or an independent test connection. Publication
approval does not authorize changing the running server's firewall or VPN.

The original `FINAL_ACCEPTANCE_REPORT.md`, `BUILD_STATUS.md`, `TEST_RESULTS.md`,
and archived reports remain historical source-stage snapshots. Their wording
must not be used as evidence that later tests ran.
