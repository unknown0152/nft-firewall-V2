# NFT Firewall V2 Build Status

Release disposition: **FINAL RELEASE APPROVED**

Release validation completed: 2026-08-25

Target version: `2.0.3`

Validated source commit:
`e2b3fa0a20fa6e36325792397564966b21045120`

Annotated tag: `v2.0.3`

Tag object: `9038ff5f6ecd32d707cb8f6fffcd9e6dc9f3b20d`

| Phase | Status | Evidence boundary |
| --- | --- | --- |
| Source isolation and baseline | PASS | Exact clean source commit and reachable history inspected |
| Configuration/compiler/provenance | PASS | Pinned unit, race, vet, static, security, fuzz, and source-contract gates |
| Generation state and recovery | PASS | Immutable generations, schema migration, crash recovery, safe apply, timeout rollback, and boot verification |
| Docker stable identity | PASS | Exact configured tuple plus live bridge recreation and recovery |
| Package lifecycle/systemd graph | PASS | Fresh install, 2.0.2 upgrade, removal behavior, inert package lifecycle, early restore, readiness, and reboot |
| Network enforcement | PASS | Namespace and real-provider WireGuard tests, active-flow tunnel loss, provenance, IPv4/IPv6 policy, and zero physical leak |
| Reproducible release build | PASS | Independent protected-parent builds and byte-for-byte comparison |
| Package/archive inspection | PASS | amd64/arm64 binaries and Debian packages, ZIP/tar tree equality, modes, metadata, and checksums |
| Secret scanning | PASS | Source tree, reachable history, and independently extracted release trees |
| Dashboard contract | PASS | Fail-closed `nftfw.status.v2` consumer behavior |
| Post-tag validation | PASS | Exact annotated tag and final payload validation |
| Final release | PASS | External approval status `FINAL_RELEASE_APPROVED` |

The tracked source reports at the immutable `v2.0.3` tag intentionally record
the earlier pre-promotion Stage R boundary. Promotion evidence was generated
after that commit and was not used to rewrite or move the tag. The current
default branch adds public release and host-handoff documentation only; it
does not change the validated runtime source boundary.

Release integrity is provided by exact Git identities, SHA-256 manifests, and
reproducibility evidence. Publisher signatures are not currently provided.
