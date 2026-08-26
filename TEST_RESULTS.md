# NFT Firewall V2 2.0.3 Test Results

Release disposition: **FINAL RELEASE APPROVED**

Validated source commit:
`e2b3fa0a20fa6e36325792397564966b21045120`

Annotated tag: `v2.0.3`

Post-tag validation completed: 2026-08-25 23:35:37 UTC

The detailed raw evidence remains outside the public repository because it
contains disposable-lab and provider topology. The public result below records
only non-secret gate outcomes bound to the exact source and tag.

## Source and quality gates

All required source gates passed with Go `go1.25.13 linux/amd64`.

| Gate | Result |
| --- | --- |
| Formatting | PASS |
| Module verification and tidy check | PASS |
| Full unit and regression suite | PASS |
| Race suite | PASS |
| Vet | PASS |
| Staticcheck v0.7.0 | PASS |
| govulncheck v1.7.0 | PASS, no reachable vulnerabilities |
| gosec v2.28.0 reviewed profile | PASS |
| Bounded fuzz targets | PASS |
| Shell syntax and ShellCheck | PASS |
| Stage R source/package/systemd contracts | PASS |
| Current-tree secret scan | PASS, zero findings |
| Exact reachable-history secret scan | PASS |

## Build and artifact gates

| Gate | Result |
| --- | --- |
| Independent protected-parent candidate builds | PASS |
| Byte-for-byte candidate comparison | PASS |
| Static amd64 and arm64 binaries | PASS |
| amd64 and arm64 Debian packages | PASS |
| ZIP and tar extracted-tree equality | PASS |
| File type, mode, size, content, and manifest inspection | PASS |
| Extracted-tree secret scans | PASS |
| Tagged final build | PASS |
| Post-tag two-build reproducibility | PASS |
| Final checksum-set verification | PASS |

The Stage R comparison record reported
`STAGE_R_CANDIDATE_COMPARISON_PASS`. The R2 attestation reported
`R2_PASSED_TAG_BUILD_AUTHORIZED`. The post-tag manifest reported
`POST_TAG_VALIDATION_PASS`, and the final approval record reported
`FINAL_RELEASE_APPROVED`.

## Privileged R2 gates

| Gate | Result |
| --- | --- |
| nftables namespace policy and ownership | PASS |
| Connection-provenance and reply-path enforcement | PASS |
| Tunnel-loss active TCP/UDP behavior | PASS |
| Physical-uplink IPv4 leak capture | PASS, zero leaked Internet packets |
| Physical-uplink IPv6 leak capture | PASS, zero leaked IPv6 packets |
| Safe apply, commit, timeout rollback, and emergency rollback | PASS |
| Generation/database crash and recovery behavior | PASS |
| Offline schema 1-5 to schema 6 migration contract | PASS |
| Fresh package install and removal lifecycle | PASS |
| Supported 2.0.2-to-2.0.3 package upgrade | PASS |
| systemd early restore and readiness graph | PASS |
| Boot and reboot recovery | PASS |
| Docker stable bridge recreation and recovery | PASS |
| Real-provider WireGuard/OVPN path | PASS |
| Dashboard `nftfw.status.v2` fail-closed contract | PASS |

## Reference live-host validation

A controlled development-host deployment completed with:

- release `2.0.3`;
- a committed healthy generation;
- kill switch enforced;
- host and container IPv4 egress through the declared VPN;
- IPv6 disabled for a provider without IPv6;
- Docker and dashboard integrations healthy;
- only the explicitly declared inbound TCP services exposed; and
- committed enforcement restored successfully after reboot.

This proves the reviewed reference topology. It does not prove a different
machine's interfaces, routes, management policy, VPN profile, Docker networks,
or service exposure. Every new host must complete `docs/HOST-HANDOFF.md` and
the read-only preflight before activation.

## Reproduction commands

The unprivileged gates can be rerun from the exact release source:

```bash
make check
go test -race ./...
go vet ./...
bash -n scripts/*.sh packaging/deb/* packaging/systemd/*
shellcheck \
  scripts/*.sh \
  tests/acceptance/*.sh \
  tests/chaos/*.sh \
  tests/namespaces/*.sh \
  tests/packaging/*.sh \
  tests/stage-r/*.sh \
  packaging/deb/preinst \
  packaging/deb/postinst \
  packaging/deb/prerm \
  packaging/deb/postrm
python3 scripts/secret-scan.py tree --root . --output -
```

Privileged acceptance scripts mutate isolated network namespaces, Docker, or
test firewall state and must run only in a disposable, explicitly approved
environment with an independent recovery path.
