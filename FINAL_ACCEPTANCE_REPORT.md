# NFT Firewall V2 Final Acceptance Report

| Item | Value |
| --- | --- |
| Version | `@RELEASE_VERSION@` |
| Git commit | `@GIT_COMMIT@` |
| Git tag | `@GIT_TAG@` |
| Build date | `@BUILD_DATE@` |
| Product repository | `/root/nft-firewall-work/nft-firewall-v2` |
| Host baseline | `/root/nft-firewall-work/HOST_BASELINE.md` |

The packaging process replaces the metadata tokens in this report inside the
release tree. The tracked source keeps tokens because a Git commit cannot
contain its own final hash.

## Environment

Baseline: Debian GNU/Linux 13.5, Linux 6.12.94 amd64, systemd 257.13,
nftables 1.1.3, iproute2 6.15.0, WireGuard tools 1.0.20210914, native IPv4
and IPv6, KVM guest. Docker was absent and Go was 1.24.4 at baseline.

Build/acceptance: Go 1.25.13, Docker 26.1.5 with firewall/routing/proxy
ownership disabled, and 2 GiB temporary build swap. The host started and ended
guarded firewall acceptance with no V2-owned host table active.

## Architecture acceptance

PASS. V2 is an independent Go repository. Desired, observed, and effective
state are separate. The compiler is deterministic and pure. `nftfwd` is the
single mutation boundary over root-only control and read-only status Unix
sockets. Owned operation is limited to `inet nftfw_filter`, `ip nftfw_nat`,
and `ip6 nftfw_filter6`; no normal operation uses `flush ruleset`.

SQLite stores migrations, generations, pending/committed state, provenance
claims, endpoint/integration state, reconciliation and audit. Safe apply uses
a persistent deadline, daemon enforcement, independent systemd timer, and
pre-network committed snapshot.

## V1 parity and invariants

PASS. The frozen V1 checkout, full source manifest, test assertion index, and
history inventory were reviewed. Every significant capability is classified
in `V1_FEATURE_PARITY.md`; deliberate drops include technical/security
rationale. Extracted guarantees are in `SECURITY_INVARIANTS.md`.

## Gate summary

| Gate | Result |
| --- | --- |
| Build, amd64 and arm64 | PASS |
| Unit tests | PASS |
| Race tests | PASS |
| Vet/static analysis | PASS |
| Vulnerability analysis | PASS, no reachable findings |
| Fuzz/property tests | PASS |
| Namespace firewall | PASS |
| Simulated WireGuard kill switch | PASS |
| Real provider WireGuard | PASS |
| IPv4 leak capture | PASS, zero packets |
| IPv6 leak capture | PASS, zero packets |
| Active TCP/UDP connection failure | PASS |
| Docker lifecycle and real container | PASS |
| Provenance union/removal | PASS |
| Safe apply, commit, crash, timeout rollback | PASS |
| Drift and unrelated-table preservation | PASS |
| Database migration/corruption/backup | PASS |
| Service/API crash and abuse | PASS |
| systemd verification/hardening | PASS |
| Security audit | PASS, no unresolved high/critical |
| Secret/history/archive scan | PASS, no leaks found |
| Debian amd64/arm64 packages | PASS |
| Archive integrity and reproducibility | PASS |
| Full VPS reboot | NOT EXECUTED; see limitation below |

Detailed non-secret evidence is in `TEST_RESULTS.md`. Raw sanitized logs remain
under `/root/nft-firewall-work/test-results` and are not archived because they
contain host/provider topology diagnostics.

## Network acceptance

The namespace suite used actual nftables rules and an in-kernel WireGuard
tunnel. Healthy host/container IPv4 and IPv6 passed. After tunnel removal,
new and established TCP/UDP host/container traffic failed without appearing
on the physical capture:

```text
LEAKED INTERNET PACKETS: 0
LEAKED IPV6 INTERNET PACKETS: 0
```

The supplied real provider profile was root-owned mode `0600` and its key was
never printed. It passed handshake, changed public IPv4, DNS, IPv6, namespace
container, actual Docker container, endpoint refresh, daemon restart, loss,
physical capture, WireGuard recovery, and Docker recovery:

```text
REAL LEAKED PHYSICAL PACKETS: 0
REAL WIREGUARD ACCEPTANCE: PASS
```

Guarded host acceptance separately proved an independent transient rollback,
retained the declared active SSH connection, captured direct IPv4/IPv6
attempts with an absent test VPN, committed and explicitly rolled back, killed
the test daemon, and observed independent timeout rollback. Both host capture
counts were zero and an unrelated table survived.

## Systemd hardening

`systemd-analyze verify` passed. Exposure scores on the acceptance host were
2.8 for the web service and 3.9 for the privileged daemon, rollback, and early
restore services. The daemon receives only `CAP_NET_ADMIN`; the dashboard has
an empty capability set and status-only access. Exceptions are documented in
`docs/ARCHITECTURE.md` and are required for netlink, local sockets, endpoint
DNS, and the loopback HTTP listener.

## Security audit

The review covered command injection, argument injection, temp/path/symlink
safety, socket authorization, capabilities, nft ownership, hidden allows,
conntrack/IPv6/physical bypass, rollback races, parser/resource bounds,
database injection/concurrency, HTTP XSS/CSRF/timeouts, and secret handling.
All high findings discovered during implementation were repaired and
regression tested. See `SECURITY_AUDIT.md`.

Gitleaks scanned the complete V2 history, current tree, and extracted release
with redaction enabled and found no leak. Independent filename/content checks
also passed. The release builder produced byte-identical ZIP and tar.gz files
on two builds from the same commit before the final tagged run.

## Limitations

1. No full VPS reboot was executed because this was the only live SSH
   management host. Boot ordering and every early snapshot branch were tested
   through the real systemd unit and namespace/state harness.
2. The real provider test was isolated in namespaces; its tunnel did not
   replace the VPS management namespace's default route. Host-level firewall
   mutation was tested separately under two independent rollback mechanisms.
3. DNS authoritative TTLs are not available through the current standard Go
   resolver; endpoint refresh uses a documented 60-second cadence and bounded
   age/history.
4. IPv6 NAT, remote ChatOps, notifications, Prometheus export, report images,
   and intrusion-event adapters are not implemented in v2.0.0.
5. V2 observes and can update one WireGuard peer endpoint, but tunnel creation,
   private keys, and policy routing remain operator responsibilities.

No limitation is an unresolved high or critical finding. The reboot item is
reported `NOT EXECUTED`, not PASS.

## Release artifacts

Expected enclosing paths:

```text
/root/nft-firewall-work/releases/nft-firewall-v2-@RELEASE_VERSION@.zip
/root/nft-firewall-work/releases/nft-firewall-v2-@RELEASE_VERSION@.tar.gz
/root/nft-firewall-work/releases/SHA256SUMS
```

The release builder appends exact binary/package checksums to the embedded
copy of this report before manifest generation. It appends the enclosing ZIP
and tar checksum to the external copy after archive creation, because an
archive cannot contain its own checksum.
