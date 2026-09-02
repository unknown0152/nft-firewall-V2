# NFT Firewall V2

NFT Firewall V2 2.1.0 turns a working WireGuard provider profile into a
managed, fail-closed Debian firewall. On a supported clean server, setup has
one operator input:

```bash
sudo apt install "./nft-firewall-v2_2.1.0_$(dpkg --print-architecture).deb"
sudo nftfw setup --vpn /path/to/working-vpn.conf
```

The package installation is inert. The setup command then discovers the
uplink, private LAN, SSH management ports, resolver, firewall ownership, and
container state. It imports the VPN profile without printing secrets,
generates the strict policy, prepares one exact Debian GRUB/initramfs boot
boundary, and pauses for an explicit reboot. The operator reruns the same
profile-only command after that reboot; only then does setup create the
managed WireGuard interface and policy routing, install the rollback guard,
apply safely, validate the tunnel and kill switch, commit, and enable boot
protection. NFTFW never reboots the server automatically.
All parsing and clean-host discovery finish before the setup journal exists.
The journal is published with the complete redacted plan immediately before
the backup and protected mutation phases begin.

Before the first reboot, setup owns only the protected backup, native
initramfs sources, fixed root-only
`90-nftfw-ipv6-disabled.cfg` fragment, regenerated GRUB configuration, and
durable `reboot_required` journal. It has not enabled forwarding, changed
Docker ownership, started the VPN, published enforcement, or exposed a port.
Resume requires a changed boot ID, exactly one `ipv6.disable=1` kernel token,
the kernel disable parameter, no IPv6 address state, and unchanged prepared
boot and plan identities.

On the resumed boot, the packaged pre-network service atomically replaces the
initramfs all-interface deny table with a checksum-bound resume guard. That
guard permits only DHCP, the already reviewed private-LAN management ports,
and the cached WireGuard endpoint; the cached root-only endpoint set means DNS
is not required at this boundary. Docker service and socket activation remain
held separately. Rerunning the same setup command verifies the guard, writes
NFTFW's Docker and forwarding ownership, asks for the restart confirmation,
and only then releases Docker. Any missing, additional, changed, or
contradictory table/hold state fails closed.

After resume, setup deliberately starts `nftfwd` before publishing its final
`Requisite=nftfw-early.service` drop-ins. After commit it starts and verifies
early enforcement, verifies the checksum-bound initramfs deny guard, and only
then publishes the final boot dependencies. The kernel argument is the
pre-driver IPv6 boundary; the initramfs nftables guard remains defense in
depth and is removed only by the verified readiness service.

The clean-host result is:

- IPv4 Internet through the WireGuard VPN only;
- no physical-uplink fallback;
- IPv6 disabled;
- eligible Docker IPv4 bridge networks routed through the VPN only;
- current private-LAN SSH management preserved;
- no public inbound exposure;
- a loopback-only read-only dashboard;
- durable boot recovery and automatic rollback.

## Release status

The current tree targets **2.1.0** and requires **Go 1.27.0**. Until Stage
E-R2, tagging, and final publication approval are complete, local Stage E-R
candidate artifacts are deliberately quarantined and cannot run or install.
The last published stable line remains 2.0.3.

The E-R2 run for source `01d559e884277a9b819aa712dec5620fed2d796a`
passed seventeen disposable package, boot, network, Docker, recovery, and
nonmutation subjects, then hard-stopped on the mandatory installed dashboard
performance gate: CLI status p95 was 67.224 ms, but `/api/status` p95 was
65.231 ms against an exclusive 50 ms budget. No tag was created. Amendment AA
corrects the demonstrated process fan-out while keeping every fresh,
fail-closed check: one immutable nftables ruleset read now supplies ownership,
integrity, fingerprint, and foreign-provenance results, and one immutable-ID
Docker inspect batch verifies all authorized networks. A fresh disposable
managed-Docker diagnostic measured CLI p95 36.367 ms and dashboard p95 32.658
ms, with all resource budgets passing; it had no independent provider
assignment and therefore is not protected-status acceptance. Adjacent-request regressions prove that
nftables drift, forwarding loss, Docker drift, WireGuard loss, database
failure, and provenance failure degrade the very next completed response.
The complete E-R2 matrix must run the strict shipped harness, which requires a
healthy protected result on every sample, for the eventual frozen candidate.
This tree remains source-only and is not yet a release.

## Supported clean-host setup

The one-file path intentionally supports a narrow first matrix:

- Debian 13 stable with systemd;
- amd64 or arm64;
- exactly one usable IPv4 default uplink;
- local console or directly connected private LAN management;
- one strict wg-quick-style profile with one peer and `0.0.0.0/0`;
- nftables JSON support and no competing firewall owner;
- one unambiguous local Debian GRUB installation (`grub-pc` on BIOS or the
  matching GRUB EFI family), writable local boot storage, and no systemd-boot,
  UKI, extlinux, alternate GRUB tree, or existing IPv6-disable argument;
- no existing NFTFW state, except one fully verified terminal first-setup
  rollback described below;
- Docker absent, or reachable only through the local socket with no running
  or retained containers and only eligible, non-overlapping IPv4 bridge
  networks.

Managed setup may adopt the built-in bridge and normal Compose-style bridge
networks when they contain no workload. Eligible empty custom networks remain
supported so containers can be created after protection is active. Any
running or retained container requires a separate existing-host plan and is
refused by clean-host setup. Setup shows every network and ownership change
before mutation. If Docker daemon settings must change, setup asks again
immediately before one Docker restart. Macvlan, ipvlan, overlay, Swarm,
Kubernetes, internal, IPv6, overlapping, malformed, or changing Docker
topologies are refused.

A failed first setup does not erase audit or provenance evidence. After
`nftfw setup rollback` reports `rolled_back`, the same setup command permits a
terminal retry only when the exact restored backup, inactive managed units,
clean firewall/routing state, rolled-back immutable generations, endpoint
cache, and monotonic provenance ledger all validate together. The previous
terminal journal is archived durably before a new transaction can mutate;
every incomplete or ambiguous state still requires adoption or recovery.

Existing NFTFW installations, multiple uplinks, split tunnels, provider
hooks, multiple peers, and native IPv6 are not silently changed. An existing
compatible 2.0.3 advanced-mode installation can generate a redacted worksheet:

```bash
sudo nftfw setup adopt --vpn /path/to/working-vpn.conf --dry-run
```

The 2.1.0 adoption command is planning-only. It verifies the configuration,
schema-6 generation, enforcement pointer, immutable snapshot, provenance,
unit states, routing, resolver, and eligible Docker topology twice without a
mutation lock or host changes. Actual conversion remains a separately
approved, topology-specific Stage E-L operation.

## Daily commands

```bash
sudo nftfw health
sudo nftfw tunnel status
sudo nftfw exposure list
sudo nftfw lan list
sudo nftfw config show --effective
```

With managed Docker enabled, `health` and `config show` report the adopted
network names and prove that kernel IPv4 forwarding is NFTFW-owned.

Later exposure remains explicit and VPN-side only:

```bash
sudo nftfw expose add tcp 80 443
sudo nftfw expose remove tcp 80 443
sudo nftfw lan allow tcp 8096
sudo nftfw lan deny tcp 8096
```

Mutating managed commands show the resulting policy and require confirmation.
Use `--dry-run`, `--yes`, and `--json` for automation.
Each committed change is compiled from the exact protected files and guarded
by independent file-transaction and pending-generation rollback timers.

## Security model

NFTFW owns only `inet nftfw_filter`, `ip nftfw_nat`, and
`ip6 nftfw_filter6`. It never runs `nft flush ruleset`. Safe apply,
generation commit, exact rollback, immutable boot snapshots, a monotonic
provenance ledger, and independent systemd rollback services protect the
transition.

Before a 2.0.3-to-2.1.0 package upgrade, the release-provided
`nftfw-package-rollback` helper creates a root-only, checksummed bundle. Its
package-manager bridge carries the exact 2.0.3 payload at a temporary lower
Debian version, allowing the unmodified exact 2.0.3 package to complete its
own guarded installation without editing dpkg state or bypassing maintainer
scripts. The bridge pre-install boundary accepts only Debian's exact
three-argument downgrade call while `dpkg-query` reports the observed
`iHR 2.1.0` transition. It also binds the generated bridge version,
architecture, both package hashes, both binary hashes, optional exact
schema-6 history, protected file metadata, and the verified bundle transition
identity; configured or neighboring package states fail closed. While exact
2.0.3 runs its historical lock-taking backup, the controller retains the real
global mutation lock and gives only the dpkg descendant tree a protected
transaction-local view of that pathname in a private mount namespace. This
avoids self-deadlock without exposing an unlocked mutation interval.
Before boot handoff or either dpkg step, the controller extracts the bound
exact 2.0.3 binary and silently validates the current configuration with that
parser; a v2.1-only field refuses without disclosing configuration content.
The bridge accepts a schema-6 database only as a root-owned, single-link,
mode-0600 regular file whose group is either the legacy `root` group or the
exact `nftfw-web` service group.

The VPN importer accepts only documented WireGuard data fields. It rejects
hooks, commands, `SaveConfig`, provider routing directives, split tunnels,
IPv6 values, unknown fields, multiple peers, unsafe files, and replacement
during read. VPN keys are stored only in the root-owned managed WireGuard
file, never in intent, status, logs, evidence, or the dashboard.

The dashboard is read-only, binds to loopback by default, and has no control
socket, nftables, WireGuard, or Docker privilege.

## Documentation

- `QUICKSTART.md`: supported two-command setup and verification.
- `SUPPORTED-PLATFORMS.md`: exact accepted and refused topologies.
- `VPN-PROFILES.md`: strict provider-profile contract.
- `INSTALL.md`: package and source installation behavior.
- `docs/CLI.md`: managed and advanced commands.
- `docs/RECOVERY.md`: setup, tunnel, generation, boot, and database recovery.
- `docs/UPGRADING.md`: compatible 2.0.3-to-2.1.0 upgrade behavior.
- `SECURITY.md`: security boundary and reporting.
- `docs/ARCHITECTURE.md`: compiler, state, setup, routing, and service design.
