# Installation

NFT Firewall V2 `2.0.3` is an accepted release. Use the exact annotated
`v2.0.3` tag at commit
`e2b3fa0a20fa6e36325792397564966b21045120`, or a package whose bytes and
checksums came from that validated release build.

Installation is deliberately separate from activation. Before installing,
complete the read-only preflight and host-specific checklist in
`docs/HOST-HANDOFF.md`.

## Requirements

- Linux with nftables kernel support
- nftables 1.0 or newer with JSON output
- iproute2 and WireGuard tools
- systemd
- root for installation and control operations
- Go 1.25.13 only when building from source

The installer does not install or start a VPN profile. WireGuard creation,
private keys, routing, and provider configuration remain separate operator
responsibilities.

## GitHub release package

```bash
sha256sum -c --ignore-missing NFTFW-2.0.3-SHA256SUMS
sudo apt install \
  "./nft-firewall-v2_2.0.3_$(dpkg --print-architecture).deb"
```

Download the checksum file and package for the target architecture from the
GitHub `v2.0.3` release. A checksum proves file integrity but not publisher
identity; independently verify the tag and expected commit when the download
path is not already trusted.

Do not install artifacts labeled `RELEASE-CANDIDATE-NOT-DEPLOYABLE`,
development, or CI. Those build dispositions are intentionally rejected by
the binaries and Debian pre-install guard.

## Debian package lifecycle

Use the package matching the target architecture. A fresh install creates
service identities, protected directories, the example
configuration, six unit files, and inert dependency examples. It may run
`systemctl daemon-reload`; it does **not** enable, start, stop, or restart any
NFTFW unit and does not create an enforcement pointer or apply firewall policy.

A supported 2.0.2-to-2.0.3 upgrade preserves enabled/disabled and
active/inactive state and does not restart services automatically. An in-place
upgrade from a pre-2.0.2 version or legacy `/var/lib/nftfw/state.db` is refused
before the old package can stop services. It requires the reviewed offline
`nftfw state migrate` procedure and a separate package handoff; do not delete
or rename state to bypass that guard.

## Source tree lifecycle

The source installer must not be run directly from an ordinary user-owned Git
checkout or extraction. First verify the final archive
against the separately obtained release checksum, then extract it into a new
root-owned protected staging directory (for example, a mode `0700` directory
beneath `/root`). Verify the archive's internal `SHA256SUMS` there. Populate
`source/dist` only with the already verified release binaries for the target
architecture and a checksum manifest covering those exact files, or build
them with Go 1.25.13 inside that protected stage.

Before invoking `source/scripts/install.sh`, the full release-input directory
chain and the installer/configuration/unit inputs must satisfy its protected
root-ownership checks. In particular, `source/dist/SHA256SUMS` and each
candidate binary must be root-owned regular non-symlink files that are not
writable by group or other users. Execute only those protected, verified
inputs. Do not relax the guard, run a user-writable copy with `sudo`, or reuse a
staging path whose contents can be replaced by another user.

The source installer rechecks binary checksums, versions, configuration, and
staged systemd units before host writes; preserves an existing configuration;
backs up compatible generation state with the installed nonmigrating binary
under the canonical lock; copies binaries/units/examples; and performs
`systemctl daemon-reload`. It leaves a fresh installation inactive and does not
apply a firewall policy.

## Deliberate activation and first apply

Installation is not activation. Enabling the early/readiness boot graph,
installing final consumer drop-ins, starting units, and performing first safe
apply are deployment-plan steps. They require the separately approved guarded
handoff and rollback procedure; they are not generic post-install commands.

Before the first apply, at minimum validate the real configuration
and topology without assuming the example values:

```bash
sudoedit /etc/nftfw/nftfw.toml
sudo nftfw config validate
sudo nftfw doctor
sudo nftfw plan
```

Do not use `--unsafe` remotely. The first safe apply must use an independent
recovery path and a second management session, then verify the
returned generation before commit.

## Installed state paths

| Path | Purpose | Expected access |
| --- | --- | --- |
| `/usr/lib/nftfw/` | Executables | root-owned, not writable by group/other |
| `/etc/nftfw/nftfw.toml` | Desired policy | root-owned, `0640` or stricter |
| `/var/lib/nftfw/generation-state/state.db` | Replaceable generation/operational database | root-only directory |
| `/var/lib/nftfw/provenance-ledger.db` | Monotonic interface-ID ledger and retired tombstones | root-only; separate from generation rollback |
| `/var/lib/nftfw/generations/` | Immutable generation `.nft` and `.snapshot.json` artifacts | root-only directory |
| `/var/lib/nftfw/active.snapshot.json` | Legacy evidence only; 2.0.3 does not publish this path | preserve if encountered; do not treat as active state |
| `/var/lib/nftfw/enforcement-enabled` | Generation/checksum enforcement pointer | root-only directory |
| `/run/nftfw/control.sock` | Mutating API | root peer only |
| `/run/nftfw/status.sock` | Read-only API | dashboard group readable |

The release is validated, but a release cannot determine a target host's
correct topology or management policy. Installation and activation still
require a reviewed host handoff, independent recovery access, and explicit
operator action.
