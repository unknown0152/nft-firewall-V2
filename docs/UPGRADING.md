# Upgrading

NFT Firewall V2 2.1.0 preserves the 2.0.3 advanced configuration, schema-6
state, generation, snapshot, enforcement, provenance, API, nftables ownership,
and nonactivating package contracts.

Installing 2.1.0 does not convert an existing host to managed mode, import a
VPN, transfer route ownership, restart services, interrupt the tunnel, or
apply a firewall. It also does not rewrite `daemon.json`, enable kernel
forwarding, install the Docker socket drop-in, or restart Docker. Those are
separate managed-setup/adoption operations.

## Supported package path

The corrected package supports the established 2.0.2-family schema-6 state
layout used by 2.0.3:

```text
/var/lib/nftfw/generation-state/state.db
/var/lib/nftfw/provenance-ledger.db
```

An in-place package upgrade from a version older than `2.0.2~`, an unknown
installed version, or legacy `/var/lib/nftfw/state.db` is refused. That stop
occurs before dpkg can invoke the legacy package's removal script. Do not
delete or rename state to evade the guard.

The release CLI provides a separate, nonactivating database migration for
exact legacy schema 1 through 5. Run it only after stopping legacy writers and
creating a clean, sidecar-free input with the prior release's backup
procedure:

```bash
sudo NFTFW_RUNTIME_DIR=/run/nftfw ./nftfw-linux-amd64 state migrate \
  /var/lib/nftfw/generation-state/state.db \
  --database /var/lib/nftfw/state.db \
  --backup /var/lib/nftfw/backups/legacy-state-before-v6.db
sudo ./nftfw-linux-amd64 state verify \
  --database /var/lib/nftfw/generation-state/state.db
```

The command takes the canonical mutation lock, refuses SQLite sidecars,
unknown objects, weakened constraints, malformed/noncontiguous histories,
current/future schemas, unsafe or enforcement-enabled state roots, oversized
inputs, and existing outputs. It writes a byte-identical protected backup,
migrates a separate destination, verifies exact schema 6, and leaves the
legacy source unchanged. It never changes the provenance ledger, package
state, systemd state, or firewall. Completing the older-package handoff remains
a separately reviewed deployment operation; database migration alone does not
bypass the package pre-install guard.

For a supported 2.0.2/2.0.3-to-2.1.0 upgrade, first record unit
enabled/disabled and active/inactive state, then validate and back up the
generation database with the currently installed binary:

```bash
sudo nftfw config validate
sudo nftfw state verify --database /var/lib/nftfw/generation-state/state.db
sudo nftfw state backup /var/lib/nftfw/backups/pre-upgrade.db \
  --database /var/lib/nftfw/generation-state/state.db
```

## Required exact-package rollback bundle

Before installing 2.1.0, retain the exact approved 2.0.3 and 2.1.0 packages
and their release-manifest SHA-256 values. Extract only the new package into a
new root-only directory, then run its helper:

```bash
sudo install -d -o root -g root -m 0700 /run/nftfw-rollback-helper
sudo dpkg-deb -x ./nft-firewall-v2_2.1.0_amd64.deb \
  /run/nftfw-rollback-helper
sudo /run/nftfw-rollback-helper/usr/lib/nftfw/package-rollback prepare \
  --old-package /absolute/path/nft-firewall-v2_2.0.3_amd64.deb \
  --new-package /absolute/path/nft-firewall-v2_2.1.0_amd64.deb \
  --old-sha256 OLD_RELEASE_SHA256 \
  --new-sha256 NEW_RELEASE_SHA256 \
  --bundle /var/backups/nftfw-migration/UTC-2.1.0-package-rollback
sudo /var/backups/nftfw-migration/UTC-2.1.0-package-rollback/execute \
  verify --bundle /var/backups/nftfw-migration/UTC-2.1.0-package-rollback
```

Use the actual architecture and an unused canonical bundle path. The helper
requires protected root ownership, binds itself to the 2.1.0 package, verifies
both exact release packages, and builds a checksummed Debian rollback bridge.
That bridge has a version lower than 2.0.3 but an extracted payload identical
to exact 2.0.3. On rollback it first becomes the configured package, then the
unmodified exact 2.0.3 package sees a supported forward version transition
and runs its own pre-install checks. No dpkg status edit, state deletion,
maintainer-script skip, or unverified payload copy is used.

The copied controller begins only from configured exact 2.1.0, the exact
manifest-named configured bridge, or already restored exact 2.0.3. During the
first step, Debian 13 changes its database to the `iHR 2.1.0` transition and
invokes the bridge `preinst` with exactly `upgrade`, `2.1.0`, and the generated
bridge version. That one boundary is accepted; configured `ii`, unpacked,
failed, malformed, extra-argument, wrong-version, wrong-architecture, or
ambiguous states are rejected. The pre-install script also verifies the
installed 2.1.0 binary and protected metadata, exact optional schema-6
history, and the transition identity bound to both package and binary hashes
in the verified bundle manifest.

Before boot-policy handoff or dpkg mutation, the controller extracts the
bundle-bound exact 2.0.3 binary and uses it to validate the current
`nftfw.toml` with output suppressed. It repeats that validation immediately
before package replacement. A configuration containing 2.1-only managed
fields refuses with a fixed message and no configuration value disclosure;
restore the protected pre-upgrade configuration or use the package-removal
handoff instead of weakening this check.

When the schema-6 database exists, the bridge accepts both real ownership
histories: a root CLI-created mode-0600 `root:root` file and a v2.1
systemd-created mode-0600 `root:nftfw-web` file. The UID, exact runtime group
GID, mode, regular-file type, single link, protected parent chain, and exact
migration history are all checked. No other group identity is accepted.

The outer controller holds the real canonical mutation lock throughout both
dpkg steps. Because exact 2.0.3's historical `preinst` takes the same pathname
for its verified backup, only the dpkg descendant tree receives a private
mount-namespace view backed by a fresh protected inode. External NFTFW
processes continue to see the locked canonical inode. Missing `unshare` or
`mount`, namespace/bind failure, unsafe metadata, inode aliasing, or residue is
a hard rollback failure; never substitute a canonical unlock window.

The deployment controller must arm the copied `execute` helper as its
daemon-independent timeout action before installing 2.1.0. To invoke an
approved rollback manually or from that timer:

```bash
sudo /var/backups/nftfw-migration/UTC-2.1.0-package-rollback/execute \
  execute --bundle /var/backups/nftfw-migration/UTC-2.1.0-package-rollback
```

Execution is resumable from configured 2.1.0, the exact named bridge, or
already-restored 2.0.3. It holds the global NFTFW mutation lock and, when the
one-file setup owns the IPv6-disabled boot policy, invokes the protected boot
handoff first. That handoff restores the exact captured GRUB fragment state,
regenerates and verifies the captured next-boot command line, and restores the
captured initramfs ownership state before downgrade. If the running kernel
still has the managed `ipv6.disable=1`, the transaction remains durably
`rollback_reboot_required`; neither package removal nor the rollback bridge
may claim that the running boot was restored. The bridge then verifies the old
binary identity and package payload and leaves compatible schema-6 state,
configuration, provenance, generations, drop-ins, WireGuard, Docker, and unit
lifecycle state in place.

The Debian `preinst` creates an additional timestamped verified backup when a
nonempty compatible generation database exists. The source installer follows
the same fail-closed sequence. `sqlite3` is used only for an immutable,
read-only check that the migration history is exactly schema 6. The protected,
currently installed `nftfw` binary then performs a nonmigrating online backup
while holding the canonical NFTFW mutation lock, and that binary verifies the
backup through its read-only state path. There is no unlocked `sqlite3` backup
fallback. Either installation path aborts if the lock, installed backup
command, schema check, backup, or verification cannot be proven safe.

An upgrade is refused while managed setup is between `reboot_required` and a
terminal result. The installed helper takes the canonical setup lock and
accepts package replacement only for an exact `complete` or `rolled_back`
managed boot journal. Finish the same profile-only setup command, or complete
`nftfw setup rollback` (including any required reboot), before retrying the
package upgrade. Do not replace the binary, generator, or hold units manually.

The monotonic provenance ledger has a different lifecycle. A generation-state
backup never replaces or rewinds it. Preserve a protected copy as evidence;
restoration requires the separately reviewed merge-only compatibility path
that rejects changed mappings, deletion, ID reuse, or regression. The ledger
uses DELETE journaling: preserve its canonical main file and any optional
`-journal`. Unexpected ledger `-wal` or `-shm` files are defensive/forensic
evidence, not ordinary restore inputs.

## Lifecycle preservation

Package and source upgrades may run `systemctl daemon-reload`, but do not
enable, disable, start, stop, or restart NFTFW units. An inactive installation
remains inactive. An active daemon continues running its previous process image
until an administrator performs the separately reviewed migration/readiness
checks and explicitly restarts it.

After an approved upgrade, verify without claiming the new executable is
active merely because files were replaced:

```bash
sudo nftfw version
sudo nftfw config validate
sudo nftfw doctor
systemctl is-enabled nftfw-early nftfw-enforcement-ready nftfwd \
  nftfw-rollback.timer nftfw-setup-rollback.timer \
  nftfw-managed-rollback.timer nftfw-vpn nftfw-web
systemctl is-active nftfw-early nftfw-enforcement-ready nftfwd \
  nftfw-rollback.timer nftfw-setup-rollback.timer \
  nftfw-managed-rollback.timer nftfw-vpn nftfw-web
```

Any restart, migration, early restore, or policy reconciliation is a separate
deployment action with rollback and readiness checks. Keep the prior package,
configuration, generation backup, provenance-ledger evidence, and release
checksums until post-upgrade validation completes.

## Managed-mode adoption

The clean-server `nftfw setup --vpn` command refuses an existing 2.0.3 host.
Generate the topology-specific worksheet after the inert package upgrade:

```bash
sudo nftfw setup adopt --vpn /path/to/working-vpn.conf --dry-run
sudo nftfw setup adopt --vpn /path/to/working-vpn.conf --dry-run --json
```

The planner verifies the exact schema-6 generation, pointer/snapshot,
provenance, current units, routing/resolver, exposure-port summary, and eligible
Docker topology twice. Its output contains ownership transfers, interruptions,
backup inputs, rollback boundaries, and the explicit statements
`live_state_changed: false` and `rollback_required: false`. It omits provider
keys, endpoint/address values, public IPs/domains, container/image/volume IDs,
and Docker network names.

On exact 2.0.3, `nftfw-vpn.service`, `nftfw-setup-rollback.timer`, and
`nftfw-managed-rollback.timer` did not exist. The planner accepts only the
single canonical systemd observation `LoadState=not-found`,
`ActiveState=inactive`, empty unit-file state, empty fragment path, and exact
unit identity for those three names. It still rejects absence on 2.1.0 and
every alias, shadow, malformed property, contradiction, or observation race.

2.1.0 deliberately provides no generic adoption executor. Invocation without
`--dry-run` returns `ADOPTION_EXECUTION_REQUIRES_SEPARATE_LIVE_PLAN`. Actual
conversion requires a separately approved Stage E-L transaction because it
transfers WireGuard, DNS, policy-route, sysctl, firewall, Docker, and boot
ownership. Do not delete the existing database, ledger, enforcement pointer,
or nftables tables to imitate a clean host.

On a new managed host, Docker adoption is part of that same setup transaction.
It is not performed by package upgrade. Existing advanced-mode Docker tuples
remain unchanged and retain their fixed bridge semantics unless explicitly
configured otherwise. In particular, a v2.0.3 static entry retains its
historical interface-name provenance and ledger ID; 2.1.0 does not silently
translate it to `docker:<network>` or rebind it after bridge recreation.
Managed mode adds `dynamic_bridge = true`, exact stable `docker:<network>`
provenance, NFTFW-owned IPv4 forwarding, strict daemon JSON merge, the socket
drop-in, and automatic same-tuple bridge recreation handling without changing
the schema-6 generation database contract. Converting an existing static
advanced entry to managed ownership requires a separately approved Stage E-L
transaction.
