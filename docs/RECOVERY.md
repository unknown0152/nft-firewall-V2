# Recovery

NFT Firewall V2 2.1.0 retains the 2.0.3 generation, boot, package, and
rollback architecture and adds separate managed-setup and managed-policy
file-publication journals and watchdogs. Recovery still depends on
local-console or independent LAN access and the actual deployed generation.

## Adoption-planner interruption

`nftfw setup adopt --vpn PATH --dry-run` has no recovery transaction. It does
not acquire the setup mutation lock or create a journal, backup, intent,
generated policy, VPN copy, route, nftables object, sysctl, systemd change, or
Docker change. Killing it at any point requires no rollback. Run the same
command again; if the two race-consistent observations differ, it refuses with
`ADOPTION_OBSERVATION_CHANGED`.

Every planner error confirms `live state changed: NO` and `rollback required:
NO`. The detailed-log pointer is the existing root-only daemon journal; the
planner itself writes no log.

## Managed setup interruption

Profile parsing, clean-host discovery, endpoint resolution, Docker inspection,
route preflight, and plan compilation are read-only and run before the setup
journal is created. A refusal in that boundary changes no protected state and
requires no rollback. `SETUP_JOURNAL_WRITE_FAILED` likewise stops before the
backup or any protected mutation.

After a journal is durably published, inspect the root-only setup journal:

```bash
sudo nftfw setup status
sudo systemctl status nftfw-setup-rollback.timer
sudo journalctl -u nftfw-setup-rollback.service -u nftfwd
```

An expired pre-commit transaction is rolled back from its verified setup
bundle:

```bash
sudo nftfw setup rollback
```

After status is exactly phase `failed`, status `rolled_back`, generate a new
dry-run with the intended VPN profile. This terminal retry is not a general
existing-host adoption path. It proceeds only if the current and archived
journals are canonical and checksum-bound; captured files, sysctls, and unit
state exactly match the backup; managed firewall/routing/tunnel state is
absent; every retained generation is `rolled_back`; immutable snapshots,
endpoint cache, and monotonic provenance mappings verify; and the newly
compiled stable identities match. The next real run archives the exact old
journal durably before its first mutation and the daemon allocates the next
generation ID. Any failed predicate returns
`DISCOVERY_EXISTING_NFTFW_REQUIRES_ADOPT` without changing the host.

An interrupted `inspect` phase, or `backup` phase without a recorded backup,
is still before protected mutation. Recovery marks it terminal without
stopping services, changing nftables, or attempting a nonexistent restore.
Before the temporary guard or any later mutation begins, the complete
checksummed backup path is durable in the journal. Missing that boundary in a
guard-or-later phase, or a missing prepared-plan schema, fails closed before
stopping services instead of guessing.

The generated guard is passed through real `nft --check` before it is applied.
Its LAN and endpoint prefix sets use interval semantics, but endpoint inputs
remain exact canonical IPv4 `/32` values. `SETUP_GUARD_CHECK_FAILED` therefore
stops before the guard reaches the kernel and triggers the verified
backup-bound transaction rollback; it is never a reason to bypass the check
or apply the file manually.

Rollback first stops the managed tunnel when it may exist, rolls back only the
exact pending generation, restores files, sysctls, unit state, routes, DNS,
and resolver ownership, then removes the temporary guard. It never flushes the
ruleset.

When Docker was adopted, the setup backup also contains a SHA-256 for the
exact prior `daemon.json`, the Docker socket drop-in state, the previous
`net.ipv4.ip_forward` value, and Docker enabled/active state. A failure before,
during, or after the confirmed Docker restart restores those exact resources
while the temporary setup guard still blocks physical container forwarding.
On a post-reboot resume, `docker.service` and `docker.socket` are additionally
held inactive. Restart confirmation occurs before that hold is released; on
rollback, the exact prior Docker files are restored and systemd is reloaded
before release. The hold's ready/release files are fixed-content, root-owned,
single-link runtime state and are removed after a successful handoff.
Checksum failure stops restoration with
`SETUP_BACKUP_RESTORE_CHECKSUM_FAILED`.

If the firewall generation committed but the process died before recording
that fact in the setup journal, recovery verifies the active committed
generation and continues forward to boot readiness. If commit state cannot be
proved, it reports `SETUP_COMMIT_STATE_UNKNOWN` and does not perform a
destructive rollback.

Post-commit handoff failures recover forward:

- `SETUP_EARLY_ENFORCEMENT_FAILED`: early restore or readiness did not start;
- `SETUP_INITRAMFS_MARKER_UNSAFE` or
  `SETUP_INITRAMFS_MARKER_INVALID`: an existing activation marker cannot be
  authenticated;
- `SETUP_INITRAMFS_GUARD_FAILED`: regeneration or archive/order/checksum
  verification failed;
- `SETUP_FINAL_DEPENDENCY_PUBLISH_FAILED` or
  `SETUP_FINAL_DEPENDENCY_RELOAD_FAILED`: final drop-ins were not durably
  published and reloaded.

Do not reboot while any of these errors remains in a running or
`committed_recovery_failed` setup journal. The live committed policy and
temporary guard are the recovery boundary, but boot readiness has not yet
been proven. Recovery must first make `nftfw-early` and
`nftfw-enforcement-ready` active, verify every installed initramfs contains
the checksum-bound loader before udev, and publish the final dependency
drop-ins. A failed archive listing is a verification failure, never evidence
that the loader is absent.

Docker-specific setup failures are actionable and remain pre-commit:

- `SETUP_POLICY_CHECK_FAILED`: the generated nftables candidate did not pass
  before Docker ownership change;
- `SETUP_DOCKER_CONFIG_CHANGED_AFTER_PLAN`: `daemon.json` changed after the
  reviewed plan;
- `SETUP_DOCKER_RESTART_FAILED`: the one confirmed Docker restart failed;
- `SETUP_DOCKER_IPV4_FORWARDING_FAILED`: kernel forwarding is not exactly
  `1`;
- `SETUP_DOCKER_TOPOLOGY_CHANGED` or
  `SETUP_DOCKER_VALIDATION_FAILED`: an authorized network tuple or bridge
  changed.

Do not retry by enabling Docker iptables or adding a broad forwarding rule.
Let rollback complete, inspect Docker through `docs/DOCKER.md`, and run a new
dry-run. The disposable exact-rollback fixture keeps Docker's five firewall,
forwarding, masquerade, and proxy ownership settings coherent at baseline;
when a restart must be exercised, only a restart-requiring proxy setting such
as the prior `userland-proxy` value differs before setup.

## Docker runtime rebind

The daemon checks Docker topology on its regular refresh loop. A network
recreation with the same authorized name, driver, canonical subnet/gateway
tuple, and a new race-consistent full ID may produce a new Linux bridge name.
NFTFW marks Docker degraded, compiles and commits a new generation for the new
bridge, atomically persists the generated binding, republishes mutable claims,
and then records Docker healthy.

The firewall generation is committed before the generated binding is
published. If the daemon dies or the file write fails in between, the old
generated binding causes the next refresh to repeat the safe rebind; the
already-active generation remains fail-closed. A semantic tuple change,
undeclared bridge, missing bridge, or invalid daemon ownership never enters
the rebind path.

```bash
sudo nftfw health
sudo nftfw config show --effective
sudo journalctl -u nftfwd -u docker
```

Look for the `docker_bridge_rebound` audit event and a healthy Docker
integration state. Do not edit `bridge_interface` manually.

## Managed exposure or LAN change interruption

Managed `expose` and `lan` mutations first save exact checksummed copies of
`intent.toml` and `nftfw.toml` under
`/var/lib/nftfw/managed-change/`. The daemon reloads those protected files,
compiles them, safe-applies the resulting generation, and commits only after
tunnel validation. The journal records the returned generation before the
commit request.

`nftfw-managed-rollback.timer` checks every 15 seconds. Recovery asks the
privileged daemon for the exact journaled generation state:

- `committed`: verify the new file hashes and finish forward;
- `pending`, `applied`, or `commit_prepared`: roll back that exact generation
  and restore the exact prior file bytes;
- `rolled_back` or no generation recorded: restore the exact prior file bytes;
- unavailable, malformed, or unknown generation state: leave the journal in
  place and fail closed for another timer/operator attempt.

The ordinary generation timer remains independent, so a crash after kernel
apply but before the CLI records the generation still expires and rolls back
the pending firewall while the managed-change timer restores the old files.

```bash
sudo systemctl status nftfw-managed-rollback.timer
sudo journalctl -u nftfw-managed-rollback.service -u nftfwd
sudo nftfw managed-recover
sudo nftfw health
sudo nftfw config show --effective
```

Do not delete `/var/lib/nftfw/managed-change/` during recovery. The journal
contains hashes and non-secret policy data, not VPN keys.

## Uncommitted apply

Pending safe applies are checked every five seconds by `nftfwd` and every 15
seconds by `nftfw-rollback.timer`. The configured deadline is 30 through 600
seconds. On expiry, the previous committed generation is installed as one
atomic nftables transaction. Mutable runtime sets are then reconstructed as a
separate step while the same shared NFTFW mutation lock is held. If that
runtime-state restoration fails, the recovery path installs the owned
emergency-deny policy and reports an error. A confirmed safe-applied
first-generation rollback removes only V2-owned tables and clears boot
enforcement.

```bash
sudo nftfw status
sudo nftfw rollback <pending-generation>
sudo systemctl start nftfw-rollback.service
sudo journalctl -u nftfw-rollback.service -u nftfwd
```

Rollback is idempotent. Commit rejects an expired safe-applied generation and
initiates its rollback; the daemon and independent timer likewise roll it back
at expiry. Rollback rejects tampered, historical, or otherwise inapplicable
generation identifiers, but expiry itself is the reason an eligible rollback
must remain permitted.

### Ambiguous first apply

If `nft --file` reports an error, the kernel transaction may still have
completed before userspace observed a timeout, cancellation, or output-limit
failure. With no earlier committed generation, product-named tables in that
state are not enough to prove ownership. V2 therefore retains the pending
record and refuses automatic deletion. The corrupt-database fallback also
refuses to mutate product-named tables when no verified enforcement pointer
exists.

Preserve the generation database and journal, immutable snapshots, enforcement
pointer, and monotonic provenance ledger. Inspect live rules from a trusted
console and establish ownership before any manual removal. Do not use `nft
flush ruleset`. When no product-named table exists, the pending failure can be
finalized without a kernel mutation.

## Daemon or CLI failure

The CLI process is not needed after apply. If `nftfwd` exits or is killed,
systemd restarts it. Pending metadata survives. If the daemon cannot recover,
the independent timer invokes `nftfwd --rollback-expired` directly.

```bash
sudo systemctl restart nftfwd
sudo systemctl is-active nftfwd nftfw-rollback.timer
sudo nftfw health
```

## Database failure

Do not initialize a blank database over known enforcement state. The
root-owned generation/checksum `enforcement-enabled` pointer prevents that
downgrade. When SQLite cannot be opened, the independent path cannot safely
trust its deadline state. It attempts a restore only after the scoped foreign
netfilter-rules audit succeeds and the pointer, immutable snapshot, policy
checksum, and monotonic provenance assignments all verify. It repeats the
foreign audit immediately before the atomic nftables apply and then requires
owned-table integrity to pass. Even after a successful defensive restore, the
command returns nonzero and readiness remains blocked because no database
recovery transition was authorized. With a healthy database, configuration
failure alone never authorizes a restore: an actually expired pending
generation is still required. A missing pointer never authorizes deletion of
product-named tables.

Do not copy a backup over live state without a reviewed offline recovery
procedure. Preserve, under unique names, at least:

```text
/var/lib/nftfw/generation-state/state.db{,-wal,-shm}
/var/lib/nftfw/provenance-ledger.db
/var/lib/nftfw/provenance-ledger.db-journal  # optional DELETE-mode rollback journal
/var/lib/nftfw/generations/
/var/lib/nftfw/managed-change/  # only while a managed policy transaction is unresolved
/var/lib/nftfw/active.snapshot.json  # legacy evidence only; never published by 2.0.3
/var/lib/nftfw/enforcement-enabled
```

Generation backup restore must validate the generation/checksum pointer and
must never overwrite or rewind the ledger. Ledger restoration is merge-only
and rejects changed mappings, removed tombstones, ID reuse, or regression. Use
a unique recovery directory if prior failed files already exist, and preserve
failed generation-database WAL/SHM files and the ledger's optional DELETE-mode
`-journal` for diagnosis. Ledger `-wal` or `-shm` files are not canonical 2.0.3
state; if encountered, preserve them separately as unexpected forensic or
defensive evidence rather than treating them as normal restore inputs. Never
use `nft flush ruleset`; it can remove unrelated protections.

## Exact package rollback transition

Start or resume package rollback only through the copied, verified bundle
helper documented in `docs/UPGRADING.md`. Its outer controller accepts a
configured exact 2.1.0 package, the exact configured bridge, or already
restored exact 2.0.3. When starting from 2.1.0, Debian itself enters
`iHR 2.1.0` and supplies the bridge `preinst` exactly three arguments. The
bridge accepts only that transient boundary and the manifest-named target;
`ii`, unpacked, failed, malformed, unrelated, or ambiguous states are not
recovery shortcuts.

Before restoring any boot ownership or invoking dpkg, the controller extracts
the manifest-bound exact 2.0.3 binary and validates the current configuration
with that parser while suppressing parser output. It repeats the check
immediately before package replacement. A failure means the current file uses
fields that exact 2.0.3 cannot restore; put back the protected pre-upgrade
configuration or use the package-removal handoff. Do not remove fields merely
to bypass the refusal, and do not expect the error to print private content.

The optional schema database may come from either supported ownership
history: legacy root CLI creation (`root:root`) or v2.1 systemd creation
(`root:nftfw-web`). In both cases the bridge requires UID 0, exactly mode
0600, one hard link, an exact runtime service GID when that group is used, and
schema history `1,2,3,4,5,6`. Any other group or metadata is a hard stop.

The controller must retain the canonical `/run/nftfw/mutation.lock` for the
whole transaction. Exact 2.0.3's historical pre-install backup also takes that
pathname, so dpkg runs in a private mount namespace where only that pathname
is bound to a fresh protected transaction-local inode. Do not replace this
with unlocking the canonical lock. Failure to create or prove the isolated
binding stops rollback before the exact package is installed.

Do not edit `/var/lib/dpkg/status`, invoke maintainer scripts manually, copy
package payload files, or alter the bundle manifest. Preserve the bundle and
dpkg logs if the exact transition refuses; repair requires a separately
reviewed package-manager recovery procedure.

## Boot enforcement

Managed setup first creates a durable `reboot_required` transaction. It owns
one fixed GRUB fragment containing one `ipv6.disable=1`, regenerates and
verifies every Linux boot entry, and enables the native checksum-bound
initramfs guard. It does not auto-reboot. Before the explicit reboot, do not
delete the journal, backup, fragment, or initramfs marker; rerunning the same
setup command on the same boot simply remains `reboot_required`.

After reboot, `nftfw setup status` reports `resume_ready` only when the boot ID
changed, the fixed fragment/generated configuration still match, the running
command line contains exactly one token, the kernel disable parameter is set,
no IPv6 address state exists, and the native guard verifies. Rerun the same
profile-only setup command to continue the original transaction. Missing,
quoted, duplicated, conflicting, or changed proof fails closed before Docker,
forwarding, VPN, routing, or firewall mutation.

`SETUP_EFI_BOOT_IDENTITY_UNSUPPORTED` is also a deliberate hard refusal. The
bounded EFI parser requires exactly one well-formed `BootCurrent`, exactly one
`BootOrder` with the current entry first, no `BootNext`, one active local-disk
Debian entry using the architecture-correct shim, and no PXE, HTTP-boot, or
MAC device path anywhere in the firmware evidence. Preserve the output of
`sudo efibootmgr -v`; do not delete or rewrite firmware entries as an ad-hoc
recovery step. A virtual-machine test fixture must prevent firmware network
options from being regenerated across the required reboot rather than weaken
or bypass this identity check.

During root switch the initramfs table still denies all interfaces. Before
`network-pre.target` is released, `nftfw-setup-boot-hold.service` takes the
canonical setup lock, proves the exact pending transaction, and atomically
replaces that table with `inet nftfw_setup_resume_guard`. Only DHCP, declared
LAN management, reply traffic, loopback, and marked UDP to the protected
cached provider endpoint are allowed. DNS is deliberately unnecessary.
`nftfw-setup-docker-hold.service` independently blocks both Docker consumers
until setup owns their configuration and forwarding. A crash after the table
swap but before the ready marker is recoverable by exact revalidation; zero,
two, changed, or additional tables remain blocked.

The initramfs loader is an explicit prerequisite of initramfs-tools' udev
script. It verifies the kernel-wide disable contract, never re-enables
loopback, checks the embedded rules checksum, and applies
`inet nftfw_initramfs_guard` with drop policies as defense in depth. Any
missing input, checksum, ordering, module, command-line, or nftables error
blocks boot networking in the initramfs.

Useful midpoint diagnostics, without weakening the holds:

```bash
sudo nftfw setup status
sudo systemctl status nftfw-setup-boot-hold nftfw-setup-docker-hold
sudo journalctl -b -u nftfw-setup-boot-hold -u nftfw-setup-docker-hold
```

Do not manually start Docker, remove generator output, delete either guard, or
add a broad nftables accept. Correct the protected evidence or invoke the
normal setup rollback path.

When a generation is committed, V2 writes an immutable checked snapshot and a
generation/checksum enforcement pointer. At boot, `nftfw-early.service`
resolves durable prepared/pending state, restores the uniquely selected
snapshot before `network-pre.target`, and remains active. The nonmutating
`nftfw-enforcement-ready.service` must verify that enforcement before audited
network consumers start. Runtime trusted leases are excluded so expired access
cannot replay.

`network-pre.target` pulls early and readiness independently. Readiness orders
after early but has no `Wants=`, `Requires=`, or `Requisite=` edge to it, so
the common boot transaction can run early first while a manual readiness start
cannot activate snapshot restoration. The verifier, required by
`network-pre.target`, is the fail-closed success dependency. Final consumer
drop-ins retain `Requisite=` plus `After=` on readiness so a routine consumer
restart cannot activate either readiness or early restore.

After verification, readiness invokes the static initramfs handoff mode. It
takes the canonical mutation lock and removes the bootstrap table only when
its table comment and all three chain hook/priority/policy/comment identities
match exactly. Absence is valid on the first live setup. An unexpected rule,
set, chain, alias, or table identity is foreign state and is never deleted.
Final managed sysctls retain disabled-mode defense in depth. Kernel-wide
disablement means no loopback IPv6 address exists in this managed mode.

If a required pointer or snapshot is missing, corrupt, symlinked, oversized,
or has an invalid checksum, recovery fails before an nftables mutation and
readiness remains blocked. It does not select the emergency-deny policy merely
because immutable recovery evidence is unusable. Emergency deny is reserved
for a failure to restore separate mutable runtime security state after a
generation installation path has already run.

```bash
sudo systemctl status nftfw-early nftfw-enforcement-ready
sudo journalctl -b -u nftfw-early -u nftfw-enforcement-ready
sudo nftfw reconcile
sudo /usr/lib/nftfw/initramfs/nftfw-initramfs-manage verify-enabled
```

Manual rollback before the first reboot restores the captured fragment and
generated configuration and reaches `rolled_back`. Rollback after the kernel
has booted with managed disablement restores the next-boot files exactly but
reports `rollback_reboot_required`; it never claims the running kernel has
changed. Reboot explicitly, then run `nftfw setup rollback` once more to
verify the restored boot and terminalize `rolled_back`. If safe apply already
allocated an uncommitted generation, that exact generation remains in the
terminal journal so its rolled-back database row, immutable snapshot,
protected backup, and next retry stay cryptographically and monotonically
bound. A rollback that never allocated a generation remains at zero.

Package removal, the source uninstaller, and exact-2.0.3 downgrade invoke the
same narrow boot handoff before the 2.1.0 helper disappears. They refuse a
foreign or changed fragment/generated configuration or an unverifiable
initramfs. When they print `rollback_reboot_required`, a reboot is still
mandatory even though the on-disk next boot has already been restored.
Package-only boot handoff is not a complete firewall rollback and therefore
does not publish retained setup generation evidence as retryable.

## Managed WireGuard failure

An absent or unhealthy tunnel is a degraded status, not a reason to open the
uplink. Host public traffic remains blocked. Bootstrap endpoint UDP remains
narrowly permitted so NFTFW can recover the tunnel.

```bash
sudo nftfw tunnel status
sudo nftfw tunnel restart
sudo nftfw health
```

Managed mode owns `nftfw0`, its DNS handoff, route table, policy rules, and
WireGuard lifecycle. Advanced 2.0.3-compatible configurations continue to use
their separately managed WireGuard path.

## Emergency host access

Use console/provider recovery if both declared management policy and rollback
paths were administratively disabled. The product deliberately has no hidden
SSH allow rule. Any manual nftables recovery should address only the three
V2-owned tables and preserve unrelated host policy.
