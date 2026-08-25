# Package installation layout

> **2.0.3 is a RELEASE CANDIDATE - NOT DEPLOYABLE.** Stage R2 has not run.
> This layout description is not permission to install candidate artifacts or
> modify a host. Even an accepted final release requires separate explicit
> approval of the completed server deployment plan.

Stage R candidate quarantine is intrinsic as well as documentary: its Debian
`preinst` refuses every non-release build disposition, candidate `nftfw`
permits only `version`, and candidate `nftfwd`/`nftfw-web` refuse startup. The
portable installer therefore cannot validate or install a candidate binary.

Debian packages place binaries in `/usr/lib/nftfw`, vendor units in
`/usr/lib/systemd/system`, configuration in `/etc/nftfw`, and state in
`/var/lib/nftfw`. The source installer places its units in
`/etc/systemd/system`. Neither installation path enables, starts, stops, or
restarts NFTFW units; activation is a separate reviewed deployment step.

The source installer is only for a checksum-verified final release extracted
into a root-owned directory. It requires `dpkg` for Debian version ordering
and `sqlite3` for immutable schema inspection. The checksum manifest and
candidate binaries must be root-owned regular files that are not writable by
group or other users. A source upgrade refuses an installed version newer
than the candidate and refuses a same-version overwrite unless both binaries
report the same full 40-hex commit identity.

The Debian builder likewise binds the protected native candidate's full commit
into `preinst`. A same-version package reinstall must prove that the protected
installed binary reports that exact version and commit; a normal Debian
`2.0.3~rcN` to `2.0.3` upgrade remains a version increase and is allowed.

Pre-2.0.2 state requires the reviewed offline `nftfw state migrate` contract
and a separate package handoff. Both installation paths still refuse an
in-place legacy package upgrade instead of moving or rewriting state. Every
official 2.0.3 RC/final uses schema 6; an existing canonical database must
prove the exact migration history `1,2,3,4,5,6` through an immutable read
before the installed, nonmigrating backup/verify commands may run.

Both paths safely create the inactive volatile lock parent `/run/nftfw` as
`root:nftfw-web` mode `0750`. This allows immediate read/planning commands while
all units remain inactive; it does not create an enforcement pointer or apply
policy.
