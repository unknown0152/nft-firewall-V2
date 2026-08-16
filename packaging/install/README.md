# Package installation layout

Release packages place binaries in `/usr/lib/nftfw`, units in
`/etc/systemd/system`, configuration in `/etc/nftfw`, and state in
`/var/lib/nftfw`. `scripts/install.sh` is the canonical portable installer;
the Debian metadata is intentionally minimal until distro signing/repository
automation exists.
