# Security Policy and Guarantees

Report vulnerabilities privately to the repository owner. Do not include live
keys, tokens, public address inventories, production packet captures, or an
operational state database in a report.

## Enforced guarantees

- Input and forwarding are default deny. Strict VPN mode also makes output
  default deny and is the only supported mode in v2.0.0.
- Internet-bound host and container policy is pinned to the declared
  WireGuard interface.
- Physical WireGuard bootstrap requires the declared uplink, validated
  endpoint host address, UDP destination port, and nonzero WireGuard fwmark.
- Container-to-uplink drops precede forward conntrack acceptance. Output has
  no blanket established/related accept that could become an egress bypass.
- IPv6 behavior is mandatory and explicit. Disabled mode installs early
  IPv6 drop hooks; VPN and native modes use equivalent typed inet policy.
- Normal operation never invokes `flush ruleset` and never deletes a table it
  does not own.
- Every candidate passes internal validation and `nft --check` before one
  atomic apply transaction.
- Safe apply records pending state before kernel mutation and requires a
  verified independent rollback timer. A committed snapshot is available to
  the early boot and corrupt-database fallback paths.
- Dynamic block removal is claim-specific. Manual, feed, GeoIP, automated,
  and temporary reasons cannot erase each other.
- Temporary access always expires in both SQLite and the kernel set; permanent
  allow claims are rejected.
- Configuration and sensitive state reject unsafe ownership, permissions,
  symlinks, ambiguous topology, unknown fields, malformed addresses, and
  unsafe broad prefixes.
- Privileged API authorization comes from Unix peer credentials, not request
  content. Request and response bodies are bounded and schemas reject unknown
  or operation-inapplicable fields.
- Child processes receive validated argument arrays. Production Go code does
  not invoke a command through a shell string.
- Threat-feed downloads require HTTPS, public destinations, bounded redirects,
  time, bytes, and entries, plus atomic provenance updates.
- The web process is read-only, local by default, emits restrictive headers,
  and has no control or Docker socket.

## Trust assumptions

The Linux kernel, nft executable, systemd, root account, installed binaries,
configured DNS resolver, and package verification path are trusted. A root or
kernel compromise can bypass this controller. WireGuard routing is assumed to
be configured consistently with the declared interface and fwmark; `doctor`
checks the live values it can observe.

The product retains the last known good kernel state on policy/configuration
errors where possible. If persistent enforcement metadata is present but its
snapshot is invalid, it installs a minimal owned emergency default-deny
policy instead of opening traffic.

See `docs/THREAT-MODEL.md` for the full model and `SECURITY_AUDIT.md` for the
release review.
