# V1 Security Invariants Extracted for V2

These guarantees and failure lessons were inferred from V1 implementation,
tests, installers, systemd units, comments, and migration documents. They are
requirements, not an assertion that every V1 mechanism was sufficient.

## Policy and leak prevention

1. Input and forwarding are default deny. A VPN kill switch also requires
   output default deny.
2. Internet egress is tied to the intended WireGuard interface; route changes
   alone must not permit physical fallback.
3. WireGuard bootstrap is the narrow exception: known endpoint address, UDP
   port, physical interface, and packet mark where available.
4. Containers cannot bypass the host kill switch through a bridge, changing
   address, Docker-managed NAT, an exposed port, or an established conntrack
   entry.
5. IPv6 cannot become an implicit bypass for an IPv4-only policy. Disabled,
   VPN, and native behavior must be explicit.
6. An already-established TCP or UDP flow must not escape through the physical
   interface after WireGuard disappears.
7. DHCP, neighbor discovery, replies to legitimate inbound traffic, and tunnel
   bootstrap must be narrowly sufficient without becoming general egress.

## Configuration and compilation

8. Configuration is validated completely before any firewall mutation.
   Unknown keys, malformed values, unsafe duplicates, ambiguous zones,
   impossible interfaces/routes, `/0`, and contradictory policy fail closed.
9. Application and country names are data/presets, not firewall-core logic.
10. Policy generation is deterministic and separate from system observation
    and mutation, so plan/explain/enforcement cannot silently diverge.
11. Every exact candidate passes nftables kernel validation before atomic
    application.
12. Product ownership is identifiable and scoped; recovery must never destroy
    unrelated nftables objects.

## Durable safety and recovery

13. A working generation remains known-good when a candidate fails parsing,
    compilation, check, apply, or post-apply health.
14. Safe apply rollback survives CLI exit, SSH loss, daemon restart/crash, and
    pending state across boot. It cannot depend on interactive input.
15. An independent rollback mechanism is armed and verified before remote host
    mutation.
16. Boot restores committed enforcement before normal network services. Broken
    persistent state fails closed rather than recreating an empty allow-all
    database/ruleset.
17. Rollback and backup operate only on V2 ownership and are idempotent.
18. Drift in an owned rule, verdict, chain, or table is detected; unrelated
    tables survive reconciliation.

## Dynamic and external state

19. Each block reason has provenance. Removing a feed/GeoIP/temporary claim
    cannot erase an independent manual or automated claim for the same prefix.
20. Temporary trusted access expires durably and in the kernel; it must not
    replay as permanent access after restart or boot.
21. Endpoint DNS results are validated, bounded, cached atomically, refreshed,
    and audited. Failure retains only bounded recent known addresses and never
    widens physical access.
22. Threat feeds have HTTPS, network, time, byte, line, entry, and sanity
    limits. A failed refresh retains prior claims and cannot remove other
    sources.
23. GeoIP is optional, licensed/operator-supplied data with the same atomic
    provenance behavior.
24. Docker observation is separate from mutation; Docker's privileged socket
    never reaches the web process, and Docker firewall/proxy ownership must be
    disabled when V2 owns container policy.

## Privilege, integrity, and observability

25. One narrow privileged controller owns firewall mutation. Callers request
    typed operations; they do not execute arbitrary commands.
26. Local authorization uses kernel peer identity and protected socket modes,
    never a username claimed in JSON.
27. Requests, command output, configuration, downloaded data, and persisted
    objects have explicit bounds. Unknown operation fields are rejected.
28. Shell interpolation and argument injection are absent from production
    execution paths.
29. Sensitive config/state/key paths reject symlinks, unsafe ownership, and
    group/other writes. WireGuard private keys never enter status, audit, test
    evidence, or release artifacts.
30. Audit covers configuration loads, plans, generations, rollback, claims,
    endpoint changes, integrations, drift, recovery, and denied privileged
    requests without secret data. Rejections before state opens remain visible
    through process error/journal output.
31. The dashboard is local, read-only, unprivileged, safely escaped, and has no
    control or Docker capability.
32. Optional notifications or remote adapters cannot be dependencies of core
    enforcement, rollback, or boot recovery.

## V1 hazards not repeated

- No host-wide `flush ruleset` during apply or recovery.
- No ownership-less JSON set whose update can erase another producer.
- No free-form ChatOps-to-shell path and no arbitrary root wrapper.
- No permanent representation of a timed access grant.
- No marker-comment-only integrity decision; structural owned JSON is checked.
- No configuration parser or status read that silently changes policy.
- No broad physical exception during endpoint refresh or VPN recovery.
- No claim that a generated rule proves leak prevention without traffic and
  packet-capture tests.
