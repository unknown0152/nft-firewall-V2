# Host Handoff

NFT Firewall V2 enforces the topology declared by the operator. It cannot
discover which interfaces, networks, ports, containers, or management paths
should be trusted. Use this procedure for every new host, even when it appears
identical to an existing deployment.

## 1. Establish recovery

Before installation or service changes:

- Confirm local-console, hypervisor-console, or provider recovery access.
- Open a second independent LAN management session.
- Record the current default route, management interface/network, VPN
  interface, DNS path, and listening services.
- Preserve the currently working VPN profile without copying its private key
  into this repository or a support report.
- Back up existing firewall configuration, service enablement state, NFTFW
  configuration/state if present, and the container runtime configuration.

Do not continue when the only recovery path uses the route that the new
firewall or VPN will replace.

## 2. Run the read-only preflight

Run the publication-only preflight from the default branch, then check out the
exact release source:

```bash
sudo ./scripts/host-preflight.sh
git checkout v2.0.3
test "$(git rev-parse HEAD)" = \
  e2b3fa0a20fa6e36325792397564966b21045120
```

The script changes no firewall, network, sysctl, service, or file. Resolve
every failure and review every warning. Its output can contain host topology;
redact addresses, domains, interface names, usernames, and device identifiers
before posting it publicly. The script was added after the immutable release
tag and therefore is not present after the checkout command.

## 3. Assign component ownership

Only one component should own each responsibility.

| Responsibility | Required owner |
| --- | --- |
| NFTFW-owned filter/NAT tables | NFT Firewall V2 |
| WireGuard interface, keys, and provider routes | Operator, `wg-quick`, or another reviewed VPN manager |
| Docker bridge creation | Docker/Compose |
| Docker forwarding, masquerade, and proxy policy | NFT Firewall V2 when Docker integration is enabled |
| Public TLS and application authentication | Reverse proxy/application outside NFTFW |
| Host DNS and LAN addressing | Existing network manager |

Disable or reconfigure competing firewall managers only through a separate,
reviewed host plan. Do not stop `ufw`, `firewalld`, `nftables.service`, or
another manager merely to make a preflight warning disappear.

## 4. Record the real topology

Create a local, non-public handoff record containing:

- physical uplink interface and its current IPv4/IPv6 addressing;
- LAN management network and allowed management services;
- WireGuard interface, endpoint hostname/port, fwmark, and bootstrap IPs;
- host services that should be reachable from LAN, VPN, or the Internet;
- Docker network name, explicit bridge interface, subnet, and gateway;
- DNAT destinations and the separate forward policies that authorize them;
- chosen IPv6 mode: `disabled`, `vpn`, or `native`;
- expected inbound and outbound verification probes; and
- exact rollback and reboot recovery commands.

Never put keys, tokens, VPN profiles, public address inventories, production
packet captures, or operational databases in Git.

## 5. Prepare forwarding and Docker

Container routing requires persistent IPv4 forwarding. Configure it through
the host's normal sysctl management and verify both the saved setting and the
runtime value:

```bash
sysctl net.ipv4.ip_forward
```

When NFTFW owns Docker forwarding/NAT, `/etc/docker/daemon.json` must be
protected and explicitly set all five values to `false`:

```json
{
  "iptables": false,
  "ip6tables": false,
  "ip-forward": false,
  "ip-masq": false,
  "userland-proxy": false
}
```

Changing these settings and restarting Docker can interrupt container
networking. Back up the file, verify Compose definitions, and schedule that
restart as a separate disruptive step. Docker socket access for `nftfwd` is
also a separate explicit opt-in described in `CONFIGURATION.md`.

## 6. Choose IPv6 deliberately

- Use `disabled` when the VPN has no IPv6 and the host must have no IPv6
  egress.
- Use `vpn` only when the WireGuard interface and provider routing carry IPv6.
- Use `native` only after reviewing the strict public-egress behavior and the
  host's native IPv6 topology.

The mode in NFTFW policy and the host's addressing/routing configuration must
agree. Test both fresh and already-established IPv6 flows during tunnel loss.

The 2.1.0 one-file setup has a narrower first-install contract for
`ipv6_mode = "disabled"`. On a supported clean Debian GRUB host it owns one
fixed GRUB fragment, prepares `ipv6.disable=1`, and exits with
`reboot_required` before changing runtime routing, forwarding, Docker, VPN, or
firewall state. The operator performs the reboot; rerunning the identical
setup resumes only after the new boot proves the prepared kernel argument,
kernel disable state, empty IPv6 address state, and changed boot identity. Do
not substitute a runtime-only IPv6 sysctl for that required transaction.

## 7. Install without activation

Install a verified release package. A fresh install and supported upgrade do
not enable, start, stop, or restart NFTFW units and do not apply policy.

Record existing unit state before an upgrade:

```bash
systemctl is-enabled \
  nftfw-early nftfw-enforcement-ready nftfwd \
  nftfw-rollback.timer nftfw-web
systemctl is-active \
  nftfw-early nftfw-enforcement-ready nftfwd \
  nftfw-rollback.timer nftfw-web
```

## 8. Configure and inspect

Copy `configs/nftfw.example.toml` to `/etc/nftfw/nftfw.toml`, then replace
every example value. Provenance IDs are permanent interface-name assignments;
do not reuse an ID for a different interface.

```bash
sudoedit /etc/nftfw/nftfw.toml
sudo nftfw config validate
sudo nftfw doctor
sudo nftfw plan --show-nft
```

`doctor` and `plan` must pass. Review the exact management rule, VPN bootstrap,
public service exposure, container forwarding, NAT, and IPv6 hooks.

## 9. Install boot dependencies

The package ships inert example drop-ins. Select only the consumers that must
wait for verified enforcement. Final consumer drop-ins should use
`Requisite=` and `After=` on `nftfw-enforcement-ready.service` so a routine
consumer restart cannot activate early restoration by itself.

Before first activation, verify the complete graph:

```bash
systemd-analyze verify \
  nftfw-early.service \
  nftfw-enforcement-ready.service \
  nftfwd.service \
  nftfw-rollback.service \
  nftfw-rollback.timer \
  nftfw-web.service
systemctl list-dependencies network-pre.target
```

## 10. Activate and safe-apply

Enable only the reviewed units, confirm the rollback timer is active, then
apply from the console or with a second independent management session:

```bash
sudo systemctl enable --now nftfw-rollback.timer
sudo systemctl enable --now nftfwd
sudo systemctl enable --now nftfw-web
sudo nftfw apply --safe
sudo nftfw status
```

Before commit, verify:

- both management sessions remain usable;
- the WireGuard handshake is current;
- host and container public IPv4 use the VPN address;
- IPv6 matches the selected mode;
- intended inbound services work only on declared paths;
- undeclared LAN, VPN, and public ports remain closed;
- DNS works through the intended path;
- Docker bridge recreation does not change the authorized tuple; and
- unrelated nftables tables still exist.

Commit only after all checks pass:

```bash
sudo nftfw commit <generation>
sudo nftfw health
```

## 11. Reboot validation

Do not reboot until the committed snapshot, enforcement pointer, early restore,
readiness verifier, rollback timer, VPN recovery, and rollback bundle have
been checked.

This instruction applies to the later advanced-mode activation reboot. It is
separate from the one-file setup's mandatory pre-policy `reboot_required`
boundary described above, which deliberately occurs before a generation can
be committed.

After the controlled reboot:

```bash
sudo systemctl is-active \
  nftfw-early nftfw-enforcement-ready nftfwd \
  nftfw-rollback.timer nftfw-web
sudo nftfw health
sudo nftfw status
sudo journalctl -b \
  -u nftfw-early \
  -u nftfw-enforcement-ready \
  -u nftfwd \
  -u nftfw-rollback.service
```

Repeat the management, VPN egress, inbound-port, container, Docker, and IPv6
checks. A host is ready only after this reboot validation succeeds.

## 12. Rollback

Keep the previous package, configuration, database backup, immutable
generation artifacts, provenance-ledger evidence, unit-state record, and
container/VPN configuration until the new host has passed reboot validation.

For an uncommitted safe apply:

```bash
sudo nftfw rollback <pending-generation>
sudo systemctl start nftfw-rollback.service
```

For package or database recovery, follow `RECOVERY.md` and `UPGRADING.md`.
Never use `nft flush ruleset`; it can remove unrelated protections.
