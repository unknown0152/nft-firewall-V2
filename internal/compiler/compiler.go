// Package compiler turns a validated policy into a deterministic nft script.
// It does not execute nft or read the host.
package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/policy"
)

const (
	FilterTable = "nftfw_filter"
	NATTable    = "nftfw_nat"
	Filter6     = "nftfw_filter6"
)

type Input struct {
	Policy      policy.Effective
	BlockedV4   []string
	BlockedV6   []string
	BootstrapV4 []string
	BootstrapV6 []string
	DockerNets  []string
	DockerNets6 []string
}

type Artifact struct {
	Generation uint64
	Script     string
	Checksum   string
}

func Compile(in Input, generation uint64) (Artifact, error) {
	if err := config.Validate(in.Policy.Config); err != nil {
		return Artifact{}, err
	}
	for _, item := range []struct {
		name, family string
		values       []string
	}{
		{"blocked_v4", "ipv4", in.BlockedV4}, {"blocked_v6", "ipv6", in.BlockedV6},
		{"wg_bootstrap_v4", "ipv4", in.BootstrapV4}, {"wg_bootstrap_v6", "ipv6", in.BootstrapV6},
		{"docker_nets", "ipv4", in.DockerNets},
		{"docker_nets6", "ipv6", in.DockerNets6},
	} {
		for _, raw := range item.values {
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				return Artifact{}, fmt.Errorf("invalid runtime prefix %q: %w", raw, err)
			}
			if p.Bits() == 0 {
				return Artifact{}, fmt.Errorf("runtime prefix %q is /0", raw)
			}
			if (item.family == "ipv4" && !p.Addr().Is4()) || (item.family == "ipv6" && !p.Addr().Is6()) {
				return Artifact{}, fmt.Errorf("%s contains address from wrong family: %q", item.name, raw)
			}
			if strings.HasPrefix(item.name, "wg_bootstrap_") && p.Bits() != p.Addr().BitLen() {
				return Artifact{}, fmt.Errorf("%s contains non-host endpoint prefix: %q", item.name, raw)
			}
		}
	}
	if err := validateNATTargets(in.Policy.Config.NAT, in.DockerNets); err != nil {
		return Artifact{}, err
	}
	var b strings.Builder
	line := func(s string) { b.WriteString(s); b.WriteByte('\n') }
	line("#!/usr/sbin/nft -f")
	line("# nftfw transaction; owned tables only; global ruleset replacement omitted")
	line(fmt.Sprintf("# generation: %d", generation))
	line(fmt.Sprintf("# policy checksum: %s", policyChecksum(in.Policy)))
	line("")
	emitFilter(&b, in)
	line("")
	emitNAT(&b, in)
	line("")
	emitIPv6(&b, in)
	script := b.String()
	sum := sha256.Sum256([]byte(script))
	return Artifact{Generation: generation, Script: script, Checksum: hex.EncodeToString(sum[:])}, nil
}

func policyChecksum(e policy.Effective) string {
	// The compiler input is already validated; this checksum intentionally
	// excludes runtime claims, which are represented by their own sets.
	data := fmt.Sprintf("%#v", e.Config)
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func emitFilter(b *strings.Builder, in Input) {
	c := in.Policy.Config
	line := func(s string) { b.WriteString(s); b.WriteByte('\n') }
	line("table inet " + FilterTable + " {")
	emitSet(b, "blocked_v4", "ipv4_addr", in.BlockedV4, false)
	emitSet(b, "blocked_v6", "ipv6_addr", in.BlockedV6, false)
	// Trusted leases are intentionally absent from committed generations.
	// Runtime reconciliation installs them with kernel-enforced expirations.
	emitSet(b, "trusted_v4", "ipv4_addr", nil, true)
	emitSet(b, "trusted_v6", "ipv6_addr", nil, true)
	emitSet(b, "wg_bootstrap_v4", "ipv4_addr", in.BootstrapV4, false)
	emitSet(b, "wg_bootstrap_v6", "ipv6_addr", in.BootstrapV6, false)
	emitSet(b, "docker_nets", "ipv4_addr", in.DockerNets, false)
	emitSet(b, "docker_nets6", "ipv6_addr", in.DockerNets6, false)
	line("    chain input {")
	line("        type filter hook input priority filter; policy drop;")
	line("        iifname \"lo\" accept comment \"nftfw:loopback\"")
	line("        ct state invalid drop comment \"nftfw:invalid\"")
	if c.System.IPv6Mode != "disabled" {
		line("        ip6 hoplimit 255 meta l4proto ipv6-icmp icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept comment \"nftfw:ipv6-neighbor-discovery\"")
	}
	for _, protocol := range []string{"tcp", "udp"} {
		if ports := trustedPorts(in.Policy, protocol); len(ports) > 0 {
			line("        ip saddr @trusted_v4 " + protocol + " dport { " + strings.Join(ports, ", ") + " } accept comment \"nftfw:trusted-services-v4-" + protocol + "\"")
			line("        ip6 saddr @trusted_v6 " + protocol + " dport { " + strings.Join(ports, ", ") + " } accept comment \"nftfw:trusted-services-v6-" + protocol + "\"")
		}
	}
	emitPolicies(b, in.Policy, "input", "deny")
	line("        ct state established,related accept comment \"nftfw:input-established\"")
	line("        ip saddr @blocked_v4 drop comment \"nftfw:block-v4\"")
	line("        ip6 saddr @blocked_v6 drop comment \"nftfw:block-v6\"")
	emitPolicies(b, in.Policy, "input", "allow")
	line("        counter drop comment \"nftfw:input-default-deny\"")
	line("    }")
	line("    chain output {")
	line("        type filter hook output priority filter; policy drop;")
	line("        oifname \"lo\" accept comment \"nftfw:loopback\"")
	line("        ct state invalid drop comment \"nftfw:invalid\"")
	line("        ip daddr @docker_nets meta l4proto icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept comment \"nftfw:container-path-errors-v4\"")
	line("        ip6 daddr @docker_nets6 meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept comment \"nftfw:container-path-errors-v6\"")
	if c.System.IPv6Mode != "disabled" {
		line("        ip6 hoplimit 255 meta l4proto ipv6-icmp icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept comment \"nftfw:ipv6-neighbor-discovery\"")
		line(fmt.Sprintf("        oifname %s udp sport 546 udp dport 547 accept comment \"nftfw:dhcpv6-bootstrap\"", quote(c.Interfaces, "uplink")))
	}
	line(fmt.Sprintf("        oifname %s ct direction reply ct state established,related accept comment \"nftfw:uplink-reply-only\"", quote(c.Interfaces, "uplink")))
	line(fmt.Sprintf("        oifname %s udp sport 68 udp dport 67 accept comment \"nftfw:dhcp-bootstrap\"", quote(c.Interfaces, "uplink")))
	if c.WireGuard.EndpointPort > 0 {
		line(fmt.Sprintf("        oifname %s meta mark %s ip daddr @wg_bootstrap_v4 udp dport %d accept comment \"nftfw:wg-bootstrap-v4\"", quote(c.Interfaces, "uplink"), c.WireGuard.Fwmark, c.WireGuard.EndpointPort))
		line(fmt.Sprintf("        oifname %s meta mark %s ip6 daddr @wg_bootstrap_v6 udp dport %d accept comment \"nftfw:wg-bootstrap-v6\"", quote(c.Interfaces, "uplink"), c.WireGuard.Fwmark, c.WireGuard.EndpointPort))
	}
	line("        ip daddr @blocked_v4 drop comment \"nftfw:block-v4\"")
	line("        ip6 daddr @blocked_v6 drop comment \"nftfw:block-v6\"")
	line(fmt.Sprintf("        oifname %s counter comment \"nftfw:vpn-only-egress\"", strconv.Quote(c.WireGuard.Interface)))
	emitPolicies(b, in.Policy, "output", "deny")
	emitPolicies(b, in.Policy, "output", "allow")
	line("        counter drop comment \"nftfw:output-default-deny\"")
	line("    }")
	line("    chain forward {")
	line("        type filter hook forward priority filter; policy drop;")
	line("        ct state invalid drop comment \"nftfw:invalid\"")
	line(fmt.Sprintf("        oifname %s ct direction reply ct state established,related accept comment \"nftfw:forward-uplink-reply-only\"", quote(c.Interfaces, "uplink")))
	line("        ip saddr @blocked_v4 drop comment \"nftfw:block-forward-source-v4\"")
	line("        ip daddr @blocked_v4 drop comment \"nftfw:block-forward-destination-v4\"")
	line("        ip6 saddr @blocked_v6 drop comment \"nftfw:block-forward-source-v6\"")
	line("        ip6 daddr @blocked_v6 drop comment \"nftfw:block-forward-destination-v6\"")
	line(fmt.Sprintf("        ip saddr @docker_nets oifname %s tcp flags syn tcp option maxseg size set %d comment \"nftfw:container-vpn-mss-out-v4\"", strconv.Quote(c.WireGuard.Interface), c.WireGuard.TCPMSS))
	line(fmt.Sprintf("        ip6 saddr @docker_nets6 oifname %s tcp flags syn tcp option maxseg size set %d comment \"nftfw:container-vpn-mss-out-v6\"", strconv.Quote(c.WireGuard.Interface), c.WireGuard.TCPMSS))
	line(fmt.Sprintf("        iifname %s ip daddr @docker_nets tcp flags syn tcp option maxseg size set %d comment \"nftfw:container-vpn-mss-in-v4\"", strconv.Quote(c.WireGuard.Interface), c.WireGuard.TCPMSS))
	line(fmt.Sprintf("        iifname %s ip6 daddr @docker_nets6 tcp flags syn tcp option maxseg size set %d comment \"nftfw:container-vpn-mss-in-v6\"", strconv.Quote(c.WireGuard.Interface), c.WireGuard.TCPMSS))
	line(fmt.Sprintf("        ip saddr @docker_nets oifname %s drop comment \"nftfw:container-physical-deny\"", quote(c.Interfaces, "uplink")))
	line(fmt.Sprintf("        ip6 saddr @docker_nets6 oifname %s drop comment \"nftfw:container-physical-deny-v6\"", quote(c.Interfaces, "uplink")))
	line(fmt.Sprintf("        oifname %s drop comment \"nftfw:forward-physical-deny\"", quote(c.Interfaces, "uplink")))
	emitPolicies(b, in.Policy, "forward", "deny")
	line("        ct state established,related accept comment \"nftfw:forward-established\"")
	line(fmt.Sprintf("        ip saddr @docker_nets oifname %s counter comment \"nftfw:container-vpn-egress\"", strconv.Quote(c.WireGuard.Interface)))
	line(fmt.Sprintf("        ip6 saddr @docker_nets6 oifname %s counter comment \"nftfw:container-vpn-egress-v6\"", strconv.Quote(c.WireGuard.Interface)))
	emitPolicies(b, in.Policy, "forward", "allow")
	line("        counter drop comment \"nftfw:forward-default-deny\"")
	line("    }")
	line("}")
}

func emitSet(b *strings.Builder, name, typ string, elems []string, timeout bool) {
	line := func(s string) { b.WriteString(s); b.WriteByte('\n') }
	line(fmt.Sprintf("    set %s {", name))
	flags := "interval"
	if timeout {
		flags += ", timeout"
	}
	line(fmt.Sprintf("        type %s; flags %s; comment \"nftfw-owned:%s\"", typ, flags, name))
	if len(elems) > 0 {
		copyElems := append([]string(nil), elems...)
		sort.Strings(copyElems)
		line("        elements = { " + strings.Join(copyElems, ", ") + " }")
	}
	line("    }")
}

func emitNAT(b *strings.Builder, in Input) {
	c := in.Policy.Config
	line := func(s string) { b.WriteString(s); b.WriteByte('\n') }
	line("table ip " + NATTable + " {")
	emitSet(b, "docker_nets_nat", "ipv4_addr", in.DockerNets, false)
	line("    chain prerouting {")
	line("        type nat hook prerouting priority dstnat; policy accept;")
	line("        counter comment \"nftfw:dnat-chain\"")
	rules := append([]config.NATRule(nil), c.NAT...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })
	for _, rule := range rules {
		for _, source := range natSources(rule.Source, in.Policy) {
			prefix := "        iifname " + strconv.Quote(rule.ExternalInterface) + " "
			if source != "" {
				prefix += source + " "
			}
			line(fmt.Sprintf("%s%s dport %d dnat to %s:%d comment %s", prefix, rule.Protocol, rule.ExternalPort, rule.Destination, rule.DestinationPort, quoteString("nftfw-nat:"+rule.Name)))
		}
	}
	line("    }")
	line("    chain postrouting {")
	line("        type nat hook postrouting priority srcnat; policy accept;")
	line(fmt.Sprintf("        ip saddr @docker_nets_nat oifname %s masquerade comment \"nftfw:vpn-only-nat\"", strconv.Quote(c.WireGuard.Interface)))
	line("    }")
	line("}")
}

func validateNATTargets(rules []config.NATRule, networks []string) error {
	if len(rules) == 0 {
		return nil
	}
	prefixes := make([]netip.Prefix, 0, len(networks))
	for _, raw := range networks {
		prefix, err := netip.ParsePrefix(raw)
		if err == nil && prefix.Addr().Is4() {
			prefixes = append(prefixes, prefix)
		}
	}
	for _, rule := range rules {
		destination, _ := netip.ParseAddr(rule.Destination)
		contained := false
		for _, prefix := range prefixes {
			if prefix.Contains(destination) {
				contained = true
				break
			}
		}
		if !contained {
			return fmt.Errorf("NAT rule %s destination is outside observed container networks", rule.Name)
		}
	}
	return nil
}

func natSources(name string, effective policy.Effective) []string {
	if name == "any" {
		return []string{""}
	}
	zone := effective.Zones[name]
	var sources []string
	for _, network := range zone.Networks {
		if prefix, err := netip.ParsePrefix(network); err == nil && prefix.Addr().Is4() {
			sources = append(sources, "ip saddr "+prefix.String())
		}
	}
	if len(sources) == 0 {
		return []string{""}
	}
	sort.Strings(sources)
	return sources
}

func emitIPv6(b *strings.Builder, in Input) {
	c := in.Policy.Config
	line := func(s string) { b.WriteString(s); b.WriteByte('\n') }
	line("table ip6 " + Filter6 + " {")
	if c.System.IPv6Mode != "disabled" {
		// inet/nftfw_filter already applies the typed policy to both families.
		// Keep a separately owned mode marker without installing a competing
		// base chain that would run before and preempt the inet policy.
		line(fmt.Sprintf("    chain mode_marker { comment %s; }", strconv.Quote("nftfw:ipv6-mode-"+c.System.IPv6Mode)))
		line("}")
		return
	}
	priority := -300
	line(fmt.Sprintf("    chain input { type filter hook input priority %d; policy drop;", priority))
	line("        iifname \"lo\" accept comment \"nftfw:ipv6-mode-disabled\"")
	line("    }")
	line(fmt.Sprintf("    chain output { type filter hook output priority %d; policy drop;", priority))
	line("        oifname \"lo\" accept comment \"nftfw:ipv6-loopback\"")
	line("    }")
	line(fmt.Sprintf("    chain forward { type filter hook forward priority %d; policy drop;", priority))
	line("        ct state invalid drop comment \"nftfw:ipv6-invalid\"")
	line("    }")
	line("}")
}

func emitPolicies(b *strings.Builder, e policy.Effective, chain, action string) {
	for _, p := range e.SortedPolicies() {
		if p.Action != action || !policyAppliesToChain(p, chain) {
			continue
		}
		if svc, ok := e.Svcs[p.Service]; ok {
			emitPolicyRules(b, p, svc, e, chain)
		}
	}
}

func policyAppliesToChain(p config.Policy, chain string) bool {
	switch chain {
	case "input":
		return p.To == "host" && p.From != "host"
	case "output":
		return (p.From == "host" || p.From == "any") && p.To != "host"
	case "forward":
		return p.From != "host" && p.To != "host"
	default:
		return false
	}
}

func emitPolicyRules(b *strings.Builder, p config.Policy, svc config.Service, e policy.Effective, chain string) {
	verdict := p.Action
	if verdict == "allow" {
		verdict = "accept"
	} else {
		verdict = "drop"
	}
	if chain == "output" {
		for _, dst := range zoneSelectors(p.To, "destination", e) {
			prefix := "        " + dst.Expression + " "
			if p.To == "any" || dst.RequiresVPN {
				prefix += "oifname " + strconv.Quote(e.Config.WireGuard.Interface) + " "
			}
			b.WriteString(prefix + serviceExpr(svc, dst.Family) + " " + verdict + " comment " + quoteString("nftfw-policy:"+p.Name) + "\n")
		}
		return
	}
	sources := zoneSelectors(p.From, "source", e)
	dests := zoneSelectors(p.To, "destination", e)
	if chain == "input" && p.To == "host" {
		dests = []zoneSelector{{}}
	}
	if len(sources) == 0 {
		return
	}
	for _, src := range sources {
		for _, dst := range dests {
			if dst.Family != "" && src.Family != dst.Family {
				continue
			}
			prefix := "        "
			if chain == "input" {
				prefix += src.Expression + " "
			} else {
				prefix += src.Expression + " "
				if dst.Expression != "" {
					prefix += dst.Expression + " "
				}
				if p.To == "any" {
					prefix += "oifname " + strconv.Quote(e.Config.WireGuard.Interface) + " "
				}
			}
			expr := prefix + serviceExpr(svc, src.Family) + " " + verdict + " comment " + quoteString("nftfw-policy:"+p.Name)
			b.WriteString(expr + "\n")
		}
	}
}

type zoneSelector struct {
	Expression  string
	Family      string
	RequiresVPN bool
}

func zoneSelectors(name, direction string, e policy.Effective) []zoneSelector {
	if name == "host" {
		return nil
	}
	addressDirection := "saddr"
	interfaceDirection := "iifname"
	if direction == "destination" {
		addressDirection = "daddr"
		interfaceDirection = "oifname"
	}
	if name == "any" {
		return []zoneSelector{{Expression: "meta nfproto ipv4", Family: "ip"}, {Expression: "meta nfproto ipv6", Family: "ip6"}}
	}
	zone, ok := e.Zones[name]
	if !ok {
		return nil
	}
	var result []zoneSelector
	seen := map[string]bool{}
	add := func(selector zoneSelector) {
		key := selector.Family + "\x00" + selector.Expression
		if !seen[key] {
			seen[key] = true
			result = append(result, selector)
		}
	}
	for _, network := range zone.Networks {
		add(zoneSelector{Expression: addressMatch(network, addressDirection), Family: familyExpr(network), RequiresVPN: destinationRequiresVPN(network)})
	}
	interfaces := append([]string(nil), zone.Interfaces...)
	for _, configured := range e.Config.Interfaces {
		if configured.Zone == name {
			interfaces = append(interfaces, configured.Name)
		}
	}
	sort.Strings(interfaces)
	for _, name := range interfaces {
		quoted := strconv.Quote(name)
		add(zoneSelector{Expression: interfaceDirection + " " + quoted + " meta nfproto ipv4", Family: "ip"})
		add(zoneSelector{Expression: interfaceDirection + " " + quoted + " meta nfproto ipv6", Family: "ip6"})
	}
	return result
}

func destinationRequiresVPN(raw string) bool {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return true
	}
	address := prefix.Addr()
	return !address.IsPrivate() && !address.IsLinkLocalUnicast() && !address.IsLoopback()
}

func serviceExpr(s config.Service, family string) string {
	if s.Protocol == "icmp" {
		if family == "ip6" {
			return "meta l4proto ipv6-icmp"
		}
		return "meta l4proto icmp"
	}
	ports := append([]int(nil), s.Ports...)
	sort.Ints(ports)
	values := make([]string, len(ports))
	for i, p := range ports {
		values[i] = strconv.Itoa(p)
	}
	return s.Protocol + " dport { " + strings.Join(values, ", ") + " }"
}

func trustedPorts(e policy.Effective, protocol string) []string {
	seen := map[int]bool{}
	for _, name := range e.Config.Runtime.TrustedServices {
		svc, ok := e.Svcs[name]
		if !ok || svc.Protocol != protocol {
			continue
		}
		for _, p := range svc.Ports {
			seen[p] = true
		}
	}
	values := make([]int, 0, len(seen))
	for p := range seen {
		values = append(values, p)
	}
	sort.Ints(values)
	result := make([]string, len(values))
	for i, p := range values {
		result[i] = strconv.Itoa(p)
	}
	return result
}

func familyExpr(prefix string) string {
	if strings.Contains(prefix, ":") {
		return "ip6"
	}
	return "ip"
}

func addressMatch(prefix, direction string) string {
	return familyExpr(prefix) + " " + direction + " " + prefix
}

func quote(in []config.Interface, role string) string {
	for _, i := range in {
		if i.Role == role {
			return strconv.Quote(i.Name)
		}
	}
	return strconv.Quote("")
}

func quoteString(s string) string { return strconv.Quote(s) }
