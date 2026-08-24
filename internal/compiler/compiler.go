// Package compiler turns a validated policy into a deterministic nft script.
// It does not execute nft or read the host.
package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/policy"
	"github.com/unknown0152/nft-firewall-v2/internal/provenance"
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
	Provenance []provenance.Assignment
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
	if err := validateContainerTopology(in.Policy.Config, in.DockerNets, in.DockerNets6); err != nil {
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
	assignments := make([]provenance.Assignment, 0, len(in.Policy.Config.Interfaces))
	for _, configured := range sortedInterfaces(in.Policy.Config.Interfaces) {
		assignments = append(assignments, provenance.Assignment{Name: configured.Name, ID: configured.ProvenanceID})
	}
	return Artifact{Generation: generation, Script: script, Checksum: hex.EncodeToString(sum[:]), Provenance: assignments}, nil
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
	line("        ct state invalid drop comment \"nftfw:invalid\"")
	line("        iifname \"lo\" accept comment \"nftfw:loopback\"")
	emitProvenanceTags(b, c.Interfaces, "input")
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
	emitInputReplies(b, c.Interfaces)
	line("        ip saddr @blocked_v4 drop comment \"nftfw:block-v4\"")
	line("        ip6 saddr @blocked_v6 drop comment \"nftfw:block-v6\"")
	emitPolicies(b, in.Policy, "input", "allow")
	line("        counter drop comment \"nftfw:input-default-deny\"")
	line("    }")
	line("    chain output {")
	line("        type filter hook output priority filter; policy drop;")
	line("        ct state invalid drop comment \"nftfw:invalid\"")
	emitOutputProvenanceTags(b, c.Interfaces)
	line("        oifname \"lo\" accept comment \"nftfw:loopback\"")
	emitProvenanceReplies(b, c.Interfaces, "output")
	emitContainerPathErrors(b, c)
	if c.System.IPv6Mode != "disabled" {
		line("        ip6 hoplimit 255 meta l4proto ipv6-icmp icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept comment \"nftfw:ipv6-neighbor-discovery\"")
		line(fmt.Sprintf("        oifname %s udp sport 546 udp dport 547 accept comment \"nftfw:dhcpv6-bootstrap\"", quote(c.Interfaces, "uplink")))
	}
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
	emitProvenanceTags(b, c.Interfaces, "forward")
	emitProvenanceReplies(b, c.Interfaces, "forward")
	line("        ip saddr @blocked_v4 drop comment \"nftfw:block-forward-source-v4\"")
	line("        ip daddr @blocked_v4 drop comment \"nftfw:block-forward-destination-v4\"")
	line("        ip6 saddr @blocked_v6 drop comment \"nftfw:block-forward-source-v6\"")
	line("        ip6 daddr @blocked_v6 drop comment \"nftfw:block-forward-destination-v6\"")
	emitContainerForwardGuards(b, c)
	line(fmt.Sprintf("        oifname %s drop comment \"nftfw:forward-physical-deny\"", quote(c.Interfaces, "uplink")))
	emitPolicies(b, in.Policy, "forward", "deny")
	emitContainerVPNMarkers(b, c)
	emitPolicies(b, in.Policy, "forward", "allow")
	line("        counter drop comment \"nftfw:forward-default-deny\"")
	line("    }")
	line("}")
}

func emitProvenanceTags(b *strings.Builder, interfaces []config.Interface, chain string) {
	line := func(s string) { b.WriteString(s); b.WriteByte('\n') }
	for _, configured := range sortedInterfaces(interfaces) {
		encoded := uint32(configured.ProvenanceID) << 24
		line(fmt.Sprintf(
			"        iifname %s ct direction original ct mark & 0x%08x == 0x00000000 ct mark set (ct mark & 0x%08x) | 0x%08x counter comment %s",
			strconv.Quote(configured.Name), provenance.Mask, provenance.KeepMask, encoded,
			quoteString("nftfw:provenance-tag-"+chain+":"+configured.Name),
		))
	}
}

func emitProvenanceReplies(b *strings.Builder, interfaces []config.Interface, chain string) {
	line := func(s string) { b.WriteString(s); b.WriteByte('\n') }
	for _, configured := range sortedInterfaces(interfaces) {
		encoded := uint32(configured.ProvenanceID) << 24
		line(fmt.Sprintf(
			"        oifname %s ct mark & 0x%08x == 0x%08x ct direction reply ct state established,related accept comment %s",
			strconv.Quote(configured.Name), provenance.Mask, encoded,
			quoteString("nftfw:provenance-reply-"+chain+":"+configured.Name),
		))
	}
}

func emitOutputProvenanceTags(b *strings.Builder, interfaces []config.Interface) {
	line := func(s string) { b.WriteString(s); b.WriteByte('\n') }
	for _, configured := range sortedInterfaces(interfaces) {
		encoded := uint32(configured.ProvenanceID) << 24
		line(fmt.Sprintf(
			"        oifname %s ct direction original ct mark & 0x%08x == 0x00000000 ct mark set (ct mark & 0x%08x) | 0x%08x counter comment %s",
			strconv.Quote(configured.Name), provenance.Mask, provenance.KeepMask, encoded,
			quoteString("nftfw:provenance-tag-output:"+configured.Name),
		))
	}
}

func emitInputReplies(b *strings.Builder, interfaces []config.Interface) {
	line := func(s string) { b.WriteString(s); b.WriteByte('\n') }
	for _, configured := range sortedInterfaces(interfaces) {
		// Host-original flows are tagged by their selected output interface. A
		// reply must return on that exact interface with the same connection mark.
		encoded := uint32(configured.ProvenanceID) << 24
		line(fmt.Sprintf(
			"        iifname %s ct mark & 0x%08x == 0x%08x ct direction reply ct state established,related accept comment %s",
			strconv.Quote(configured.Name), provenance.Mask, encoded, quoteString("nftfw:input-reply-only"),
		))
	}
}

type containerBinding struct {
	Interface string
	Prefix    string
	Family    string
}

func containerBindings(c config.Config) []containerBinding {
	var result []containerBinding
	for _, configured := range c.Interfaces {
		if configured.Role != "container" {
			continue
		}
		for _, raw := range configured.CIDRs {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				continue
			}
			family := "ip6"
			if prefix.Addr().Is4() {
				family = "ip"
			}
			result = append(result, containerBinding{Interface: configured.Name, Prefix: prefix.Masked().String(), Family: family})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Interface != result[j].Interface {
			return result[i].Interface < result[j].Interface
		}
		if result[i].Family != result[j].Family {
			return result[i].Family < result[j].Family
		}
		return result[i].Prefix < result[j].Prefix
	})
	return result
}

func emitContainerPathErrors(b *strings.Builder, c config.Config) {
	line := func(s string) { b.WriteString(s); b.WriteByte('\n') }
	for _, binding := range containerBindings(c) {
		if binding.Family == "ip" {
			line(fmt.Sprintf("        oifname %s ip daddr %s meta l4proto icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept comment %s", strconv.Quote(binding.Interface), binding.Prefix, quoteString("nftfw:container-path-errors-v4:"+binding.Interface)))
		} else {
			line(fmt.Sprintf("        oifname %s ip6 daddr %s meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept comment %s", strconv.Quote(binding.Interface), binding.Prefix, quoteString("nftfw:container-path-errors-v6:"+binding.Interface)))
		}
	}
}

func emitContainerForwardGuards(b *strings.Builder, c config.Config) {
	line := func(s string) { b.WriteString(s); b.WriteByte('\n') }
	vpn := strconv.Quote(c.WireGuard.Interface)
	uplink := quote(c.Interfaces, "uplink")
	for _, binding := range containerBindings(c) {
		familySuffix := "v4"
		if binding.Family == "ip6" {
			familySuffix = "v6"
		}
		line(fmt.Sprintf("        iifname %s %s saddr %s oifname %s tcp flags syn tcp option maxseg size set %d comment %s", strconv.Quote(binding.Interface), binding.Family, binding.Prefix, vpn, c.WireGuard.TCPMSS, quoteString("nftfw:container-vpn-mss-out-"+familySuffix+":"+binding.Interface)))
		line(fmt.Sprintf("        iifname %s oifname %s %s daddr %s tcp flags syn tcp option maxseg size set %d comment %s", vpn, strconv.Quote(binding.Interface), binding.Family, binding.Prefix, c.WireGuard.TCPMSS, quoteString("nftfw:container-vpn-mss-in-"+familySuffix+":"+binding.Interface)))
		line(fmt.Sprintf("        iifname %s %s saddr %s oifname %s drop comment %s", strconv.Quote(binding.Interface), binding.Family, binding.Prefix, uplink, quoteString("nftfw:container-physical-deny-"+familySuffix+":"+binding.Interface)))
	}
}

func emitContainerVPNMarkers(b *strings.Builder, c config.Config) {
	line := func(s string) { b.WriteString(s); b.WriteByte('\n') }
	vpn := strconv.Quote(c.WireGuard.Interface)
	for _, binding := range containerBindings(c) {
		familySuffix := "v4"
		if binding.Family == "ip6" {
			familySuffix = "v6"
		}
		line(fmt.Sprintf("        iifname %s %s saddr %s oifname %s counter comment %s", strconv.Quote(binding.Interface), binding.Family, binding.Prefix, vpn, quoteString("nftfw:container-vpn-egress-"+familySuffix+":"+binding.Interface)))
	}
}

func sortedInterfaces(interfaces []config.Interface) []config.Interface {
	result := append([]config.Interface(nil), interfaces...)
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
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
			external := "iifname " + strconv.Quote(rule.ExternalInterface)
			prefix := "        " + external + " "
			if source != "" {
				if strings.HasPrefix(source, external+" ") {
					// Avoid duplicating the same interface predicate when the
					// source zone explicitly names external_interface.
					prefix = "        " + source + " "
				} else {
					prefix += source + " "
				}
			}
			line(fmt.Sprintf("%s%s dport %d dnat to %s:%d comment %s", prefix, rule.Protocol, rule.ExternalPort, rule.Destination, rule.DestinationPort, quoteString("nftfw-nat:"+rule.Name)))
		}
	}
	line("    }")
	line("    chain postrouting {")
	line("        type nat hook postrouting priority srcnat; policy accept;")
	for _, binding := range containerBindings(c) {
		if binding.Family != "ip" {
			continue
		}
		line(fmt.Sprintf("        iifname %s ip saddr %s oifname %s masquerade comment %s", strconv.Quote(binding.Interface), binding.Prefix, strconv.Quote(c.WireGuard.Interface), quoteString("nftfw:vpn-only-nat:"+binding.Interface)))
	}
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

func validateContainerTopology(c config.Config, observedV4, observedV6 []string) error {
	expectedV4 := map[string]bool{}
	expectedV6 := map[string]bool{}
	for _, binding := range containerBindings(c) {
		if binding.Family == "ip" {
			expectedV4[binding.Prefix] = true
		} else {
			expectedV6[binding.Prefix] = true
		}
	}
	canonical := func(values []string, ipv4 bool) (map[string]bool, error) {
		result := make(map[string]bool, len(values))
		for _, raw := range values {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix.Bits() == 0 || prefix.Addr().Is4() != ipv4 {
				return nil, fmt.Errorf("invalid observed container network %q", raw)
			}
			value := prefix.Masked().String()
			if result[value] {
				return nil, fmt.Errorf("duplicate observed container network %q", value)
			}
			result[value] = true
		}
		return result, nil
	}
	actualV4, err := canonical(observedV4, true)
	if err != nil {
		return err
	}
	actualV6, err := canonical(observedV6, false)
	if err != nil {
		return err
	}
	if !samePrefixSet(expectedV4, actualV4) || !samePrefixSet(expectedV6, actualV6) {
		return errors.New("observed container subnets do not exactly match declared stable container interfaces")
	}
	return nil
}

func samePrefixSet(left, right map[string]bool) bool {
	if len(left) != len(right) {
		return false
	}
	for value := range left {
		if !right[value] {
			return false
		}
	}
	return true
}

func natSources(name string, effective policy.Effective) []string {
	if name == "any" {
		return []string{""}
	}
	var sources []string
	for _, selector := range zoneSelectors(name, "source", effective) {
		if selector.Family == "ip" {
			// NAT source zones obey the same interface-and-network conjunction
			// as filter policy. The separate external_interface predicate stays
			// authoritative and makes a mismatched zone/interface fail closed.
			sources = append(sources, selector.Expression)
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
	var networkSelectors []zoneSelector
	for _, network := range zone.Networks {
		networkSelectors = append(networkSelectors, zoneSelector{Expression: addressMatch(network, addressDirection), Family: familyExpr(network), RequiresVPN: destinationRequiresVPN(network)})
	}
	interfaces := append([]string(nil), zone.Interfaces...)
	for _, configured := range e.Config.Interfaces {
		if configured.Zone == name {
			interfaces = append(interfaces, configured.Name)
		}
	}
	interfaces = uniqueStrings(interfaces)
	if len(networkSelectors) > 0 && len(interfaces) > 0 {
		var result []zoneSelector
		for _, selector := range networkSelectors {
			for _, interfaceName := range interfaces {
				result = append(result, zoneSelector{
					Expression:  interfaceDirection + " " + strconv.Quote(interfaceName) + " " + selector.Expression,
					Family:      selector.Family,
					RequiresVPN: selector.RequiresVPN,
				})
			}
		}
		return result
	}
	if len(networkSelectors) > 0 {
		return networkSelectors
	}
	var result []zoneSelector
	for _, interfaceName := range interfaces {
		quoted := strconv.Quote(interfaceName)
		result = append(result,
			zoneSelector{Expression: interfaceDirection + " " + quoted + " meta nfproto ipv4", Family: "ip"},
			zoneSelector{Expression: interfaceDirection + " " + quoted + " meta nfproto ipv6", Family: "ip6"},
		)
	}
	return result
}

func uniqueStrings(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
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
