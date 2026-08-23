// Package policy contains the declarative model and pure decision logic.
package policy

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/unknown0152/nft-firewall-v2/internal/config"
)

type Effective struct {
	Config config.Config
	Zones  map[string]config.Zone
	Svcs   map[string]config.Service
}

func Compile(c config.Config) (Effective, error) {
	if err := config.Validate(c); err != nil {
		return Effective{}, err
	}
	e := Effective{Config: c, Zones: map[string]config.Zone{}, Svcs: map[string]config.Service{}}
	for _, z := range c.Zones {
		e.Zones[z.Name] = z
	}
	for _, s := range c.Services {
		e.Svcs[s.Name] = s
	}
	return e, nil
}

type Query struct {
	From     string
	To       string
	Protocol string
	Port     int
}

type RuntimeContext struct {
	BlockedPrefixes []string
	TrustedPrefixes []string
}

type Decision struct {
	Action      string
	Matched     *config.Policy
	SourceZone  string
	Destination string
	Reason      string
	Rule        string
}

func (e Effective) Explain(q Query) Decision {
	return e.ExplainEffective(q, RuntimeContext{})
}

func (e Effective) ExplainEffective(q Query, runtime RuntimeContext) Decision {
	srcZone := e.sourceZone(q.From)
	dest := q.To
	fromAddress, fromIsAddress := netip.ParseAddr(q.From)
	toAddress, toIsAddress := netip.ParseAddr(q.To)
	if fromIsAddress == nil && fromAddress.IsLoopback() || toIsAddress == nil && toAddress.IsLoopback() {
		return Decision{Action: "allow", SourceZone: srcZone, Destination: dest, Reason: "loopback traffic is explicitly allowed", Rule: "nftfw:loopback"}
	}
	if e.Config.System.IPv6Mode == "disabled" && (fromIsAddress == nil && fromAddress.Is6() || toIsAddress == nil && toAddress.Is6()) {
		return Decision{Action: "deny", SourceZone: srcZone, Destination: dest, Reason: "IPv6 mode is disabled", Rule: "nftfw:ipv6-mode-disabled"}
	}
	if fromIsAddress == nil && addressInPrefixes(fromAddress, runtime.BlockedPrefixes) {
		return Decision{Action: "deny", SourceZone: srcZone, Destination: dest, Reason: "source address has an active block claim", Rule: "nftfw:block-source"}
	}
	if toIsAddress == nil && addressInPrefixes(toAddress, runtime.BlockedPrefixes) {
		return Decision{Action: "deny", SourceZone: srcZone, Destination: dest, Reason: "destination address has an active block claim", Rule: "nftfw:block-destination"}
	}
	if q.To == "host" && fromIsAddress == nil && addressInPrefixes(fromAddress, runtime.TrustedPrefixes) && e.isTrustedService(q.Protocol, q.Port) {
		return Decision{Action: "allow", SourceZone: srcZone, Destination: dest, Reason: "source has an active temporary access lease for this trusted service", Rule: "nftfw:trusted-services"}
	}
	for _, p := range e.SortedPolicies() {
		if p.Action != "allow" && p.Action != "deny" {
			continue
		}
		if !zoneMatches(p.From, srcZone, q.From) || !destMatches(p.To, dest, e) {
			continue
		}
		svc, ok := e.Svcs[p.Service]
		if !ok || svc.Protocol != q.Protocol || (svc.Protocol != "icmp" && !containsPort(svc.Ports, q.Port)) {
			continue
		}
		cp := p
		return Decision{Action: p.Action, Matched: &cp, SourceZone: srcZone, Destination: dest, Reason: fmt.Sprintf("%s -> %s, service %s, action %s", p.From, p.To, p.Service, p.Action), Rule: "nftfw-policy:" + p.Name}
	}
	return Decision{Action: "deny", SourceZone: srcZone, Destination: dest, Reason: "no allow policy matched; default deny", Rule: "nftfw:default-deny"}
}

func (e Effective) isTrustedService(protocol string, port int) bool {
	for _, name := range e.Config.Runtime.TrustedServices {
		service, ok := e.Svcs[name]
		if ok && service.Protocol == protocol && (protocol == "icmp" || containsPort(service.Ports, port)) {
			return true
		}
	}
	return false
}

func addressInPrefixes(address netip.Addr, prefixes []string) bool {
	for _, raw := range prefixes {
		prefix, err := netip.ParsePrefix(raw)
		if err == nil && prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (e Effective) sourceZone(raw string) string {
	if raw == "" || raw == "host" {
		return "host"
	}
	if _, ok := e.Zones[raw]; ok {
		return raw
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return "unknown"
	}
	for _, z := range e.Config.Zones {
		for _, rawNet := range z.Networks {
			prefix, err := netip.ParsePrefix(rawNet)
			if err == nil && prefix.Contains(addr) {
				return z.Name
			}
		}
	}
	for _, in := range e.Config.Interfaces {
		for _, rawNet := range in.CIDRs {
			prefix, err := netip.ParsePrefix(rawNet)
			if err == nil && prefix.Contains(addr) && in.Zone != "" {
				return in.Zone
			}
		}
	}
	return "unknown"
}

func zoneMatches(want, actual, raw string) bool {
	if want == "any" || want == actual {
		return true
	}
	return want == "host" && (raw == "" || raw == "host")
}

func destMatches(want, actual string, e Effective) bool {
	if want == "any" || want == actual {
		return true
	}
	if want == "host" && (actual == "" || actual == "host") {
		return true
	}
	if z, ok := e.Zones[want]; ok {
		for _, n := range z.Networks {
			if p, err := netip.ParsePrefix(n); err == nil {
				if a, err := netip.ParseAddr(actual); err == nil && p.Contains(a) {
					return true
				}
			}
		}
	}
	return false
}

func containsPort(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

func (e Effective) SortedPolicies() []config.Policy {
	result := append([]config.Policy(nil), e.Config.Policies...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Action != result[j].Action {
			return result[i].Action == "deny"
		}
		return result[i].Name < result[j].Name
	})
	return result
}
