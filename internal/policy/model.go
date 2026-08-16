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

type Decision struct {
	Action      string
	Matched     *config.Policy
	SourceZone  string
	Destination string
	Reason      string
}

func (e Effective) Explain(q Query) Decision {
	srcZone := e.sourceZone(q.From)
	dest := q.To
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
		return Decision{Action: p.Action, Matched: &cp, SourceZone: srcZone, Destination: dest, Reason: fmt.Sprintf("%s -> %s, service %s, action %s", p.From, p.To, p.Service, p.Action)}
	}
	return Decision{Action: "deny", SourceZone: srcZone, Destination: dest, Reason: "no allow policy matched; default deny"}
}

func (e Effective) sourceZone(raw string) string {
	if raw == "" || raw == "host" {
		return "host"
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
