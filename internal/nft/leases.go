package nft

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type TimedElement struct {
	Prefix         string
	TimeoutSeconds int64
}

// ReplaceClaimSets updates all provenance-derived block and access sets in one
// nft transaction. Expiring access entries also expire in the kernel if the
// daemon stops running.
func (b *Backend) ReplaceClaimSets(ctx context.Context, blockedV4, blockedV6 []string, trustedV4, trustedV6 []TimedElement) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	sets := []struct {
		name    string
		family  string
		plain   []string
		timed   []TimedElement
		trusted bool
	}{
		{name: "blocked_v4", family: "ipv4", plain: blockedV4},
		{name: "blocked_v6", family: "ipv6", plain: blockedV6},
		{name: "trusted_v4", family: "ipv4", timed: trustedV4, trusted: true},
		{name: "trusted_v6", family: "ipv6", timed: trustedV6, trusted: true},
	}
	var script strings.Builder
	for _, set := range sets {
		fmt.Fprintf(&script, "flush set inet %s %s\n", FilterTable, set.name)
		var encoded []string
		if set.trusted {
			elements := append([]TimedElement(nil), set.timed...)
			sort.Slice(elements, func(i, j int) bool { return elements[i].Prefix < elements[j].Prefix })
			for _, element := range elements {
				if err := validateSetPrefix(element.Prefix, set.family); err != nil {
					return fmt.Errorf("set %s: %w", set.name, err)
				}
				if element.TimeoutSeconds < 0 || element.TimeoutSeconds > int64((365*24*time.Hour)/time.Second) {
					return fmt.Errorf("set %s has invalid timeout", set.name)
				}
				value := element.Prefix
				if element.TimeoutSeconds > 0 {
					value += fmt.Sprintf(" timeout %ds", element.TimeoutSeconds)
				}
				encoded = append(encoded, value)
			}
		} else {
			values := append([]string(nil), set.plain...)
			sort.Strings(values)
			for _, value := range values {
				if err := validateSetPrefix(value, set.family); err != nil {
					return fmt.Errorf("set %s: %w", set.name, err)
				}
			}
			encoded = values
		}
		if len(encoded) > 0 {
			fmt.Fprintf(&script, "add element inet %s %s { %s }\n", FilterTable, set.name, strings.Join(encoded, ", "))
		}
	}
	return b.applyRuntimeTransaction(ctx, script.String(), "nftfw-claims-")
}

func validateSetPrefix(raw, family string) error {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || prefix.Bits() == 0 {
		return fmt.Errorf("invalid set element %q", raw)
	}
	if family == "ipv4" && !prefix.Addr().Is4() || family == "ipv6" && !prefix.Addr().Is6() {
		return fmt.Errorf("wrong-family set element %q", raw)
	}
	return nil
}

func (b *Backend) applyRuntimeTransaction(ctx context.Context, script, prefix string) error {
	if err := b.Check(ctx, script); err != nil {
		return err
	}
	path, cleanup, err := b.tempScript(script, prefix)
	if err != nil {
		return err
	}
	defer cleanup()
	ctx, cancel := context.WithTimeout(ctx, b.Timeout)
	defer cancel()
	_, stderr, runErr := b.Runner.Run(ctx, "--file", path)
	if runErr != nil {
		return fmt.Errorf("nft runtime set replacement failed: %s: %w", strings.TrimSpace(stderr), runErr)
	}
	return nil
}
