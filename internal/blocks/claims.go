package blocks

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/state"
)

type Service struct {
	Store *state.Store
	Max   int
}

var sourcePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{0,63}(/[a-zA-Z0-9_.-]{1,64})?$`)

func (s Service) Add(ctx context.Context, address, source, reason, actor string, expires *time.Time) (int64, error) {
	if s.Store == nil {
		return 0, fmt.Errorf("block claim store is unavailable")
	}
	if !sourcePattern.MatchString(source) || strings.HasPrefix(source, "allow") {
		return 0, fmt.Errorf("invalid block claim source %q", source)
	}
	p, err := netip.ParsePrefix(address)
	if err != nil {
		a, e := netip.ParseAddr(address)
		if e != nil {
			return 0, fmt.Errorf("invalid block address: %w", e)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	family := "ipv6"
	if p.Addr().Is4() {
		family = "ipv4"
	}
	return s.Store.AddClaimBounded(ctx, state.Claim{Address: p.Masked().String(), Family: family, Source: source, Reason: reason, Actor: actor, ExpiresAt: expires}, s.Max)
}

func (s Service) AddAllow(ctx context.Context, address, reason, actor string, expires *time.Time) (int64, error) {
	if s.Store == nil {
		return 0, fmt.Errorf("allow claim store is unavailable")
	}
	p, err := netip.ParsePrefix(address)
	if err != nil {
		a, parseErr := netip.ParseAddr(address)
		if parseErr != nil {
			return 0, fmt.Errorf("invalid allow address: %w", parseErr)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Bits() == 0 {
		return 0, fmt.Errorf("allow /0 is forbidden")
	}
	family := "ipv6"
	if p.Addr().Is4() {
		family = "ipv4"
	}
	return s.Store.AddClaimBounded(ctx, state.Claim{Address: p.Masked().String(), Family: family, Source: "allow", Reason: reason, Actor: actor, ExpiresAt: expires}, s.Max)
}

func (s Service) Remove(ctx context.Context, id int64, actor string) error {
	return s.RemoveBlock(ctx, id, actor)
}

func (s Service) RemoveBlock(ctx context.Context, id int64, actor string) error {
	if s.Store == nil {
		return fmt.Errorf("claim store is unavailable")
	}
	return s.Store.RemoveOperatorClaim(ctx, id, actor, "block")
}

func (s Service) RemoveAllow(ctx context.Context, id int64, actor string) error {
	if s.Store == nil {
		return fmt.Errorf("claim store is unavailable")
	}
	return s.Store.RemoveOperatorClaim(ctx, id, actor, "allow")
}

func (s Service) Effective(ctx context.Context) (v4, v6 []string, err error) {
	if s.Store == nil {
		return nil, nil, fmt.Errorf("claim store is unavailable")
	}
	claims, err := s.Store.Claims(ctx, time.Now().UTC())
	if err != nil {
		return nil, nil, err
	}
	return state.EffectiveAddresses(claims, "ipv4"), state.EffectiveAddresses(claims, "ipv6"), nil
}
