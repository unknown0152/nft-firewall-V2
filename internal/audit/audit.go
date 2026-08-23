package audit

import (
	"context"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
)

type Logger struct{ Store *state.Store }

func (l Logger) Record(ctx context.Context, actor, event, detail string) error {
	if l.Store == nil {
		return nil
	}
	return l.Store.Audit(ctx, actor, event, detail)
}
func (l Logger) Recent(ctx context.Context, limit int) ([]map[string]any, error) {
	return l.Store.RecentAudit(ctx, limit)
}
