package recovery

import (
	"context"
	"github.com/unknown0152/nft-firewall-v2/internal/reconcile"
)

type Controller struct{ Manager *reconcile.Manager }

func (c Controller) RollbackExpired(ctx context.Context) (bool, error) {
	if c.Manager == nil {
		return false, nil
	}
	return c.Manager.RollbackExpired(ctx)
}
