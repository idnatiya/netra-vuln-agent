package usecase

import (
	"context"
	"fmt"
)

type Heartbeat struct {
	Host    HostInspector
	Central Central
}

// Run does not use the spool: stale heartbeats are useless.
func (h *Heartbeat) Run(ctx context.Context) error {
	if err := h.Central.SendHeartbeat(ctx, h.Host.Inspect(ctx)); err != nil {
		return fmt.Errorf("send heartbeat: %w", err)
	}
	return nil
}
