package usecase

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
)

type Flush struct {
	Spool   Spool
	Central Central
	Log     *slog.Logger
}

// Run sends spooled reports oldest first and stops at the first send failure
// (central is probably down). Permanently rejected reports are dropped.
func (f *Flush) Run(ctx context.Context) (sent int, err error) {
	ids, err := f.Spool.List()
	if err != nil {
		return 0, fmt.Errorf("list spool: %w", err)
	}
	for _, id := range ids {
		r, err := f.Spool.Load(id)
		if err != nil {
			f.Log.Warn("dropping unreadable spool file", "id", id, "err", err)
			f.remove(id)
			continue
		}
		if err := f.Central.SendReport(ctx, r); err != nil {
			if errors.Is(err, ErrRejected) {
				f.Log.Warn("central rejected spooled report, dropping", "id", id, "err", err)
				f.remove(id)
				continue
			}
			return sent, fmt.Errorf("send spooled report %s: %w", id, err)
		}
		f.remove(id)
		sent++
	}
	return sent, nil
}

func (f *Flush) remove(id string) {
	if err := f.Spool.Remove(id); err != nil {
		f.Log.Warn("remove spool file", "id", id, "err", err)
	}
}
