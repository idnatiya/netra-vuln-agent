package usecase

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
)

// Check validates agent readiness. The local config is already validated on load.
// Central and Creds are nil in standalone mode (only Trivy is checked).
type Check struct {
	Scanner Scanner
	Central Central
	Creds   CredentialStore
	Log     *slog.Logger
}

func (c *Check) Run(ctx context.Context) error {
	var errs []error

	if v, err := c.Scanner.Version(ctx); err != nil {
		errs = append(errs, fmt.Errorf("trivy: %w", err))
	} else {
		c.Log.Info("check trivy: ok", "version", v)
	}
	if c.Central == nil {
		c.Log.Info("check central: skipped (standalone)")
		return errors.Join(errs...)
	}

	if c.Creds.HostToken() == "" {
		errs = append(errs, errors.New("token: empty, run `vuln-agent enroll`"))
	} else {
		c.Log.Info("check token: present")
	}

	if cfg, err := c.Central.FetchScanConfig(ctx); err != nil {
		errs = append(errs, fmt.Errorf("central: %w", err))
	} else if err := cfg.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("central scan config: %w", err))
	} else {
		c.Log.Info("check central: ok")
	}

	return errors.Join(errs...)
}
