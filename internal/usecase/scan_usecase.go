package usecase

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/idnatiya/netra-vuln-agent/internal/entity"
)

// scanGrace is the margin on top of Trivy's --timeout before the process is killed
// (default 30m + 10m = 40m).
const scanGrace = 10 * time.Minute

// Scan runs one scan cycle. Central, Spool and Flush are nil in standalone mode:
// the report is then only kept in History.
type Scan struct {
	Scanner Scanner
	Host    HostInspector
	Central Central
	Spool   Spool
	History Spool // local report history (both modes)
	Cache   ScanConfigCache
	// ExtraSkipDirs come from the local config and are added to the scan config in effect.
	ExtraSkipDirs []string
	Flush         *Flush
	Now           func() time.Time
	Log           *slog.Logger
}

func (s *Scan) Run(ctx context.Context) error {
	if s.Central == nil {
		return s.runStandalone(ctx)
	}
	if n, err := s.Flush.Run(ctx); err != nil {
		s.Log.Warn("flush spool before scan failed", "sent", n, "err", err)
	} else if n > 0 {
		s.Log.Info("flushed spool", "sent", n)
	}

	r, scanErr := s.scan(ctx, s.withExtraSkipDirs(s.scanConfig(ctx)))
	s.saveHistory(r)

	if err := s.Central.SendReport(ctx, r); err != nil {
		if errors.Is(err, ErrRejected) {
			return fmt.Errorf("send report: %w", err)
		}
		if serr := s.Spool.Save(r); serr != nil {
			return errors.Join(fmt.Errorf("send report: %w", err), fmt.Errorf("spool report: %w", serr))
		}
		return fmt.Errorf("send report (spooled): %w", err)
	}
	if scanErr != nil {
		return fmt.Errorf("scan failed (reported to central): %w", scanErr)
	}
	return nil
}

func (s *Scan) runStandalone(ctx context.Context) error {
	r, scanErr := s.scan(ctx, s.withExtraSkipDirs(s.localScanConfig()))
	if err := s.History.Save(r); err != nil {
		return errors.Join(scanErr, fmt.Errorf("save report: %w", err))
	}
	if scanErr != nil {
		return fmt.Errorf("scan failed: %w", scanErr)
	}
	return nil
}

// saveHistory keeps a local copy; failure must not block sending to central.
func (s *Scan) saveHistory(r entity.Report) {
	if err := s.History.Save(r); err != nil {
		s.Log.Warn("save local report history", "err", err)
	}
}

// scan runs Trivy and builds the report; on failure the report has status error.
func (s *Scan) scan(ctx context.Context, cfg entity.ScanConfig) (entity.Report, error) {
	start := s.Now()
	scanCtx, cancel := context.WithTimeout(ctx, cfg.Timeout+scanGrace)
	findings, scanErr := s.Scanner.Scan(scanCtx, cfg)
	cancel()

	version, err := s.Scanner.Version(ctx)
	if err != nil {
		s.Log.Warn("read trivy version", "err", err)
	}

	r := entity.Report{
		Host:         s.Host.Inspect(ctx),
		Status:       entity.StatusOK,
		ScannedAt:    start,
		Duration:     s.Now().Sub(start),
		TrivyVersion: version,
		Findings:     findings,
	}
	if scanErr != nil {
		r.Status = entity.StatusError
		r.Error = entity.TruncateError(scanErr.Error())
		r.Findings = nil
		s.Log.Error("trivy scan failed", "err", scanErr)
	}
	s.Log.Info("scan finished", "status", r.Status, "findings", len(r.Findings), "duration", r.Duration)
	return r, scanErr
}

// scanConfig: config from central -> local cache -> default.
func (s *Scan) scanConfig(ctx context.Context) entity.ScanConfig {
	cfg, err := s.Central.FetchScanConfig(ctx)
	if err == nil {
		err = cfg.Validate()
	}
	if err == nil {
		if cerr := s.Cache.Save(cfg); cerr != nil {
			s.Log.Warn("cache scan config", "err", cerr)
		}
		return cfg
	}
	s.Log.Warn("fetch scan config failed, falling back", "err", err)
	return s.localScanConfig()
}

// localScanConfig: last config cached from central -> default.
func (s *Scan) localScanConfig() entity.ScanConfig {
	cfg, err := s.Cache.Load()
	if err == nil {
		err = cfg.Validate()
	}
	if err == nil {
		s.Log.Info("using cached scan config")
		return cfg
	}
	s.Log.Info("using default scan config", "cache_err", err)
	return entity.DefaultScanConfig()
}

// withExtraSkipDirs appends the local extra skip dirs that are not listed yet.
// If the result is invalid (e.g. over the limit), the extras are dropped.
func (s *Scan) withExtraSkipDirs(cfg entity.ScanConfig) entity.ScanConfig {
	if len(s.ExtraSkipDirs) == 0 {
		return cfg
	}
	merged := cfg
	merged.SkipDirs = slices.Clone(cfg.SkipDirs)
	for _, d := range s.ExtraSkipDirs {
		if !slices.Contains(merged.SkipDirs, d) {
			merged.SkipDirs = append(merged.SkipDirs, d)
		}
	}
	if err := merged.Validate(); err != nil {
		s.Log.Warn("ignoring extra_skip_dirs", "err", err)
		return cfg
	}
	return merged
}
