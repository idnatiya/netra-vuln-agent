package config

import (
	"log/slog"
	"path/filepath"
	"slices"
	"time"

	"github.com/idnatiya/netra-vuln-agent/internal/gateway/central"
	"github.com/idnatiya/netra-vuln-agent/internal/gateway/hostinfo"
	"github.com/idnatiya/netra-vuln-agent/internal/gateway/trivy"
	"github.com/idnatiya/netra-vuln-agent/internal/repository"
	"github.com/idnatiya/netra-vuln-agent/internal/usecase"
)

const (
	DefaultPath = "/etc/vuln-agent/config.yaml"
	StateDir    = "/var/lib/vuln-agent"
	TrivyBin    = "/opt/vuln-agent/bin/trivy"
	spoolMax    = 5
)

// App is the agent wired for one loaded config.
type App struct {
	Host    *hostinfo.Linux
	Scanner *trivy.Runner
	Scan    *usecase.Scan
	Central *central.Client
	Spool   *repository.ReportRepository
	Flush   *usecase.Flush
}

func NewApp(f *File, version string, log *slog.Logger) (*App, error) {
	cfg := f.Config
	app := &App{
		Host:    &hostinfo.Linux{HostnameOverride: cfg.HostnameOverride, AgentVersion: version},
		Scanner: &trivy.Runner{Bin: TrivyBin, CacheDir: filepath.Join(StateDir, "cache"), TmpDir: StateDir},
	}
	if dirs := cfg.ScanAppDirs(); len(dirs) > 0 {
		pm2, err := app.Host.PM2Dirs()
		if err != nil {
			log.Warn("read pm2 app list", "err", err)
		}
		app.Scanner.AppDirs = slices.Concat(dirs, pm2)
	}
	app.Scan = &usecase.Scan{
		Scanner: app.Scanner, Host: app.Host,
		Cache: &repository.ScanConfigRepository{Path: filepath.Join(StateDir, "scan-config.json")},
		Now:   time.Now, Log: log, ExtraSkipDirs: cfg.ExtraSkipDirs,
	}
	httpClient, err := central.NewHTTPClient(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	app.Central = &central.Client{
		BaseURL:   cfg.CentralURL,
		ClientID:  cfg.ClientID,
		Token:     f.HostToken(),
		UserAgent: "vuln-agent/" + version,
		HTTP:      httpClient,
	}
	app.Spool = &repository.ReportRepository{Path: filepath.Join(StateDir, "spool"), Max: spoolMax}
	app.Flush = &usecase.Flush{Spool: app.Spool, Central: app.Central, Log: log}
	app.Scan.Central, app.Scan.Spool, app.Scan.Flush = app.Central, app.Spool, app.Flush
	return app, nil
}
