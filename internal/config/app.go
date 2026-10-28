package config

import (
	"log/slog"
	"path/filepath"
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
	historyMax  = 30
)

// App is the agent wired for one loaded config. Central, Spool, and Flush are
// nil when standalone.
type App struct {
	Host    *hostinfo.Linux
	Scanner *trivy.Runner
	Scan    *usecase.Scan
	Central *central.Client
	Spool   *repository.ReportRepository
	Flush   *usecase.Flush
}

// History is the local report history (both modes).
func History() *repository.ReportRepository {
	return &repository.ReportRepository{Path: filepath.Join(StateDir, "reports"), Max: historyMax}
}

func NewApp(f *File, version string, log *slog.Logger) (*App, error) {
	cfg := f.Config
	app := &App{
		Host:    &hostinfo.Linux{HostnameOverride: cfg.HostnameOverride, AgentVersion: version},
		Scanner: &trivy.Runner{Bin: TrivyBin, CacheDir: filepath.Join(StateDir, "cache"), TmpDir: StateDir},
	}
	app.Scan = &usecase.Scan{
		Scanner: app.Scanner, Host: app.Host, History: History(),
		Cache: &repository.ScanConfigRepository{Path: filepath.Join(StateDir, "scan-config.json")},
		Now:   time.Now, Log: log,
	}
	if cfg.Standalone() {
		return app, nil
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
