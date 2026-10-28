// Command vuln-agent runs Trivy and keeps the results locally; with central_url
// set it also sends them to central. The agent is passive: it only sends data
// and reads declarative scan config.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/idnatiya/netra-vuln-agent/internal/adapter/central"
	"github.com/idnatiya/netra-vuln-agent/internal/adapter/hostinfo"
	"github.com/idnatiya/netra-vuln-agent/internal/adapter/localconfig"
	"github.com/idnatiya/netra-vuln-agent/internal/adapter/spool"
	"github.com/idnatiya/netra-vuln-agent/internal/adapter/trivy"
	"github.com/idnatiya/netra-vuln-agent/internal/adapter/web"
	"github.com/idnatiya/netra-vuln-agent/internal/usecase"
)

var version = "dev" // -ldflags "-X main.version=..."

const (
	defaultConfig = "/etc/vuln-agent/config.yaml"
	stateDir      = "/var/lib/vuln-agent"
	trivyBin      = "/opt/vuln-agent/bin/trivy"
	spoolMax      = 5
	historyMax    = 30
	serveAddr     = "127.0.0.1:8090"
	enrollEnv     = "VULN_AGENT_ENROLL_TOKEN"
)

const usage = `usage: vuln-agent <command> [-config path]

commands:
  scan       run one scan cycle, keep the report locally, and send it to central
  report     print the newest report as JSON [-html for the HTML page]
  serve      serve the local reports read-only over HTTP [-addr 127.0.0.1:8090]
  heartbeat  send a heartbeat
  flush      resend spooled reports
  enroll     enroll this host (token from $VULN_AGENT_ENROLL_TOKEN or stdin) [-force]
  check      validate config, Trivy binary, and central connectivity
  version    print version

Without central_url in the config the agent runs standalone: scan only keeps
reports locally, heartbeat is a no-op, and flush/enroll are not available.
`

func main() { os.Exit(run(os.Args[1:], os.Stdin)) }

func run(args []string, stdin io.Reader) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	cmd := args[0]
	if cmd == "version" {
		fmt.Println(version)
		return 0
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	configPath := fs.String("config", defaultConfig, "config file")
	force := fs.Bool("force", false, "enroll: overwrite existing host token")
	html := fs.Bool("html", false, "report: print the HTML page instead of JSON")
	addr := fs.String("addr", serveAddr, "serve: listen address")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("cmd", cmd)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch cmd {
	case "report":
		err = report(os.Stdout, *html)
	case "serve":
		err = serve(ctx, log, *addr)
	default:
		err = dispatch(ctx, log, cmd, *configPath, *force, stdin)
	}
	if err != nil {
		log.Error("failed", "err", err)
		return 1
	}
	return 0
}

func dispatch(ctx context.Context, log *slog.Logger, cmd, configPath string, force bool, stdin io.Reader) error {
	cfgFile, warnings, err := localconfig.Load(configPath)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		log.Warn(w)
	}
	cfg := cfgFile.Config
	host := &hostinfo.Linux{HostnameOverride: cfg.HostnameOverride, AgentVersion: version}
	scanner := &trivy.Runner{Bin: trivyBin, CacheDir: filepath.Join(stateDir, "cache"), TmpDir: stateDir}
	scan := &usecase.Scan{
		Scanner: scanner, Host: host, History: history(),
		Cache: &localconfig.ScanConfigCache{Path: filepath.Join(stateDir, "scan-config.json")},
		Now:   time.Now, Log: log,
	}
	if cfg.Standalone() {
		return dispatchStandalone(ctx, log, cmd, scan)
	}

	httpClient, err := central.NewHTTPClient(cfg.CAFile)
	if err != nil {
		return err
	}
	cen := &central.Client{
		BaseURL:   cfg.CentralURL,
		ClientID:  cfg.ClientID,
		Token:     cfgFile.HostToken(),
		UserAgent: "vuln-agent/" + version,
		HTTP:      httpClient,
	}
	sp := &spool.Dir{Path: filepath.Join(stateDir, "spool"), Max: spoolMax}
	flush := &usecase.Flush{Spool: sp, Central: cen, Log: log}

	needsToken := cmd == "scan" || cmd == "heartbeat" || cmd == "flush"
	if needsToken && cfgFile.HostToken() == "" {
		return errors.New("host not enrolled: run `vuln-agent enroll` first")
	}

	switch cmd {
	case "scan":
		scan.Central, scan.Spool, scan.Flush = cen, sp, flush
		return runScan(ctx, log, scan)
	case "heartbeat":
		return (&usecase.Heartbeat{Host: host, Central: cen}).Run(ctx)
	case "flush":
		n, err := flush.Run(ctx)
		log.Info("flush done", "sent", n)
		return err
	case "enroll":
		tok, err := enrollToken(stdin)
		if err != nil {
			return err
		}
		if err := (&usecase.Enroll{Host: host, Central: cen, Creds: cfgFile}).Run(ctx, tok, force); err != nil {
			return err
		}
		log.Info("enrolled", "client_id", cfg.ClientID, "config", configPath)
		return nil
	case "check":
		return (&usecase.Check{Scanner: scanner, Central: cen, Creds: cfgFile, Log: log}).Run(ctx)
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func dispatchStandalone(ctx context.Context, log *slog.Logger, cmd string, scan *usecase.Scan) error {
	switch cmd {
	case "scan":
		return runScan(ctx, log, scan)
	case "heartbeat":
		log.Info("standalone (no central_url): heartbeat skipped")
		return nil
	case "check":
		return (&usecase.Check{Scanner: scan.Scanner, Log: log}).Run(ctx)
	case "flush", "enroll":
		return fmt.Errorf("%s needs central: set central_url and client_id in the config", cmd)
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func history() *spool.Dir {
	return &spool.Dir{Path: filepath.Join(stateDir, "reports"), Max: historyMax}
}

// runScan scans, then refreshes reports/latest.html even when the scan failed.
func runScan(ctx context.Context, log *slog.Logger, scan *usecase.Scan) error {
	err := scan.Run(ctx)
	if herr := writeLatestHTML(filepath.Join(stateDir, "reports", "latest.html")); herr != nil {
		log.Warn("write latest.html", "err", herr)
	}
	return err
}

func writeLatestHTML(path string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".latest-*.html")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	err = web.Render(tmp, history(), "", false)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func report(w io.Writer, html bool) error {
	h := history()
	if html {
		return web.Render(w, h, "", false)
	}
	ids, err := h.List()
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return web.ErrNoReports
	}
	r, err := h.Load(ids[len(ids)-1])
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func serve(ctx context.Context, log *slog.Logger, addr string) error {
	srv := web.NewServer(addr, history(), log)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
	log.Info("serving reports", "addr", addr)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// enrollToken reads the token from env or the first line of stdin, never from CLI args.
func enrollToken(stdin io.Reader) (string, error) {
	if t := os.Getenv(enrollEnv); t != "" {
		return t, nil
	}
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read enroll token from stdin: %w", err)
	}
	if t := strings.TrimSpace(line); t != "" {
		return t, nil
	}
	return "", fmt.Errorf("enroll token required via $%s or stdin", enrollEnv)
}
