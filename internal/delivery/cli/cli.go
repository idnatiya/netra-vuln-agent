// Package cli is the vuln-agent command line: it parses the subcommand and runs
// the matching usecase. The agent is passive: it only sends data and reads
// declarative scan config.
package cli

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

	"github.com/idnatiya/netra-vuln-agent/internal/config"
	reporthttp "github.com/idnatiya/netra-vuln-agent/internal/delivery/http"
	"github.com/idnatiya/netra-vuln-agent/internal/usecase"
)

const (
	serveAddr = "127.0.0.1:8090"
	enrollEnv = "VULN_AGENT_ENROLL_TOKEN"
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
  install    install this binary, the pinned Trivy, a default config, and systemd timers (root)
  version    print version

Without central_url in the config the agent runs standalone: scan only keeps
reports locally, heartbeat is a no-op, and flush/enroll are not available.
`

// Run executes one subcommand and returns the process exit code.
func Run(args []string, stdin io.Reader, version, trivyVersion string) int {
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
	configPath := fs.String("config", config.DefaultPath, "config file")
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
	case "install":
		err = install(ctx, log, trivyVersion)
	default:
		err = dispatch(ctx, log, cmd, *configPath, version, *force, stdin)
	}
	if err != nil {
		log.Error("failed", "err", err)
		return 1
	}
	return 0
}

func dispatch(ctx context.Context, log *slog.Logger, cmd, configPath, version string, force bool, stdin io.Reader) error {
	cfgFile, warnings, err := config.Load(configPath)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		log.Warn(w)
	}
	app, err := config.NewApp(cfgFile, version, log)
	if err != nil {
		return err
	}
	if cfgFile.Config.Standalone() {
		return dispatchStandalone(ctx, log, cmd, app)
	}

	needsToken := cmd == "scan" || cmd == "heartbeat" || cmd == "flush"
	if needsToken && cfgFile.HostToken() == "" {
		return errors.New("host not enrolled: run `vuln-agent enroll` first")
	}

	switch cmd {
	case "scan":
		return runScan(ctx, log, app.Scan)
	case "heartbeat":
		return (&usecase.Heartbeat{Host: app.Host, Central: app.Central}).Run(ctx)
	case "flush":
		n, err := app.Flush.Run(ctx)
		log.Info("flush done", "sent", n)
		return err
	case "enroll":
		tok, err := enrollToken(stdin)
		if err != nil {
			return err
		}
		if err := (&usecase.Enroll{Host: app.Host, Central: app.Central, Creds: cfgFile}).Run(ctx, tok, force); err != nil {
			return err
		}
		log.Info("enrolled", "client_id", cfgFile.Config.ClientID, "config", configPath)
		return nil
	case "check":
		return (&usecase.Check{Scanner: app.Scanner, Central: app.Central, Creds: cfgFile, Log: log}).Run(ctx)
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func dispatchStandalone(ctx context.Context, log *slog.Logger, cmd string, app *config.App) error {
	switch cmd {
	case "scan":
		return runScan(ctx, log, app.Scan)
	case "heartbeat":
		log.Info("standalone (no central_url): heartbeat skipped")
		return nil
	case "check":
		return (&usecase.Check{Scanner: app.Scanner, Log: log}).Run(ctx)
	case "flush", "enroll":
		return fmt.Errorf("%s needs central: set central_url and client_id in the config", cmd)
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// runScan scans, then refreshes reports/latest.html even when the scan failed.
func runScan(ctx context.Context, log *slog.Logger, scan *usecase.Scan) error {
	err := scan.Run(ctx)
	if herr := writeLatestHTML(filepath.Join(config.StateDir, "reports", "latest.html")); herr != nil {
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
	err = reporthttp.Render(tmp, config.History(), "", false)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func report(w io.Writer, html bool) error {
	h := config.History()
	if html {
		return reporthttp.Render(w, h, "", false)
	}
	ids, err := h.List()
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return reporthttp.ErrNoReports
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
	srv := reporthttp.NewServer(addr, config.History(), log)
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
