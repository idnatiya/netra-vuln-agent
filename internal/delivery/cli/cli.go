// Package cli is the vuln-agent command line: it parses the subcommand and runs
// the matching usecase. The agent is passive: it only sends data and reads
// declarative scan config.
package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/idnatiya/netra-vuln-agent/internal/config"
	"github.com/idnatiya/netra-vuln-agent/internal/usecase"
)

const (
	enrollEnv = "VULN_AGENT_ENROLL_TOKEN"
)

const usage = `usage: vuln-agent <command> [-config path]

commands:
  scan       run one scan cycle and send the report to central
  heartbeat  send a heartbeat
  flush      resend spooled reports
  enroll     enroll this host (token from $VULN_AGENT_ENROLL_TOKEN or stdin) [-force]
  check      validate config, Trivy binary, and central connectivity
  install    install this binary, the pinned Trivy, a default config, and systemd timers (root)
  version    print version
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
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("cmd", cmd)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch cmd {
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

	needsToken := cmd == "scan" || cmd == "heartbeat" || cmd == "flush"
	if needsToken && cfgFile.HostToken() == "" {
		return errors.New("host not enrolled: run `vuln-agent enroll` first")
	}

	switch cmd {
	case "scan":
		return app.Scan.Run(ctx)
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
