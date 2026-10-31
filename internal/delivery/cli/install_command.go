package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/idnatiya/netra-vuln-agent/internal/config"
	"github.com/idnatiya/netra-vuln-agent/internal/gateway/trivy"
	"github.com/idnatiya/netra-vuln-agent/internal/repository"
	"github.com/idnatiya/netra-vuln-agent/internal/usecase"
)

const (
	agentBin     = "/opt/vuln-agent/bin/vuln-agent"
	pathLink     = "/usr/bin/vuln-agent" // not /usr/local/bin: sudo's secure_path on RHEL 7/8 lacks it
	trivyBaseURL = "https://github.com/aquasecurity/trivy/releases/download"
	unitDir      = "/etc/systemd/system"
)

const unitLimits = `CPUQuota=100%
MemoryMax=1G
Nice=19
IOSchedulingClass=idle
`

var units = map[string]string{
	"vuln-agent-scan.service": `[Unit]
Description=vuln-agent scan
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/vuln-agent scan
` + unitLimits,
	"vuln-agent-scan.timer": `[Unit]
Description=Daily vuln-agent scan

[Timer]
OnCalendar=daily
RandomizedDelaySec=2h
Persistent=true

[Install]
WantedBy=timers.target
`,
	"vuln-agent-heartbeat.service": `[Unit]
Description=vuln-agent heartbeat
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/vuln-agent heartbeat
` + unitLimits,
	"vuln-agent-heartbeat.timer": `[Unit]
Description=vuln-agent heartbeat every 15 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min

[Install]
WantedBy=timers.target
`,
}

// install puts the running binary, the pinned Trivy, a default config, and the
// systemd timers in place. It is run by an operator and is safe to rerun.
// install sets the host up. With centralURL and clientID (the one-line installer
// from central) it fills them into a new config and, when $VULN_AGENT_ENROLL_TOKEN
// is set and the host has no token yet, enrolls and starts the first scan.
func install(ctx context.Context, log *slog.Logger, version, trivyVersion, centralURL, clientID string) error {
	if os.Geteuid() != 0 {
		return errors.New("install must run as root")
	}
	if (centralURL == "") != (clientID == "") {
		return errors.New("-central-url and -client-id go together")
	}
	if centralURL != "" {
		if err := (config.Config{CentralURL: centralURL, ClientID: clientID}).Validate(); err != nil {
			return err
		}
	}
	for _, d := range []struct {
		path string
		mode fs.FileMode
	}{
		{filepath.Dir(agentBin), 0o755},
		{filepath.Dir(config.DefaultPath), 0o700},
		{config.StateDir, 0o700},
		{filepath.Join(config.StateDir, "spool"), 0o700},
		{filepath.Join(config.StateDir, "cache"), 0o700},
	} {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return err
		}
		if err := os.Chmod(d.path, d.mode); err != nil {
			return err
		}
	}

	if err := installSelf(); err != nil {
		return fmt.Errorf("install agent binary: %w", err)
	}
	tmpLink := pathLink + ".tmp"
	os.Remove(tmpLink)
	if err := os.Symlink(agentBin, tmpLink); err != nil {
		return err
	}
	if err := os.Rename(tmpLink, pathLink); err != nil {
		return err
	}

	if v, _ := (&trivy.Runner{Bin: config.TrivyBin}).Version(ctx); v == trivyVersion {
		log.Info("trivy already installed", "version", v)
	} else {
		arch, ok := map[string]string{"amd64": "64bit", "arm64": "ARM64"}[runtime.GOARCH]
		if !ok {
			return fmt.Errorf("unsupported arch %s", runtime.GOARCH)
		}
		log.Info("installing trivy", "version", trivyVersion, "replacing", v)
		client := &http.Client{Timeout: 10 * time.Minute}
		if err := trivy.Install(ctx, client, trivyBaseURL, trivyVersion, arch, config.TrivyBin); err != nil {
			return fmt.Errorf("install trivy: %w", err)
		}
	}

	f, err := os.OpenFile(config.DefaultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	switch {
	case errors.Is(err, fs.ErrExist):
		log.Info("config exists, left unchanged", "config", config.DefaultPath)
	case err != nil:
		return err
	default:
		_, err = f.WriteString(config.Template(centralURL, clientID))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		log.Info("wrote config template", "config", config.DefaultPath)
	}

	if err := removeReportPage(ctx); err != nil {
		return err
	}
	for name, body := range units {
		if err := os.WriteFile(filepath.Join(unitDir, name), []byte(body), 0o644); err != nil {
			return err
		}
	}
	cmds := [][]string{
		{"daemon-reload"},
		{"enable", "--now", "vuln-agent-scan.timer", "vuln-agent-heartbeat.timer"},
	}
	for _, args := range cmds {
		if out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, out)
		}
	}

	if centralURL == "" {
		log.Info("installed; set central_url and client_id in the config, run `vuln-agent enroll`, then `vuln-agent check`")
		return nil
	}
	return enrollAfterInstall(ctx, log, version, centralURL, clientID)
}

// enrollAfterInstall enrolls with $VULN_AGENT_ENROLL_TOKEN unless the host
// already has a token, then starts the first scan. Re-running install to update
// an enrolled host is a no-op here.
func enrollAfterInstall(ctx context.Context, log *slog.Logger, version, centralURL, clientID string) error {
	cfgFile, warnings, err := config.Load(config.DefaultPath)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		log.Warn(w)
	}
	if cfgFile.Config.CentralURL != centralURL || cfgFile.Config.ClientID != clientID {
		log.Warn("existing config names another central or client; it was left unchanged",
			"config", config.DefaultPath, "central_url", cfgFile.Config.CentralURL, "client_id", cfgFile.Config.ClientID)
	}
	if cfgFile.HostToken() != "" {
		log.Info("installed; host already enrolled", "client_id", cfgFile.Config.ClientID)
		return nil
	}
	tok := os.Getenv(enrollEnv)
	if tok == "" {
		log.Info("installed; enroll with `vuln-agent enroll` (token from $" + enrollEnv + " or stdin)")
		return nil
	}
	app, err := config.NewApp(cfgFile, version, log)
	if err != nil {
		return err
	}
	if err := (&usecase.Enroll{Host: app.Host, Central: app.Central, Creds: cfgFile}).Run(ctx, tok, false); err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	if out, err := exec.CommandContext(ctx, "systemctl", "start", "--no-block", "vuln-agent-scan.service").CombinedOutput(); err != nil {
		return fmt.Errorf("start first scan: %w: %s", err, out)
	}
	log.Info("installed and enrolled; first scan started", "client_id", cfgFile.Config.ClientID)
	return nil
}

// removeReportPage removes the report page service and local report history
// left by older versions.
// ponytail: migration only, delete once every VM runs this version.
func removeReportPage(ctx context.Context) error {
	unit := filepath.Join(unitDir, "vuln-agent-serve.service")
	if _, err := os.Stat(unit); err == nil {
		if out, err := exec.CommandContext(ctx, "systemctl", "disable", "--now", "vuln-agent-serve.service").CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl disable --now vuln-agent-serve.service: %w: %s", err, out)
		}
		if err := os.Remove(unit); err != nil {
			return err
		}
	}
	return os.RemoveAll(filepath.Join(config.StateDir, "reports"))
}

// installSelf copies the running binary to agentBin unless it already runs from there.
func installSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	if exe == agentBin {
		return nil
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	if err := repository.WriteFileAtomic(agentBin, b); err != nil {
		return err
	}
	return os.Chmod(agentBin, 0o755)
}
