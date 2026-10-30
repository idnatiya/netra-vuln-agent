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
)

const (
	agentBin     = "/opt/vuln-agent/bin/vuln-agent"
	pathLink     = "/usr/bin/vuln-agent" // not /usr/local/bin: sudo's secure_path on RHEL 7/8 lacks it
	trivyBaseURL = "https://github.com/aquasecurity/trivy/releases/download"
	unitDir      = "/etc/systemd/system"
)

const defaultConfigYAML = `# Fill in central_url and client_id, then run ` + "`vuln-agent enroll`" + `.
central_url: ""
client_id: ""
token: ""
hostname_override: ""
ca_file: ""
# Folders to exclude, added to the default skip list, e.g. ["/data/backup"].
extra_skip_dirs: []
# Folders scanned for app dependencies (Composer, node_modules), plus pm2 apps.
# Unset = ["/var/www", "/srv", "/opt"]; [] = OS packages only.
#app_dirs: ["/var/www", "/srv", "/opt"]
`

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
func install(ctx context.Context, log *slog.Logger, trivyVersion string) error {
	if os.Geteuid() != 0 {
		return errors.New("install must run as root")
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
		_, err = f.WriteString(defaultConfigYAML)
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

	log.Info("installed; set central_url and client_id in the config, run `vuln-agent enroll`, then `vuln-agent check`")
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
