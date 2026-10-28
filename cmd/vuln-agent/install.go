package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/idnatiya/netra-vuln-agent/internal/adapter/trivy"
)

var trivyVersion = "0.72.0" // -ldflags "-X main.trivyVersion=..." (Makefile TRIVY_VERSION)

const (
	agentBin     = "/opt/vuln-agent/bin/vuln-agent"
	pathLink     = "/usr/bin/vuln-agent" // not /usr/local/bin: sudo's secure_path on RHEL 7/8 lacks it
	trivyBaseURL = "https://github.com/aquasecurity/trivy/releases/download"
	unitDir      = "/etc/systemd/system"
)

const defaultConfigYAML = `# Standalone by default (empty central_url). For central mode, fill in
# central_url and client_id, then run ` + "`vuln-agent enroll`" + `.
central_url: ""
client_id: ""
token: ""
hostname_override: ""
ca_file: ""
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
	// Not enabled by install: serve has no auth (see README).
	"vuln-agent-serve.service": `[Unit]
Description=vuln-agent read-only report server (127.0.0.1:8090)

[Service]
ExecStart=/usr/bin/vuln-agent serve
` + unitLimits + `
[Install]
WantedBy=multi-user.target
`,
}

// install puts the running binary, the pinned Trivy, a default config, and the
// systemd timers in place. It is run by an operator and is safe to rerun.
func install(ctx context.Context, log *slog.Logger) error {
	if os.Geteuid() != 0 {
		return errors.New("install must run as root")
	}
	for _, d := range []struct {
		path string
		mode fs.FileMode
	}{
		{filepath.Dir(agentBin), 0o755},
		{filepath.Dir(defaultConfig), 0o700},
		{stateDir, 0o700},
		{filepath.Join(stateDir, "spool"), 0o700},
		{filepath.Join(stateDir, "reports"), 0o700},
		{filepath.Join(stateDir, "cache"), 0o700},
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

	if v, _ := (&trivy.Runner{Bin: trivyBin}).Version(ctx); v == trivyVersion {
		log.Info("trivy already installed", "version", v)
	} else {
		arch, ok := map[string]string{"amd64": "64bit", "arm64": "ARM64"}[runtime.GOARCH]
		if !ok {
			return fmt.Errorf("unsupported arch %s", runtime.GOARCH)
		}
		log.Info("installing trivy", "version", trivyVersion, "replacing", v)
		client := &http.Client{Timeout: 10 * time.Minute}
		if err := installTrivy(ctx, client, trivyBaseURL, trivyVersion, arch, trivyBin); err != nil {
			return fmt.Errorf("install trivy: %w", err)
		}
	}

	f, err := os.OpenFile(defaultConfig, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	switch {
	case errors.Is(err, fs.ErrExist):
		log.Info("config exists, left unchanged", "config", defaultConfig)
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
		log.Info("wrote standalone config", "config", defaultConfig)
	}

	for name, body := range units {
		if err := os.WriteFile(filepath.Join(unitDir, name), []byte(body), 0o644); err != nil {
			return err
		}
	}
	for _, args := range [][]string{
		{"daemon-reload"},
		{"enable", "--now", "vuln-agent-scan.timer", "vuln-agent-heartbeat.timer"},
	} {
		if out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, out)
		}
	}

	log.Info("installed; for central mode set central_url and client_id in the config, then run `vuln-agent enroll`; finally run `vuln-agent check`")
	return nil
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
	src, err := os.Open(exe)
	if err != nil {
		return err
	}
	defer src.Close()
	return writeExecutable(agentBin, src)
}

// installTrivy downloads the Trivy release tarball, verifies it against the
// release checksums file, and installs the trivy binary at dest.
func installTrivy(ctx context.Context, client *http.Client, baseURL, version, arch, dest string) error {
	release := fmt.Sprintf("%s/v%s/", baseURL, version)
	tarball := fmt.Sprintf("trivy_%s_Linux-%s.tar.gz", version, arch)

	sums, err := fetch(ctx, client, release+fmt.Sprintf("trivy_%s_checksums.txt", version))
	if err != nil {
		return err
	}
	defer sums.Close()
	want := ""
	sc := bufio.NewScanner(sums)
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) == 2 && f[1] == tarball {
			want = f[0]
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if want == "" {
		return fmt.Errorf("no checksum for %s", tarball)
	}

	tmp, err := os.CreateTemp(filepath.Dir(dest), ".trivy-*.tar.gz")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	body, err := fetch(ctx, client, release+tarball)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(tmp, h), body)
	body.Close()
	if err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("checksum mismatch for %s: got %s, want %s", tarball, got, want)
	}

	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	gz, err := gzip.NewReader(tmp)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%s has no trivy binary", tarball)
		}
		if err != nil {
			return err
		}
		if hdr.Name == "trivy" && hdr.Typeflag == tar.TypeReg {
			return writeExecutable(dest, tr)
		}
	}
}

func fetch(ctx context.Context, client *http.Client, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return resp.Body, nil
}

// writeExecutable atomically replaces path with r's contents, mode 0755.
func writeExecutable(path string, r io.Reader) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = io.Copy(tmp, r)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
