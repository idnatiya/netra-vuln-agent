// Package trivy runs the Trivy binary via os/exec and slims down its output.
package trivy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/idnatiya/netra-vuln-agent/internal/domain"
)

const (
	stderrTail     = 2048
	versionTimeout = 30 * time.Second
)

type Runner struct {
	Bin      string // /opt/vuln-agent/bin/trivy
	CacheDir string // /var/lib/vuln-agent/cache
	TmpDir   string // temp output location; not /tmp since it is skipped and may be PrivateTmp
}

// Args builds the Trivy arguments. cfg must already pass Validate.
func (r *Runner) Args(cfg domain.ScanConfig, output string) []string {
	args := []string{
		"rootfs", "/",
		"--scanners", "vuln",
		"--list-all-pkgs=false",
		fmt.Sprintf("--ignore-unfixed=%t", cfg.IgnoreUnfixed),
		"--severity", strings.Join(cfg.Severities, ","),
		"--timeout", cfg.Timeout.String(),
		"--cache-dir", r.CacheDir,
	}
	if len(cfg.SkipDirs) > 0 {
		args = append(args, "--skip-dirs", strings.Join(cfg.SkipDirs, ","))
	}
	return append(args, "--format", "json", "-q", "--output", output)
}

func (r *Runner) Scan(ctx context.Context, cfg domain.ScanConfig) ([]domain.Finding, error) {
	f, err := os.CreateTemp(r.TmpDir, "trivy-*.json")
	if err != nil {
		return nil, fmt.Errorf("create output file: %w", err)
	}
	out := f.Name()
	f.Close()
	defer os.Remove(out)

	var stderr tail
	cmd := lowPriority(ctx, r.Bin, r.Args(cfg, out)...)
	cmd.Stderr = &stderr
	cmd.WaitDelay = 10 * time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("trivy killed: %w; stderr: %s", ctx.Err(), stderr.String())
		}
		return nil, fmt.Errorf("trivy: %w; stderr: %s", err, stderr.String())
	}

	f, err = os.Open(out)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

func (r *Runner) Version(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, versionTimeout)
	defer cancel()
	b, err := exec.CommandContext(ctx, r.Bin, "version", "--format", "json").Output()
	if err != nil {
		return "", fmt.Errorf("trivy version: %w", err)
	}
	var v struct{ Version string }
	if err := json.Unmarshal(b, &v); err != nil || v.Version == "" {
		return "", fmt.Errorf("trivy version: unexpected output %.200q", b)
	}
	return v.Version, nil
}

// lowPriority wraps the command with ionice/nice when available. Both exec
// the next program, so the PID stays the same and ctx cancellation still kills Trivy.
func lowPriority(ctx context.Context, bin string, args ...string) *exec.Cmd {
	argv := append([]string{bin}, args...)
	if _, err := exec.LookPath("nice"); err == nil {
		argv = append([]string{"nice", "-n", "19"}, argv...)
	}
	if _, err := exec.LookPath("ionice"); err == nil {
		argv = append([]string{"ionice", "-c", "3"}, argv...)
	}
	return exec.CommandContext(ctx, argv[0], argv[1:]...)
}

// report declares only the fields we use; json.Decoder skips the rest
// without allocating them.
type report struct {
	Results []struct {
		Target          string
		Type            string
		Vulnerabilities []struct {
			VulnerabilityID  string
			PkgName          string
			PkgPath          string
			InstalledVersion string
			FixedVersion     string
			Severity         string
			Title            string
		}
	}
}

func Parse(r io.Reader) ([]domain.Finding, error) {
	var rep report
	if err := json.NewDecoder(r).Decode(&rep); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("trivy output is empty")
		}
		return nil, fmt.Errorf("decode trivy output: %w", err)
	}
	findings := []domain.Finding{}
	for _, res := range rep.Results {
		for _, v := range res.Vulnerabilities {
			findings = append(findings, domain.Finding{
				Target:           res.Target,
				Type:             res.Type,
				VulnerabilityID:  v.VulnerabilityID,
				PkgName:          v.PkgName,
				PkgPath:          v.PkgPath,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				Severity:         v.Severity,
				Title:            v.Title,
			})
		}
	}
	return findings, nil
}

// tail keeps the last stderrTail bytes written to it.
type tail struct{ b []byte }

func (t *tail) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > stderrTail {
		t.b = t.b[len(t.b)-stderrTail:]
	}
	return len(p), nil
}

func (t *tail) String() string { return strings.TrimSpace(strings.ToValidUTF8(string(t.b), "")) }
