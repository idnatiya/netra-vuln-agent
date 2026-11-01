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
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/idnatiya/netra-vuln-agent/internal/entity"
)

const (
	stderrTail     = 2048
	versionTimeout = 30 * time.Second
)

type Runner struct {
	Bin      string // /opt/vuln-agent/bin/trivy
	CacheDir string // /var/lib/vuln-agent/cache
	TmpDir   string // temp output location; not /tmp since it is skipped and may be PrivateTmp
	// AppDirs are scanned for language packages (Composer, npm, ...); / itself only for OS packages.
	AppDirs []string
}

// Run kinds. Apps get two light runs that both skip installed dependency
// trees: lockfiles via fs mode (composer.lock, package-lock.json, ...) and
// binaries/jars via rootfs (fs mode does not read those).
const (
	RunOS       = "os"
	RunLockfile = "lockfile"
	RunBinary   = "binary"
)

var depDirs = []string{"**/node_modules", "**/vendor", "**/.git"}

// Args builds the Trivy arguments for one run. cfg must already pass Validate.
func (r *Runner) Args(cfg entity.ScanConfig, kind, target, output string) []string {
	mode, pkgTypes, skip := "rootfs", "library", slices.Concat(cfg.SkipDirs, depDirs)
	switch kind {
	case RunOS:
		pkgTypes, skip = "os", cfg.SkipDirs
	case RunLockfile:
		mode = "fs"
	}
	args := []string{
		mode, target,
		"--scanners", "vuln",
		"--pkg-types", pkgTypes,
		fmt.Sprintf("--list-all-pkgs=%t", kind == RunLockfile), // framework versions for EOL checks
		fmt.Sprintf("--ignore-unfixed=%t", cfg.IgnoreUnfixed),
		"--severity", strings.Join(cfg.Severities, ","),
		"--timeout", cfg.Timeout.String(),
		"--cache-dir", r.CacheDir,
	}
	if len(skip) > 0 {
		args = append(args, "--skip-dirs", strings.Join(skip, ","))
	}
	return append(args, "--format", "json", "-q", "--output", output)
}

// Scan runs Trivy for OS packages on /, then the lockfile and binary runs in
// each existing app dir, and merges the findings with paths relative to /.
func (r *Runner) Scan(ctx context.Context, cfg entity.ScanConfig) ([]entity.Finding, []entity.Software, error) {
	findings, _, err := r.run(ctx, cfg, RunOS, "/")
	if err != nil {
		return nil, nil, err
	}
	var software []entity.Software
	for _, dir := range AppTargets(r.AppDirs) {
		// Trivy reports paths relative to the scanned dir.
		prefix := strings.Trim(dir, "/") + "/"
		for _, kind := range []string{RunLockfile, RunBinary} {
			fs, sw, err := r.run(ctx, cfg, kind, dir)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", dir, err)
			}
			for _, s := range sw {
				s.Path = filepath.Clean("/" + prefix + s.Path)
				software = append(software, s)
			}
			for _, f := range fs {
				if f.PkgPath != "" {
					f.PkgPath = prefix + f.PkgPath
				} else { // Target is the file path (lockfile, gobinary, jar, ...)
					f.Target = prefix + f.Target
				}
				findings = append(findings, f)
			}
		}
	}
	return findings, software, nil
}

// AppTargets cleans the app dirs, drops missing ones, / itself, duplicates,
// and dirs inside another listed dir (that run already covers them).
func AppTargets(dirs []string) []string {
	var out []string
	for _, d := range dirs {
		d = filepath.Clean(d)
		if fi, err := os.Stat(d); d == "/" || err != nil || !fi.IsDir() {
			continue
		}
		out = append(out, d)
	}
	slices.Sort(out)
	all := slices.Compact(out)
	return slices.DeleteFunc(slices.Clone(all), func(d string) bool {
		return slices.ContainsFunc(all, func(p string) bool { return strings.HasPrefix(d, p+"/") })
	})
}

func (r *Runner) run(ctx context.Context, cfg entity.ScanConfig, kind, target string) ([]entity.Finding, []entity.Software, error) {
	f, err := os.CreateTemp(r.TmpDir, "trivy-*.json")
	if err != nil {
		return nil, nil, fmt.Errorf("create output file: %w", err)
	}
	out := f.Name()
	f.Close()
	defer os.Remove(out)

	var stderr tail
	cmd := lowPriority(ctx, r.Bin, r.Args(cfg, kind, target, out)...)
	cmd.Stderr = &stderr
	cmd.WaitDelay = 10 * time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, nil, fmt.Errorf("trivy killed: %w; stderr: %s", ctx.Err(), stderr.String())
		}
		return nil, nil, fmt.Errorf("trivy: %w; stderr: %s", err, stderr.String())
	}

	f, err = os.Open(out)
	if err != nil {
		return nil, nil, err
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
		Packages []struct { // only with --list-all-pkgs (lockfile runs)
			Name    string
			Version string
		}
	}
}

// Parse returns the findings and the Frameworks found in the package lists;
// a framework's Path is the folder of its lockfile, relative to the target.
func Parse(r io.Reader) ([]entity.Finding, []entity.Software, error) {
	var rep report
	if err := json.NewDecoder(r).Decode(&rep); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil, errors.New("trivy output is empty")
		}
		return nil, nil, fmt.Errorf("decode trivy output: %w", err)
	}
	var software []entity.Software
	for _, res := range rep.Results {
		for _, p := range res.Packages {
			name, ok := entity.Frameworks[p.Name]
			s := entity.Software{Name: name, Version: p.Version, Path: filepath.Dir(res.Target)}
			if ok && !slices.ContainsFunc(software, func(o entity.Software) bool { return o.Name == s.Name && o.Path == s.Path }) {
				software = append(software, s)
			}
		}
	}
	findings := []entity.Finding{}
	for _, res := range rep.Results {
		for _, v := range res.Vulnerabilities {
			findings = append(findings, entity.Finding{
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
	return findings, software, nil
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
