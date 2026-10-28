// Package scanconfig holds the scan settings central may override and their
// validation rules. Shared by agent and central; stdlib only.
package scanconfig

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Config is the only part of a scan that central is allowed to control.
type Config struct {
	Severities    []string
	IgnoreUnfixed bool
	SkipDirs      []string
	Timeout       time.Duration // value of Trivy's --timeout
}

// SeverityLevels are the Trivy severity names, lowest first.
var SeverityLevels = []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

const (
	minTimeout  = time.Minute
	maxTimeout  = 2 * time.Hour
	maxSkipDirs = 100
)

func Default() Config {
	return Config{
		Severities:    []string{"HIGH", "CRITICAL"},
		IgnoreUnfixed: true,
		SkipDirs: []string{
			"/proc", "/sys", "/dev", "/run", "/tmp", "/snap", "/var/lib/snapd",
			"/var/lib/docker", "/var/lib/containerd", "/mnt", "/media", "/var/cache",
			"/root/.cache", "/home/*/.cache", "/home/*/.local/share/pnpm", "/usr/share/doc",
		},
		Timeout: 30 * time.Minute,
	}
}

// Validate rejects values that could be abused as Trivy arguments.
func (c Config) Validate() error {
	if len(c.Severities) == 0 {
		return errors.New("severity must not be empty")
	}
	for _, s := range c.Severities {
		if !slices.Contains(SeverityLevels, s) {
			return fmt.Errorf("invalid severity %q", s)
		}
	}
	if c.Timeout < minTimeout || c.Timeout > maxTimeout {
		return fmt.Errorf("timeout %s out of range [%s, %s]", c.Timeout, minTimeout, maxTimeout)
	}
	if len(c.SkipDirs) > maxSkipDirs {
		return fmt.Errorf("too many skip_dirs (%d > %d)", len(c.SkipDirs), maxSkipDirs)
	}
	for _, d := range c.SkipDirs {
		// Must be absolute (so it cannot start with "-") and comma-free, since all are joined into one argument.
		if !strings.HasPrefix(d, "/") || strings.ContainsAny(d, ",\x00\n\r") {
			return fmt.Errorf("invalid skip_dir %q", d)
		}
	}
	return nil
}
