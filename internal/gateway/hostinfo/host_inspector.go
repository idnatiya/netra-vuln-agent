// Package hostinfo reads Linux host metadata on a best-effort basis.
package hostinfo

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/idnatiya/netra-vuln-agent/internal/entity"
)

const cmdTimeout = 30 * time.Second

type Linux struct {
	HostnameOverride string
	AgentVersion     string
	Root             string // filesystem prefix, "" = "/"; for tests
}

func (l *Linux) Inspect(ctx context.Context) entity.HostInfo {
	osr := parseOSRelease(l.read("/etc/os-release"))
	family := osFamily(osr)
	h := entity.HostInfo{
		Hostname:      l.HostnameOverride,
		OSFamily:      family,
		OSName:        osr["NAME"],
		OSVersion:     osr["VERSION_ID"],
		Arch:          runtime.GOARCH,
		KernelRunning: strings.TrimSpace(l.read("/proc/sys/kernel/osrelease")),
		UptimeSeconds: parseUptime(l.read("/proc/uptime")),
		AgentVersion:  l.AgentVersion,
	}
	if h.Hostname == "" {
		h.Hostname, _ = os.Hostname()
	}
	switch family {
	case "debian":
		h.RebootRequired = l.exists("/var/run/reboot-required")
		h.AutoUpdateEnabled = l.aptUnattendedEnabled()
	case "rhel":
		// needs-restarting -r: exit 1 = reboot required, 0 = not required.
		var ee *exec.ExitError
		h.RebootRequired = errors.As(run(ctx, "needs-restarting", "-r"), &ee) && ee.ExitCode() == 1
		h.AutoUpdateEnabled = run(ctx, "systemctl", "is-enabled", "--quiet", "dnf-automatic.timer") == nil ||
			run(ctx, "systemctl", "is-enabled", "--quiet", "dnf-automatic-install.timer") == nil
	}
	return h
}

func (l *Linux) path(p string) string {
	if l.Root == "" {
		return p
	}
	return filepath.Join(l.Root, p)
}

func (l *Linux) read(p string) string {
	b, _ := os.ReadFile(l.path(p))
	return string(b)
}

func (l *Linux) exists(p string) bool {
	_, err := os.Stat(l.path(p))
	return err == nil
}

var aptUnattended = regexp.MustCompile(`(?m)^\s*APT::Periodic::Unattended-Upgrade\s+"([0-9]+)"\s*;`)

// aptUnattendedEnabled follows apt semantics: files are read in order, the last value wins.
func (l *Linux) aptUnattendedEnabled() bool {
	files, _ := filepath.Glob(l.path("/etc/apt/apt.conf.d/*"))
	slices.Sort(files)
	enabled := false
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, m := range aptUnattended.FindAllStringSubmatch(string(b), -1) {
			enabled = m[1] != "0"
		}
	}
	return enabled
}

func parseOSRelease(s string) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		m[k] = strings.Trim(v, `"'`)
	}
	return m
}

func osFamily(osr map[string]string) string {
	ids := append([]string{osr["ID"]}, strings.Fields(osr["ID_LIKE"])...)
	for _, id := range ids {
		switch id {
		case "debian", "ubuntu":
			return "debian"
		case "rhel", "centos", "fedora", "almalinux", "rocky":
			return "rhel"
		}
	}
	return osr["ID"]
}

func parseUptime(s string) int64 {
	f, _ := strconv.ParseFloat(strings.Fields(s + " 0")[0], 64)
	return int64(f)
}

func run(ctx context.Context, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Run()
}
