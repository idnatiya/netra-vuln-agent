package test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/idnatiya/netra-vuln-agent/internal/gateway/hostinfo"
)

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, c := range files {
		full := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInspectDebian(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"/etc/os-release":                       "NAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nID=ubuntu\nID_LIKE=debian\n",
		"/proc/sys/kernel/osrelease":            "5.15.0-100-generic\n",
		"/proc/uptime":                          "12345.67 99999.00\n",
		"/var/run/reboot-required":              "",
		"/etc/apt/apt.conf.d/20auto-upgrades":   "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n",
		"/etc/apt/apt.conf.d/50unattended-upgr": "// comment only\n",
	})
	h := (&hostinfo.Linux{Root: root, HostnameOverride: "web-1", AgentVersion: "1.0"}).Inspect(context.Background())
	if h.Hostname != "web-1" || h.OSFamily != "debian" || h.OSName != "Ubuntu" || h.OSVersion != "22.04" ||
		h.KernelRunning != "5.15.0-100-generic" || h.UptimeSeconds != 12345 || !h.RebootRequired ||
		!h.AutoUpdateEnabled || h.AgentVersion != "1.0" {
		t.Fatalf("got %+v", h)
	}
}

func TestAptUnattendedOverride(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"/etc/os-release":                     "ID=debian\n",
		"/etc/apt/apt.conf.d/20auto-upgrades": "APT::Periodic::Unattended-Upgrade \"1\";\n",
		"/etc/apt/apt.conf.d/99disable":       "APT::Periodic::Unattended-Upgrade \"0\";\n",
	})
	if (&hostinfo.Linux{Root: root}).Inspect(context.Background()).AutoUpdateEnabled {
		t.Fatal("later file should disable")
	}
}

func TestOSFamily(t *testing.T) {
	for in, want := range map[string]string{
		"ID=almalinux\nID_LIKE=\"rhel centos fedora\"": "rhel",
		"ID=centos\nID_LIKE=\"rhel fedora\"":           "rhel",
		"ID=debian":                                    "debian",
		"ID=alpine":                                    "alpine",
	} {
		root := t.TempDir()
		writeFiles(t, root, map[string]string{"/etc/os-release": in + "\n"})
		if got := (&hostinfo.Linux{Root: root}).Inspect(context.Background()).OSFamily; got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestPM2Dirs(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"/root/.pm2/dump.pm2":        `[{"name":"api","pm_cwd":"/srv/api"},{"name":"x","pm_cwd":"relative"}]`,
		"/home/deploy/.pm2/dump.pm2": `[{"name":"web","pm_cwd":"/home/deploy/web","env":{"A":"1"}}]`,
		"/home/broken/.pm2/dump.pm2": `{not json`,
	})
	dirs, err := (&hostinfo.Linux{Root: root}).PM2Dirs()
	if !slices.Equal(dirs, []string{"/srv/api", "/home/deploy/web"}) {
		t.Fatalf("dirs = %v", dirs)
	}
	if err == nil || !strings.Contains(err.Error(), "broken") {
		t.Fatalf("err = %v", err)
	}
	if dirs, err := (&hostinfo.Linux{Root: t.TempDir()}).PM2Dirs(); dirs != nil || err != nil {
		t.Fatalf("no pm2: %v, %v", dirs, err)
	}
}
