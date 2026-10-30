package test

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/idnatiya/netra-vuln-agent/internal/config"
)

const validYAML = "central_url: https://central.example.com\nclient_id: client_a\ntoken: \"\"\n"

func writeConfig(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad(t *testing.T) {
	f, warn, err := config.Load(writeConfig(t, validYAML, 0o600))
	if err != nil || len(warn) != 0 || f.Config.ClientID != "client_a" {
		t.Fatalf("f=%+v warn=%q err=%v", f, warn, err)
	}
	if _, warn, _ := config.Load(writeConfig(t, validYAML, 0o644)); len(warn) != 1 {
		t.Fatalf("expected permission warning, got %q", warn)
	}
	// Plain http (e.g. over Tailscale) is allowed but warned about.
	f, warn, err = config.Load(writeConfig(t, "central_url: http://central.tailnet.ts.net:8080\nclient_id: a\n", 0o600))
	if err != nil || len(warn) != 1 || !strings.Contains(warn[0], "plain http") {
		t.Fatalf("http: warn=%q err=%v", warn, err)
	}
	for _, bad := range []string{
		"hostname_override: web1\n", // central_url is required
		"client_id: a\n",
		"token: t\n",
		"central_url: ftp://central.example.com\nclient_id: a\n",
		"central_url: central.example.com\nclient_id: a\n",
		"central_url: https://central.example.com\n",
		validYAML + "exec: rm -rf /\n",
		validYAML + "serve_addr: \"\"\n", // removed field
	} {
		if _, _, err := config.Load(writeConfig(t, bad, 0o600)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestSaveHostToken(t *testing.T) {
	p := writeConfig(t, validYAML, 0o644)
	f, _, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.SaveHostToken("s3cret"); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	f2, _, err := config.Load(p)
	if err != nil || f2.HostToken() != "s3cret" || f2.Config.ClientID != "client_a" {
		t.Fatalf("reload: %+v %v", f2, err)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(p), ".*tmp*")); len(left) != 0 {
		t.Fatalf("temp left: %v", left)
	}
}

func TestSecretNotLeaked(t *testing.T) {
	c := config.Config{Token: "s3cret"}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "token", c.Token, "cfg", c)
	out := buf.String() + fmt.Sprintf("%v %+v %#v %s", c, c, c, c.Token)
	if strings.Contains(out, "s3cret") {
		t.Fatalf("token leaked: %s", out)
	}
}

func TestLoadExtraSkipDirs(t *testing.T) {
	for extras, wantErr := range map[string]bool{
		``:                    false,
		`extra_skip_dirs: []`: false,
		`extra_skip_dirs: ["/data/*/tmp", "/srv/uploads"]`: false,
		`extra_skip_dirs: ["data"]`:                        true,
		`extra_skip_dirs: ["/a,/b"]`:                       true,
		`extra_skip_dirs: ["--config=/x"]`:                 true,
	} {
		f, _, err := config.Load(writeConfig(t, validYAML+extras+"\n", 0o600))
		if (err != nil) != wantErr {
			t.Errorf("%q: err = %v, want error %v", extras, err, wantErr)
		}
		if err == nil && extras == `extra_skip_dirs: ["/data/*/tmp", "/srv/uploads"]` && len(f.Config.ExtraSkipDirs) != 2 {
			t.Errorf("parsed %v", f.Config.ExtraSkipDirs)
		}
	}
}

func TestAppDirs(t *testing.T) {
	for yml, want := range map[string]string{
		``:                               "[/var/www /srv /opt]",
		`app_dirs: []`:                   "[]",
		`app_dirs: ["/home/deploy/app"]`: "[/home/deploy/app]",
		`app_dirs: ["app"]`:              "error",
		`app_dirs: ["-x"]`:               "error",
	} {
		f, _, err := config.Load(writeConfig(t, validYAML+yml+"\n", 0o600))
		got := "error"
		if err == nil {
			got = fmt.Sprint(f.Config.ScanAppDirs())
		}
		if got != want {
			t.Errorf("%q: got %s (%v), want %s", yml, got, err, want)
		}
	}
}
