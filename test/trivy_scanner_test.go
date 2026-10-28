package test

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/idnatiya/netra-vuln-agent/internal/gateway/trivy"

	"github.com/idnatiya/netra-vuln-agent/internal/entity"
)

func TestParseNormal(t *testing.T) {
	f, err := os.Open("testdata/normal.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := trivy.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("len = %d", len(got))
	}
	want := entity.Finding{
		Target: "vm1 (ubuntu 22.04)", Type: "ubuntu", VulnerabilityID: "CVE-2024-0001", PkgName: "openssl",
		InstalledVersion: "3.0.2-0ubuntu1.10", FixedVersion: "3.0.2-0ubuntu1.15", Severity: "CRITICAL",
		Title: "openssl: something bad",
	}
	if got[0] != want {
		t.Fatalf("got %+v", got[0])
	}
	if got[2].Type != "gobinary" || got[2].Target != "usr/local/bin/app" {
		t.Fatalf("got %+v", got[2])
	}
	if got[3].PkgPath != "var/www/shop/node_modules/devalue/package.json" {
		t.Fatalf("got %+v", got[3])
	}
}

func TestParseEmpty(t *testing.T) {
	for _, in := range []string{
		`{"SchemaVersion":2}`,
		`{"SchemaVersion":2,"Results":null}`,
		`{"SchemaVersion":2,"Results":[{"Target":"x","Type":"debian"}]}`,
	} {
		got, err := trivy.Parse(strings.NewReader(in))
		if err != nil || got == nil || len(got) != 0 {
			t.Fatalf("%s: got %v, %v", in, got, err)
		}
	}
	if _, err := trivy.Parse(strings.NewReader("")); err == nil {
		t.Fatal("empty output accepted")
	}
	if _, err := trivy.Parse(strings.NewReader(`{"Results":[`)); err == nil {
		t.Fatal("truncated output accepted")
	}
}

func TestParseLarge(t *testing.T) {
	const n = 50000
	path := filepath.Join(t.TempDir(), "large.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(f)
	w.WriteString(`{"SchemaVersion":2,"Results":[{"Target":"big","Type":"debian","Vulnerabilities":[`)
	for i := range n {
		if i > 0 {
			w.WriteString(",")
		}
		fmt.Fprintf(w, `{"VulnerabilityID":"CVE-%d","PkgName":"p%d","InstalledVersion":"1","FixedVersion":"2","Severity":"HIGH","Title":"t","Description":"%s","References":["a","b","c"]}`,
			i, i, strings.Repeat("d", 500))
	}
	w.WriteString(`]}]}`)
	w.Flush()
	f.Close()

	f, _ = os.Open(path)
	defer f.Close()
	got, err := trivy.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != n || got[n-1].VulnerabilityID != fmt.Sprintf("CVE-%d", n-1) {
		t.Fatalf("len=%d last=%+v", len(got), got[len(got)-1])
	}
}

func TestArgs(t *testing.T) {
	r := &trivy.Runner{CacheDir: "/var/lib/vuln-agent/cache"}
	got := r.Args(entity.DefaultScanConfig(), "/", "os", "/out.json")
	for _, want := range [][]string{
		{"rootfs", "/"},
		{"--pkg-types", "os"},
		{"--scanners", "vuln"},
		{"--severity", "HIGH,CRITICAL"},
		{"--timeout", "30m0s"},
		{"--cache-dir", "/var/lib/vuln-agent/cache"},
		{"--output", "/out.json"},
	} {
		if i := slices.Index(got, want[0]); i < 0 || got[i+1] != want[1] {
			t.Fatalf("missing %v in %v", want, got)
		}
	}
	if !slices.Contains(got, "--ignore-unfixed=true") || !slices.Contains(got, "--list-all-pkgs=false") {
		t.Fatalf("flags missing: %v", got)
	}
	cfg := entity.DefaultScanConfig()
	cfg.SkipDirs = nil
	if slices.Contains(r.Args(cfg, "/", "os", "/o"), "--skip-dirs") {
		t.Fatal("--skip-dirs without value")
	}
}

func fakeRunner(t *testing.T, mode string) *trivy.Runner {
	t.Helper()
	bin, _ := filepath.Abs("testdata/fake-trivy.sh")
	fixture, _ := filepath.Abs("testdata/normal.json")
	t.Setenv("FAKE_TRIVY_MODE", mode)
	t.Setenv("FAKE_TRIVY_FIXTURE", fixture)
	t.Setenv("FAKE_TRIVY_LOG", filepath.Join(t.TempDir(), "runs.log"))
	return &trivy.Runner{Bin: bin, CacheDir: t.TempDir(), TmpDir: t.TempDir()}
}

func TestScanExec(t *testing.T) {
	r := fakeRunner(t, "ok")
	app := t.TempDir()
	r.AppDirs = []string{app, filepath.Join(app, "nested"), "/does/not/exist"}
	os.Mkdir(filepath.Join(app, "nested"), 0o755)
	got, err := r.Scan(context.Background(), entity.DefaultScanConfig())
	if err != nil || len(got) != 8 {
		t.Fatalf("got %d, %v", len(got), err)
	}
	runs, _ := os.ReadFile(os.Getenv("FAKE_TRIVY_LOG"))
	if want := "/ os\n" + app + " library\n"; string(runs) != want {
		t.Fatalf("runs = %q, want %q", runs, want)
	}
	prefix := strings.TrimPrefix(app, "/") + "/"
	if got[2].Target != "usr/local/bin/app" || got[6].Target != prefix+"usr/local/bin/app" {
		t.Fatalf("binary target: %q / %q", got[2].Target, got[6].Target)
	}
	if got[7].PkgPath != prefix+"var/www/shop/node_modules/devalue/package.json" || got[7].Target != got[3].Target {
		t.Fatalf("app pkg path: %+v", got[7])
	}
	if left, _ := os.ReadDir(r.TmpDir); len(left) != 0 {
		t.Fatalf("temp file not removed: %v", left)
	}
	if v, err := r.Version(context.Background()); err != nil || v != "0.99.0" {
		t.Fatalf("version %q, %v", v, err)
	}
}

func TestAppTargets(t *testing.T) {
	d := t.TempDir()
	for _, sub := range []string{"www/a", "srv"} {
		os.MkdirAll(filepath.Join(d, sub), 0o755)
	}
	os.WriteFile(filepath.Join(d, "file"), nil, 0o644)
	got := trivy.AppTargets([]string{d + "/www/a", d + "/www/", d + "/srv", d + "/srv", d + "/missing", d + "/file", "/"})
	if want := []string{d + "/srv", d + "/www"}; !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestScanExecFail(t *testing.T) {
	_, err := fakeRunner(t, "fail").Scan(context.Background(), entity.DefaultScanConfig())
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v", err)
	}
}

func TestScanExecTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := fakeRunner(t, "hang").Scan(ctx, entity.DefaultScanConfig())
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("err=%v after %s", err, time.Since(start))
	}
}
