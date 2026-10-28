package test

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	reporthttp "github.com/idnatiya/netra-vuln-agent/internal/delivery/http"

	"github.com/idnatiya/netra-vuln-agent/internal/entity"
)

type fakeReports struct {
	ids     []string
	reports map[string]entity.Report
}

func (f *fakeReports) List() ([]string, error) { return f.ids, nil }
func (f *fakeReports) Load(id string) (entity.Report, error) {
	r, ok := f.reports[id]
	if !ok {
		return r, os.ErrNotExist
	}
	return r, nil
}

func history() *fakeReports {
	old := entity.Finding{VulnerabilityID: "CVE-OLD", PkgName: "openssl", Severity: "HIGH"}
	kept := entity.Finding{VulnerabilityID: "CVE-KEPT", PkgName: "bash", Severity: "CRITICAL"}
	added := entity.Finding{VulnerabilityID: "CVE-NEW", PkgName: "curl", Severity: "HIGH", Title: "<script>x</script>"}
	return &fakeReports{
		ids: []string{"report-1.json.gz", "report-2.json.gz", "report-3.json.gz"},
		reports: map[string]entity.Report{
			"report-1.json.gz": {Status: entity.StatusOK, Findings: []entity.Finding{old, kept}},
			"report-2.json.gz": {Status: entity.StatusError, Error: "timeout"},
			"report-3.json.gz": {Status: entity.StatusOK, Host: entity.HostInfo{Hostname: "vm1"}, Findings: []entity.Finding{added, kept}},
		},
	}
}

func render(t *testing.T, reports reporthttp.Reports, id string) string {
	t.Helper()
	var b bytes.Buffer
	if err := reporthttp.Render(&b, reports, id, false); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestRenderDiffSkipsErrorScans(t *testing.T) {
	html := render(t, history(), "")
	if !strings.Contains(html, "1 new · 1 resolved") {
		t.Fatalf("missing diff summary:\n%s", html)
	}
	compAt, newAt, resolvedAt := strings.Index(html, "Components ("), strings.Index(html, "<h3>[+] New</h3>"), strings.Index(html, "<h3>[-] Resolved</h3>")
	if !(compAt >= 0 && compAt < newAt && newAt < resolvedAt) {
		t.Fatalf("sections out of order:\n%s", html)
	}
	comps, added, resolved := html[compAt:newAt], html[newAt:resolvedAt], html[resolvedAt:]
	if strings.Index(comps, "CVE-KEPT") > strings.Index(comps, "CVE-NEW") || strings.Contains(comps, "CVE-OLD") {
		t.Fatal("components not sorted CRITICAL first, or hold a resolved finding")
	}
	if !strings.Contains(added, "CVE-NEW") || strings.Contains(added, "CVE-KEPT") || !strings.Contains(resolved, "CVE-OLD") {
		t.Fatalf("new/resolved wrong:\n%s", html)
	}
	if !strings.Contains(html, `<dt>high</dt><dd class="n high">1</dd>`) {
		t.Fatal("HIGH count != 1")
	}
	if strings.Contains(render(t, history(), "report-1.json.gz"), "Since the previous scan") {
		t.Fatal("first report has nothing to compare with")
	}
	if err := reporthttp.Render(io.Discard, &fakeReports{}, "", false); !errors.Is(err, reporthttp.ErrNoReports) {
		t.Fatalf("err = %v", err)
	}
}

func TestRenderEscapes(t *testing.T) {
	var b bytes.Buffer
	if err := reporthttp.Render(&b, history(), "", false); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	if strings.Contains(s, "<script>") || !strings.Contains(s, "&lt;script&gt;") || !strings.Contains(s, "CVE-KEPT") {
		t.Fatalf("bad html:\n%s", s)
	}
	if strings.Contains(s, `href="/reports/`) {
		t.Fatal("static file must not link to the server")
	}
}

func TestHandler(t *testing.T) {
	h := reporthttp.Handler(history(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, tc := range []struct {
		method, path string
		code         int
		want         string
	}{
		{"GET", "/", 200, "CVE-NEW"},
		{"GET", "/reports/report-1.json.gz", 200, "CVE-OLD"},
		{"GET", "/reports/report-1.json.gz.json", 200, `"VulnerabilityID":"CVE-OLD"`},
		{"GET", "/reports/missing.json.gz.json", 404, ""},
		{"GET", "/reports/..%2f..%2fetc%2fpasswd", 404, ""},
		{"GET", "/reports/..%2fconfig.json.gz.json", 404, ""},
		{"POST", "/", 405, ""},
		{"GET", "/healthz", 200, "ok"},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != tc.code || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s %s = %d %q", tc.method, tc.path, rec.Code, rec.Body.String())
		}
		if rec.Header().Get("Content-Security-Policy") == "" {
			t.Errorf("%s: missing CSP", tc.path)
		}
	}
}

func TestRenderComponents(t *testing.T) {
	r := &fakeReports{ids: []string{"report-1.json.gz"}, reports: map[string]entity.Report{"report-1.json.gz": {
		Status: entity.StatusOK,
		Host:   entity.HostInfo{OSFamily: "debian", KernelRunning: "6.8.0-147-generic"},
		Findings: []entity.Finding{
			{Type: "ubuntu", VulnerabilityID: "CVE-K1", PkgName: "linux-image-6.8.0-147-generic", InstalledVersion: "6.8.0-147.147", Severity: "HIGH"},
			{Type: "ubuntu", VulnerabilityID: "CVE-K2", PkgName: "linux-modules-6.8.0-124-generic", InstalledVersion: "6.8.0-124.124", Severity: "HIGH"},
			{Type: "ubuntu", VulnerabilityID: "CVE-S1", PkgName: "openssl", InstalledVersion: "3.0.13-0ubuntu3.5", Severity: "CRITICAL"},
			{Type: "ubuntu", VulnerabilityID: "CVE-S1", PkgName: "libssl3", InstalledVersion: "3.0.13-0ubuntu3.5", Severity: "CRITICAL"},
			{Type: "node-pkg", Target: "Node.js", VulnerabilityID: "GHSA-x", PkgName: "lodash", PkgPath: "srv/web/node_modules/lodash/package.json", Severity: "HIGH"},
		},
	}}}
	html := render(t, r, "")
	for _, want := range []string{
		"Components (4)",
		"libssl3, openssl", "sudo apt-get install --only-upgrade -y libssl3 openssl",
		`<span class="tag high">running</span>`, "fallback, not running",
		"cd /srv/web &amp;&amp; npm update lodash", "https://github.com/advisories/GHSA-x",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Index(html, "libssl3, openssl") > strings.Index(html, "Linux kernel") {
		t.Error("critical component not first")
	}
}
