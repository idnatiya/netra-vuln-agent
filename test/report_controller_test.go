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
	newAt, resolvedAt, openAt := strings.Index(html, "<h3>New</h3>"), strings.Index(html, "<h3>Resolved</h3>"), strings.Index(html, "Open findings")
	if !(newAt >= 0 && newAt < strings.Index(html, "CVE-NEW") && strings.Index(html, "CVE-NEW") < resolvedAt &&
		resolvedAt < strings.Index(html, "CVE-OLD") && strings.Index(html, "CVE-OLD") < openAt) {
		t.Fatalf("new/resolved sections wrong:\n%s", html)
	}
	open := html[openAt:]
	if strings.Index(open, "CVE-KEPT") > strings.Index(open, "CVE-NEW") {
		t.Fatal("open findings not sorted CRITICAL first")
	}
	if !strings.Contains(html, `<b>High</b><span class="high">1</span>`) {
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
