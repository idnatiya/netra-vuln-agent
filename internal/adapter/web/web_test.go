package web

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/idnatiya/netra-vuln-agent/internal/domain"
)

type fakeReports struct {
	ids     []string
	reports map[string]domain.Report
}

func (f *fakeReports) List() ([]string, error) { return f.ids, nil }
func (f *fakeReports) Load(id string) (domain.Report, error) {
	r, ok := f.reports[id]
	if !ok {
		return r, os.ErrNotExist
	}
	return r, nil
}

func history() *fakeReports {
	old := domain.Finding{VulnerabilityID: "CVE-OLD", PkgName: "openssl", Severity: "HIGH"}
	kept := domain.Finding{VulnerabilityID: "CVE-KEPT", PkgName: "bash", Severity: "CRITICAL"}
	added := domain.Finding{VulnerabilityID: "CVE-NEW", PkgName: "curl", Severity: "HIGH", Title: "<script>x</script>"}
	return &fakeReports{
		ids: []string{"report-1.json.gz", "report-2.json.gz", "report-3.json.gz"},
		reports: map[string]domain.Report{
			"report-1.json.gz": {Status: domain.StatusOK, Findings: []domain.Finding{old, kept}},
			"report-2.json.gz": {Status: domain.StatusError, Error: "timeout"},
			"report-3.json.gz": {Status: domain.StatusOK, Host: domain.HostInfo{Hostname: "vm1"}, Findings: []domain.Finding{added, kept}},
		},
	}
}

func TestBuildDiffSkipsErrorScans(t *testing.T) {
	p, err := build(history(), "")
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "report-3.json.gz" || !p.Compared {
		t.Fatalf("id=%s compared=%v", p.ID, p.Compared)
	}
	if len(p.New) != 1 || p.New[0].VulnerabilityID != "CVE-NEW" || len(p.Resolved) != 1 || p.Resolved[0].VulnerabilityID != "CVE-OLD" {
		t.Fatalf("new=%+v resolved=%+v", p.New, p.Resolved)
	}
	if p.Findings[0].Severity != "CRITICAL" || p.Counts["HIGH"] != 1 {
		t.Fatalf("findings=%+v counts=%v", p.Findings, p.Counts)
	}
	if p, _ := build(history(), "report-1.json.gz"); p.Compared {
		t.Fatal("first report has nothing to compare with")
	}
	if _, err := build(&fakeReports{}, ""); !errors.Is(err, ErrNoReports) {
		t.Fatalf("err = %v", err)
	}
}

func TestRenderEscapes(t *testing.T) {
	var b bytes.Buffer
	if err := Render(&b, history(), "", false); err != nil {
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
	h := Handler(history(), slog.New(slog.NewTextHandler(io.Discard, nil)))
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
