// Package web renders the local report history as HTML (a static file or a
// read-only HTTP server). It never triggers scans or runs commands.
package web

import (
	"cmp"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/idnatiya/netra-vuln-agent/internal/domain"
)

// Reports is the local report history; List returns ids oldest first.
type Reports interface {
	List() ([]string, error)
	Load(id string) (domain.Report, error)
}

// ErrNoReports means no scan has been kept yet.
var ErrNoReports = errors.New("no reports yet: run `vuln-agent scan`")

//go:embed report.html.tmpl
var tmplText string

var tmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"lower": strings.ToLower,
	"time":  func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
	"dur":   func(d time.Duration) string { return d.Round(time.Second).String() },
	"name":  displayName,
}).Parse(tmplText))

type page struct {
	ID       string
	Report   domain.Report
	Counts   map[string]int
	Findings []domain.Finding
	Compared bool // a previous ok report exists, so New/Resolved are meaningful
	New      []domain.Finding
	Resolved []domain.Finding
	History  []string // newest first
	Linked   bool     // render links to other reports (served, not a static file)
}

// Render writes the HTML page for report id, or the newest one when id is "".
func Render(w io.Writer, reports Reports, id string, linked bool) error {
	p, err := build(reports, id)
	if err != nil {
		return err
	}
	p.Linked = linked
	return tmpl.Execute(w, p)
}

func build(reports Reports, id string) (page, error) {
	ids, err := reports.List()
	if err != nil {
		return page{}, err
	}
	if len(ids) == 0 {
		return page{}, ErrNoReports
	}
	i := len(ids) - 1
	if id != "" {
		if i = slices.Index(ids, id); i < 0 {
			return page{}, fmt.Errorf("report %q: %w", id, errNotFound)
		}
	}
	cur, err := reports.Load(ids[i])
	if err != nil {
		return page{}, err
	}
	p := page{ID: ids[i], Report: cur, Counts: map[string]int{}, Findings: sorted(cur.Findings)}
	for _, f := range cur.Findings {
		p.Counts[f.Severity]++
	}
	for j := len(ids) - 1; j >= 0; j-- {
		p.History = append(p.History, ids[j])
	}
	// Compare with the newest earlier successful scan; an error scan says nothing about findings.
	for j := i - 1; j >= 0 && cur.Status == domain.StatusOK; j-- {
		prev, err := reports.Load(ids[j])
		if err != nil || prev.Status != domain.StatusOK {
			continue
		}
		p.Compared = true
		p.New = diff(cur.Findings, prev.Findings)
		p.Resolved = diff(prev.Findings, cur.Findings)
		break
	}
	return p, nil
}

var errNotFound = errors.New("not found")

// diff returns findings in a that are not in b, keyed like central's finding_key.
func diff(a, b []domain.Finding) []domain.Finding {
	seen := make(map[[5]string]bool, len(b))
	for _, f := range b {
		seen[key(f)] = true
	}
	var out []domain.Finding
	for _, f := range a {
		if !seen[key(f)] {
			out = append(out, f)
		}
	}
	return sorted(out)
}

func key(f domain.Finding) [5]string {
	return [5]string{f.VulnerabilityID, f.PkgName, f.InstalledVersion, f.Target, f.PkgPath}
}

var severityRank = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

func sorted(fs []domain.Finding) []domain.Finding {
	out := slices.Clone(fs)
	slices.SortStableFunc(out, func(a, b domain.Finding) int {
		ra, oka := severityRank[a.Severity]
		rb, okb := severityRank[b.Severity]
		if !oka {
			ra = len(severityRank)
		}
		if !okb {
			rb = len(severityRank)
		}
		return cmp.Or(cmp.Compare(ra, rb), cmp.Compare(a.PkgName, b.PkgName), cmp.Compare(a.VulnerabilityID, b.VulnerabilityID))
	})
	return out
}

// displayName turns "report-<unixnano>.json.gz" into a readable timestamp.
func displayName(id string) string {
	var ns int64
	if _, err := fmt.Sscanf(id, "report-%d.json.gz", &ns); err != nil {
		return id
	}
	return time.Unix(0, ns).UTC().Format("2006-01-02 15:04:05 UTC")
}

// Handler serves the history read-only:
//
//	GET /                    newest report
//	GET /reports/{id}        one report (id from the history list)
//	GET /reports/{id}.json   its raw JSON
//	GET /healthz
func Handler(reports Reports, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		servePage(w, reports, "", log)
	})
	mux.HandleFunc("GET /reports/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if base, ok := strings.CutSuffix(id, ".json"); ok && strings.HasSuffix(base, ".json.gz") {
			serveJSON(w, reports, base, log)
			return
		}
		servePage(w, reports, id, log)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	return headers(mux)
}

func headers(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(w, r)
	})
}

func servePage(w http.ResponseWriter, reports Reports, id string, log *slog.Logger) {
	p, err := build(reports, id)
	if err != nil {
		httpError(w, err, log)
		return
	}
	p.Linked = true
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, p); err != nil {
		log.Warn("render report", "err", err)
	}
}

func serveJSON(w http.ResponseWriter, reports Reports, id string, log *slog.Logger) {
	ids, err := reports.List()
	if err != nil {
		httpError(w, err, log)
		return
	}
	// Only ids from the listing are loaded, so the path can never escape the history dir.
	if !slices.Contains(ids, id) {
		httpError(w, errNotFound, log)
		return
	}
	r, err := reports.Load(id)
	if err != nil {
		httpError(w, err, log)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(r)
}

func httpError(w http.ResponseWriter, err error, log *slog.Logger) {
	switch {
	case errors.Is(err, errNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	case errors.Is(err, ErrNoReports):
		http.Error(w, ErrNoReports.Error(), http.StatusNotFound)
	default:
		log.Warn("serve report", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// NewServer returns a read-only server with timeouts. There is no auth, so a
// non-loopback address exposes the host's vulnerabilities to that network.
func NewServer(addr string, reports Reports, log *slog.Logger) *http.Server {
	if host, _, err := net.SplitHostPort(addr); err != nil || !isLoopback(host) {
		log.Warn("serve: listening on a non-loopback address without auth; anyone who can reach it can read the reports", "addr", addr)
	}
	return &http.Server{
		Addr:              addr,
		Handler:           Handler(reports, log),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
