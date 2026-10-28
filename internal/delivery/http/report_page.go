// Package http renders the local report history as HTML (a static file or a
// read-only HTTP server). It never triggers scans or runs commands.
package http

import (
	"cmp"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/idnatiya/netra-vuln-agent/internal/entity"
)

// Reports is the local report history; List returns ids oldest first.
type Reports interface {
	List() ([]string, error)
	Load(id string) (entity.Report, error)
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
	Report   entity.Report
	Counts   map[string]int
	Findings []entity.Finding
	Compared bool // a previous ok report exists, so New/Resolved are meaningful
	New      []entity.Finding
	Resolved []entity.Finding
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
	for j := i - 1; j >= 0 && cur.Status == entity.StatusOK; j-- {
		prev, err := reports.Load(ids[j])
		if err != nil || prev.Status != entity.StatusOK {
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
func diff(a, b []entity.Finding) []entity.Finding {
	seen := make(map[[5]string]bool, len(b))
	for _, f := range b {
		seen[key(f)] = true
	}
	var out []entity.Finding
	for _, f := range a {
		if !seen[key(f)] {
			out = append(out, f)
		}
	}
	return sorted(out)
}

func key(f entity.Finding) [5]string {
	return [5]string{f.VulnerabilityID, f.PkgName, f.InstalledVersion, f.Target, f.PkgPath}
}

var severityRank = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

func sorted(fs []entity.Finding) []entity.Finding {
	out := slices.Clone(fs)
	slices.SortStableFunc(out, func(a, b entity.Finding) int {
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
