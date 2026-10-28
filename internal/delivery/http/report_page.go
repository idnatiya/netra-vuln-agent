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
	"path"
	"slices"
	"strings"
	"time"
	"unicode"

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
	"join":  strings.Join,
	"sevshort": func(s string) string {
		if s == "CRITICAL" {
			return "CRIT"
		}
		return s
	},
	"kind": func(k entity.ComponentKind) string {
		return map[entity.ComponentKind]string{entity.ComponentOS: "OS packages", entity.ComponentApp: "Application", entity.ComponentBinary: "Binary"}[k]
	},
	"advisory": func(id string) string {
		if strings.HasPrefix(id, "GHSA-") {
			return "https://github.com/advisories/" + id
		}
		return "https://avd.aquasec.com/nvd/" + strings.ToLower(id)
	},
}).Parse(tmplText))

type page struct {
	ID         string
	Report     entity.Report
	Counts     map[string]int
	Components []component
	Compared   bool // a previous ok report exists, so New/Resolved are meaningful
	New        []entity.Finding
	Resolved   []entity.Finding
	History    []string // newest first
	Linked     bool     // render links to other reports (served, not a static file)
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
	p := page{ID: ids[i], Report: cur, Counts: map[string]int{}, Components: components(cur.Findings, cur.Host)}
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

// component is the findings of one upgrade action, with how to fix it.
type component struct {
	Kind     entity.ComponentKind
	Key      string
	Title    string
	Note     string
	Command  string // shown for the operator to copy; never run by the agent
	Kernel   string // "running" or "standby" for kernel packages
	Packages []string
	Types    []string
	Critical int
	High     int
	CVEs     int
	Findings []entity.Finding
}

// components groups findings like central's dashboard, most severe first.
func components(findings []entity.Finding, host entity.HostInfo) []component {
	idx := map[[2]string]int{}
	var out []component
	for _, f := range sorted(findings) {
		kind, key := f.Component()
		k := [2]string{string(kind), key}
		i, ok := idx[k]
		if !ok {
			i = len(out)
			idx[k] = i
			out = append(out, component{Kind: kind, Key: key})
		}
		c := &out[i]
		c.Findings = append(c.Findings, f)
		if !slices.Contains(c.Packages, f.PkgName) {
			c.Packages = append(c.Packages, f.PkgName)
		}
		if !slices.Contains(c.Types, f.Type) {
			c.Types = append(c.Types, f.Type)
		}
		switch f.Severity {
		case "CRITICAL":
			c.Critical++
		case "HIGH":
			c.High++
		}
	}
	for i := range out {
		c := &out[i]
		cves := map[string]bool{}
		for _, f := range c.Findings {
			cves[f.VulnerabilityID] = true
		}
		c.CVEs = len(cves)
		slices.Sort(c.Packages)
		advise(c, host)
	}
	slices.SortStableFunc(out, func(a, b component) int {
		return cmp.Or(cmp.Compare(b.Critical, a.Critical), cmp.Compare(b.High, a.High), cmp.Compare(a.Key, b.Key))
	})
	return out
}

// advise fills in the title, note, and fix command. Same rules as central's
// componentAdvice (dashboard/src/domain/rules.ts).
func advise(c *component, h entity.HostInfo) {
	deb := h.OSFamily == "debian"
	pkgs := strings.Join(c.Packages, " ")
	title := path.Base(c.Key)
	isKernel := len(c.Packages) > 0 && !slices.ContainsFunc(c.Packages, func(p string) bool {
		return !strings.HasPrefix(p, "linux-") && !strings.HasPrefix(p, "kernel")
	})
	has := func(types ...string) bool {
		return slices.ContainsFunc(c.Types, func(t string) bool { return slices.Contains(types, t) })
	}

	switch {
	case c.Kind == entity.ComponentOS && isKernel && runningKernel(c.Key, h.KernelRunning):
		c.Title, c.Kernel = "Linux kernel", "running"
		c.Note = "This is the running kernel. Upgrade, then reboot into the new one."
		c.Command = ifDeb(deb, "sudo apt-get update && sudo apt-get full-upgrade -y && sudo reboot", "sudo dnf upgrade -y 'kernel*' && sudo reboot")
	case c.Kind == entity.ComponentOS && isKernel:
		c.Title, c.Kernel = "Linux kernel", "standby"
		c.Note = fmt.Sprintf("Not running (the host booted %s). Kept as a fallback; remove it once the running kernel is fine.", cmp.Or(h.KernelRunning, "another kernel"))
		ver := c.Key
		if i := strings.LastIndex(ver, "."); i >= 0 {
			ver = ver[:i]
		}
		c.Command = ifDeb(deb, "dpkg -l 'linux-*"+ver+"*' | awk '/^ii/{print $2}' | xargs sudo apt-get purge -y", "sudo dnf remove 'kernel*-"+c.Key+"*'")
	case c.Kind == entity.ComponentOS:
		c.Title = strings.Join(c.Packages[:min(2, len(c.Packages))], ", ")
		if more := len(c.Packages) - 2; more > 0 {
			c.Title += fmt.Sprintf(" +%d", more)
		}
		c.Note = "Upgrade these OS packages."
		c.Command = ifDeb(deb, "sudo apt-get update && sudo apt-get install --only-upgrade -y "+pkgs, "sudo dnf upgrade -y "+pkgs)
	case c.Kind == entity.ComponentBinary:
		c.Title = title
		c.Note = "A compiled binary with outdated libraries. Upgrade the package or app that ships it; this finds the package:"
		c.Command = ifDeb(deb, "dpkg -S "+c.Key, "rpm -qf "+c.Key)
	case slices.Contains(entity.CacheDirs, title):
		c.Title, c.Note = title, "A package cache, not a running app. Clear it, or accept the risk."
	case has("composer", "composer-vendor"):
		c.Title, c.Note = title, "PHP app (Composer). Update the dependencies, test, and deploy."
		c.Command = "cd " + c.Key + " && composer update --with-dependencies " + pkgs
	case has("node-pkg", "npm", "yarn", "pnpm"):
		c.Title, c.Note = title, "Node.js app. Update the dependencies, rebuild, and deploy."
		c.Command = "cd " + c.Key + " && npm update " + pkgs
	case has("python-pkg", "pip", "pipenv", "poetry", "uv"):
		c.Title, c.Note = title, "Python packages. Upgrade them in the app's environment."
		c.Command = "pip install -U " + pkgs
	case has("jar", "pom", "gradle", "sbt"):
		c.Title, c.Note = title, "Java app. Bump the dependencies in its build, rebuild, and deploy."
	default:
		c.Title, c.Note = title, "Update the dependencies of this app."
	}
}

func ifDeb(deb bool, apt, dnf string) string {
	if deb {
		return apt
	}
	return dnf
}

// runningKernel says whether an installed kernel package version is the running kernel.
// Ubuntu: running "6.8.0-147-generic", installed "6.8.0-147.147".
// RHEL: running "5.14.0-427.13.1.el9_4.x86_64", installed "5.14.0-427.13.1.el9_4".
func runningKernel(installed, running string) bool {
	if installed == "" || running == "" {
		return false
	}
	base := running // drop the flavour, e.g. "-generic"
	if i := strings.LastIndex(running, "-"); i >= 0 && flavour(running[i+1:]) {
		base = running[:i]
	}
	return strings.HasPrefix(running, installed) || installed == base || strings.HasPrefix(installed, base+".")
}

func flavour(s string) bool {
	if s == "" || !unicode.IsLetter(rune(s[0])) {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool { return r > unicode.MaxASCII || !(unicode.IsLetter(r) || unicode.IsDigit(r)) })
}
