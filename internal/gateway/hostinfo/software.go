package hostinfo

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/idnatiya/netra-vuln-agent/internal/entity"
)

const versionTimeout = 10 * time.Second

// probe reads one product's version from a fixed local command. Nothing here
// comes from central, so the agent stays passive.
type probe struct {
	name string
	bins []string // first found in PATH (or as an absolute glob) wins
	args []string
	re   *regexp.Regexp // group 1 = version; output is stdout + stderr
}

var probes = []probe{
	{"php", []string{"php"}, []string{"-v"}, regexp.MustCompile(`PHP (\d+\.\d+\.\d+)`)},
	{"nodejs", []string{"node", "nodejs"}, []string{"-v"}, regexp.MustCompile(`v(\d+\.\d+\.\d+)`)},
	{"nginx", []string{"nginx"}, []string{"-v"}, regexp.MustCompile(`nginx/(\d+\.\d+\.\d+)`)},
	{"apache", []string{"apache2", "httpd"}, []string{"-v"}, regexp.MustCompile(`Apache/(\d+\.\d+\.\d+)`)},
	{"mysql", []string{"mysqld"}, []string{"--version"}, regexp.MustCompile(`Ver (\d+\.\d+\.\d+)`)},
	{"mariadb", []string{"mariadbd"}, []string{"--version"}, regexp.MustCompile(`Ver (\d+\.\d+\.\d+)`)},
	{"redis", []string{"redis-server"}, []string{"--version"}, regexp.MustCompile(`v=(\d+\.\d+\.\d+)`)},
	{"postgresql", []string{"postgres", "/usr/lib/postgresql/*/bin/postgres", "/usr/pgsql-*/bin/postgres"},
		[]string{"--version"}, regexp.MustCompile(`PostgreSQL\) (\d+(?:\.\d+)+)`)},
}

// pm2 is read from its package.json: running pm2 could start its daemon.
var pm2Packages = []string{"/usr/lib/node_modules/pm2/package.json", "/usr/local/lib/node_modules/pm2/package.json"}

// Software lists the installed runtimes and databases, best effort.
func (l *Linux) Software(ctx context.Context) []entity.Software {
	var out []entity.Software
	for _, p := range probes {
		bin := l.find(p.bins)
		if bin == "" {
			continue
		}
		b, _ := l.exec(ctx, bin, p.args...) // some print the version and still exit non-zero
		if m := p.re.FindSubmatch(b); m != nil {
			name := p.name
			if name == "mysql" && strings.Contains(string(b), "MariaDB") { // mysqld can be MariaDB
				name = "mariadb"
			}
			if !slices.ContainsFunc(out, func(s entity.Software) bool { return s.Name == name }) {
				out = append(out, entity.Software{Name: name, Version: string(m[1]), Path: bin})
			}
		}
	}
	for _, f := range pm2Packages {
		var pkg struct{ Version string }
		if b, err := os.ReadFile(l.path(f)); err == nil && json.Unmarshal(b, &pkg) == nil && pkg.Version != "" {
			out = append(out, entity.Software{Name: "pm2", Version: pkg.Version, Path: filepath.Dir(f)})
			break
		}
	}
	return out
}

// find returns the first binary that exists: a PATH lookup (plus the sbin
// dirs, which a service PATH may lack) or an absolute glob.
func (l *Linux) find(bins []string) string {
	for _, b := range bins {
		if strings.HasPrefix(b, "/") {
			if m, _ := filepath.Glob(l.path(b)); len(m) > 0 {
				slices.Sort(m)
				return m[len(m)-1] // newest version dir
			}
			continue
		}
		if l.Root == "" {
			if p, err := exec.LookPath(b); err == nil {
				return p
			}
		}
		for _, dir := range []string{"/usr/sbin", "/usr/local/sbin", "/usr/bin", "/usr/local/bin"} {
			if p := l.path(filepath.Join(dir, b)); l.exists(filepath.Join(dir, b)) {
				return p
			}
		}
	}
	return ""
}

func (l *Linux) exec(ctx context.Context, bin string, args ...string) ([]byte, error) {
	if l.Exec != nil {
		return l.Exec(ctx, bin, args...)
	}
	ctx, cancel := context.WithTimeout(ctx, versionTimeout)
	defer cancel()
	return exec.CommandContext(ctx, bin, args...).CombinedOutput()
}
