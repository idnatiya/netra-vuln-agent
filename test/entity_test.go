package test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/idnatiya/netra-vuln-agent/internal/entity"
)

func TestTruncateError(t *testing.T) {
	if got := entity.TruncateError("short"); got != "short" {
		t.Fatalf("got %q", got)
	}
	// "é" is 2 bytes; the "x" prefix shifts the cut point into the middle of a rune.
	got := entity.TruncateError("x" + strings.Repeat("é", entity.MaxErrorBytes))
	if len(got) > entity.MaxErrorBytes || !utf8.ValidString(got) {
		t.Fatalf("len=%d valid=%v", len(got), utf8.ValidString(got))
	}
}

func TestComponent(t *testing.T) {
	for _, c := range []struct {
		f    entity.Finding
		kind entity.ComponentKind
		key  string
	}{
		{entity.Finding{Type: "ubuntu", PkgName: "linux-libc-dev", InstalledVersion: "6.8.0-124.124"}, entity.ComponentOS, "6.8.0-124.124"},
		{entity.Finding{Type: "rocky", PkgName: "openssl-libs", InstalledVersion: "1:3.0.7-27.el9"}, entity.ComponentOS, "1:3.0.7-27.el9"},
		{entity.Finding{Type: "gobinary", Target: "usr/bin/dockerd"}, entity.ComponentBinary, "/usr/bin/dockerd"},
		{entity.Finding{Type: "composer-vendor", PkgPath: "var/www/shop/vendor/composer/installed.json"}, entity.ComponentApp, "/var/www/shop"},
		{entity.Finding{Type: "node-pkg", PkgPath: "home/u/front/node_modules/@a/b/node_modules/c/package.json"}, entity.ComponentApp, "/home/u/front"},
		{entity.Finding{Type: "python-pkg", PkgPath: "usr/lib/python3/dist-packages/urllib3-2.0.7.dist-info/METADATA"}, entity.ComponentApp, "/usr/lib/python3"},
		{entity.Finding{Type: "python-pkg", PkgPath: "srv/api/.venv/lib/python3.12/site-packages/x-1.dist-info/METADATA"}, entity.ComponentApp, "/srv/api"},
		{entity.Finding{Type: "python-pkg", PkgPath: "home/u/.cache/uv/archive-v0/abc/aiohttp-3.14.3.dist-info/METADATA"}, entity.ComponentApp, "/home/u/.cache"},
		{entity.Finding{Type: "jar", PkgPath: "opt/api/app.jar"}, entity.ComponentApp, "/opt/api/app.jar"},
		{entity.Finding{Type: "jar", PkgPath: "home/u/.m2/repository/at/yawk/lz4/lz4-java-1.10.1.jar"}, entity.ComponentApp, "/home/u/.m2"},
		{entity.Finding{Type: "composer", Target: "var/www/blog/composer.lock"}, entity.ComponentApp, "/var/www/blog"},
	} {
		if kind, key := c.f.Component(); kind != c.kind || key != c.key {
			t.Errorf("%+v: got %s %q, want %s %q", c.f, kind, key, c.kind, c.key)
		}
	}
}
