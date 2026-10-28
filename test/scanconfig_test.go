package test

import (
	"testing"
	"time"

	"github.com/idnatiya/netra-vuln-agent/pkg/scanconfig"
)

func TestConfigValidate(t *testing.T) {
	mod := func(f func(*scanconfig.Config)) scanconfig.Config {
		c := scanconfig.Default()
		f(&c)
		return c
	}
	tests := []struct {
		name    string
		cfg     scanconfig.Config
		wantErr bool
	}{
		{"default", scanconfig.Default(), false},
		{"empty severity", mod(func(c *scanconfig.Config) { c.Severities = nil }), true},
		{"bad severity", mod(func(c *scanconfig.Config) { c.Severities = []string{"HIGH", "--exit-code"} }), true},
		{"timeout too short", mod(func(c *scanconfig.Config) { c.Timeout = time.Second }), true},
		{"timeout too long", mod(func(c *scanconfig.Config) { c.Timeout = 3 * time.Hour }), true},
		{"relative skip dir", mod(func(c *scanconfig.Config) { c.SkipDirs = []string{"tmp"} }), true},
		{"flag skip dir", mod(func(c *scanconfig.Config) { c.SkipDirs = []string{"--config=/x"} }), true},
		{"comma skip dir", mod(func(c *scanconfig.Config) { c.SkipDirs = []string{"/a,/b"} }), true},
		{"glob skip dir ok", mod(func(c *scanconfig.Config) { c.SkipDirs = []string{"/home/*/.cache"} }), false},
		{"no skip dirs ok", mod(func(c *scanconfig.Config) { c.SkipDirs = nil }), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cfg.Validate(); (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
