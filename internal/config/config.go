// Package config reads/writes /etc/vuln-agent/config.yaml and wires the agent (app.go).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/idnatiya/netra-vuln-agent/internal/repository"
	"github.com/idnatiya/netra-vuln-agent/pkg/scanconfig"
	"gopkg.in/yaml.v3"
)

// Secret hides its value from fmt and slog. YAML still writes the real value.
type Secret string

func (Secret) String() string       { return "[redacted]" }
func (Secret) GoString() string     { return "[redacted]" }
func (Secret) LogValue() slog.Value { return slog.StringValue("[redacted]") }
func (s Secret) Reveal() string     { return string(s) }

// MarshalJSON prevents leaks via slog.JSONHandler when a struct is logged.
// Deliberately not MarshalText: yaml.v3 uses it and would corrupt config.yaml.
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }

type Config struct {
	CentralURL       string `yaml:"central_url"`
	ClientID         string `yaml:"client_id"`
	Token            Secret `yaml:"token"`
	HostnameOverride string `yaml:"hostname_override"`
	CAFile           string `yaml:"ca_file"`
	// ExtraSkipDirs are added to the skip_dirs in effect (default or from central).
	ExtraSkipDirs []string `yaml:"extra_skip_dirs"`
	// AppDirs are scanned for app dependencies (Composer, npm, ...), plus the
	// pm2 app dirs. Unset = DefaultAppDirs; [] = OS packages only.
	AppDirs *[]string `yaml:"app_dirs"`
}

// DefaultAppDirs are the usual homes of web apps (Laravel, Node).
var DefaultAppDirs = []string{"/var/www", "/srv", "/opt"}

const maxAppDirs = 50

// ScanAppDirs is the app_dirs setting in effect.
func (c Config) ScanAppDirs() []string {
	if c.AppDirs == nil {
		return slices.Clone(DefaultAppDirs)
	}
	return *c.AppDirs
}

func (c Config) Validate() error {
	if c.AppDirs != nil {
		if len(*c.AppDirs) > maxAppDirs {
			return fmt.Errorf("too many app_dirs (%d > %d)", len(*c.AppDirs), maxAppDirs)
		}
		for _, d := range *c.AppDirs {
			if !strings.HasPrefix(d, "/") || strings.ContainsAny(d, "\x00\n\r") {
				return fmt.Errorf("invalid app_dir %q: must be an absolute path", d)
			}
		}
	}
	if len(c.ExtraSkipDirs) > 0 {
		sc := scanconfig.Default()
		sc.SkipDirs = append(sc.SkipDirs, c.ExtraSkipDirs...)
		if err := sc.Validate(); err != nil {
			return fmt.Errorf("extra_skip_dirs: %w", err)
		}
	}
	if c.CentralURL == "" {
		return errors.New("central_url is empty")
	}
	u, err := url.Parse(c.CentralURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("central_url must be an http(s) URL, got %q", c.CentralURL)
	}
	if c.ClientID == "" {
		return errors.New("client_id is empty")
	}
	if c.CAFile != "" {
		if _, err := os.Stat(c.CAFile); err != nil {
			return fmt.Errorf("ca_file: %w", err)
		}
	}
	return nil
}

// File is a loaded config.yaml; it implements usecase.CredentialStore.
type File struct {
	Path   string
	Config Config
}

// Load reads and validates the config. Overly permissive file modes and plain
// http are returned as warnings, not errors.
func Load(path string) (f *File, warnings []string, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		warnings = append(warnings, fmt.Sprintf("%s has mode %v, expected 0600", path, fi.Mode().Perm()))
	}
	if strings.HasPrefix(c.CentralURL, "http://") {
		// Acceptable only over an already-encrypted network (e.g. Tailscale/WireGuard).
		warnings = append(warnings, "central_url uses plain http: the host token is sent unencrypted unless the network itself is encrypted (e.g. Tailscale)")
	}
	return &File{Path: path, Config: c}, warnings, nil
}

func (f *File) HostToken() string { return f.Config.Token.Reveal() }

// SaveHostToken rewrites the config atomically with mode 600.
// Comments in the original file are not preserved.
func (f *File) SaveHostToken(token string) error {
	c := f.Config
	c.Token = Secret(token)
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	if err := repository.WriteFileAtomic(f.Path, b); err != nil {
		return err
	}
	f.Config = c
	return nil
}
