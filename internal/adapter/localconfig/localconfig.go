// Package localconfig reads/writes /etc/vuln-agent/config.yaml and the ScanConfig cache.
package localconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/idnatiya/netra-vuln-agent/internal/domain"
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
}

// Standalone reports whether the agent runs without central (no central_url):
// scans are kept only locally.
func (c Config) Standalone() bool { return c.CentralURL == "" }

func (c Config) Validate() error {
	if c.Standalone() {
		if c.ClientID != "" || c.Token != "" {
			return errors.New("central_url is empty (standalone) but client_id or token is set")
		}
		return nil
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
	if err := writeAtomic(f.Path, b); err != nil {
		return err
	}
	f.Config = c
	return nil
}

// ScanConfigCache stores the last valid ScanConfig received from central.
type ScanConfigCache struct{ Path string }

func (c *ScanConfigCache) Load() (domain.ScanConfig, error) {
	var cfg domain.ScanConfig
	b, err := os.ReadFile(c.Path)
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(b, &cfg)
	return cfg, err
}

func (c *ScanConfigCache) Save(cfg domain.ScanConfig) error {
	b, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return writeAtomic(c.Path, b)
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
