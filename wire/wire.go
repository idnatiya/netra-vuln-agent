// Package wire is the JSON contract between agent and central. These are the
// only JSON-tagged contract types; both sides map them to their own domain.
//
// Compatibility rules:
//   - Central ignores unknown request fields (newer agents keep working).
//   - The agent rejects unknown response fields, so central must not add any.
package wire

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/idnatiya/netra-vuln-agent/scanconfig"
)

type Host struct {
	Hostname                  string `json:"hostname"`
	OSFamily                  string `json:"os_family"`
	OSName                    string `json:"os_name"`
	OSVersion                 string `json:"os_version"`
	Arch                      string `json:"arch"`
	KernelRunning             string `json:"kernel_running"`
	UptimeSeconds             int64  `json:"uptime_seconds"`
	RebootRequired            bool   `json:"reboot_required"`
	UnattendedUpgradesEnabled bool   `json:"unattended_upgrades_enabled"`
	AgentVersion              string `json:"agent_version"`
}

type Finding struct {
	Target           string `json:"target"`
	Type             string `json:"type"`
	VulnerabilityID  string `json:"vulnerability_id"`
	PkgName          string `json:"pkg_name"`
	PkgPath          string `json:"pkg_path,omitempty"`
	InstalledVersion string `json:"installed_version"`
	FixedVersion     string `json:"fixed_version"`
	Severity         string `json:"severity"`
	Title            string `json:"title"`
}

// Report is the body of POST /api/v1/report (Content-Encoding: gzip).
type Report struct {
	ClientID string `json:"client_id"`
	Host
	TrivyVersion        string    `json:"trivy_version"`
	ScannedAt           time.Time `json:"scanned_at"`
	ScanDurationSeconds float64   `json:"scan_duration_seconds"`
	Status              string    `json:"status"` // "ok" | "error"
	Error               string    `json:"error,omitempty"`
	Findings            []Finding `json:"findings"`
}

// Heartbeat is the body of POST /api/v1/heartbeat.
type Heartbeat struct {
	ClientID string `json:"client_id"`
	Host
}

// EnrollRequest is the body of POST /api/v1/enroll (no Authorization header).
type EnrollRequest struct {
	ClientID    string `json:"client_id"`
	EnrollToken string `json:"enroll_token"`
	Host
}

type EnrollResponse struct {
	HostToken string `json:"host_token"`
}

// ScanConfig is the body of GET /api/v1/config and the format stored per client.
// All fields are optional; missing ones use the agent default.
type ScanConfig struct {
	Severity      *[]string `json:"severity,omitempty"`
	IgnoreUnfixed *bool     `json:"ignore_unfixed,omitempty"`
	SkipDirs      *[]string `json:"skip_dirs,omitempty"`
	Timeout       *string   `json:"timeout,omitempty"` // Go duration, e.g. "30m"
}

// Resolve applies the overrides to scanconfig.Default and validates the result.
func (s ScanConfig) Resolve() (scanconfig.Config, error) {
	cfg := scanconfig.Default()
	if s.Severity != nil {
		cfg.Severities = *s.Severity
	}
	if s.IgnoreUnfixed != nil {
		cfg.IgnoreUnfixed = *s.IgnoreUnfixed
	}
	if s.SkipDirs != nil {
		cfg.SkipDirs = *s.SkipDirs
	}
	if s.Timeout != nil {
		t, err := time.ParseDuration(*s.Timeout)
		if err != nil {
			return cfg, err
		}
		cfg.Timeout = t
	}
	return cfg, cfg.Validate()
}

// ParseScanConfig strictly decodes stored or admin-supplied overrides, validates
// the resulting config, and returns canonical JSON with only the allowed fields.
func ParseScanConfig(b []byte) ([]byte, error) {
	var cfg ScanConfig
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("scan config: %w (allowed: severity, ignore_unfixed, skip_dirs, timeout)", err)
	}
	if _, err := cfg.Resolve(); err != nil {
		return nil, fmt.Errorf("scan config: %w", err)
	}
	return json.Marshal(cfg)
}
