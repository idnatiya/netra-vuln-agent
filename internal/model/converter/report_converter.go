// Package converter maps agent entities to the public wire contract.
package converter

import (
	"github.com/idnatiya/netra-vuln-agent/internal/entity"
	"github.com/idnatiya/netra-vuln-agent/pkg/wire"
)

func ToWireHost(h entity.HostInfo) wire.Host {
	return wire.Host{
		Hostname:                  h.Hostname,
		OSFamily:                  h.OSFamily,
		OSName:                    h.OSName,
		OSVersion:                 h.OSVersion,
		Arch:                      h.Arch,
		KernelRunning:             h.KernelRunning,
		UptimeSeconds:             h.UptimeSeconds,
		RebootRequired:            h.RebootRequired,
		UnattendedUpgradesEnabled: h.AutoUpdateEnabled,
		AgentVersion:              h.AgentVersion,
	}
}

func ToWireReport(clientID string, r entity.Report) wire.Report {
	findings := make([]wire.Finding, len(r.Findings))
	for i, f := range r.Findings {
		findings[i] = wire.Finding(f)
	}
	software := make([]wire.Software, len(r.Software))
	for i, s := range r.Software {
		software[i] = wire.Software(s)
	}
	return wire.Report{
		ClientID:            clientID,
		Host:                ToWireHost(r.Host),
		TrivyVersion:        r.TrivyVersion,
		ScannedAt:           r.ScannedAt.UTC(),
		ScanDurationSeconds: r.Duration.Seconds(),
		Status:              string(r.Status),
		Error:               r.Error,
		Findings:            findings,
		Software:            software,
	}
}
