package central

import (
	"github.com/idnatiya/netra-vuln-agent/internal/domain"
	"github.com/idnatiya/netra-vuln-agent/wire"
)

// Mapping from agent domain to the shared wire contract (internal/wire).

func toWireHost(h domain.HostInfo) wire.Host {
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

func toWireReport(clientID string, r domain.Report) wire.Report {
	findings := make([]wire.Finding, len(r.Findings))
	for i, f := range r.Findings {
		findings[i] = wire.Finding(f)
	}
	return wire.Report{
		ClientID:            clientID,
		Host:                toWireHost(r.Host),
		TrivyVersion:        r.TrivyVersion,
		ScannedAt:           r.ScannedAt.UTC(),
		ScanDurationSeconds: r.Duration.Seconds(),
		Status:              string(r.Status),
		Error:               r.Error,
		Findings:            findings,
	}
}
