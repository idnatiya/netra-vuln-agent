package entity

// HostInfo is the host metadata sent with reports and heartbeats.
type HostInfo struct {
	Hostname          string
	OSFamily          string // "debian", "rhel", or the os-release ID
	OSName            string
	OSVersion         string
	Arch              string
	KernelRunning     string
	UptimeSeconds     int64
	RebootRequired    bool
	AutoUpdateEnabled bool // unattended-upgrades (Debian) or dnf-automatic (RHEL)
	AgentVersion      string
}
