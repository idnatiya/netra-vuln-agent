// Package entity holds agent entities and pure business rules (stdlib only).
package entity

// Finding is a single slimmed-down vulnerability from a scan.
type Finding struct {
	Target           string
	Type             string
	VulnerabilityID  string
	PkgName          string
	PkgPath          string // file the package was found in (language packages); empty for OS packages
	InstalledVersion string
	FixedVersion     string
	Severity         string
	Title            string
}
