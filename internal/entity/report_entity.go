package entity

import (
	"strings"
	"time"
)

type ScanStatus string

const (
	StatusOK    ScanStatus = "ok"
	StatusError ScanStatus = "error"
)

// MaxErrorBytes is the maximum length of the error message in a report.
const MaxErrorBytes = 4096

// Report is the result of one scan cycle.
type Report struct {
	Host         HostInfo
	Status       ScanStatus
	Error        string
	ScannedAt    time.Time
	Duration     time.Duration
	TrivyVersion string
	Findings     []Finding
}

// TruncateError cuts s to at most MaxErrorBytes without breaking UTF-8.
func TruncateError(s string) string {
	if len(s) <= MaxErrorBytes {
		return s
	}
	return strings.ToValidUTF8(s[:MaxErrorBytes], "")
}
