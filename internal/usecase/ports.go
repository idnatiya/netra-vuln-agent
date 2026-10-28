// Package usecase holds agent orchestration. Ports are defined here and
// implemented by the adapter packages.
package usecase

import (
	"context"
	"errors"

	"github.com/idnatiya/netra-vuln-agent/internal/domain"
)

// ErrRejected is returned by Central when central permanently rejects a payload
// (e.g. 400/413/422). Such payloads are not spooled and are dropped from the spool.
var ErrRejected = errors.New("rejected by central")

type Scanner interface {
	Scan(ctx context.Context, cfg domain.ScanConfig) ([]domain.Finding, error)
	Version(ctx context.Context) (string, error)
}

// HostInspector is best-effort: fields that cannot be read are left empty.
type HostInspector interface {
	Inspect(ctx context.Context) domain.HostInfo
}

type Central interface {
	FetchScanConfig(ctx context.Context) (domain.ScanConfig, error)
	SendReport(ctx context.Context, r domain.Report) error
	SendHeartbeat(ctx context.Context, h domain.HostInfo) error
	Enroll(ctx context.Context, enrollToken string, h domain.HostInfo) (hostToken string, err error)
}

// Spool stores reports that failed to send. List returns ids oldest first.
type Spool interface {
	Save(r domain.Report) error
	List() ([]string, error)
	Load(id string) (domain.Report, error)
	Remove(id string) error
}

type ScanConfigCache interface {
	Load() (domain.ScanConfig, error)
	Save(cfg domain.ScanConfig) error
}

type CredentialStore interface {
	HostToken() string
	SaveHostToken(token string) error
}
