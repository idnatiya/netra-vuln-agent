// Package usecase holds agent orchestration. Ports are defined here and
// implemented by the repository and gateway packages.
package usecase

import (
	"context"
	"errors"

	"github.com/idnatiya/netra-vuln-agent/internal/entity"
)

// ErrRejected is returned by Central when central permanently rejects a payload
// (e.g. 400/413/422). Such payloads are not spooled and are dropped from the spool.
var ErrRejected = errors.New("rejected by central")

type Scanner interface {
	// Scan returns the findings and the framework versions found in lockfiles.
	Scan(ctx context.Context, cfg entity.ScanConfig) ([]entity.Finding, []entity.Software, error)
	Version(ctx context.Context) (string, error)
}

// HostInspector is best-effort: fields that cannot be read are left empty.
type HostInspector interface {
	Inspect(ctx context.Context) entity.HostInfo
	// Software lists installed runtimes and databases (php, nginx, ...).
	Software(ctx context.Context) []entity.Software
}

type Central interface {
	FetchScanConfig(ctx context.Context) (entity.ScanConfig, error)
	SendReport(ctx context.Context, r entity.Report) error
	SendHeartbeat(ctx context.Context, h entity.HostInfo) error
	Enroll(ctx context.Context, enrollToken string, h entity.HostInfo) (hostToken string, err error)
}

// Spool stores reports that failed to send. List returns ids oldest first.
type Spool interface {
	Save(r entity.Report) error
	List() ([]string, error)
	Load(id string) (entity.Report, error)
	Remove(id string) error
}

type ScanConfigCache interface {
	Load() (entity.ScanConfig, error)
	Save(cfg entity.ScanConfig) error
}

type CredentialStore interface {
	HostToken() string
	SaveHostToken(token string) error
}
