package usecase

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/idnatiya/netra-vuln-agent/internal/domain"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

type fakeScanner struct {
	findings []domain.Finding
	err      error
	gotCfg   domain.ScanConfig
}

func (f *fakeScanner) Scan(_ context.Context, cfg domain.ScanConfig) ([]domain.Finding, error) {
	f.gotCfg = cfg
	return f.findings, f.err
}
func (f *fakeScanner) Version(context.Context) (string, error) { return "0.99.0", nil }

type fakeHost struct{}

func (fakeHost) Inspect(context.Context) domain.HostInfo { return domain.HostInfo{Hostname: "vm1"} }

type fakeCentral struct {
	cfg        domain.ScanConfig
	cfgErr     error
	sendErrs   []error // consumed one per SendReport; exhausted = success
	sent       []domain.Report
	enrollTok  string
	enrollSeen string
}

func (f *fakeCentral) FetchScanConfig(context.Context) (domain.ScanConfig, error) {
	return f.cfg, f.cfgErr
}
func (f *fakeCentral) SendReport(_ context.Context, r domain.Report) error {
	if len(f.sendErrs) > 0 {
		err := f.sendErrs[0]
		f.sendErrs = f.sendErrs[1:]
		if err != nil {
			return err
		}
	}
	f.sent = append(f.sent, r)
	return nil
}
func (f *fakeCentral) SendHeartbeat(context.Context, domain.HostInfo) error { return nil }
func (f *fakeCentral) Enroll(_ context.Context, tok string, _ domain.HostInfo) (string, error) {
	f.enrollSeen = tok
	return f.enrollTok, nil
}

type fakeSpool struct {
	ids     []string
	reports map[string]domain.Report
	n       int
}

func newFakeSpool() *fakeSpool { return &fakeSpool{reports: map[string]domain.Report{}} }

func (f *fakeSpool) Save(r domain.Report) error {
	f.n++
	id := fmt.Sprint(f.n)
	f.ids = append(f.ids, id)
	f.reports[id] = r
	return nil
}
func (f *fakeSpool) List() ([]string, error) { return slices.Clone(f.ids), nil }
func (f *fakeSpool) Load(id string) (domain.Report, error) {
	r, ok := f.reports[id]
	if !ok {
		return r, errors.New("corrupt")
	}
	return r, nil
}
func (f *fakeSpool) Remove(id string) error {
	f.ids = slices.DeleteFunc(f.ids, func(s string) bool { return s == id })
	delete(f.reports, id)
	return nil
}

type fakeCache struct {
	cfg   *domain.ScanConfig
	saved int
}

func (f *fakeCache) Load() (domain.ScanConfig, error) {
	if f.cfg == nil {
		return domain.ScanConfig{}, errors.New("no cache")
	}
	return *f.cfg, nil
}
func (f *fakeCache) Save(cfg domain.ScanConfig) error { f.cfg = &cfg; f.saved++; return nil }

type fakeCreds struct{ token string }

func (f *fakeCreds) HostToken() string            { return f.token }
func (f *fakeCreds) SaveHostToken(t string) error { f.token = t; return nil }

func newScan(sc *fakeScanner, c *fakeCentral, sp *fakeSpool, cache *fakeCache) *Scan {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return &Scan{
		Scanner: sc, Host: fakeHost{}, Central: c, Spool: sp, History: newFakeSpool(), Cache: cache,
		Flush: &Flush{Spool: sp, Central: c, Log: discard},
		Now:   func() time.Time { now = now.Add(time.Second); return now },
		Log:   discard,
	}
}

func TestScanSuccess(t *testing.T) {
	remote := domain.DefaultScanConfig()
	remote.Severities = []string{"CRITICAL"}
	sc := &fakeScanner{findings: []domain.Finding{{VulnerabilityID: "CVE-1"}}}
	c := &fakeCentral{cfg: remote}
	cache := &fakeCache{}
	err := newScan(sc, c, newFakeSpool(), cache).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(c.sent) != 1 || c.sent[0].Status != domain.StatusOK || len(c.sent[0].Findings) != 1 {
		t.Fatalf("sent = %+v", c.sent)
	}
	if !slices.Equal(sc.gotCfg.Severities, []string{"CRITICAL"}) || cache.saved != 1 {
		t.Fatalf("remote config not used/cached: %+v saved=%d", sc.gotCfg, cache.saved)
	}
	if c.sent[0].TrivyVersion != "0.99.0" || c.sent[0].Host.Hostname != "vm1" || c.sent[0].Duration <= 0 {
		t.Fatalf("metadata missing: %+v", c.sent[0])
	}
}

func TestScanKeepsHistory(t *testing.T) {
	c := &fakeCentral{cfg: domain.DefaultScanConfig(), sendErrs: []error{errors.New("down")}}
	s := newScan(&fakeScanner{}, c, newFakeSpool(), &fakeCache{})
	_ = s.Run(context.Background())
	if h := s.History.(*fakeSpool); len(h.ids) != 1 {
		t.Fatalf("history = %v, want 1 report even when send fails", h.ids)
	}
}

func TestScanStandalone(t *testing.T) {
	cached := domain.DefaultScanConfig()
	cached.Severities = []string{"CRITICAL"}
	sc := &fakeScanner{findings: []domain.Finding{{VulnerabilityID: "CVE-1"}}}
	s := newScan(sc, nil, nil, &fakeCache{cfg: &cached})
	s.Central, s.Spool, s.Flush = nil, nil, nil
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := s.History.(*fakeSpool)
	if len(h.ids) != 1 || len(h.reports[h.ids[0]].Findings) != 1 {
		t.Fatalf("history = %+v", h.reports)
	}
	if !slices.Equal(sc.gotCfg.Severities, []string{"CRITICAL"}) {
		t.Fatalf("cached config not used: %+v", sc.gotCfg)
	}

	sc.err = errors.New("boom")
	if err := s.Run(context.Background()); err == nil || len(h.ids) != 2 || h.reports[h.ids[1]].Status != domain.StatusError {
		t.Fatalf("err=%v history=%+v", err, h.reports)
	}
}

func TestScanTrivyErrorIsReported(t *testing.T) {
	sc := &fakeScanner{findings: []domain.Finding{{}}, err: errors.New(strings.Repeat("x", 10000))}
	c := &fakeCentral{cfg: domain.DefaultScanConfig()}
	err := newScan(sc, c, newFakeSpool(), &fakeCache{}).Run(context.Background())
	if err == nil {
		t.Fatal("want error")
	}
	r := c.sent[0]
	if r.Status != domain.StatusError || len(r.Error) != domain.MaxErrorBytes || r.Findings != nil {
		t.Fatalf("status=%s errlen=%d findings=%v", r.Status, len(r.Error), r.Findings)
	}
}

func TestScanSendFailureSpools(t *testing.T) {
	sp := newFakeSpool()
	c := &fakeCentral{cfg: domain.DefaultScanConfig(), sendErrs: []error{errors.New("down")}}
	if err := newScan(&fakeScanner{}, c, sp, &fakeCache{}).Run(context.Background()); err == nil {
		t.Fatal("want error")
	}
	if len(sp.ids) != 1 {
		t.Fatalf("spool = %v", sp.ids)
	}
}

func TestScanRejectedNotSpooled(t *testing.T) {
	sp := newFakeSpool()
	c := &fakeCentral{cfg: domain.DefaultScanConfig(), sendErrs: []error{fmt.Errorf("400: %w", ErrRejected)}}
	if err := newScan(&fakeScanner{}, c, sp, &fakeCache{}).Run(context.Background()); !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v", err)
	}
	if len(sp.ids) != 0 {
		t.Fatalf("spool = %v", sp.ids)
	}
}

func TestScanConfigFallback(t *testing.T) {
	cached := domain.DefaultScanConfig()
	cached.Severities = []string{"LOW"}
	invalid := domain.DefaultScanConfig()
	invalid.SkipDirs = []string{"--evil"}

	tests := []struct {
		name  string
		c     *fakeCentral
		cache *fakeCache
		want  []string
	}{
		{"remote down uses cache", &fakeCentral{cfgErr: errors.New("down")}, &fakeCache{cfg: &cached}, []string{"LOW"}},
		{"remote invalid uses cache", &fakeCentral{cfg: invalid}, &fakeCache{cfg: &cached}, []string{"LOW"}},
		{"no cache uses default", &fakeCentral{cfgErr: errors.New("down")}, &fakeCache{}, []string{"HIGH", "CRITICAL"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := &fakeScanner{}
			if err := newScan(sc, tt.c, newFakeSpool(), tt.cache).Run(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(sc.gotCfg.Severities, tt.want) {
				t.Fatalf("severities = %v, want %v", sc.gotCfg.Severities, tt.want)
			}
		})
	}
}

func TestFlush(t *testing.T) {
	sp := newFakeSpool()
	for i := range 4 {
		sp.Save(domain.Report{Error: fmt.Sprint(i)})
	}
	sp.reports["2"] = domain.Report{} // still present
	delete(sp.reports, "1")           // corrupt: dropped

	// id 2 succeeds, id 3 rejected permanently (dropped), id 4 fails transiently (stop).
	c := &fakeCentral{sendErrs: []error{nil, ErrRejected, errors.New("down")}}
	sent, err := (&Flush{Spool: sp, Central: c, Log: discard}).Run(context.Background())
	if err == nil || sent != 1 {
		t.Fatalf("sent=%d err=%v", sent, err)
	}
	if !slices.Equal(sp.ids, []string{"4"}) {
		t.Fatalf("remaining = %v", sp.ids)
	}
}

func TestEnroll(t *testing.T) {
	ctx := context.Background()
	c := &fakeCentral{enrollTok: "host-tok"}

	creds := &fakeCreds{token: "old"}
	e := &Enroll{Host: fakeHost{}, Central: c, Creds: creds}
	if err := e.Run(ctx, "enroll-tok", false); !errors.Is(err, ErrAlreadyEnrolled) {
		t.Fatalf("err = %v", err)
	}
	if err := e.Run(ctx, "enroll-tok", true); err != nil || creds.token != "host-tok" || c.enrollSeen != "enroll-tok" {
		t.Fatalf("err=%v token=%q", err, creds.token)
	}
	if err := e.Run(ctx, "", true); err == nil {
		t.Fatal("empty enroll token accepted")
	}
}
