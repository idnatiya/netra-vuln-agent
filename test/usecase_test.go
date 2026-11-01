package test

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

	"github.com/idnatiya/netra-vuln-agent/internal/usecase"

	"github.com/idnatiya/netra-vuln-agent/internal/entity"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

type fakeScanner struct {
	findings []entity.Finding
	software []entity.Software
	err      error
	gotCfg   entity.ScanConfig
}

func (f *fakeScanner) Scan(_ context.Context, cfg entity.ScanConfig) ([]entity.Finding, []entity.Software, error) {
	f.gotCfg = cfg
	return f.findings, f.software, f.err
}
func (f *fakeScanner) Version(context.Context) (string, error) { return "0.99.0", nil }

type fakeHost struct{}

func (fakeHost) Inspect(context.Context) entity.HostInfo { return entity.HostInfo{Hostname: "vm1"} }
func (fakeHost) Software(context.Context) []entity.Software {
	return []entity.Software{{Name: "php", Version: "8.1.2", Path: "/usr/bin/php"}}
}

type fakeCentral struct {
	cfg        entity.ScanConfig
	cfgErr     error
	sendErrs   []error // consumed one per SendReport; exhausted = success
	sent       []entity.Report
	enrollTok  string
	enrollSeen string
}

func (f *fakeCentral) FetchScanConfig(context.Context) (entity.ScanConfig, error) {
	return f.cfg, f.cfgErr
}
func (f *fakeCentral) SendReport(_ context.Context, r entity.Report) error {
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
func (f *fakeCentral) SendHeartbeat(context.Context, entity.HostInfo) error { return nil }
func (f *fakeCentral) Enroll(_ context.Context, tok string, _ entity.HostInfo) (string, error) {
	f.enrollSeen = tok
	return f.enrollTok, nil
}

type fakeSpool struct {
	ids     []string
	reports map[string]entity.Report
	n       int
}

func newFakeSpool() *fakeSpool { return &fakeSpool{reports: map[string]entity.Report{}} }

func (f *fakeSpool) Save(r entity.Report) error {
	f.n++
	id := fmt.Sprint(f.n)
	f.ids = append(f.ids, id)
	f.reports[id] = r
	return nil
}
func (f *fakeSpool) List() ([]string, error) { return slices.Clone(f.ids), nil }
func (f *fakeSpool) Load(id string) (entity.Report, error) {
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
	cfg   *entity.ScanConfig
	saved int
}

func (f *fakeCache) Load() (entity.ScanConfig, error) {
	if f.cfg == nil {
		return entity.ScanConfig{}, errors.New("no cache")
	}
	return *f.cfg, nil
}
func (f *fakeCache) Save(cfg entity.ScanConfig) error { f.cfg = &cfg; f.saved++; return nil }

type fakeCreds struct{ token string }

func (f *fakeCreds) HostToken() string            { return f.token }
func (f *fakeCreds) SaveHostToken(t string) error { f.token = t; return nil }

func newScan(sc *fakeScanner, c *fakeCentral, sp *fakeSpool, cache *fakeCache) *usecase.Scan {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return &usecase.Scan{
		Scanner: sc, Host: fakeHost{}, Central: c, Spool: sp, Cache: cache,
		Flush: &usecase.Flush{Spool: sp, Central: c, Log: discard},
		Now:   func() time.Time { now = now.Add(time.Second); return now },
		Log:   discard,
	}
}

func TestScanSuccess(t *testing.T) {
	remote := entity.DefaultScanConfig()
	remote.Severities = []string{"CRITICAL"}
	sc := &fakeScanner{findings: []entity.Finding{{VulnerabilityID: "CVE-1"}},
		software: []entity.Software{{Name: "laravel", Version: "10.0.0", Path: "/var/www/shop"}}}
	c := &fakeCentral{cfg: remote}
	cache := &fakeCache{}
	err := newScan(sc, c, newFakeSpool(), cache).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(c.sent) != 1 || c.sent[0].Status != entity.StatusOK || len(c.sent[0].Findings) != 1 {
		t.Fatalf("sent = %+v", c.sent)
	}
	if !slices.Equal(sc.gotCfg.Severities, []string{"CRITICAL"}) || cache.saved != 1 {
		t.Fatalf("remote config not used/cached: %+v saved=%d", sc.gotCfg, cache.saved)
	}
	if got := c.sent[0].Software; len(got) != 2 || got[0].Name != "php" || got[1].Name != "laravel" {
		t.Fatalf("software = %+v", got)
	}
	if c.sent[0].TrivyVersion != "0.99.0" || c.sent[0].Host.Hostname != "vm1" || c.sent[0].Duration <= 0 {
		t.Fatalf("metadata missing: %+v", c.sent[0])
	}
}

func TestScanTrivyErrorIsReported(t *testing.T) {
	sc := &fakeScanner{findings: []entity.Finding{{}}, err: errors.New(strings.Repeat("x", 10000))}
	c := &fakeCentral{cfg: entity.DefaultScanConfig()}
	err := newScan(sc, c, newFakeSpool(), &fakeCache{}).Run(context.Background())
	if err == nil {
		t.Fatal("want error")
	}
	r := c.sent[0]
	if r.Status != entity.StatusError || len(r.Error) != entity.MaxErrorBytes || r.Findings != nil {
		t.Fatalf("status=%s errlen=%d findings=%v", r.Status, len(r.Error), r.Findings)
	}
}

func TestScanSendFailureSpools(t *testing.T) {
	sp := newFakeSpool()
	c := &fakeCentral{cfg: entity.DefaultScanConfig(), sendErrs: []error{errors.New("down")}}
	if err := newScan(&fakeScanner{}, c, sp, &fakeCache{}).Run(context.Background()); err == nil {
		t.Fatal("want error")
	}
	if len(sp.ids) != 1 {
		t.Fatalf("spool = %v", sp.ids)
	}
}

func TestScanRejectedNotSpooled(t *testing.T) {
	sp := newFakeSpool()
	c := &fakeCentral{cfg: entity.DefaultScanConfig(), sendErrs: []error{fmt.Errorf("400: %w", usecase.ErrRejected)}}
	if err := newScan(&fakeScanner{}, c, sp, &fakeCache{}).Run(context.Background()); !errors.Is(err, usecase.ErrRejected) {
		t.Fatalf("err = %v", err)
	}
	if len(sp.ids) != 0 {
		t.Fatalf("spool = %v", sp.ids)
	}
}

func TestScanConfigFallback(t *testing.T) {
	cached := entity.DefaultScanConfig()
	cached.Severities = []string{"LOW"}
	invalid := entity.DefaultScanConfig()
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

func TestScanExtraSkipDirs(t *testing.T) {
	central := entity.DefaultScanConfig()
	central.SkipDirs = []string{"/x"}
	tooMany := make([]string, 100)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("/extra%d", i)
	}

	tests := []struct {
		name   string
		c      *fakeCentral
		extras []string
		want   []string
	}{
		{"central adds and skips duplicates", &fakeCentral{cfg: central}, []string{"/data", "/x"}, []string{"/x", "/data"}},
		{"over the limit drops extras", &fakeCentral{cfg: central}, tooMany, []string{"/x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := &fakeScanner{}
			cache := &fakeCache{}
			s := newScan(sc, tt.c, newFakeSpool(), cache)
			s.ExtraSkipDirs = tt.extras
			if err := s.Run(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(sc.gotCfg.SkipDirs, tt.want) {
				t.Fatalf("skip dirs = %v, want %v", sc.gotCfg.SkipDirs, tt.want)
			}
			if !slices.Equal(cache.cfg.SkipDirs, central.SkipDirs) {
				t.Fatalf("cache = %v, want central config without extras", cache.cfg.SkipDirs)
			}
		})
	}
}

func TestFlush(t *testing.T) {
	sp := newFakeSpool()
	for i := range 4 {
		sp.Save(entity.Report{Error: fmt.Sprint(i)})
	}
	sp.reports["2"] = entity.Report{} // still present
	delete(sp.reports, "1")           // corrupt: dropped

	// id 2 succeeds, id 3 rejected permanently (dropped), id 4 fails transiently (stop).
	c := &fakeCentral{sendErrs: []error{nil, usecase.ErrRejected, errors.New("down")}}
	sent, err := (&usecase.Flush{Spool: sp, Central: c, Log: discard}).Run(context.Background())
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
	e := &usecase.Enroll{Host: fakeHost{}, Central: c, Creds: creds}
	if err := e.Run(ctx, "enroll-tok", false); !errors.Is(err, usecase.ErrAlreadyEnrolled) {
		t.Fatalf("err = %v", err)
	}
	if err := e.Run(ctx, "enroll-tok", true); err != nil || creds.token != "host-tok" || c.enrollSeen != "enroll-tok" {
		t.Fatalf("err=%v token=%q", err, creds.token)
	}
	if err := e.Run(ctx, "", true); err == nil {
		t.Fatal("empty enroll token accepted")
	}
}
