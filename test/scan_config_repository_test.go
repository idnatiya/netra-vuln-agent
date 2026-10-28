package test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/idnatiya/netra-vuln-agent/internal/entity"
	"github.com/idnatiya/netra-vuln-agent/internal/repository"
)

func TestScanConfigRepository(t *testing.T) {
	c := &repository.ScanConfigRepository{Path: filepath.Join(t.TempDir(), "scan-config.json")}
	if _, err := c.Load(); err == nil {
		t.Fatal("missing cache loaded")
	}
	want := entity.DefaultScanConfig()
	want.Timeout = 45 * time.Minute
	if err := c.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := c.Load()
	if err != nil || got.Timeout != want.Timeout || len(got.SkipDirs) != len(want.SkipDirs) {
		t.Fatalf("got %+v %v", got, err)
	}
}
