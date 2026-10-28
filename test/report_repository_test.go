package test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/idnatiya/netra-vuln-agent/internal/repository"

	"github.com/idnatiya/netra-vuln-agent/internal/entity"
)

func TestRotationAndOrder(t *testing.T) {
	d := &repository.ReportRepository{Path: filepath.Join(t.TempDir(), "spool"), Max: 5}
	for i := range 8 {
		if err := d.Save(entity.Report{Error: fmt.Sprint(i), Findings: []entity.Finding{{PkgName: "p"}}}); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(d.Path, "junk.txt"), nil, 0o600)

	ids, err := d.List()
	if err != nil || len(ids) != 5 {
		t.Fatalf("ids=%v err=%v", ids, err)
	}
	for i, id := range ids {
		r, err := d.Load(id)
		if err != nil {
			t.Fatal(err)
		}
		if want := fmt.Sprint(i + 3); r.Error != want || r.Findings[0].PkgName != "p" {
			t.Fatalf("ids[%d] = %+v, want Error %s", i, r, want)
		}
	}
	if err := d.Remove(ids[0]); err != nil {
		t.Fatal(err)
	}
	if ids, _ := d.List(); len(ids) != 4 {
		t.Fatalf("after remove: %v", ids)
	}
	if fi, _ := os.Stat(d.Path); fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir perm %v", fi.Mode().Perm())
	}
}

func TestListMissingDir(t *testing.T) {
	ids, err := (&repository.ReportRepository{Path: filepath.Join(t.TempDir(), "nope")}).List()
	if err != nil || len(ids) != 0 {
		t.Fatalf("ids=%v err=%v", ids, err)
	}
}
