// Package spool stores reports that failed to send on the filesystem.
package spool

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/idnatiya/netra-vuln-agent/internal/domain"
)

const (
	prefix = "report-"
	suffix = ".json.gz"
)

type Dir struct {
	Path string
	Max  int // number of files kept; older ones are deleted
}

// Save writes atomically (tmp + rename) so flush never reads a partial file.
func (d *Dir) Save(r domain.Report) error {
	if err := os.MkdirAll(d.Path, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(d.Path, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	zw := gzip.NewWriter(tmp)
	err = json.NewEncoder(zw).Encode(r)
	if cerr := zw.Close(); err == nil {
		err = cerr
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("write spool: %w", err)
	}
	// Zero-padded nanoseconds: name order = time order.
	name := fmt.Sprintf("%s%020d%s", prefix, time.Now().UnixNano(), suffix)
	if err := os.Rename(tmp.Name(), filepath.Join(d.Path, name)); err != nil {
		return err
	}
	return d.prune()
}

func (d *Dir) List() ([]string, error) {
	entries, err := os.ReadDir(d.Path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if n := e.Name(); e.Type().IsRegular() && strings.HasPrefix(n, prefix) && strings.HasSuffix(n, suffix) {
			ids = append(ids, n)
		}
	}
	slices.Sort(ids)
	return ids, nil
}

func (d *Dir) Load(id string) (domain.Report, error) {
	var r domain.Report
	f, err := os.Open(d.file(id))
	if err != nil {
		return r, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return r, err
	}
	err = json.NewDecoder(zr).Decode(&r)
	return r, err
}

func (d *Dir) Remove(id string) error { return os.Remove(d.file(id)) }

func (d *Dir) file(id string) string { return filepath.Join(d.Path, filepath.Base(id)) }

func (d *Dir) prune() error {
	ids, err := d.List()
	if err != nil {
		return err
	}
	for len(ids) > d.Max {
		if err := d.Remove(ids[0]); err != nil {
			return err
		}
		ids = ids[1:]
	}
	return nil
}
