package repository

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/idnatiya/netra-vuln-agent/internal/entity"
)

// ScanConfigRepository stores the last valid ScanConfig received from central.
type ScanConfigRepository struct{ Path string }

func (c *ScanConfigRepository) Load() (entity.ScanConfig, error) {
	var cfg entity.ScanConfig
	b, err := os.ReadFile(c.Path)
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(b, &cfg)
	return cfg, err
}

func (c *ScanConfigRepository) Save(cfg entity.ScanConfig) error {
	b, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return WriteFileAtomic(c.Path, b)
}

// WriteFileAtomic writes data to path with mode 600 via a temp file + rename.
func WriteFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
