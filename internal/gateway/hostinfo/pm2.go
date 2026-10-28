package hostinfo

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PM2Dirs returns the working dirs of the apps saved with `pm2 save`, read from
// /root/.pm2/dump.pm2 and /home/*/.pm2/dump.pm2. It only reads files; pm2 is
// never run. Apps under a custom $PM2_HOME are not found.
func (l *Linux) PM2Dirs() ([]string, error) {
	dumps, _ := filepath.Glob(l.path("/home/*/.pm2/dump.pm2"))
	dumps = append([]string{l.path("/root/.pm2/dump.pm2")}, dumps...)
	var dirs []string
	var errs []error
	for _, p := range dumps {
		b, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		var procs []struct {
			Cwd string `json:"pm_cwd"`
		}
		if err == nil {
			err = json.Unmarshal(b, &procs)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
			continue
		}
		for _, proc := range procs {
			if strings.HasPrefix(proc.Cwd, "/") {
				dirs = append(dirs, proc.Cwd)
			}
		}
	}
	return dirs, errors.Join(errs...)
}
