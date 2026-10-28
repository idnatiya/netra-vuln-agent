package trivy

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Install downloads the Trivy release tarball, verifies it against the
// release checksums file, and installs the trivy binary at dest.
func Install(ctx context.Context, client *http.Client, baseURL, version, arch, dest string) error {
	release := fmt.Sprintf("%s/v%s/", baseURL, version)
	tarball := fmt.Sprintf("trivy_%s_Linux-%s.tar.gz", version, arch)

	sums, err := fetch(ctx, client, release+fmt.Sprintf("trivy_%s_checksums.txt", version))
	if err != nil {
		return err
	}
	defer sums.Close()
	want := ""
	sc := bufio.NewScanner(sums)
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) == 2 && f[1] == tarball {
			want = f[0]
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if want == "" {
		return fmt.Errorf("no checksum for %s", tarball)
	}

	tmp, err := os.CreateTemp(filepath.Dir(dest), ".trivy-*.tar.gz")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	body, err := fetch(ctx, client, release+tarball)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(tmp, h), body)
	body.Close()
	if err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("checksum mismatch for %s: got %s, want %s", tarball, got, want)
	}

	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	gz, err := gzip.NewReader(tmp)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%s has no trivy binary", tarball)
		}
		if err != nil {
			return err
		}
		if hdr.Name == "trivy" && hdr.Typeflag == tar.TypeReg {
			return writeExecutable(dest, tr)
		}
	}
}

func fetch(ctx context.Context, client *http.Client, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return resp.Body, nil
}

// writeExecutable atomically replaces path with r's contents, mode 0755.
func writeExecutable(path string, r io.Reader) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = io.Copy(tmp, r)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
