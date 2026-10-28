package test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/idnatiya/netra-vuln-agent/internal/gateway/trivy"
)

func TestInstallTrivy(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{"README.md": "docs", "trivy": "#!/bin/sh\necho trivy\n"} {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	tarball := buf.Bytes()
	sum := sha256.Sum256(tarball)

	for _, tc := range []struct {
		name, checksum string
		wantErr        bool
	}{
		{"good checksum", hex.EncodeToString(sum[:]), false},
		{"bad checksum", hex.EncodeToString(make([]byte, 32)), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/v1.2.3/trivy_1.2.3_checksums.txt", func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte("deadbeef  trivy_1.2.3_Linux-ARM64.tar.gz\n" + tc.checksum + "  trivy_1.2.3_Linux-64bit.tar.gz\n"))
			})
			mux.HandleFunc("/v1.2.3/trivy_1.2.3_Linux-64bit.tar.gz", func(w http.ResponseWriter, _ *http.Request) {
				w.Write(tarball)
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()

			dest := filepath.Join(t.TempDir(), "trivy")
			err := trivy.Install(context.Background(), srv.Client(), srv.URL, "1.2.3", "64bit", dest)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want error")
				}
				if _, serr := os.Stat(dest); serr == nil {
					t.Fatal("trivy installed despite checksum mismatch")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			fi, err := os.Stat(dest)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o755 {
				t.Errorf("mode = %v, want 0755", fi.Mode().Perm())
			}
			if b, _ := os.ReadFile(dest); string(b) != "#!/bin/sh\necho trivy\n" {
				t.Errorf("content = %q", b)
			}
			if left, _ := filepath.Glob(filepath.Join(filepath.Dir(dest), ".*")); len(left) > 0 {
				t.Errorf("temp files left: %v", left)
			}
		})
	}
}
