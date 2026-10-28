package test

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/idnatiya/netra-vuln-agent/internal/gateway/central"

	"github.com/idnatiya/netra-vuln-agent/internal/entity"
	"github.com/idnatiya/netra-vuln-agent/internal/usecase"
)

func newTestClient(t *testing.T, h http.HandlerFunc) *central.Client {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return &central.Client{BaseURL: srv.URL, ClientID: "client_a", Token: "host-tok", UserAgent: "vuln-agent/test", HTTP: srv.Client()}
}

func TestSendReportGzip(t *testing.T) {
	var got map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/report" ||
			r.Header.Get("Authorization") != "Bearer host-tok" || r.Header.Get("Content-Encoding") != "gzip" {
			t.Errorf("bad request: %s %s %v", r.Method, r.URL.Path, r.Header)
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		json.NewDecoder(zr).Decode(&got)
	})
	r := entity.Report{
		Host:      entity.HostInfo{Hostname: "vm1", AutoUpdateEnabled: true},
		Status:    entity.StatusOK,
		ScannedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Duration:  90 * time.Second,
		Findings:  []entity.Finding{{VulnerabilityID: "CVE-1", PkgName: "openssl"}},
	}
	if err := c.SendReport(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	f := got["findings"].([]any)[0].(map[string]any)
	if got["client_id"] != "client_a" || got["hostname"] != "vm1" || got["unattended_upgrades_enabled"] != true ||
		got["scan_duration_seconds"] != 90.0 || got["status"] != "ok" || f["vulnerability_id"] != "CVE-1" {
		t.Fatalf("payload = %v", got)
	}
}

func TestEmptyFindingsIsArray(t *testing.T) {
	var raw map[string]json.RawMessage
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		zr, _ := gzip.NewReader(r.Body)
		json.NewDecoder(zr).Decode(&raw)
	})
	c.SendReport(context.Background(), entity.Report{Status: entity.StatusError, Error: "boom"})
	if string(raw["findings"]) != "[]" || string(raw["error"]) != `"boom"` {
		t.Fatalf("findings=%s error=%s", raw["findings"], raw["error"])
	}
}

func TestStatusMapping(t *testing.T) {
	for code, rejected := range map[int]bool{400: true, 413: true, 422: true, 401: false, 429: false, 500: false} {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) })
		err := c.SendReport(context.Background(), entity.Report{})
		if err == nil || errors.Is(err, usecase.ErrRejected) != rejected {
			t.Errorf("%d: err = %v", code, err)
		}
	}
}

func TestFetchScanConfig(t *testing.T) {
	tests := []struct {
		body    string
		wantErr bool
	}{
		{`{}`, false},
		{`{"severity":["CRITICAL"],"timeout":"45m","ignore_unfixed":false,"skip_dirs":["/data"]}`, false},
		{`{"severity":["HIGH"],"command":"rm -rf /"}`, true}, // unknown field
		{`{"skip_dirs":["--config=/etc/x"]}`, true},
		{`{"timeout":"forever"}`, true},
	}
	for _, tt := range tests {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer host-tok" {
				w.WriteHeader(401)
				return
			}
			io.WriteString(w, tt.body)
		})
		cfg, err := c.FetchScanConfig(context.Background())
		if (err != nil) != tt.wantErr {
			t.Fatalf("%s: err = %v", tt.body, err)
		}
		if tt.body == `{}` && cfg.Timeout != 30*time.Minute {
			t.Fatalf("defaults not applied: %+v", cfg)
		}
	}
}

func TestEnrollNoAuthHeader(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		if r.Header.Get("Authorization") != "" || req["enroll_token"] != "enr" || req["client_id"] != "client_a" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"host_token":"new-tok"}`)
	})
	tok, err := c.Enroll(context.Background(), "enr", entity.HostInfo{Hostname: "vm1"})
	if err != nil || tok != "new-tok" {
		t.Fatalf("tok=%q err=%v", tok, err)
	}
}
