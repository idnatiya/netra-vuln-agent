// Command fakecentral is a development stand-in for the central API. It accepts
// agent traffic, logs a summary, and saves raw reports to disk. Not for production:
// state is in memory and any enroll token is accepted.
package main

import (
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const maxBody = 20 << 20

type server struct {
	out         string
	config      []byte
	failReports bool

	mu     sync.Mutex
	tokens map[string]string // host token -> hostname, persisted to <out>/tokens.json
}

func main() {
	addr := flag.String("addr", "100.77.238.106:8080", "listen address (keep it on the tailnet)")
	out := flag.String("out", "dev-out", "directory for raw reports")
	configFile := flag.String("config", "", "JSON file served by GET /api/v1/config (default {})")
	failReports := flag.Bool("fail-reports", false, "answer reports with 500 (to test the agent spool)")
	flag.Parse()

	s := &server{out: *out, config: []byte("{}"), failReports: *failReports, tokens: map[string]string{}}
	if *configFile != "" {
		b, err := os.ReadFile(*configFile)
		if err != nil {
			slog.Error("read config", "err", err)
			os.Exit(1)
		}
		s.config = b
	}
	if err := os.MkdirAll(s.out, 0o700); err != nil {
		slog.Error("create out dir", "err", err)
		os.Exit(1)
	}
	// Tokens survive restarts so flags like -fail-reports can be toggled without re-enrolling.
	if b, err := os.ReadFile(s.tokensFile()); err == nil {
		if err := json.Unmarshal(b, &s.tokens); err != nil {
			slog.Error("read tokens", "err", err)
			os.Exit(1)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("POST /api/v1/enroll", s.enroll)
	mux.HandleFunc("GET /api/v1/config", s.auth(s.scanConfig))
	mux.HandleFunc("POST /api/v1/heartbeat", s.auth(s.heartbeat))
	mux.HandleFunc("POST /api/v1/report", s.auth(s.report))

	slog.Info("fakecentral listening", "addr", *addr, "out", s.out, "fail_reports", s.failReports)
	srv := &http.Server{Addr: *addr, Handler: mux, ReadTimeout: time.Minute, WriteTimeout: time.Minute}
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("listen", "err", err)
		os.Exit(1)
	}
}

func (s *server) enroll(w http.ResponseWriter, r *http.Request) {
	var req map[string]any
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	host, _ := req["hostname"].(string)
	if req["enroll_token"] == "" || host == "" {
		http.Error(w, "enroll_token and hostname required", http.StatusBadRequest)
		return
	}
	b := make([]byte, 16)
	rand.Read(b)
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	s.tokens[tok] = host
	b, _ = json.Marshal(s.tokens)
	err := os.WriteFile(s.tokensFile(), b, 0o600)
	s.mu.Unlock()
	if err != nil {
		slog.Error("save tokens", "err", err)
	}
	delete(req, "enroll_token")
	slog.Info("enroll", "remote", r.RemoteAddr, "payload", req)
	json.NewEncoder(w).Encode(map[string]string{"host_token": tok})
}

func (s *server) tokensFile() string { return filepath.Join(s.out, "tokens.json") }

// auth only accepts tokens fakecentral issued (see tokens.json).
func (s *server) auth(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		s.mu.Lock()
		host, known := s.tokens[tok]
		s.mu.Unlock()
		if !ok || !known {
			slog.Warn("unauthorized", "path", r.URL.Path, "remote", r.RemoteAddr)
			http.Error(w, "unknown host token (re-enroll with `vuln-agent enroll -force`)", http.StatusUnauthorized)
			return
		}
		next(w, r, host)
	}
}

func (s *server) scanConfig(w http.ResponseWriter, r *http.Request, host string) {
	slog.Info("config", "host", host)
	w.Header().Set("Content-Type", "application/json")
	w.Write(s.config)
}

func (s *server) heartbeat(w http.ResponseWriter, r *http.Request, host string) {
	var hb map[string]any
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&hb); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	slog.Info("heartbeat", "host", host, "payload", hb)
}

func (s *server) report(w http.ResponseWriter, r *http.Request, host string) {
	if s.failReports {
		slog.Warn("report rejected with 500 (-fail-reports)", "host", host)
		http.Error(w, "simulated outage", http.StatusInternalServerError)
		return
	}
	body := io.Reader(http.MaxBytesReader(w, r.Body, maxBody))
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body = io.LimitReader(zr, maxBody)
	}
	raw, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var rep map[string]any
	if err := json.Unmarshal(raw, &rep); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	findings, _ := rep["findings"].([]any)
	bySeverity := map[string]int{}
	for _, f := range findings {
		if m, ok := f.(map[string]any); ok {
			sev, _ := m["severity"].(string)
			bySeverity[sev]++
		}
	}
	name := filepath.Join(s.out, fmt.Sprintf("report-%s-%s.json", host, time.Now().Format("20060102-150405")))
	if err := os.WriteFile(name, raw, 0o600); err != nil {
		slog.Error("save report", "err", err)
	}
	delete(rep, "findings")
	slog.Info("report", "host", host, "findings", len(findings), "by_severity", bySeverity, "saved", name, "meta", rep)
}
