package http

import (
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Handler serves the history read-only:
//
//	GET /                    newest report
//	GET /reports/{id}        one report (id from the history list)
//	GET /reports/{id}.json   its raw JSON
//	GET /healthz
func Handler(reports Reports, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		servePage(w, reports, "", log)
	})
	mux.HandleFunc("GET /reports/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if base, ok := strings.CutSuffix(id, ".json"); ok && strings.HasSuffix(base, ".json.gz") {
			serveJSON(w, reports, base, log)
			return
		}
		servePage(w, reports, id, log)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	return headers(mux)
}

func headers(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(w, r)
	})
}

func servePage(w http.ResponseWriter, reports Reports, id string, log *slog.Logger) {
	p, err := build(reports, id)
	if err != nil {
		httpError(w, err, log)
		return
	}
	p.Linked = true
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, p); err != nil {
		log.Warn("render report", "err", err)
	}
}

func serveJSON(w http.ResponseWriter, reports Reports, id string, log *slog.Logger) {
	ids, err := reports.List()
	if err != nil {
		httpError(w, err, log)
		return
	}
	// Only ids from the listing are loaded, so the path can never escape the history dir.
	if !slices.Contains(ids, id) {
		httpError(w, errNotFound, log)
		return
	}
	r, err := reports.Load(id)
	if err != nil {
		httpError(w, err, log)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(r)
}

func httpError(w http.ResponseWriter, err error, log *slog.Logger) {
	switch {
	case errors.Is(err, errNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	case errors.Is(err, ErrNoReports):
		http.Error(w, ErrNoReports.Error(), http.StatusNotFound)
	default:
		log.Warn("serve report", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// NewServer returns a read-only server with timeouts. There is no auth, so a
// non-loopback address exposes the host's vulnerabilities to that network.
func NewServer(addr string, reports Reports, log *slog.Logger) *http.Server {
	if host, _, err := net.SplitHostPort(addr); err != nil || !isLoopback(host) {
		log.Warn("serve: listening on a non-loopback address without auth; anyone who can reach it can read the reports", "addr", addr)
	}
	return &http.Server{
		Addr:              addr,
		Handler:           Handler(reports, log),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
