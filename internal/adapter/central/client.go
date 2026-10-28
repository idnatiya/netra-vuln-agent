// Package central is the HTTPS client for the central API.
package central

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/idnatiya/netra-vuln-agent/internal/domain"
	"github.com/idnatiya/netra-vuln-agent/internal/usecase"
	"github.com/idnatiya/netra-vuln-agent/wire"
)

const (
	maxResponseBytes = 64 << 10
	httpTimeout      = 2 * time.Minute
)

type Client struct {
	BaseURL   string
	ClientID  string
	Token     string // host token; never log it
	UserAgent string
	HTTP      *http.Client
}

// NewHTTPClient builds an http.Client with timeouts, TLS >= 1.2 and an optional custom CA.
func NewHTTPClient(caFile string) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read ca_file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %s: no PEM certificates", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	return &http.Client{Transport: tr, Timeout: httpTimeout}, nil
}

func (c *Client) FetchScanConfig(ctx context.Context) (domain.ScanConfig, error) {
	var d wire.ScanConfig
	if err := c.do(ctx, http.MethodGet, "/api/v1/config", nil, false, true, &d); err != nil {
		return domain.ScanConfig{}, err
	}
	cfg, err := d.Resolve()
	if err != nil {
		return cfg, fmt.Errorf("invalid scan config from central: %w", err)
	}
	return cfg, nil
}

func (c *Client) SendReport(ctx context.Context, r domain.Report) error {
	return c.do(ctx, http.MethodPost, "/api/v1/report", toWireReport(c.ClientID, r), true, true, nil)
}

func (c *Client) SendHeartbeat(ctx context.Context, h domain.HostInfo) error {
	return c.do(ctx, http.MethodPost, "/api/v1/heartbeat", wire.Heartbeat{ClientID: c.ClientID, Host: toWireHost(h)}, false, true, nil)
}

func (c *Client) Enroll(ctx context.Context, enrollToken string, h domain.HostInfo) (string, error) {
	req := wire.EnrollRequest{ClientID: c.ClientID, EnrollToken: enrollToken, Host: toWireHost(h)}
	var resp wire.EnrollResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/enroll", req, false, false, &resp); err != nil {
		return "", err
	}
	return resp.HostToken, nil
}

func (c *Client) do(ctx context.Context, method, path string, in any, gz, auth bool, out any) error {
	var body io.Reader
	if in != nil {
		var buf bytes.Buffer
		w := io.Writer(&buf)
		var zw *gzip.Writer
		if gz {
			zw = gzip.NewWriter(&buf)
			w = zw
		}
		if err := json.NewEncoder(w).Encode(in); err != nil {
			return err
		}
		if zw != nil {
			if err := zw.Close(); err != nil {
				return err
			}
		}
		body = &buf
	}

	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.BaseURL, "/")+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if gz {
		req.Header.Set("Content-Encoding", "gzip")
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	lr := io.LimitReader(resp.Body, maxResponseBytes)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(lr, 512))
		err := fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(msg)))
		switch resp.StatusCode {
		case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
			return fmt.Errorf("%w: %w", usecase.ErrRejected, err)
		}
		return err
	}
	if out == nil {
		return nil
	}
	dec := json.NewDecoder(lr)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%s %s: decode response: %w", method, path, err)
	}
	return nil
}
