package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/netguard"
)

// Errors returned by adapters.
var (
	ErrPackageNotFound = errors.New("package not found")
	ErrVersionNotFound = errors.New("version not found")
	ErrTooLarge        = errors.New("registry response exceeds the size limit")
	ErrNotJSON         = errors.New("registry returned an unexpected content type")
)

// DefaultMaxBytes bounds a single metadata response (packuments of large packages reach tens of MiB).
const DefaultMaxBytes = 64 << 20

// Client fetches registry metadata. It never downloads artifacts; the data-plane serves those and the
// sandbox worker fetches them for analysis. Requests are SSRF-guarded (no internal addresses) and
// size-limited. An optional upstream HTTP proxy routes the traffic through the organization's egress.
type Client struct {
	http      *http.Client
	userAgent string
	maxBytes  int64
}

// NewClient builds a registry client. proxy is an optional http(s) proxy URL; when empty, environment
// proxy settings apply.
func NewClient(proxy string) *Client {
	guard := &netguard.ProxyGuard{
		Proxy:   http.ProxyFromEnvironment,
		Blocked: netguard.IsInternal,
		What:    "registry host",
		Dialer:  &net.Dialer{Timeout: 10 * time.Second},
	}
	if proxy != "" {
		if pu, err := url.Parse(proxy); err == nil {
			guard.Proxy = http.ProxyURL(pu)
		}
	}
	tr := &http.Transport{
		Proxy:                 guard.ProxyFunc,
		DialContext:           guard.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &Client{
		http:      &http.Client{Timeout: 3 * time.Minute, Transport: tr, CheckRedirect: registryRedirect},
		userAgent: "AegisProxy-Packages/3.0 (+package-firewall)",
		maxBytes:  DefaultMaxBytes,
	}
}

// HTTPClient exposes the SSRF-guarded, size-limited HTTP client so advisory sources and the sandbox
// worker share the same egress path and proxy configuration.
func (c *Client) HTTPClient() *http.Client { return c.http }

// WithMaxBytes overrides the per-response size limit (0 = default).
func (c *Client) WithMaxBytes(n int64) *Client {
	if n > 0 {
		c.maxBytes = n
	}
	return c
}

// registryRedirect follows up to five https redirects without carrying custom headers to another host.
func registryRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if req.URL.Scheme != "https" && !isLoopbackHost(req.URL.Hostname()) {
		return errors.New("refusing non-https redirect")
	}
	if !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
		for k := range req.Header {
			switch k {
			case "User-Agent", "Accept", "Accept-Encoding", "If-None-Match", "If-Modified-Since":
			default:
				req.Header.Del(k)
			}
		}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

// getJSON fetches url and decodes the JSON body into v. accept sets the Accept header.
func (c *Client) getJSON(ctx context.Context, url, accept string, v any) error {
	body, ctype, err := c.get(ctx, url, accept)
	if err != nil {
		return err
	}
	if ctype != "" && !strings.Contains(ctype, "json") && !strings.Contains(ctype, "javascript") {
		// Some registries mislabel JSON; only reject an obvious HTML error page.
		head := strings.ToLower(strings.TrimSpace(string(body[:min(len(body), 200)])))
		if strings.HasPrefix(head, "<!doctype html") || strings.HasPrefix(head, "<html") {
			return fmt.Errorf("%w: %s", ErrNotJSON, ctype)
		}
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("decode %s: %w", url, err)
	}
	return nil
}

// GetBytes fetches url and returns the raw body, size-limited and SSRF-guarded (the sandbox worker
// uses it to download an artifact for analysis). Decompression is NOT applied: the bytes are the
// exact artifact the registry serves, so their digests match the metadata.
func (c *Client) GetBytes(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > c.maxBytes {
		return nil, fmt.Errorf("%w (%d MiB)", ErrTooLarge, c.maxBytes>>20)
	}
	return body, nil
}

// get fetches url and returns the body (size-limited), the content type, and a typed error for the
// not-found and too-large cases.
func (c *Client) get(ctx context.Context, url, accept string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", c.userAgent)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusGone:
		return nil, "", ErrPackageNotFound
	default:
		return nil, "", fmt.Errorf("registry returned HTTP %d for %s", resp.StatusCode, url)
	}
	reader, err := decompress(resp)
	if err != nil {
		return nil, "", err
	}
	body, err := io.ReadAll(io.LimitReader(reader, c.maxBytes+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(body)) > c.maxBytes {
		return nil, "", fmt.Errorf("%w (%d MiB)", ErrTooLarge, c.maxBytes>>20)
	}
	return body, resp.Header.Get("Content-Type"), nil
}
