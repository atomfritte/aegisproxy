package threatintel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"syscall"
	"time"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/netguard"
)

// Structured threat-intelligence sources. Collectors normalize indicators into the internal
// "typed" list format ("<type>\t<value>" per line), which is cached and parsed like any feed.
const (
	FeedFormatTAXII = "taxii21"
	FeedFormatMISP  = "misp"
	FeedFormatMDE   = "mde"
	formatTyped     = "typed"

	maxSourceIndicators = 500_000
	defaultLookbackDays = 90
)

// Collector fetches a structured source and returns typed lines.
type Collector func(ctx context.Context, f models.ThreatFeed) ([]byte, error)

// IsStructured reports whether a format is fetched by a collector instead of a plain download.
func IsStructured(format string) bool {
	switch format {
	case FeedFormatTAXII, FeedFormatMISP, FeedFormatMDE:
		return true
	}
	return false
}

func cacheFormat(format string) string {
	if IsStructured(format) {
		return formatTyped
	}
	return format
}

type typedWriter struct {
	buf bytes.Buffer
	n   int
}

func (w *typedWriter) add(kind, value string) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\t\r\n") || w.n >= maxSourceIndicators {
		return
	}
	w.buf.WriteString(kind)
	w.buf.WriteByte('\t')
	w.buf.WriteString(value)
	w.buf.WriteByte('\n')
	w.n++
}

// addHostOrIP classifies a value as IP, CIDR or domain.
func (w *typedWriter) addHostOrIP(v string) {
	v = strings.TrimSpace(v)
	if _, err := netip.ParseAddr(v); err == nil {
		w.add("ip", v)
		return
	}
	if _, err := netip.ParsePrefix(v); err == nil {
		w.add("cidr", v)
		return
	}
	w.add("domain", v)
}

// parseTyped reads collector output.
func parseTyped(r io.Reader, out *Entries) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		kind, value, ok := strings.Cut(sc.Text(), "\t")
		if !ok {
			continue
		}
		switch kind {
		case "domain":
			if d, ok := NormalizeDomain(value); ok {
				out.Domains = append(out.Domains, d)
			}
		case "url":
			if u, ok := NormalizeURL(value); ok {
				out.URLs = append(out.URLs, u)
			}
		case "ip", "cidr":
			addIPOrPrefix(value, out)
		case "sha256":
			if h, ok := NormalizeHash(value); ok {
				out.Hashes = append(out.Hashes, h)
			}
		}
	}
	return sc.Err()
}

// ValidateSourceURL validates TAXII/MISP endpoints: https, internal servers allowed (on-prem MISP,
// OpenCTI), but never loopback, link-local (cloud metadata) or unspecified addresses.
func ValidateSourceURL(raw string, allowLoopback bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return errors.New("source URL must be an absolute URL")
	}
	if u.User != nil {
		return errors.New("source URL must not embed credentials; use the auth header setting")
	}
	host := strings.ToLower(u.Hostname())
	loop := host == "localhost"
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		loop = a.IsLoopback()
		if a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() || netguard.CloudMetadata(a) {
			return errors.New("source URL must not point to link-local, cloud metadata or unspecified addresses")
		}
	}
	if loop && !allowLoopback {
		return errors.New("source URL must not point to the control-plane host itself")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && loop && allowLoopback) {
		return errors.New("source URL must use https://")
	}
	return nil
}

// sourceClient allows private networks (internal TIPs) but refuses loopback and link-local at dial
// time (DNS rebinding), and trusts an optional private CA.
func sourceClient(caPEM, proxy string, allowLoopback bool) (*http.Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if strings.TrimSpace(caPEM) != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, errors.New("ca_cert_pem contains no valid certificate")
		}
		tc.RootCAs = pool
	}
	blocked := func(a netip.Addr) bool {
		a = a.Unmap()
		return (a.IsLoopback() && !allowLoopback) || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() || netguard.CloudMetadata(a)
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		if a, err := netip.ParseAddr(host); err == nil && blocked(a) {
			return fmt.Errorf("threat-intel source resolved to disallowed address %s", a.Unmap())
		}
		return nil
	}}
	// Through a proxy the source host is checked before it is handed over (the proxy resolves it).
	guard := &netguard.ProxyGuard{Proxy: http.ProxyFromEnvironment, Blocked: blocked, What: "threat-intel source", Dialer: dialer}
	if proxy != "" {
		if pu, err := url.Parse(proxy); err == nil {
			guard.Proxy = http.ProxyURL(pu)
		}
	}
	tr := &http.Transport{DialContext: guard.DialContext, TLSClientConfig: tc, TLSHandshakeTimeout: 15 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second, Proxy: guard.ProxyFunc}
	return &http.Client{Transport: tr, Timeout: 5 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func doJSON(ctx context.Context, client *http.Client, req *http.Request, v any) (http.Header, error) {
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, req.URL.Host)
	}
	if len(body) > maxFeedBytes {
		return nil, fmt.Errorf("response exceeds %d MiB", maxFeedBytes>>20)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return nil, fmt.Errorf("invalid JSON from %s: %v", req.URL.Host, err)
	}
	return resp.Header, nil
}

// ---------------------------------------------------------------------------
// STIX 2.1 / TAXII 2.1
// ---------------------------------------------------------------------------

var stixComparison = regexp.MustCompile(`(?i)\b(domain-name|url|ipv4-addr|ipv6-addr|file)\s*:\s*(value|hashes\s*\.\s*(?:'SHA-256'|"SHA-256"|SHA256|'SHA256'|SHA_256))\s*=\s*'((?:[^'\\]|\\.)*)'`)

// stixIndicators extracts equality comparisons from STIX patterns of active indicators.
func stixIndicators(objects []json.RawMessage, now time.Time, w *typedWriter) {
	for _, raw := range objects {
		var o struct {
			Type        string `json:"type"`
			PatternType string `json:"pattern_type"`
			Pattern     string `json:"pattern"`
			Revoked     bool   `json:"revoked"`
			ValidUntil  string `json:"valid_until"`
		}
		if json.Unmarshal(raw, &o) != nil || o.Type != "indicator" || o.Revoked {
			continue
		}
		if o.PatternType != "" && o.PatternType != "stix" {
			continue
		}
		if o.ValidUntil != "" {
			if t, err := time.Parse(time.RFC3339Nano, o.ValidUntil); err == nil && t.Before(now) {
				continue
			}
		}
		for _, m := range stixComparison.FindAllStringSubmatch(o.Pattern, -1) {
			value := strings.ReplaceAll(strings.ReplaceAll(m[3], `\'`, `'`), `\\`, `\`)
			switch strings.ToLower(m[1]) {
			case "domain-name":
				w.add("domain", value)
			case "url":
				w.add("url", value)
			case "ipv4-addr", "ipv6-addr":
				w.addHostOrIP(value)
			case "file":
				w.add("sha256", value)
			}
		}
	}
}

// CollectTAXII reads indicators from a TAXII 2.1 collection ("…/collections/<id>/" or its
// objects endpoint), following pagination.
func CollectTAXII(ctx context.Context, f models.ThreatFeed, client *http.Client) ([]byte, error) {
	base := strings.TrimRight(f.URL, "/")
	if !strings.HasSuffix(base, "/objects") {
		base += "/objects"
	}
	lookback := f.LookbackDays
	if lookback <= 0 {
		lookback = defaultLookbackDays
	}
	now := time.Now().UTC()
	w := &typedWriter{}
	params := url.Values{"match[type]": {"indicator"}, "added_after": {now.AddDate(0, 0, -lookback).Format(time.RFC3339)}, "limit": {"1000"}}
	for page := 0; page < 1000; page++ {
		req, _ := http.NewRequest(http.MethodGet, base+"/?"+params.Encode(), nil)
		req.Header.Set("Accept", "application/taxii+json;version=2.1")
		req.Header.Set("User-Agent", "AegisProxy-ThreatIntel/2.1 (TAXII)")
		if f.AuthHeaderName != "" && f.AuthHeaderValue != "" {
			req.Header.Set(f.AuthHeaderName, string(f.AuthHeaderValue))
		}
		var env struct {
			More    bool              `json:"more"`
			Next    string            `json:"next"`
			Objects []json.RawMessage `json:"objects"`
		}
		hdr, err := doJSON(ctx, client, req, &env)
		if err != nil {
			return nil, fmt.Errorf("TAXII: %w", err)
		}
		stixIndicators(env.Objects, now, w)
		if !env.More || len(env.Objects) == 0 {
			break
		}
		if env.Next != "" {
			params.Set("next", env.Next)
		} else if last := hdr.Get("X-TAXII-Date-Added-Last"); last != "" {
			params.Set("added_after", last)
		} else {
			break
		}
	}
	return w.buf.Bytes(), nil
}

// ---------------------------------------------------------------------------
// MISP REST API
// ---------------------------------------------------------------------------

var mispTypes = []string{"domain", "hostname", "url", "uri", "ip-dst", "ip-src", "ip-dst|port", "domain|ip", "sha256", "filename|sha256"}

// CollectMISP reads exportable (to_ids) attributes via /attributes/restSearch, honouring MISP
// warninglists (known-good values are excluded server-side).
func CollectMISP(ctx context.Context, f models.ThreatFeed, client *http.Client) ([]byte, error) {
	lookback := f.LookbackDays
	if lookback <= 0 {
		lookback = defaultLookbackDays
	}
	w := &typedWriter{}
	const limit = 10000
	for page := 1; page <= 50; page++ {
		body, _ := json.Marshal(map[string]any{"returnFormat": "json", "type": mispTypes, "to_ids": true, "deleted": false,
			"enforceWarninglist": true, "last": fmt.Sprintf("%dd", lookback), "limit": limit, "page": page})
		req, _ := http.NewRequest(http.MethodPost, strings.TrimRight(f.URL, "/")+"/attributes/restSearch", bytes.NewReader(body))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "AegisProxy-ThreatIntel/2.1 (MISP)")
		name := f.AuthHeaderName
		if name == "" {
			name = "Authorization"
		}
		if f.AuthHeaderValue != "" {
			req.Header.Set(name, string(f.AuthHeaderValue))
		}
		var res struct {
			Response struct {
				Attribute []struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"Attribute"`
			} `json:"response"`
		}
		if _, err := doJSON(ctx, client, req, &res); err != nil {
			return nil, fmt.Errorf("MISP: %w", err)
		}
		for _, a := range res.Response.Attribute {
			switch a.Type {
			case "domain", "hostname":
				w.add("domain", a.Value)
			case "url", "uri":
				w.add("url", a.Value)
			case "ip-dst", "ip-src":
				w.addHostOrIP(a.Value)
			case "ip-dst|port":
				ip, _, _ := strings.Cut(a.Value, "|")
				w.addHostOrIP(ip)
			case "domain|ip":
				d, ip, _ := strings.Cut(a.Value, "|")
				w.add("domain", d)
				w.addHostOrIP(ip)
			case "sha256":
				w.add("sha256", a.Value)
			case "filename|sha256":
				_, h, _ := strings.Cut(a.Value, "|")
				w.add("sha256", h)
			}
		}
		if len(res.Response.Attribute) < limit {
			break
		}
	}
	return w.buf.Bytes(), nil
}
