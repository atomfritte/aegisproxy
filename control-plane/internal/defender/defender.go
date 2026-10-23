// Package defender is a minimal client for the Microsoft Defender for Endpoint API: custom
// indicators (Ti.ReadWrite.All - the List Indicators API has no read-only permission), devices
// (Machine.Read.All) and machine actions for the isolation state (Machine.ReadWrite.All).
package defender

import (
	"aegisproxy/control-plane/internal/netguard"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultAPIBase   = "https://api.security.microsoft.com"
	DefaultAuthority = "https://login.microsoftonline.com"
	maxPages         = 200
)

// pageSize is the documented maximum of $top for indicators, machines and machine actions.
var pageSize = 10000

// legacyResource is the token audience the Defender for Endpoint API expects, also behind
// api.security.microsoft.com and the regional hosts (Microsoft: a token for another audience gets 403).
const legacyResource = "https://api.securitycenter.microsoft.com"

// tokenScope returns the scope for an API base URL: US Government clouds have their own resources,
// every commercial host (api., eu.api., us.api.security.microsoft.com, api.securitycenter...) uses the
// legacy resource. Other hosts (tests, private endpoints) request a token for themselves.
func tokenScope(apiBase string) string {
	u, err := url.Parse(apiBase)
	if err != nil {
		return apiBase + "/.default"
	}
	h := strings.ToLower(u.Hostname())
	switch {
	case h == "api-gcc.securitycenter.microsoft.us" || h == "api-gov.securitycenter.microsoft.us":
		return "https://" + h + "/.default"
	case strings.HasSuffix(h, ".security.microsoft.com") || strings.HasSuffix(h, ".securitycenter.microsoft.com") ||
		h == "security.microsoft.com" || h == "securitycenter.microsoft.com":
		return legacyResource + "/.default"
	}
	return strings.TrimRight(apiBase, "/") + "/.default"
}

type Config struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	APIBase      string
	Authority    string
}

type Client struct {
	cfg  Config
	http *http.Client

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

func New(cfg Config, hc *http.Client) *Client {
	if cfg.APIBase == "" {
		cfg.APIBase = DefaultAPIBase
	}
	if cfg.Authority == "" {
		cfg.Authority = DefaultAuthority
		if strings.Contains(strings.ToLower(cfg.APIBase), "api-gov.securitycenter.microsoft.us") {
			cfg.Authority = "https://login.microsoftonline.us" // GCC High and DoD
		}
	}
	cfg.APIBase, cfg.Authority = strings.TrimRight(cfg.APIBase, "/"), strings.TrimRight(cfg.Authority, "/")
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment,
			DialContext: netguard.Dialer(10 * time.Second).DialContext, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 60 * time.Second}}
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{cfg: cfg, http: hc}
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.tokenExp) {
		return c.token, nil
	}
	form := url.Values{"client_id": {c.cfg.ClientID}, "client_secret": {c.cfg.ClientSecret},
		"scope": {tokenScope(c.cfg.APIBase)}, "grant_type": {"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Authority+"/"+url.PathEscape(c.cfg.TenantID)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("Entra ID token request: %w", err)
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok)
	if resp.StatusCode != http.StatusOK || tok.AccessToken == "" {
		d := tok.Description
		if len(d) > 200 {
			d = d[:200]
		}
		return "", fmt.Errorf("Entra ID token request failed (HTTP %d %s): %s", resp.StatusCode, tok.Error, d)
	}
	c.token, c.tokenExp = tok.AccessToken, time.Now().Add(time.Duration(max(tok.ExpiresIn-120, 60))*time.Second)
	return c.token, nil
}

// sameOrigin prevents following OData nextLinks to foreign hosts (the bearer token would leak).
func (c *Client) sameOrigin(link string) bool {
	a, err1 := url.Parse(link)
	b, err2 := url.Parse(c.cfg.APIBase)
	return err1 == nil && err2 == nil && a.Scheme == b.Scheme && strings.EqualFold(a.Host, b.Host)
}

// list reads every page of a collection: it follows @odata.nextLink when the API returns one and
// otherwise pages with $top/$skip (the documented options; a full page means more may follow).
// notFoundEmpty treats 404 as an empty collection (List machines answers 404 without recent devices).
func list[T any](ctx context.Context, c *Client, path string, notFoundEmpty bool) ([]T, error) {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	base := c.cfg.APIBase + path + sep + "$top=" + strconv.Itoa(pageSize)
	next := base
	var out []T
	for page := 0; next != "" && page < maxPages; page++ {
		if !c.sameOrigin(next) {
			return nil, errors.New("refusing to follow a pagination link to another host")
		}
		tok, err := c.accessToken(ctx)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		resp, err := c.do(ctx, req)
		if err != nil {
			return nil, err
		}
		var res struct {
			Value    []T    `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusUnauthorized:
			c.mu.Lock()
			c.token = ""
			c.mu.Unlock()
			return nil, errors.New("Defender API: unauthorized (check the application permissions and admin consent)")
		case resp.StatusCode == http.StatusForbidden:
			return nil, fmt.Errorf("Defender API: forbidden for %s (missing application permission)", path)
		case resp.StatusCode == http.StatusNotFound && notFoundEmpty:
			return out, nil
		case resp.StatusCode != http.StatusOK:
			return nil, fmt.Errorf("Defender API: HTTP %d for %s", resp.StatusCode, path)
		}
		if err := json.Unmarshal(body, &res); err != nil {
			return nil, fmt.Errorf("Defender API: invalid response: %v", err)
		}
		out = append(out, res.Value...)
		switch {
		case res.NextLink != "":
			next = res.NextLink
		case len(res.Value) == pageSize:
			next = base + "&$skip=" + strconv.Itoa(len(out))
		default:
			next = ""
		}
	}
	return out, nil
}

// do sends a request and waits out throttling (HTTP 429, 100 calls per minute and 1,500 per hour per
// API) for up to three attempts, honouring Retry-After (at most one minute per wait).
func (c *Client) do(ctx context.Context, req *http.Request) (*http.Response, error) {
	for attempt := 1; ; attempt++ {
		resp, err := c.http.Do(req)
		if err != nil || resp.StatusCode != http.StatusTooManyRequests || attempt == 3 {
			return resp, err
		}
		wait := 10 * time.Second
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s >= 0 {
			wait = time.Duration(min(s, 60)) * time.Second
		}
		resp.Body.Close()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
}

// Indicator is a custom indicator of compromise.
type Indicator struct {
	IndicatorValue string     `json:"indicatorValue"`
	IndicatorType  string     `json:"indicatorType"` // FileSha256, FileSha1, FileMd5, IpAddress, DomainName, Url, CertificateThumbprint
	Action         string     `json:"action"`        // Block, AlertAndBlock, BlockAndRemediate, Alert, Audit, Warn, Allowed
	ExpirationTime *time.Time `json:"expirationTime"`
	Title          string     `json:"title"`
}

func (c *Client) Indicators(ctx context.Context) ([]Indicator, error) {
	return list[Indicator](ctx, c, "/api/indicators", false)
}

// Machine is a device known to Defender.
type Machine struct {
	ID               string     `json:"id"`
	ComputerDNSName  string     `json:"computerDnsName"`
	LastIPAddress    string     `json:"lastIpAddress"`
	RiskScore        string     `json:"riskScore"`     // None, Informational, Low, Medium, High
	ExposureLevel    string     `json:"exposureLevel"` // None, Low, Medium, High
	HealthStatus     string     `json:"healthStatus"`
	OnboardingStatus string     `json:"onboardingStatus"`
	LastSeen         *time.Time `json:"lastSeen"`
	OSPlatform       string     `json:"osPlatform"`
}

func (c *Client) Machines(ctx context.Context) ([]Machine, error) {
	return list[Machine](ctx, c, "/api/machines", true)
}

type machineAction struct {
	MachineID       string    `json:"machineId"`
	Type            string    `json:"type"`
	Status          string    `json:"status"`
	CreationTimeUtc time.Time `json:"creationDateTimeUtc"`
}

// IsolatedMachines returns the ids of machines whose latest isolation action is a successful Isolate.
func (c *Client) IsolatedMachines(ctx context.Context) (map[string]bool, error) {
	actions, err := list[machineAction](ctx, c, "/api/machineactions?$filter=type+eq+'Isolate'+or+type+eq+'Unisolate'", false)
	if err != nil {
		return nil, err
	}
	latest := map[string]machineAction{}
	for _, a := range actions {
		if a.Status != "Succeeded" {
			continue
		}
		if cur, ok := latest[a.MachineID]; !ok || a.CreationTimeUtc.After(cur.CreationTimeUtc) {
			latest[a.MachineID] = a
		}
	}
	out := map[string]bool{}
	for id, a := range latest {
		if a.Type == "Isolate" {
			out[id] = true
		}
	}
	return out, nil
}

// BlockingAction reports whether an indicator action means "block".
func BlockingAction(action string, allowed []string) bool {
	if len(allowed) == 0 {
		allowed = []string{"Block", "AlertAndBlock", "BlockAndRemediate"}
	}
	for _, a := range allowed {
		if strings.EqualFold(a, action) {
			return true
		}
	}
	return false
}
