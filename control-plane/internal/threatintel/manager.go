package threatintel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/netguard"
)

const (
	maxFeedBytes       = 96 << 20 // 96 MiB
	defaultRefreshMins = 360
	minRefreshMins     = 15
)

// FeedStatus is the runtime state of a feed download, persisted alongside the cached content.
type FeedStatus struct {
	LastAttemptAt *time.Time `json:"last_attempt_at,omitempty"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	EntryCount    int        `json:"entry_count"`
	ETag          string     `json:"etag,omitempty"`
	LastModified  string     `json:"last_modified,omitempty"`
	ContentSHA256 string     `json:"content_sha256,omitempty"`
}

type Options struct {
	CacheDir   string
	AutoUpdate bool
	HTTPProxy  string // optional explicit proxy for feed downloads
	Logger     *slog.Logger
	// OnChange is invoked (asynchronously) after a new snapshot was compiled.
	OnChange func(*Snapshot)
	// AllowLoopbackSources permits TAXII/MISP sources on the local host (tests and lab setups only).
	AllowLoopbackSources bool
}

// Manager keeps feed configuration, downloads feeds on their refresh interval, and publishes
// compiled snapshots via an atomic pointer (lock-free reads on the hot path).
type Manager struct {
	opts   Options
	log    *slog.Logger
	client *http.Client

	mu         sync.Mutex
	feeds      []models.ThreatFeed
	indicators []models.Indicator
	exceptions []models.ThreatException
	parsed     map[string]*Entries
	status     map[string]*FeedStatus
	fetching   map[string]bool

	snap      atomic.Pointer[Snapshot]
	refreshCh chan string

	collectors map[string]Collector
}

// SetCollector registers the fetcher of a structured source format (e.g. Microsoft Defender).
func (m *Manager) SetCollector(format string, c Collector) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.collectors == nil {
		m.collectors = map[string]Collector{}
	}
	m.collectors[format] = c
}

// collect runs the collector of a structured source.
func (m *Manager) collect(ctx context.Context, f models.ThreatFeed) ([]byte, error) {
	switch f.Format {
	case FeedFormatTAXII, FeedFormatMISP:
		if err := ValidateSourceURL(f.URL, m.opts.AllowLoopbackSources); err != nil {
			return nil, err
		}
		client, err := sourceClient(f.CACertPEM, m.opts.HTTPProxy, m.opts.AllowLoopbackSources)
		if err != nil {
			return nil, err
		}
		if f.Format == FeedFormatTAXII {
			return CollectTAXII(ctx, f, client)
		}
		return CollectMISP(ctx, f, client)
	}
	m.mu.Lock()
	c := m.collectors[f.Format]
	m.mu.Unlock()
	if c == nil {
		return nil, fmt.Errorf("no collector for %s sources (integration not configured)", f.Format)
	}
	return c(ctx, f)
}

func NewManager(opts Options) (*Manager, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if err := os.MkdirAll(opts.CacheDir, 0o700); err != nil {
		return nil, err
	}
	m := &Manager{
		opts:      opts,
		log:       opts.Logger.With("component", "threatintel"),
		parsed:    make(map[string]*Entries),
		status:    make(map[string]*FeedStatus),
		fetching:  make(map[string]bool),
		refreshCh: make(chan string, 16),
	}
	m.client = newFeedClient(opts.HTTPProxy)
	m.loadStatus()
	m.snap.Store(Empty())
	return m, nil
}

func newFeedClient(proxy string) *http.Client {
	// SSRF guard for admin-configured feed URLs: no internal addresses, checked on the resolved
	// address for direct connections and on the feed host before it is handed to a proxy (the
	// proxy itself is trusted).
	guard := &netguard.ProxyGuard{Proxy: http.ProxyFromEnvironment, Blocked: isInternal, What: "feed host",
		Dialer: &net.Dialer{Timeout: 10 * time.Second}}
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
		MaxIdleConns:          4,
		IdleConnTimeout:       60 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{
		Timeout:       3 * time.Minute,
		Transport:     tr,
		CheckRedirect: feedRedirect,
	}
}

// feedRedirect follows up to five https redirects. Feed credentials (the custom auth header) belong
// to the configured host: a hop to any other host carries only the standard request headers.
func feedRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if req.URL.Scheme != "https" {
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

func isInternal(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}

// ValidateFeedURL checks an admin-supplied feed URL (https only, no internal hosts).
func ValidateFeedURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return errors.New("feed URL must be an absolute URL")
	}
	if u.Scheme != "https" {
		return errors.New("feed URL must use https://")
	}
	if u.User != nil {
		return errors.New("feed URL must not embed credentials; use the auth header setting")
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return errors.New("feed URL must not point to an internal host")
	}
	if a, err := netip.ParseAddr(host); err == nil && isInternal(a) {
		return errors.New("feed URL must not point to an internal address")
	}
	return nil
}

func (m *Manager) Snapshot() *Snapshot { return m.snap.Load() }

// Configure replaces the feed configuration, custom indicators and exceptions, loads cached
// feed content for newly enabled feeds and recompiles the snapshot.
func (m *Manager) Configure(feeds []models.ThreatFeed, indicators []models.Indicator, exceptions []models.ThreatException) {
	m.mu.Lock()
	m.feeds = append([]models.ThreatFeed(nil), feeds...)
	m.indicators = append([]models.Indicator(nil), indicators...)
	m.exceptions = append([]models.ThreatException(nil), exceptions...)
	for _, f := range m.feeds {
		if f.Enabled && m.parsed[f.ID] == nil {
			if e, err := m.loadCached(f); err == nil {
				m.parsed[f.ID] = e
			}
		}
	}
	m.mu.Unlock()
	m.rebuild()
}

// FeedsWithStatus returns the configured feeds merged with runtime status (secrets redacted).
func (m *Manager) FeedsWithStatus(feeds []models.ThreatFeed) []models.ThreatFeed {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]models.ThreatFeed, len(feeds))
	for i, f := range feeds {
		f = f.Public()
		if st := m.status[f.ID]; st != nil {
			f.LastAttemptAt = st.LastAttemptAt
			f.LastSuccessAt = st.LastSuccessAt
			f.LastError = st.LastError
			f.EntryCount = st.EntryCount
			f.ETag = ""
			f.LastModified = st.LastModified
			f.ContentSHA256 = st.ContentSHA256
		}
		out[i] = f
	}
	return out
}

// RefreshNow schedules an immediate download of one feed ("" = all enabled feeds).
func (m *Manager) RefreshNow(feedID string) {
	select {
	case m.refreshCh <- feedID:
	default:
	}
}

// Run executes the update loop until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) {
	if !m.opts.AutoUpdate {
		m.log.Info("threat-intel auto-update disabled; using cached feeds and custom indicators only")
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	if m.opts.AutoUpdate {
		m.refreshDue(ctx, "", false)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-m.refreshCh:
			m.refreshDue(ctx, id, true)
		case <-ticker.C:
			if m.opts.AutoUpdate {
				m.refreshDue(ctx, "", false)
			}
		}
	}
}

func (m *Manager) refreshDue(ctx context.Context, onlyID string, force bool) {
	m.mu.Lock()
	var due []models.ThreatFeed
	now := time.Now()
	for _, f := range m.feeds {
		if !f.Enabled || m.fetching[f.ID] || (onlyID != "" && f.ID != onlyID) {
			continue
		}
		interval := time.Duration(max(f.RefreshMinutes, minRefreshMins)) * time.Minute
		if f.RefreshMinutes == 0 {
			interval = defaultRefreshMins * time.Minute
		}
		st := m.status[f.ID]
		if force || st == nil || st.LastAttemptAt == nil || now.Sub(*st.LastAttemptAt) >= interval ||
			(st.LastError != "" && now.Sub(*st.LastAttemptAt) >= 10*time.Minute) {
			due = append(due, f)
			m.fetching[f.ID] = true
		}
	}
	m.mu.Unlock()
	if len(due) == 0 {
		return
	}
	changed := false
	for _, f := range due {
		if ctx.Err() != nil {
			break
		}
		if m.fetch(ctx, f) {
			changed = true
		}
		m.mu.Lock()
		delete(m.fetching, f.ID)
		m.mu.Unlock()
	}
	m.saveStatus()
	if changed {
		m.rebuild()
	}
}

// fetch downloads one feed. It returns true when new content was parsed.
func (m *Manager) fetch(ctx context.Context, f models.ThreatFeed) bool {
	now := time.Now().UTC()
	m.mu.Lock()
	st := m.status[f.ID]
	if st == nil {
		st = &FeedStatus{}
		m.status[f.ID] = st
	}
	st.LastAttemptAt = &now
	etag, lastMod := st.ETag, st.LastModified
	haveContent := m.parsed[f.ID] != nil
	m.mu.Unlock()

	setErr := func(err error) bool {
		m.mu.Lock()
		st.LastError = err.Error()
		m.mu.Unlock()
		m.log.Warn("threat feed update failed", "feed", f.ID, "error", err)
		return false
	}
	reqCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	if IsStructured(f.Format) {
		body, err := m.collect(reqCtx, f)
		if err != nil {
			return setErr(err)
		}
		entries, err := Parse(formatTyped, bytes.NewReader(body))
		if err != nil {
			return setErr(fmt.Errorf("parse: %w", err))
		}
		sum := sha256.Sum256(body)
		hash := hex.EncodeToString(sum[:])
		if err := writeFileAtomic(m.cachePath(f.ID), body); err != nil {
			m.log.Warn("could not cache source content", "feed", f.ID, "error", err)
		}
		m.mu.Lock()
		changed := st.ContentSHA256 != hash || m.parsed[f.ID] == nil
		m.parsed[f.ID] = entries
		st.LastSuccessAt, st.LastError, st.EntryCount, st.ContentSHA256 = &now, "", entries.Len(), hash
		m.mu.Unlock()
		m.log.Info("threat-intel source updated", "feed", f.ID, "format", f.Format, "entries", entries.Len())
		return changed
	}
	if err := ValidateFeedURL(f.URL); err != nil {
		return setErr(err)
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, f.URL, nil)
	if err != nil {
		return setErr(err)
	}
	req.Header.Set("User-Agent", "AegisProxy-ThreatIntel/2.0 (+feed-sync)")
	if haveContent {
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		if lastMod != "" {
			req.Header.Set("If-Modified-Since", lastMod)
		}
	}
	if f.AuthHeaderName != "" && f.AuthHeaderValue != "" {
		req.Header.Set(f.AuthHeaderName, string(f.AuthHeaderValue))
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return setErr(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		m.mu.Lock()
		st.LastSuccessAt = &now
		st.LastError = ""
		m.mu.Unlock()
		return false
	}
	if resp.StatusCode != http.StatusOK {
		return setErr(fmt.Errorf("HTTP %d from feed server", resp.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		return setErr(err)
	}
	if len(body) > maxFeedBytes {
		return setErr(fmt.Errorf("feed exceeds %d MiB size limit", maxFeedBytes>>20))
	}
	head := strings.ToLower(string(body[:min(len(body), 512)]))
	if strings.Contains(head, "<html") || strings.Contains(head, "<!doctype html") {
		return setErr(errors.New("feed returned an HTML page instead of a list (moved or requires authentication?)"))
	}
	entries, err := Parse(f.Format, bytes.NewReader(body))
	if err != nil {
		return setErr(fmt.Errorf("parse: %w", err))
	}
	sum := sha256.Sum256(body)
	if err := writeFileAtomic(m.cachePath(f.ID), body); err != nil {
		m.log.Warn("could not cache feed content", "feed", f.ID, "error", err)
	}
	m.mu.Lock()
	m.parsed[f.ID] = entries
	st.LastSuccessAt = &now
	st.LastError = ""
	st.EntryCount = entries.Len()
	st.ETag = resp.Header.Get("ETag")
	st.LastModified = resp.Header.Get("Last-Modified")
	st.ContentSHA256 = hex.EncodeToString(sum[:])
	m.mu.Unlock()
	m.log.Info("threat feed updated", "feed", f.ID, "entries", entries.Len(), "bytes", len(body))
	return true
}

func (m *Manager) cachePath(id string) string {
	return filepath.Join(m.opts.CacheDir, safeName(id)+".txt")
}

func safeName(id string) string {
	var b strings.Builder
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func (m *Manager) loadCached(f models.ThreatFeed) (*Entries, error) {
	fh, err := os.Open(m.cachePath(f.ID))
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	e, err := Parse(cacheFormat(f.Format), io.LimitReader(fh, maxFeedBytes))
	if err != nil {
		return nil, err
	}
	if st := m.status[f.ID]; st != nil {
		st.EntryCount = e.Len()
	}
	return e, nil
}

func (m *Manager) rebuild() {
	m.mu.Lock()
	b := newBuilder()
	var versionParts []string
	now := time.Now()
	for _, f := range m.feeds {
		e := m.parsed[f.ID]
		if !f.Enabled || e == nil {
			continue
		}
		b.feeds++
		idx := b.addSource(Source{ID: f.ID, Name: f.Name, Category: f.Category})
		b.add(idx, e, f.MatchSubdomains)
		hash := ""
		if st := m.status[f.ID]; st != nil {
			hash = st.ContentSHA256
		}
		versionParts = append(versionParts, fmt.Sprintf("feed:%s:%v:%s:%d", f.ID, f.MatchSubdomains, hash, e.Len()))
	}
	// Custom indicators grouped by category so matches report a meaningful category.
	byCat := map[string]*Entries{}
	var cats []string
	for _, ind := range m.indicators {
		if !ind.Enabled || (ind.ExpiresAt != nil && now.After(*ind.ExpiresAt)) {
			continue
		}
		cat := ind.Category
		if cat == "" {
			cat = "custom"
		}
		e := byCat[cat]
		if e == nil {
			e = &Entries{}
			byCat[cat] = e
			cats = append(cats, cat)
		}
		switch ind.Type {
		case "domain":
			if d, ok := NormalizeDomain(ind.Value); ok {
				e.Domains = append(e.Domains, d)
			}
		case "url":
			if u, ok := NormalizeURL(ind.Value); ok {
				e.URLs = append(e.URLs, u)
			}
		case "ip", "cidr":
			addIPOrPrefix(strings.TrimSpace(ind.Value), e)
		case "sha256":
			if h, ok := NormalizeHash(ind.Value); ok {
				e.Hashes = append(e.Hashes, h)
			}
		}
		versionParts = append(versionParts, "ioc:"+ind.ID+":"+ind.Value+":"+cat)
	}
	sort.Strings(cats)
	for _, cat := range cats {
		idx := b.addSource(Source{ID: "custom:" + cat, Name: "Custom IOC list", Category: cat})
		b.add(idx, byCat[cat], true)
	}
	b.exc = append(b.exc, m.exceptions...)
	for _, ex := range m.exceptions {
		versionParts = append(versionParts, "exc:"+ex.Type+":"+ex.Value)
	}
	m.mu.Unlock()

	snap := b.build(versionParts)
	old := m.snap.Swap(snap)
	if old == nil || old.Version != snap.Version {
		st := snap.Status()
		m.log.Info("threat-intel snapshot compiled", "version", snap.Version, "domains", st.Domains,
			"urls", st.URLs, "ips", st.IPs, "cidrs", st.CIDRs, "hashes", st.Hashes, "feeds", st.ActiveFeeds)
		if m.opts.OnChange != nil {
			go m.opts.OnChange(snap)
		}
	}
}

func (m *Manager) statusPath() string { return filepath.Join(m.opts.CacheDir, "status.json") }

func (m *Manager) loadStatus() {
	b, err := os.ReadFile(m.statusPath())
	if err != nil {
		return
	}
	var st map[string]*FeedStatus
	if json.Unmarshal(b, &st) == nil && st != nil {
		m.status = st
	}
}

func (m *Manager) saveStatus() {
	m.mu.Lock()
	b, err := json.MarshalIndent(m.status, "", "  ")
	m.mu.Unlock()
	if err == nil {
		_ = writeFileAtomic(m.statusPath(), b)
	}
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func urlHost(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	return u.Hostname(), nil
}
