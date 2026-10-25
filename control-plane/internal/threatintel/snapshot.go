package threatintel

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/netguard"
)

// Source identifies where an indicator came from (a feed or the custom IOC list).
type Source struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
}

// Match describes a threat-intel hit.
type Match struct {
	Type       string `json:"type"` // domain | url | ip | cidr | sha256
	Indicator  string `json:"indicator"`
	Category   string `json:"category"`
	SourceID   string `json:"source_id"`
	SourceName string `json:"source_name"`
}

// Snapshot is an immutable, compiled view of all enabled feeds, custom indicators and exceptions.
// It is safe for concurrent use without locking.
type Snapshot struct {
	Version    string
	CompiledAt time.Time

	sources     []Source
	exact       map[string]uint16 // domain -> source (exact host match)
	sub         map[string]uint16 // domain -> source (domain + all subdomains)
	urls        map[string]uint16
	ips         map[netip.Addr]uint16
	prefixes    map[int]map[netip.Prefix]uint16
	prefixBits  []int
	hashes      map[string]uint16
	excDomains  map[string]struct{}
	excURLs     map[string]struct{}
	excIPs      map[netip.Addr]struct{}
	excHashes   map[string]struct{}
	activeFeeds int

	exportOnce sync.Once
	exportGzip []byte
	exportErr  error
}

// Empty returns a snapshot that matches nothing.
func Empty() *Snapshot {
	return (&builder{}).build(nil)
}

type builder struct {
	sources []Source
	exact   map[string]uint16
	sub     map[string]uint16
	urls    map[string]uint16
	ips     map[netip.Addr]uint16
	prefix  map[netip.Prefix]uint16
	hashes  map[string]uint16
	exc     []models.ThreatException
	feeds   int
}

func newBuilder() *builder {
	return &builder{
		exact:  make(map[string]uint16),
		sub:    make(map[string]uint16),
		urls:   make(map[string]uint16),
		ips:    make(map[netip.Addr]uint16),
		prefix: make(map[netip.Prefix]uint16),
		hashes: make(map[string]uint16),
	}
}

func (b *builder) addSource(src Source) uint16 {
	b.sources = append(b.sources, src)
	return uint16(len(b.sources) - 1)
}

// add merges entries; the first source to claim an indicator wins (stable by feed order).
func (b *builder) add(idx uint16, e *Entries, matchSubdomains bool) {
	for _, d := range e.Domains {
		if matchSubdomains {
			if _, ok := b.sub[d]; !ok {
				b.sub[d] = idx
			}
		} else if _, ok := b.exact[d]; !ok {
			b.exact[d] = idx
		}
	}
	for _, u := range e.URLs {
		if _, ok := b.urls[u]; !ok {
			b.urls[u] = idx
		}
	}
	for _, a := range e.IPs {
		if _, ok := b.ips[a]; !ok {
			b.ips[a] = idx
		}
	}
	for _, p := range e.Prefixes {
		if _, ok := b.prefix[p]; !ok {
			b.prefix[p] = idx
		}
	}
	for _, h := range e.Hashes {
		if _, ok := b.hashes[h]; !ok {
			b.hashes[h] = idx
		}
	}
}

func (b *builder) build(versionParts []string) *Snapshot {
	s := &Snapshot{
		CompiledAt:  time.Now().UTC(),
		sources:     b.sources,
		exact:       b.exact,
		sub:         b.sub,
		urls:        b.urls,
		ips:         b.ips,
		prefixes:    make(map[int]map[netip.Prefix]uint16),
		hashes:      b.hashes,
		excDomains:  make(map[string]struct{}),
		excURLs:     make(map[string]struct{}),
		excIPs:      make(map[netip.Addr]struct{}),
		excHashes:   make(map[string]struct{}),
		activeFeeds: b.feeds,
	}
	for p, idx := range b.prefix {
		m := s.prefixes[p.Bits()]
		if m == nil {
			m = make(map[netip.Prefix]uint16)
			s.prefixes[p.Bits()] = m
			s.prefixBits = append(s.prefixBits, p.Bits())
		}
		m[p] = idx
	}
	sort.Sort(sort.Reverse(sort.IntSlice(s.prefixBits)))
	for _, ex := range b.exc {
		v := strings.ToLower(strings.TrimSpace(ex.Value))
		switch ex.Type {
		case "domain":
			if d, ok := NormalizeDomain(v); ok {
				s.excDomains[d] = struct{}{}
			}
		case "url":
			if u, ok := NormalizeURL(ex.Value); ok {
				s.excURLs[u] = struct{}{}
			}
		case "ip":
			if a, err := netip.ParseAddr(v); err == nil {
				s.excIPs[a.Unmap()] = struct{}{}
			}
		case "sha256":
			if h, ok := NormalizeHash(v); ok {
				s.excHashes[h] = struct{}{}
			}
		}
	}
	h := sha256.New()
	for _, p := range versionParts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	s.Version = hex.EncodeToString(h.Sum(nil))[:20]
	return s
}

func (s *Snapshot) match(kind, indicator string, idx uint16) Match {
	src := s.sources[idx]
	return Match{Type: kind, Indicator: indicator, Category: src.Category, SourceID: src.ID, SourceName: src.Name}
}

// parentDomains yields host and every parent domain with at least two labels.
func parentDomains(host string, fn func(string) bool) {
	for d := host; strings.Contains(d, "."); {
		if fn(d) {
			return
		}
		i := strings.IndexByte(d, '.')
		d = d[i+1:]
	}
}

func (s *Snapshot) domainExcepted(host string) bool {
	if len(s.excDomains) == 0 {
		return false
	}
	found := false
	parentDomains(host, func(d string) bool {
		_, found = s.excDomains[d]
		return found
	})
	return found
}

// MatchHost checks a destination hostname (or IP literal) against domain and IP indicators.
func (s *Snapshot) MatchHost(rawHost string) (Match, bool) {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(rawHost)), ".")
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if host == "" {
		return Match{}, false
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return s.MatchIP(a)
	}
	if s.domainExcepted(host) {
		return Match{}, false
	}
	if idx, ok := s.exact[host]; ok {
		return s.match("domain", host, idx), true
	}
	var m Match
	var hit bool
	parentDomains(host, func(d string) bool {
		if idx, ok := s.sub[d]; ok {
			m, hit = s.match("domain", d, idx), true
		}
		return hit
	})
	return m, hit
}

// MatchURL checks an absolute URL against URL indicators (and its host against domain indicators).
func (s *Snapshot) MatchURL(rawURL string) (Match, bool) {
	u, ok := NormalizeURL(rawURL)
	if !ok {
		return Match{}, false
	}
	if _, ex := s.excURLs[u]; ex {
		return Match{}, false
	}
	if idx, ok := s.urls[u]; ok {
		return s.match("url", u, idx), true
	}
	return Match{}, false
}

// MatchIP matches the address and the IPv4 address it embeds (IPv4-mapped, NAT64, 6to4, IPv4-compatible): an
// indicator for 198.51.100.23 also covers 64:ff9b::c633:6417 behind a NAT64 gateway. Same as match_ip in the
// data-plane.
func (s *Snapshot) MatchIP(a netip.Addr) (Match, bool) {
	a = a.Unmap().WithZone("")
	v4, embedded := netguard.EmbeddedIPv4(a)
	if _, ex := s.excIPs[a]; ex {
		return Match{}, false
	}
	if _, ex := s.excIPs[v4]; embedded && ex {
		return Match{}, false
	}
	if m, ok := s.matchAddr(a); ok || !embedded {
		return m, ok
	}
	return s.matchAddr(v4)
}

func (s *Snapshot) matchAddr(a netip.Addr) (Match, bool) {
	if idx, ok := s.ips[a]; ok {
		return s.match("ip", a.String(), idx), true
	}
	for _, bits := range s.prefixBits {
		if bits > a.BitLen() {
			continue
		}
		p, err := a.Prefix(bits)
		if err != nil {
			continue
		}
		if idx, ok := s.prefixes[bits][p]; ok {
			return s.match("cidr", p.String(), idx), true
		}
	}
	return Match{}, false
}

func (s *Snapshot) MatchHash(hexDigest string) (Match, bool) {
	h, ok := NormalizeHash(hexDigest)
	if !ok {
		return Match{}, false
	}
	if _, ex := s.excHashes[h]; ex {
		return Match{}, false
	}
	if idx, ok := s.hashes[h]; ok {
		return s.match("sha256", h, idx), true
	}
	return Match{}, false
}

// Lookup classifies an arbitrary analyst-provided value (URL, domain, IP or hash).
func (s *Snapshot) Lookup(value string) []Match {
	v := strings.TrimSpace(value)
	var out []Match
	if h, ok := NormalizeHash(v); ok {
		if m, hit := s.MatchHash(h); hit {
			out = append(out, m)
		}
		return out
	}
	if strings.Contains(v, "://") {
		if m, hit := s.MatchURL(v); hit {
			out = append(out, m)
		}
		if u, err := urlHost(v); err == nil {
			if m, hit := s.MatchHost(u); hit {
				out = append(out, m)
			}
		}
		return out
	}
	if p, err := netip.ParsePrefix(v); err == nil {
		v = p.Addr().String()
	}
	if m, hit := s.MatchHost(v); hit {
		out = append(out, m)
	}
	return out
}

func (s *Snapshot) Status() models.ThreatIntelStatus {
	cidrs := 0
	for _, m := range s.prefixes {
		cidrs += len(m)
	}
	return models.ThreatIntelStatus{
		Version:     s.Version,
		CompiledAt:  s.CompiledAt,
		Domains:     len(s.exact) + len(s.sub),
		URLs:        len(s.urls),
		IPs:         len(s.ips),
		CIDRs:       cidrs,
		Hashes:      len(s.hashes),
		Exceptions:  len(s.excDomains) + len(s.excURLs) + len(s.excIPs) + len(s.excHashes),
		ActiveFeeds: s.activeFeeds,
	}
}

// dataPlaneExport is the wire format consumed by the mitmproxy data-plane workers.
type dataPlaneExport struct {
	Version    string              `json:"version"`
	CompiledAt time.Time           `json:"compiled_at"`
	Sources    []Source            `json:"sources"`
	Domains    map[string]uint16   `json:"domains"`
	DomainsSub map[string]uint16   `json:"domains_sub"`
	URLs       map[string]uint16   `json:"urls"`
	IPs        map[string]uint16   `json:"ips"`
	CIDRs      [][2]any            `json:"cidrs"`
	Hashes     map[string]uint16   `json:"hashes"`
	Exceptions map[string][]string `json:"exceptions"`
}

// ExportGzip returns the gzip-compressed JSON export for data-plane workers (computed once).
func (s *Snapshot) ExportGzip() ([]byte, error) {
	s.exportOnce.Do(func() {
		exp := dataPlaneExport{
			Version:    s.Version,
			CompiledAt: s.CompiledAt,
			Sources:    s.sources,
			Domains:    s.exact,
			DomainsSub: s.sub,
			URLs:       s.urls,
			IPs:        make(map[string]uint16, len(s.ips)),
			Hashes:     s.hashes,
			Exceptions: map[string][]string{},
		}
		if exp.Sources == nil {
			exp.Sources = []Source{}
		}
		for a, idx := range s.ips {
			exp.IPs[a.String()] = idx
		}
		for _, m := range s.prefixes {
			for p, idx := range m {
				exp.CIDRs = append(exp.CIDRs, [2]any{p.String(), idx})
			}
		}
		if exp.CIDRs == nil {
			exp.CIDRs = [][2]any{}
		}
		keys := func(m map[string]struct{}) []string {
			out := make([]string, 0, len(m))
			for k := range m {
				out = append(out, k)
			}
			sort.Strings(out)
			return out
		}
		exp.Exceptions["domains"] = keys(s.excDomains)
		exp.Exceptions["urls"] = keys(s.excURLs)
		exp.Exceptions["hashes"] = keys(s.excHashes)
		ips := make([]string, 0, len(s.excIPs))
		for a := range s.excIPs {
			ips = append(ips, a.String())
		}
		exp.Exceptions["ips"] = ips

		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
		if err := json.NewEncoder(zw).Encode(exp); err != nil {
			s.exportErr = err
			return
		}
		if err := zw.Close(); err != nil {
			s.exportErr = err
			return
		}
		s.exportGzip = buf.Bytes()
	})
	return s.exportGzip, s.exportErr
}
