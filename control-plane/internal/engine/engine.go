package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/netguard"
)

// RedirectGrant is keyed by the resolved server identity (server ID), never by the source address: servers
// behind one NAT address must not share each other's grants.
type RedirectGrant struct {
	ServerID   string
	TargetHost string
	TargetPath string
	ParentURL  string
	RuleID     string
	RuleName   string
	ExpiresAt  time.Time
}

type EvaluationRequest struct {
	ServerIP      string `json:"server_ip"`
	ProxyAuthUser string `json:"proxy_auth_user"`
	Method        string `json:"method"`
	Scheme        string `json:"scheme"`
	Host          string `json:"host"`
	Port          int    `json:"port,omitempty"`
	Path          string `json:"path"`
	FullURL       string `json:"full_url"`
	UserAgent     string `json:"user_agent"`
}

type EvaluationResult struct {
	Allowed           bool     `json:"allowed"`
	Verdict           string   `json:"verdict"` // "ALLOWED", "BLOCKED", "LEARNING_ALLOWED", "REDIRECT_OBJECT_ALLOWED", "TLS_BYPASS"
	TLSBypass         bool     `json:"tls_bypass"`
	ServerID          string   `json:"server_id"`
	ServerHostname    string   `json:"server_hostname"`
	GroupIDs          []string `json:"group_ids"`
	MatchedRuleID     string   `json:"matched_rule_id,omitempty"`
	MatchedRuleName   string   `json:"matched_rule_name,omitempty"`
	FollowRedirects   bool     `json:"follow_redirects"`
	RedirectParentURL string   `json:"redirect_parent_url,omitempty"`
	SessionID         string   `json:"session_id,omitempty"`
	SuggestedHost     string   `json:"suggested_host"`
	SuggestedPath     string   `json:"suggested_path"`
	BlockReason       string   `json:"block_reason,omitempty"`
	ThreatCategory    string   `json:"threat_category,omitempty"`
	ThreatSource      string   `json:"threat_source,omitempty"`
	ThreatIndicator   string   `json:"threat_indicator,omitempty"`
	SecurityFlags     []string `json:"security_flags,omitempty"`
}

const redirectShardCount = 32

type redirectShard struct {
	mu     sync.RWMutex
	grants map[string]RedirectGrant
}

type CompiledGroupCIDR struct {
	GroupID string
	Prefix  netip.Prefix
	RawCIDR string
}

type IndexedRule struct {
	Rule          models.PolicyRule
	GroupSet      map[string]struct{}
	AllGroups     bool
	ServerIDSet   map[string]struct{}
	AllServers    bool
	LowerHostPat  string
	CompanionHost []string
	CompanionPath []string
}

// AppliesTo reports whether a rule covers the source. "*" scopes cover sources with at least one
// group membership ("*" group) or registered servers ("*" server) — never unknown sources, so a
// catch-all rule cannot open egress for unregistered machines.
func (ir IndexedRule) AppliesTo(serverID string, groupIDs []string) bool {
	if ir.AllGroups && len(groupIDs) > 0 {
		return true
	}
	if ir.AllServers && serverID != "" && !strings.HasPrefix(serverID, UnregisteredPrefix) {
		return true
	}
	for _, g := range groupIDs {
		if _, ok := ir.GroupSet[g]; ok {
			return true
		}
	}
	if _, ok := ir.ServerIDSet[serverID]; ok {
		return true
	}
	return false
}

// UnregisteredPrefix marks synthetic server IDs of sources that matched neither a registered server
// nor a group CIDR.
const UnregisteredPrefix = "srv-unregistered-"

// CompiledPolicyIndex holds pre-parsed, O(1) lookup structures rebuilt atomically on config changes.
type CompiledPolicyIndex struct {
	Revision       uint64
	ServerByIP     map[string]models.Server
	ServerByAuth   map[string]models.Server // bare username -> Server (requires IP/subnet binding)
	ServerByToken  map[string]models.Server // hex SHA-256(token) -> Server
	StrictGroups   map[string]bool          // groups with StrictIsolation
	TokenGroups    map[string]bool          // groups with RequireProxyToken
	ParsedCIDRs    []CompiledGroupCIDR
	ExactHostRules map[string][]IndexedRule // exact lowercase hostname -> rules (sorted BLOCK first)
	WildcardRules  []IndexedRule            // rules with *.domain or * or companion wildcards (sorted BLOCK first)
}

func sortIndexedRulesBlockFirst(list []IndexedRule) {
	sort.SliceStable(list, func(i, j int) bool {
		iBlock := strings.EqualFold(list[i].Rule.Action, "BLOCK")
		jBlock := strings.EqualFold(list[j].Rule.Action, "BLOCK")
		return iBlock && !jBlock
	})
}

// NormalizeHost lowercases (ASCII) and strips surrounding ASCII whitespace, IPv6 brackets, the port and trailing
// FQDN dots ("GitHub.com.:443" -> "github.com"). A port is only stripped when the value has exactly one colon,
// so an unbracketed IPv6 literal stays whole. NormalizeHost and CanonicalizePath must stay identical to
// normalize_host and canonicalize_path of the data-plane (testdata/normalization_vectors.json).
func NormalizeHost(host string) string {
	h := asciiLower(strings.Trim(host, " \t\r\n\f\v"))
	if strings.HasPrefix(h, "[") {
		if end := strings.IndexByte(h, ']'); end != -1 {
			return h[1:end]
		}
	}
	if strings.Count(h, ":") == 1 {
		h = h[:strings.IndexByte(h, ':')]
	}
	return strings.TrimRight(h, ".")
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// HashProxyToken returns the hex SHA-256 digest used to store and look up server proxy tokens.
func HashProxyToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func BuildCompiledIndex(revision uint64, groups []models.ServerGroup, servers []models.Server, rules []models.PolicyRule) *CompiledPolicyIndex {
	idx := &CompiledPolicyIndex{
		Revision:       revision,
		ServerByIP:     make(map[string]models.Server, len(servers)),
		ServerByAuth:   make(map[string]models.Server, len(servers)),
		ServerByToken:  make(map[string]models.Server, len(servers)),
		StrictGroups:   make(map[string]bool),
		TokenGroups:    make(map[string]bool),
		ParsedCIDRs:    make([]CompiledGroupCIDR, 0, len(groups)*2),
		ExactHostRules: make(map[string][]IndexedRule, len(rules)),
		WildcardRules:  make([]IndexedRule, 0, len(rules)/2+1),
	}

	for _, g := range groups {
		if g.StrictIsolation {
			idx.StrictGroups[g.ID] = true
		}
		if g.RequireProxyToken {
			idx.TokenGroups[g.ID] = true
			continue // CIDR membership is an address match: never identifies sources for such a group
		}
		for _, cidr := range g.CIDRs {
			if pfx, err := netip.ParsePrefix(strings.TrimSpace(cidr)); err == nil {
				idx.ParsedCIDRs = append(idx.ParsedCIDRs, CompiledGroupCIDR{
					GroupID: g.ID,
					Prefix:  pfx.Masked(),
					RawCIDR: cidr,
				})
			}
		}
	}

	sharedIPs := map[string]bool{}
	for _, srv := range servers {
		cleanIP := strings.TrimSpace(srv.IP)
		if _, dup := idx.ServerByIP[cleanIP]; dup || sharedIPs[cleanIP] {
			// An address registered for several servers identifies none of them.
			delete(idx.ServerByIP, cleanIP)
			sharedIPs[cleanIP] = true
		} else if cleanIP != "" {
			idx.ServerByIP[cleanIP] = srv
		}
		uLower := strings.ToLower(strings.TrimSpace(srv.ProxyAuthUser))
		if uLower != "" {
			idx.ServerByAuth[uLower] = srv
		}
		if h := strings.ToLower(strings.TrimSpace(srv.ProxyAuthTokenHash)); h != "" {
			idx.ServerByToken[h] = srv
		}
	}

	now := time.Now().UTC()
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if r.ExpiresAt != nil && now.After(*r.ExpiresAt) {
			continue
		}
		grpSet := make(map[string]struct{}, len(r.GroupIDs))
		allGroups := false
		for _, gid := range r.GroupIDs {
			if gid == "*" {
				allGroups = true
				break
			}
			grpSet[gid] = struct{}{}
		}
		srvSet := make(map[string]struct{}, len(r.ServerIDs))
		allServers := false
		for _, sid := range r.ServerIDs {
			if sid == "*" {
				allServers = true
				break
			}
			srvSet[sid] = struct{}{}
		}

		lowerHost := NormalizeHost(r.HostPattern)
		compHosts := make([]string, 0, len(r.CompanionRules))
		compPaths := make([]string, 0, len(r.CompanionRules))
		hasWildcardCompanion := false
		for _, comp := range r.CompanionRules {
			ch, cp := splitCompanionPattern(comp)
			chLower := NormalizeHost(ch)
			compHosts = append(compHosts, chLower)
			compPaths = append(compPaths, cp)
			if strings.Contains(chLower, "*") {
				hasWildcardCompanion = true
			}
		}

		ir := IndexedRule{
			Rule:          r,
			GroupSet:      grpSet,
			AllGroups:     allGroups,
			ServerIDSet:   srvSet,
			AllServers:    allServers,
			LowerHostPat:  lowerHost,
			CompanionHost: compHosts,
			CompanionPath: compPaths,
		}

		if !strings.Contains(lowerHost, "*") && !hasWildcardCompanion {
			idx.ExactHostRules[lowerHost] = append(idx.ExactHostRules[lowerHost], ir)
			for _, ch := range compHosts {
				if ch != lowerHost {
					idx.ExactHostRules[ch] = append(idx.ExactHostRules[ch], ir)
				}
			}
		} else {
			idx.WildcardRules = append(idx.WildcardRules, ir)
		}
	}

	for h, list := range idx.ExactHostRules {
		sortIndexedRulesBlockFirst(list)
		idx.ExactHostRules[h] = list
	}
	sortIndexedRulesBlockFirst(idx.WildcardRules)

	return idx
}

type PolicyEngine struct {
	shards [redirectShardCount]redirectShard
}

func NewPolicyEngine() *PolicyEngine {
	e := &PolicyEngine{}
	for i := 0; i < redirectShardCount; i++ {
		e.shards[i].grants = make(map[string]RedirectGrant, 32)
	}
	go e.evictExpiredLoop()
	return e
}

func fnv32(key string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return h
}

func (e *PolicyEngine) evictExpiredLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for now := range ticker.C {
		for i := 0; i < redirectShardCount; i++ {
			sh := &e.shards[i]
			sh.mu.Lock()
			for k, g := range sh.grants {
				if now.After(g.ExpiresAt) {
					delete(sh.grants, k)
				}
			}
			sh.mu.Unlock()
		}
	}
}

// internalSuffixes are DNS suffixes that are never valid redirect / egress targets.
var internalSuffixes atomic.Pointer[[]string]

func init() {
	def := []string{".internal.corp", ".local", ".localdomain", ".internal", ".lan", ".home.arpa"}
	internalSuffixes.Store(&def)
}

// SetInternalSuffixes configures the internal DNS suffixes (AEGIS_INTERNAL_DOMAINS).
func SetInternalSuffixes(suffixes []string) {
	cp := append([]string(nil), suffixes...)
	internalSuffixes.Store(&cp)
}

// IsInternalAddr reports addresses that are not globally reachable: loopback, private, link-local (incl.
// 169.254.169.254 cloud metadata), other cloud metadata endpoints, CGNAT, documentation, reserved, multicast and
// unspecified ranges, also embedded in IPv6 (NAT64, 6to4, IPv4-compatible). The table is netguard.IsInternal,
// mirrored by is_internal_addr in the data-plane.
func IsInternalAddr(addr netip.Addr) bool { return netguard.IsInternal(addr) }

// IsInternalHost reports internal hostnames and addresses (see IsInternalAddr and SetInternalSuffixes).
func IsInternalHost(host string) bool {
	h := NormalizeHost(host)
	if h == "" || h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	for _, suf := range *internalSuffixes.Load() {
		if strings.HasSuffix(h, suf) || h == strings.TrimPrefix(suf, ".") {
			return true
		}
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		return IsInternalAddr(addr)
	}
	return false
}

// IsDisallowedRedirectTarget blocks 302 open redirects pointing to RFC1918, loopback, link-local (169.254.169.254), or internal corp hosts.
func IsDisallowedRedirectTarget(host string) bool {
	return IsInternalHost(host)
}

// CanonicalizePath decodes percent-encoded traversal sequences (%2e%2e, %2f), rejects null-bytes, backslash smuggling,
// malformed escapes, paths that are not valid UTF-8 or >3x nested percent-encoding, and resolves dot-segments and
// repeated slashes (/microsoft/../torvalds -> /torvalds, //a -> /a).
func CanonicalizePath(rawPath string) (string, bool) {
	if rawPath == "" {
		return "/", true
	}
	if idx := strings.IndexByte(rawPath, '?'); idx != -1 {
		rawPath = rawPath[:idx]
	}
	if idx := strings.IndexByte(rawPath, '#'); idx != -1 {
		rawPath = rawPath[:idx]
	}
	cur := rawPath
	for i := 0; i < 3; i++ {
		if strings.Contains(cur, "\x00") || strings.Contains(cur, "\\") || !utf8.ValidString(cur) {
			return "", false
		}
		unesc, err := url.PathUnescape(cur)
		if err != nil {
			return "", false
		}
		if strings.Contains(unesc, "\x00") || strings.Contains(unesc, "\\") || !utf8.ValidString(unesc) {
			return "", false
		}
		if unesc == cur {
			break
		}
		cur = unesc
	}
	// Reject 4x+ nested percent-encoding evasion attempts
	if extra, err := url.PathUnescape(cur); err != nil || extra != cur {
		return "", false
	}
	if !strings.HasPrefix(cur, "/") {
		cur = "/" + cur
	}
	cleaned := path.Clean(cur)
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}
	return cleaned, true
}

var defaultPorts = map[string]int{"http": 80, "https": 443}

// RequestOrigin returns the scheme and effective port of a request (same as the data-plane's request_origin): the
// URL's scheme, else the request's scheme, else https unless the port is 80 (CONNECT and tunnel re-checks carry no
// URL).
func RequestOrigin(fullURL, scheme string, port int) (string, int) {
	s := ""
	if fullURL != "" {
		if u, err := url.Parse(fullURL); err == nil {
			s = strings.ToLower(u.Scheme)
		}
	}
	if _, ok := defaultPorts[s]; !ok {
		s = strings.ToLower(scheme)
	}
	if _, ok := defaultPorts[s]; !ok {
		s = "https"
		if port == 80 {
			s = "http"
		}
	}
	if port <= 0 {
		port = defaultPorts[s]
	}
	return s, port
}

// RegisterRedirectGrant records a temporary object access grant for the server serverID when an allowed URL
// redirects (301/302/307/308) to a CDN/Object host. A non-empty allowedHosts (the rule's redirect_hosts patterns)
// limits the hosts that can receive a grant. The grant covers exactly the target's origin (scheme, host, port) and
// object, plus a CONNECT tunnel to that host:port.
func (e *PolicyEngine) RegisterRedirectGrant(serverID, locationURL, parentURL, ruleID, ruleName string, allowedHosts []string) {
	parsed, err := url.Parse(locationURL)
	if err != nil || serverID == "" {
		return
	}
	if base, err := url.Parse(parentURL); err == nil && parentURL != "" {
		parsed = base.ResolveReference(parsed)
	}
	if parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return
	}
	port := defaultPorts[parsed.Scheme]
	if p := parsed.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return
		}
		port = n
	}
	host := NormalizeHost(parsed.Host)
	if IsDisallowedRedirectTarget(host) {
		return
	}
	if len(allowedHosts) > 0 && !slices.ContainsFunc(allowedHosts, func(p string) bool { return MatchHost(p, host) }) {
		return
	}
	cleanPath, ok := CanonicalizePath(parsed.Path)
	if !ok {
		return
	}
	exp := time.Now().Add(2 * time.Minute)
	grant := RedirectGrant{
		ServerID:   serverID,
		TargetHost: host,
		TargetPath: cleanPath,
		ParentURL:  parentURL,
		RuleID:     ruleID,
		RuleName:   ruleName,
		ExpiresAt:  exp,
	}
	key := fmt.Sprintf("%s|%s|%s|%d|%s", serverID, parsed.Scheme, host, port, cleanPath)
	sh := &e.shards[fnv32(key)%redirectShardCount]
	sh.mu.Lock()
	if len(sh.grants) < 1024 {
		sh.grants[key] = grant
	}
	sh.mu.Unlock()

	// Also register a CONNECT pre-flight key so tunnel setup to the redirect target's host:port succeeds
	connKey := fmt.Sprintf("%s|%s|%d|CONNECT", serverID, host, port)
	shConn := &e.shards[fnv32(connKey)%redirectShardCount]
	shConn.mu.Lock()
	if len(shConn.grants) < 1024 {
		shConn.grants[connKey] = grant
	}
	shConn.mu.Unlock()
}

// CheckRedirectGrant looks up a grant of the server serverID (the requester's resolved identity) for the request's
// origin (scheme and port as returned by RequestOrigin; port 0 means the scheme's default port).
func (e *PolicyEngine) CheckRedirectGrant(serverID, scheme, host string, port int, rawPath, method string) (RedirectGrant, bool) {
	upperMethod := strings.ToUpper(strings.TrimSpace(method))
	// Redirect object grants only permit read-only retrieval (GET/HEAD) and CONNECT tunnel pre-flight, never POST/PUT exfiltration.
	if upperMethod != "GET" && upperMethod != "HEAD" && upperMethod != "CONNECT" {
		return RedirectGrant{}, false
	}
	defPort, known := defaultPorts[scheme]
	if !known || serverID == "" {
		return RedirectGrant{}, false
	}
	if port <= 0 {
		port = defPort
	}
	host = NormalizeHost(host)
	if IsDisallowedRedirectTarget(host) {
		return RedirectGrant{}, false
	}
	var key string
	if upperMethod == "CONNECT" {
		key = fmt.Sprintf("%s|%s|%d|CONNECT", serverID, host, port)
	} else {
		cleanPath, ok := CanonicalizePath(rawPath)
		if !ok {
			return RedirectGrant{}, false
		}
		key = fmt.Sprintf("%s|%s|%s|%d|%s", serverID, scheme, host, port, cleanPath)
	}
	sh := &e.shards[fnv32(key)%redirectShardCount]
	sh.mu.RLock()
	grant, ok := sh.grants[key]
	sh.mu.RUnlock()
	if ok && time.Now().Before(grant.ExpiresAt) {
		return grant, true
	}
	return RedirectGrant{}, false
}

// MatchHost checks if a request host matches a pattern like "github.com" or "*.ubuntu.com".
func MatchHost(pattern, host string) bool {
	pattern = NormalizeHost(pattern)
	host = NormalizeHost(host)
	if pattern == "*" || pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".ubuntu.com"
		root := pattern[2:]   // "ubuntu.com"
		return host == root || strings.HasSuffix(host, suffix)
	}
	return false
}

// IsDomainWidePathPattern returns true if a PathPattern covers the entire host ("", "*", "/**").
func IsDomainWidePathPattern(pattern string) bool {
	p := strings.TrimSpace(pattern)
	return p == "" || p == "*" || p == "/**"
}

// Path pattern syntax (same as match_path in the data-plane; shared vectors in testdata/path_vectors.json). Pattern
// and request path are canonicalized first (CanonicalizePath: query ignored, dot-segments and repeated slashes
// resolved), then:
//
//	"*"    a whole segment ("/simple/*"): exactly one non-empty segment; inside a segment ("/v*.json"):
//	       any characters except '/'
//	"/**"  a whole segment: zero or more segments ("/acme/**" matches /acme, /acme/x and /acme/x/y;
//	       "/a/**/b" matches /a/b and /a/x/y/b)
//	"**"   inside a segment ("/release-asset-**"): any characters including '/'
//
// Matching is a linear-time automaton (no backtracking), so hostile request paths cannot blow it up.
const (
	pathLit      = iota // the character c
	pathSegChar         // exactly one character other than '/'
	pathStar            // any run of characters other than '/'
	pathAny             // any run of characters
	pathOptSlash        // '/' followed by the next pathAny token, or neither (zero segments)
)

type pathToken struct {
	kind uint8
	c    byte
}

func compilePathPattern(p string) []pathToken {
	toks := make([]pathToken, 0, len(p))
	for i := 0; i < len(p); {
		if strings.HasPrefix(p[i:], "/**") && (i+3 == len(p) || p[i+3] == '/') {
			toks = append(toks, pathToken{kind: pathOptSlash}, pathToken{kind: pathAny})
			i += 3
			continue
		}
		if p[i] != '*' {
			toks = append(toks, pathToken{kind: pathLit, c: p[i]})
			i++
			continue
		}
		j := i
		for j < len(p) && p[j] == '*' {
			j++
		}
		switch {
		case j-i >= 2:
			toks = append(toks, pathToken{kind: pathAny})
		case (i == 0 || p[i-1] == '/') && (j == len(p) || p[j] == '/'):
			toks = append(toks, pathToken{kind: pathSegChar}, pathToken{kind: pathStar})
		default:
			toks = append(toks, pathToken{kind: pathStar})
		}
		i = j
	}
	return toks
}

func matchPathTokens(toks []pathToken, s string) bool {
	n := len(toks)
	cur, next := make([]bool, n+1), make([]bool, n+1)
	// Epsilon moves only go forward, so one ascending pass computes the closure.
	closure := func(set []bool) {
		for k := 0; k < n; k++ {
			if !set[k] {
				continue
			}
			switch toks[k].kind {
			case pathStar, pathAny:
				set[k+1] = true
			case pathOptSlash:
				set[k+2] = true
			}
		}
	}
	cur[0] = true
	closure(cur)
	for i := 0; i < len(s); i++ {
		ch := s[i]
		clear(next)
		alive := false
		for k := 0; k < n; k++ {
			if !cur[k] {
				continue
			}
			switch t := toks[k]; t.kind {
			case pathLit:
				if ch == t.c {
					next[k+1], alive = true, true
				}
			case pathSegChar:
				if ch != '/' {
					next[k+1], alive = true, true
				}
			case pathStar:
				if ch != '/' {
					next[k], alive = true, true
				}
			case pathAny:
				next[k], alive = true, true
			case pathOptSlash:
				if ch == '/' {
					next[k+1], alive = true, true
				}
			}
		}
		if !alive {
			return false
		}
		closure(next)
		cur, next = next, cur
	}
	return cur[n]
}

// MatchPath checks a path pattern ("/microsoft/**", "/simple/*", "/repos/*/releases/**", exact paths) against a
// request path; see the syntax above.
func MatchPath(pattern, reqPath string) bool {
	pattern = strings.TrimSpace(pattern)
	cleanPath, ok := CanonicalizePath(reqPath)
	if !ok {
		return false
	}
	if IsDomainWidePathPattern(pattern) {
		return true
	}
	cleanPattern, ok := CanonicalizePath(pattern)
	if !ok {
		return false
	}
	if !strings.Contains(cleanPattern, "*") {
		return cleanPath == cleanPattern
	}
	return matchPathTokens(compilePathPattern(cleanPattern), cleanPath)
}

// LegacyPathPattern translates a path pattern written for releases before 2.1, where a trailing "/*" also
// matched every deeper path and a trailing "x*" was a plain prefix, into the current syntax with the same
// meaning ("/simple/*" -> "/simple/**", "/token*" -> "/token**"). literalStar reports a '*' elsewhere in the
// pattern: older releases compared it literally, now it is a wildcard (no equivalent exists).
func LegacyPathPattern(p string) (out string, changed, literalStar bool) {
	p = strings.TrimSpace(p)
	if IsDomainWidePathPattern(p) {
		return p, false, false
	}
	out = p
	body := p
	if strings.HasSuffix(p, "*") && !strings.HasSuffix(p, "**") {
		out = p + "*"
		body = strings.TrimSuffix(p, "*")
	} else if strings.HasSuffix(p, "**") {
		body = strings.TrimRight(p, "*")
	}
	return out, out != p, strings.Contains(body, "*")
}

func MatchMethod(methods []string, reqMethod string) bool {
	if len(methods) == 0 {
		return true
	}
	reqMethod = strings.ToUpper(reqMethod)
	if reqMethod == "CONNECT" {
		// CONNECT pre-flight check is allowed if any method is allowed on the host
		return true
	}
	for _, m := range methods {
		if m == "*" || strings.EqualFold(m, reqMethod) {
			return true
		}
	}
	return false
}

func MatchRule(rule models.PolicyRule, host, path, method string) bool {
	if !rule.Enabled {
		return false
	}
	if rule.ExpiresAt != nil && time.Now().After(*rule.ExpiresAt) {
		return false
	}
	if !MatchMethod(rule.Methods, method) {
		return false
	}
	// For HTTP CONNECT tunnel initiation, path is empty or host:port.
	// Allow CONNECT for ALLOW rules if the host matches so mitmproxy can inspect the inner HTTPS path.
	// For BLOCK rules, only block at the CONNECT stage if the BLOCK rule is domain-wide ("/**", "*");
	// path-specific BLOCK rules (e.g. "github.com/torvalds/**") must NOT block CONNECT to github.com:443!
	if strings.EqualFold(method, "CONNECT") {
		if strings.EqualFold(rule.Action, "BLOCK") {
			if MatchHost(rule.HostPattern, host) && IsDomainWidePathPattern(rule.PathPattern) {
				return true
			}
			for _, comp := range rule.CompanionRules {
				compHost, compPath := splitCompanionPattern(comp)
				if MatchHost(compHost, host) && IsDomainWidePathPattern(compPath) {
					return true
				}
			}
			return false
		}
		if MatchHost(rule.HostPattern, host) {
			return true
		}
		for _, comp := range rule.CompanionRules {
			compHost, _ := splitCompanionPattern(comp)
			if MatchHost(compHost, host) {
				return true
			}
		}
		return false
	}

	if MatchHost(rule.HostPattern, host) && MatchPath(rule.PathPattern, path) {
		return true
	}

	// Check companion patterns (e.g., "codeload.github.com/microsoft/**")
	for _, comp := range rule.CompanionRules {
		compHost, compPath := splitCompanionPattern(comp)
		if MatchHost(compHost, host) && MatchPath(compPath, path) {
			return true
		}
	}
	return false
}

func splitCompanionPattern(comp string) (string, string) {
	comp = strings.TrimSpace(comp)
	idx := strings.IndexByte(comp, '/')
	if idx == -1 {
		return comp, "/**"
	}
	return comp[:idx], comp[idx:]
}

func MatchCIDR(cidrStr, ipStr string) bool {
	prefix, err := netip.ParsePrefix(cidrStr)
	if err != nil {
		return cidrStr == ipStr
	}
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	return prefix.Contains(addr)
}

// SuggestRulePattern derives a smart host & path pattern from a raw URL.
func SuggestRulePattern(host, path string) (string, string, bool) {
	host = NormalizeHost(host)
	if idx := strings.IndexByte(path, '?'); idx != -1 {
		path = path[:idx]
	}
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if host == "github.com" || host == "codeload.github.com" {
		if len(segments) >= 1 && segments[0] != "" {
			return "github.com", "/" + segments[0] + "/**", true
		}
	}
	if len(segments) >= 2 && segments[0] != "" {
		return host, "/" + segments[0] + "/" + segments[1] + "/**", true
	}
	if len(segments) == 1 && segments[0] != "" {
		return host, "/" + segments[0] + "/**", false
	}
	return host, "/**", false
}

// CompileSessionRules analyzes captured traffic flows from a Learning Session and automatically synthesizes generalized whitelist rules.
func CompileSessionRules(flows []models.TrafficFlow) []models.CompiledRuleCandidate {
	type bucket struct {
		host            string
		pathPattern     string
		methods         map[string]bool
		sampleURLs      []string
		redirectTargets map[string]bool
		followRedirects bool
		companionMap    map[string]bool
		hitCount        int
		isRedirectChild bool
	}

	buckets := make(map[string]*bucket)
	redirectedTargetHosts := make(map[string]string) // targetHost -> parentKey

	// First pass: detect redirect relationships
	for _, f := range flows {
		if strings.EqualFold(f.Method, "CONNECT") {
			continue
		}
		if f.RedirectLocation != "" {
			if u, err := url.Parse(f.RedirectLocation); err == nil && u.Host != "" {
				hPat, pPat, _ := generalizeFlow(f.Host, f.Path)
				parentKey := hPat + "|" + pPat
				redirectedTargetHosts[strings.ToLower(u.Host)] = parentKey
			}
		}
		if f.RedirectParentURL != "" {
			if u, err := url.Parse(f.RedirectParentURL); err == nil && u.Host != "" {
				hPat, pPat, _ := generalizeFlow(u.Host, u.Path)
				parentKey := hPat + "|" + pPat
				redirectedTargetHosts[strings.ToLower(f.Host)] = parentKey
			}
		}
	}

	for _, f := range flows {
		if strings.EqualFold(f.Method, "CONNECT") {
			continue
		}
		hostPat, pathPat, companions := generalizeFlow(f.Host, f.Path)
		key := hostPat + "|" + pathPat

		// Check if this host is an ephemeral CDN/Object child of a parent rule
		isChild := false
		if parentKey, ok := redirectedTargetHosts[strings.ToLower(f.Host)]; ok && parentKey != key {
			isChild = true
			if pb, exists := buckets[parentKey]; exists {
				pb.followRedirects = true
				pb.redirectTargets[f.Host] = true
			}
		}

		b, exists := buckets[key]
		if !exists {
			b = &bucket{
				host:            hostPat,
				pathPattern:     pathPat,
				methods:         make(map[string]bool),
				redirectTargets: make(map[string]bool),
				companionMap:    make(map[string]bool),
				isRedirectChild: isChild,
			}
			buckets[key] = b
		}
		b.hitCount++
		b.methods[strings.ToUpper(f.Method)] = true
		if len(b.sampleURLs) < 4 {
			already := false
			for _, s := range b.sampleURLs {
				if s == f.FullURL {
					already = true
					break
				}
			}
			if !already {
				b.sampleURLs = append(b.sampleURLs, f.FullURL)
			}
		}
		for _, c := range companions {
			b.companionMap[c] = true
		}
		if f.RedirectLocation != "" {
			b.followRedirects = true
			if u, err := url.Parse(f.RedirectLocation); err == nil && u.Host != "" {
				b.redirectTargets[strings.ToLower(u.Host)] = true
			}
		}
	}

	candidates := make([]models.CompiledRuleCandidate, 0, len(buckets))
	idx := 1
	for _, b := range buckets {
		methods := make([]string, 0, len(b.methods))
		for m := range b.methods {
			methods = append(methods, m)
		}
		sort.Strings(methods)

		companions := make([]string, 0, len(b.companionMap))
		for c := range b.companionMap {
			companions = append(companions, c)
		}
		sort.Strings(companions)

		redirs := make([]string, 0, len(b.redirectTargets))
		for r := range b.redirectTargets {
			redirs = append(redirs, r)
		}
		sort.Strings(redirs)

		// Auto-enable FollowRedirects for GitHub / S3 / Package CDNs
		follow := b.followRedirects || b.host == "github.com" || b.host == "pypi.org" || strings.Contains(b.host, "docker.io")

		candidates = append(candidates, models.CompiledRuleCandidate{
			ID:              fmt.Sprintf("cand-%d", idx),
			HostPattern:     b.host,
			PathPattern:     b.pathPattern,
			Methods:         methods,
			FollowRedirects: follow,
			CompanionRules:  companions,
			SampleURLs:      b.sampleURLs,
			RedirectTargets: redirs,
			HitCount:        b.hitCount,
			IsRedirectChild: b.isRedirectChild,
			Selected:        !b.isRedirectChild, // By default select primary rules; redirect children are covered by FollowRedirects!
		})
		idx++
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].IsRedirectChild != candidates[j].IsRedirectChild {
			return !candidates[i].IsRedirectChild
		}
		return candidates[i].HitCount > candidates[j].HitCount
	})

	return candidates
}

func generalizeFlow(host, path string) (string, string, []string) {
	host = strings.ToLower(strings.Split(host, ":")[0])
	if idx := strings.IndexByte(path, '?'); idx != -1 {
		path = path[:idx]
	}
	segments := strings.Split(strings.Trim(path, "/"), "/")

	// GitHub special intelligence: group by org (e.g. github.com/microsoft/**) + attach codeload & api companions
	if host == "github.com" || host == "codeload.github.com" {
		if len(segments) >= 1 && segments[0] != "" {
			org := segments[0]
			companions := []string{
				fmt.Sprintf("codeload.github.com/%s/**", org),
				fmt.Sprintf("api.github.com/repos/%s/**", org),
				fmt.Sprintf("raw.githubusercontent.com/%s/**", org),
			}
			return "github.com", fmt.Sprintf("/%s/**", org), companions
		}
	}

	if host == "api.github.com" && len(segments) >= 2 && segments[0] == "repos" {
		org := segments[1]
		return "github.com", fmt.Sprintf("/%s/**", org), []string{
			fmt.Sprintf("codeload.github.com/%s/**", org),
			fmt.Sprintf("api.github.com/repos/%s/**", org),
		}
	}

	if host == "objects.githubusercontent.com" || host == "release-assets.githubusercontent.com" {
		return host, "/github-production-release-asset-**", nil
	}

	if strings.HasSuffix(host, ".ubuntu.com") {
		return "*.ubuntu.com", "/ubuntu/**", nil
	}

	if len(segments) >= 2 && segments[0] != "" {
		return host, fmt.Sprintf("/%s/**", segments[0]), nil
	}
	return host, "/**", nil
}
