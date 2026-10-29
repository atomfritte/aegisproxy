package store

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/netguard"
)

// ServerIdentity is the resolved requester of a proxy request.
type ServerIdentity struct {
	ID       string
	Hostname string
	GroupIDs []string
	// Method is how the server was identified: "token", "username" (bare proxy username bound to the server's IP
	// or subnet), "ip", "cidr" or "" (unregistered source).
	Method string
	// AuthError is set when proxy credentials were presented but identify no server: "invalid_proxy_token", or
	// "proxy_token_required" (a bare username for a member of a group with require_proxy_token). The request is
	// refused (AUTH_FAILED, HTTP 407); it never falls back to the source address.
	AuthError string
}

func identified(srv models.Server, method string) ServerIdentity {
	return ServerIdentity{ID: srv.ID, Hostname: srv.Hostname, GroupIDs: append([]string(nil), srv.GroupIDs...), Method: method}
}

func unregistered(cleanIP, authErr string) ServerIdentity {
	return ServerIdentity{ID: engine.UnregisteredPrefix + cleanIP, Hostname: "unregistered-" + cleanIP, GroupIDs: []string{}, AuthError: authErr}
}

func tokenRequired(idx *engine.CompiledPolicyIndex, srv models.Server) bool {
	return slices.ContainsFunc(srv.GroupIDs, func(g string) bool { return idx.TokenGroups[g] })
}

// Identify resolves the calling server. Presented credentials decide alone: a proxy token ("username:token" or a
// bare token) or a bare proxy username bound to the server's IP/subnet; anything else is an authentication
// failure. Without credentials the source address identifies the server it is registered for (only when exactly
// one server has it and none of its groups requires a proxy token), then group CIDRs (except groups requiring a
// token). Unknown sources get no group membership. Same as Policy.identify in the data-plane.
func (s *Store) Identify(ip, proxyAuth string) ServerIdentity {
	s.mu.RLock()
	idx := s.compiledIdx
	s.mu.RUnlock()

	cleanIP := strings.TrimPrefix(strings.TrimSpace(ip), "::ffff:")
	authTrimmed := strings.TrimSpace(proxyAuth)
	if idx == nil {
		return unregistered(cleanIP, "")
	}
	if authTrimmed != "" {
		if user, tok, ok := strings.Cut(authTrimmed, ":"); ok {
			if srv, found := idx.ServerByToken[engine.HashProxyToken(tok)]; found && (user == "" || strings.EqualFold(user, srv.ProxyAuthUser)) {
				return identified(srv, "token")
			}
			return unregistered(cleanIP, "invalid_proxy_token")
		}
		if srv, found := idx.ServerByToken[engine.HashProxyToken(authTrimmed)]; found {
			return identified(srv, "token")
		}
		// A bare username only counts from the server's registered IP or SubnetCIDR (prevents cross-server
		// Proxy-Authorization spoofing).
		if srv, found := idx.ServerByAuth[strings.ToLower(authTrimmed)]; found &&
			(cleanIP == srv.IP || (srv.SubnetCIDR != "" && engine.MatchCIDR(srv.SubnetCIDR, cleanIP))) {
			if tokenRequired(idx, srv) {
				return unregistered(cleanIP, "proxy_token_required")
			}
			return identified(srv, "username")
		}
		return unregistered(cleanIP, "invalid_proxy_token")
	}

	if srv, ok := idx.ServerByIP[cleanIP]; ok && !tokenRequired(idx, srv) {
		return identified(srv, "ip")
	}
	if addr, err := netip.ParseAddr(cleanIP); err == nil {
		var matchedGroups []string
		for _, c := range idx.ParsedCIDRs {
			if c.Prefix.Contains(addr.Unmap()) && !slices.Contains(matchedGroups, c.GroupID) {
				matchedGroups = append(matchedGroups, c.GroupID)
			}
		}
		if len(matchedGroups) > 0 {
			octets := strings.NewReplacer(".", "-", ":", "-").Replace(cleanIP)
			return ServerIdentity{ID: "srv-auto-" + octets, Hostname: "node-" + octets, GroupIDs: matchedGroups, Method: "cidr"}
		}
	}
	// Strict zero-trust default: unregistered sources receive no group membership.
	return unregistered(cleanIP, "")
}

// ResolveServer returns ID, host name and groups of Identify (an authentication failure resolves to the
// unregistered source).
func (s *Store) ResolveServer(ip, proxyAuth string) (string, string, []string) {
	id := s.Identify(ip, proxyAuth)
	return id.ID, id.Hostname, id.GroupIDs
}

func matchesTLSBypassScope(b models.TLSBypassRule, srvID string, groupIDs []string, strict map[string]bool) bool {
	for _, sid := range b.ServerIDs {
		if sid == "*" || sid == srvID {
			return true
		}
	}
	if len(b.GroupIDs) > 0 {
		for _, bg := range b.GroupIDs {
			if bg == "*" {
				for _, g := range groupIDs {
					if strict[g] {
						return false
					}
				}
				return len(groupIDs) > 0
			}
			if slices.Contains(groupIDs, bg) {
				return true
			}
		}
		return false
	}
	if len(b.ServerIDs) > 0 {
		return false
	}
	// Global TLS bypass rule (no explicit scope): require at least one registered group and never
	// apply to strict-isolation (zero-internet) tiers.
	if len(groupIDs) == 0 {
		return false
	}
	for _, g := range groupIDs {
		if strict[g] {
			return false
		}
	}
	return true
}

func isPunycode(host string) bool {
	for _, label := range strings.Split(host, ".") {
		if strings.HasPrefix(label, "xn--") {
			return true
		}
	}
	return false
}

// alwaysForbiddenAddr covers destinations no rule may ever open through the proxy: loopback
// (the proxy's own services), link-local (cloud metadata 169.254.169.254), the other cloud metadata endpoints
// (Azure WireServer, see netguard.CloudMetadata), unspecified and multicast, also embedded in IPv6 (NAT64, 6to4,
// IPv4-compatible). Same as is_forbidden_addr in the data-plane.
func alwaysForbiddenAddr(a netip.Addr) bool { return netguard.IsForbiddenDestination(a) }

func blockResult(res engine.EvaluationResult, verdict, reason, name string) engine.EvaluationResult {
	res.Allowed = false
	res.Verdict = verdict
	res.BlockReason = reason
	res.MatchedRuleName = name
	res.FollowRedirects = false
	res.TLSBypass = false
	return res
}

// authFailedMessages explain AUTH_FAILED verdicts (block page / CLI text of the data-plane's 407 response).
var authFailedMessages = map[string]string{
	"invalid_proxy_token":  "Proxy authentication failed: the presented proxy credentials match no registered server (unknown, rotated or mistyped token)",
	"proxy_token_required": "Proxy authentication failed: this server's group requires its proxy token (a proxy username alone is not accepted)",
}

// Evaluate applies, in order: proxy authentication, server quarantine, threat intelligence, destination hygiene
// (internal/IP-literal/port/punycode), explicit BLOCK guardrails, TLS passthrough, learning sessions, redirect-object
// grants and ALLOW rules. Anything unmatched is denied. The Python data-plane implements the same order.
func (s *Store) Evaluate(req engine.EvaluationRequest) engine.EvaluationResult {
	ident := s.Identify(req.ServerIP, req.ProxyAuthUser)
	srvID, srvHost, groupIDs := ident.ID, ident.Hostname, ident.GroupIDs
	host := engine.NormalizeHost(req.Host)
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = "GET"
	}
	res := engine.EvaluationResult{
		Allowed:        false,
		Verdict:        models.VerdictBlocked,
		ServerID:       srvID,
		ServerHostname: srvHost,
		GroupIDs:       groupIDs,
		SuggestedHost:  host,
		SuggestedPath:  "/**",
	}
	if ident.AuthError != "" {
		return blockResult(res, models.VerdictAuthFailed, ident.AuthError, authFailedMessages[ident.AuthError])
	}

	s.mu.RLock()
	quarantined := s.quarantined[srvID]
	s.mu.RUnlock()
	if quarantined {
		return blockResult(res, models.VerdictQuarantined, "quarantined",
			"Incident response: this server is quarantined — all outbound access is blocked")
	}

	cleanPath, pathOK := engine.CanonicalizePath(req.Path)
	if !pathOK {
		return blockResult(res, models.VerdictPolicyBlocked, "malformed_path", "Security Guard: Malformed / Traversal Path Anomaly")
	}
	if method == "CONNECT" {
		cleanPath = "/"
	}
	res.SuggestedHost, res.SuggestedPath, _ = engine.SuggestRulePattern(host, cleanPath)
	if host == "" {
		return blockResult(res, models.VerdictPolicyBlocked, "missing_host", "Security Guard: Missing destination host")
	}

	s.mu.RLock()
	idx := s.compiledIdx
	tlsBypass := s.state.TLSBypass
	sessions := s.state.Sessions
	policy := s.state.SecurityPolicy
	allowedPorts := s.state.SecurityPolicy.AllowedPorts
	s.mu.RUnlock()

	// 1. Threat intelligence (malware / phishing / C2 / hijacked networks / custom IOCs).
	if s.threat != nil && policy.ThreatIntelMode != "off" {
		snap := s.threat.Snapshot()
		m, hit := snap.MatchHost(host)
		if !hit && req.FullURL != "" {
			m, hit = snap.MatchURL(req.FullURL)
		}
		if hit {
			res.ThreatCategory, res.ThreatSource, res.ThreatIndicator = m.Category, m.SourceName, m.Indicator
			if policy.ThreatIntelMode == "block" {
				res = blockResult(res, models.VerdictThreatBlocked, "threat_intel",
					fmt.Sprintf("Threat Intelligence: %s (%s)", m.Category, m.SourceName))
				res.MatchedRuleID = m.SourceID
				return res
			}
			res.SecurityFlags = append(res.SecurityFlags, "THREAT_MONITOR:"+m.Category)
		}
	}

	// 2. Destination hygiene.
	addr, addrErr := netip.ParseAddr(host)
	isIPLiteral := addrErr == nil
	if isIPLiteral && alwaysForbiddenAddr(addr) {
		return blockResult(res, models.VerdictPolicyBlocked, "forbidden_destination",
			"Security Guard: Loopback / link-local / metadata destinations are never reachable via the proxy")
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return blockResult(res, models.VerdictPolicyBlocked, "forbidden_destination", "Security Guard: localhost is never reachable via the proxy")
	}
	if req.Port > 0 && len(allowedPorts) > 0 && !slices.Contains(allowedPorts, req.Port) {
		return blockResult(res, models.VerdictPolicyBlocked, "port_not_allowed",
			fmt.Sprintf("Security Guard: destination port %d is not in the allowed port list", req.Port))
	}
	internalDest := policy.BlockPrivateDestinations && engine.IsInternalHost(host)
	if isPunycode(host) {
		switch policy.PunycodeMode {
		case "block":
			return blockResult(res, models.VerdictPolicyBlocked, "punycode",
				"Security Guard: Internationalized (punycode) domain blocked (homograph protection)")
		case "monitor":
			res.SecurityFlags = append(res.SecurityFlags, "PUNYCODE")
		}
	}

	if idx == nil {
		return res
	}

	// 3. Explicit BLOCK guardrails take precedence over every allow mechanism.
	if r, ok := matchIndexedRules(idx, host, cleanPath, method, srvID, groupIDs, true, false); ok {
		res.MatchedRuleID, res.MatchedRuleName = r.ID, r.Name
		res.BlockReason = "block_rule"
		return res
	}

	// 4. SSL/TLS no-break passthrough (scoped; never for strict-isolation tiers).
	now := time.Now().UTC()
	for _, b := range tlsBypass {
		if !b.Enabled || (b.ExpiresAt != nil && now.After(*b.ExpiresAt)) {
			continue
		}
		if internalDest && strings.Contains(b.Pattern, "*") {
			continue
		}
		if engine.MatchHost(b.Pattern, host) && matchesTLSBypassScope(b, srvID, groupIDs, idx.StrictGroups) {
			res.TLSBypass = true
			res.Allowed = true
			res.Verdict = models.VerdictTLSBypass
			res.MatchedRuleID = b.ID
			res.MatchedRuleName = "TLS Passthrough: " + b.Pattern
			return res
		}
	}

	ipLiteralNeedsExplicit := isIPLiteral && policy.BlockIPLiterals
	implicitAllowOK := !internalDest && !ipLiteralNeedsExplicit
	// Temporary grants (learning sessions, redirect objects) never open anything for strict-isolation tiers.
	strict := slices.ContainsFunc(groupIDs, func(g string) bool { return idx.StrictGroups[g] })

	// 5. Active learning session, bound to the resolved server identity (the source address only counts where
	// Identify accepted it: no credentials and registered for exactly this server). Never opens internal or
	// IP-literal destinations.
	if implicitAllowOK {
		for _, sess := range sessions {
			if sess.Status == "active" && now.Before(sess.ExpiresAt) && sess.ServerID == srvID {
				res.SessionID = sess.ID
				if sess.Mode == "record_and_allow" && !strict {
					res.Allowed = true
					res.Verdict = models.VerdictLearningAllowed
					res.MatchedRuleID = sess.ID
					res.MatchedRuleName = "Learning Session: " + sess.Name
					res.FollowRedirects = true
					return res
				}
			}
		}

		// 6. Ephemeral 302 redirect object grant of this server (GET/HEAD/CONNECT only, single hop).
		scheme, port := engine.RequestOrigin(req.FullURL, req.Scheme, req.Port)
		if grant, ok := s.engine.CheckRedirectGrant(srvID, scheme, host, port, cleanPath, method); ok && !strict {
			res.Allowed = true
			res.Verdict = models.VerdictRedirectObject
			res.MatchedRuleID = grant.RuleID
			res.MatchedRuleName = grant.RuleName + " (Object Redirect)"
			res.RedirectParentURL = grant.ParentURL
			res.FollowRedirects = false
			return res
		}
	}

	// 7. ALLOW rules. Internal and IP-literal destinations require an explicit (non-wildcard) rule.
	if r, ok := matchIndexedRules(idx, host, cleanPath, method, srvID, groupIDs, false, !implicitAllowOK); ok {
		res.Allowed = true
		res.Verdict = models.VerdictAllowed
		res.MatchedRuleID, res.MatchedRuleName = r.ID, r.Name
		res.FollowRedirects = r.FollowRedirects
		return res
	}

	if ipLiteralNeedsExplicit {
		return blockResult(res, models.VerdictPolicyBlocked, "ip_literal",
			"Security Guard: Direct IP-address destinations require an explicit whitelist rule")
	}
	if internalDest {
		return blockResult(res, models.VerdictPolicyBlocked, "internal_destination",
			"Security Guard: Internal destinations are not reachable via the egress proxy without an explicit rule")
	}
	res.BlockReason = "default_deny"
	return res
}

// matchIndexedRules finds the first BLOCK (wantBlock) or ALLOW rule that applies to the request.
// explicitOnly skips rules whose host pattern contains a wildcard.
func matchIndexedRules(idx *engine.CompiledPolicyIndex, host, path, method, srvID string, groupIDs []string, wantBlock, explicitOnly bool) (models.PolicyRule, bool) {
	check := func(ir engine.IndexedRule) bool {
		if strings.EqualFold(ir.Rule.Action, "BLOCK") != wantBlock {
			return false
		}
		if explicitOnly && strings.Contains(ir.LowerHostPat, "*") {
			return false
		}
		return ir.AppliesTo(srvID, groupIDs) && engine.MatchRule(ir.Rule, host, path, method)
	}
	for _, ir := range idx.ExactHostRules[host] {
		if check(ir) {
			return ir.Rule, true
		}
	}
	for _, ir := range idx.WildcardRules {
		if check(ir) {
			return ir.Rule, true
		}
	}
	return models.PolicyRule{}, false
}
