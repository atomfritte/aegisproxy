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

// ResolveServer identifies the calling server by proxy token, (IP-bound) proxy username,
// registered IP or group CIDR — in that order. Unknown sources get no group membership.
func (s *Store) ResolveServer(ip, proxyAuthUser string) (string, string, []string) {
	s.mu.RLock()
	idx := s.compiledIdx
	s.mu.RUnlock()

	cleanIP := strings.TrimPrefix(strings.TrimSpace(ip), "::ffff:")
	authTrimmed := strings.TrimSpace(proxyAuthUser)

	if idx != nil {
		if authTrimmed != "" {
			// 1. "username:token" (Basic auth) or bare bearer token, verified via SHA-256 digest.
			if user, tok, ok := strings.Cut(authTrimmed, ":"); ok {
				if srv, found := idx.ServerByToken[engine.HashProxyToken(tok)]; found &&
					(user == "" || strings.EqualFold(user, srv.ProxyAuthUser)) {
					return srv.ID, srv.Hostname, append([]string(nil), srv.GroupIDs...)
				}
			} else if srv, found := idx.ServerByToken[engine.HashProxyToken(authTrimmed)]; found {
				return srv.ID, srv.Hostname, append([]string(nil), srv.GroupIDs...)
			}
			// 2. Bare username is only accepted if the source IP matches the server's registered IP or
			// SubnetCIDR (prevents cross-server Proxy-Authorization spoofing).
			if !strings.Contains(authTrimmed, ":") {
				if srv, ok := idx.ServerByAuth[strings.ToLower(authTrimmed)]; ok {
					if cleanIP == srv.IP || (srv.SubnetCIDR != "" && engine.MatchCIDR(srv.SubnetCIDR, cleanIP)) {
						return srv.ID, srv.Hostname, append([]string(nil), srv.GroupIDs...)
					}
				}
			}
		}

		if srv, ok := idx.ServerByIP[cleanIP]; ok {
			return srv.ID, srv.Hostname, append([]string(nil), srv.GroupIDs...)
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
				return "srv-auto-" + octets, "node-" + octets, matchedGroups
			}
		}
	}

	// Strict zero-trust default: unregistered sources receive no group membership.
	return "srv-unregistered-" + cleanIP, "unregistered-" + cleanIP, []string{}
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
// (Azure WireServer, see netguard.CloudMetadata), unspecified and multicast. Same as is_forbidden_addr in the
// data-plane.
func alwaysForbiddenAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsUnspecified() || a.IsMulticast() ||
		netguard.CloudMetadata(a)
}

func blockResult(res engine.EvaluationResult, verdict, reason, name string) engine.EvaluationResult {
	res.Allowed = false
	res.Verdict = verdict
	res.BlockReason = reason
	res.MatchedRuleName = name
	res.FollowRedirects = false
	res.TLSBypass = false
	return res
}

// Evaluate applies, in order: server quarantine, threat intelligence, destination hygiene (internal/IP-literal/port/
// punycode), explicit BLOCK guardrails, TLS passthrough, learning sessions, redirect-object grants
// and ALLOW rules. Anything unmatched is denied. The Python data-plane implements the same order.
func (s *Store) Evaluate(req engine.EvaluationRequest) engine.EvaluationResult {
	srvID, srvHost, groupIDs := s.ResolveServer(req.ServerIP, req.ProxyAuthUser)
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

	// 5. Active learning session (strictly scoped to the reference server; never opens internal or
	// IP-literal destinations).
	if implicitAllowOK {
		for _, sess := range sessions {
			if sess.Status == "active" && now.Before(sess.ExpiresAt) &&
				(sess.ServerID == srvID || sess.ServerIP == strings.TrimPrefix(req.ServerIP, "::ffff:")) {
				res.SessionID = sess.ID
				if sess.Mode == "record_and_allow" {
					res.Allowed = true
					res.Verdict = models.VerdictLearningAllowed
					res.MatchedRuleID = sess.ID
					res.MatchedRuleName = "Learning Session: " + sess.Name
					res.FollowRedirects = true
					return res
				}
			}
		}

		// 6. Ephemeral 302 redirect object grant (GET/HEAD/CONNECT only, single hop).
		if grant, ok := s.engine.CheckRedirectGrant(req.ServerIP, host, cleanPath, method); ok {
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
