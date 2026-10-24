package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/store"
)

const (
	maxSSEClients = 200
	maxSSEPerUser = 8 // one user (or service account) cannot take all stream slots
)

func (s *Server) handleGetState(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	snap := s.store.GetSnapshot()
	servers := s.store.Servers()
	bandwidth := s.store.ComputeBandwidthSummary()
	// Notification logs carry delivery details of the webhook integrations (system settings).
	notifyLogs := []models.NotificationLog{}
	if auth.CanManageSystem(claims) {
		notifyLogs = s.notifier.GetLogs()
	}
	scope := scopeFor(claims)
	if scope != nil {
		snap, servers = scope.snapshot(snap, servers)
		bandwidth = scope.bandwidth(bandwidth)
	}

	totalFleetServers := 0
	for _, g := range snap.Groups {
		totalFleetServers += g.ServerCount
	}
	stats := map[string]int{"allowed": 0, "blocked": 0, "bypass": 0, "learning": 0, "threats": 0}
	for _, f := range snap.Flows {
		switch f.Verdict {
		case models.VerdictAllowed, models.VerdictRedirectObject:
			stats["allowed"]++
		case models.VerdictBlocked:
			stats["blocked"]++
		case models.VerdictTLSBypass:
			stats["bypass"]++
		case models.VerdictLearningAllowed:
			stats["learning"]++
		default:
			if models.IsSecurityVerdict(f.Verdict) {
				stats["blocked"]++
				stats["threats"]++
			}
		}
	}
	openEvents := 0
	for _, ev := range snap.SecurityEvents {
		if !ev.Acknowledged {
			openEvents++
		}
	}
	stats["open_security_events"] = openEvents

	notifyCfg := s.notifier.GetConfig().Public()
	feeds := snap.ThreatFeeds
	var tiStatus models.ThreatIntelStatus
	if ti := s.store.ThreatIntel(); ti != nil {
		feeds = ti.FeedsWithStatus(s.store.ThreatFeedConfigs())
		tiStatus = ti.Snapshot().Status()
	}

	me, _ := s.store.GetUserByID(claims.UserID)
	resp := map[string]any{
		"revision":            snap.Revision,
		"version":             s.version,
		"demo_mode":           s.store.DemoMode(),
		"fleet_total_servers": totalFleetServers,
		"groups":              snap.Groups,
		"servers":             publicServers(servers),
		"rules":               snap.Rules,
		"policy_sets":         snap.PolicySets,
		"change_requests":     scopedChangeRequests(snap.ChangeRequests, scope),
		"governance":          snap.Governance,
		"block_pages":         snap.BlockPages,
		"overview":            overviewStats(snap, servers, claims),
		"proxy_address":       s.cfg.ProxyAddress,
		"tls_bypass":          nonNil(snap.TLSBypass),
		"sessions":            snap.Sessions,
		"requests":            nonNil(snap.Requests),
		"users":               snap.Users,
		"entra_config":        s.store.SSOSettings(s.cfg.PublicURL).Public(),
		"notify_config":       notifyCfg,
		"notification_logs":   notifyLogs,
		"audit_events":        snap.AuditEvents,
		"bandwidth":           bandwidth,
		"stats":               stats,
		"data_planes":         s.DataPlanes(),
		"security": map[string]any{
			"policy":        snap.SecurityPolicy,
			"feeds":         feeds,
			"indicators":    nonNil(snap.Indicators),
			"exceptions":    nonNil(snap.ThreatExceptions),
			"events":        nonNil(snap.SecurityEvents),
			"threat_intel":  tiStatus,
			"dlp_detectors": store.DLPDetectors,
			"file_types":    store.FileTypes,
		},
	}
	if me != nil {
		resp["me"] = me.Public()
	}
	if r.URL.Query().Get("exclude_flows") != "1" {
		resp["flows"] = nonNil(snap.Flows)
	}
	writeJSON(w, http.StatusOK, resp)
}

// flowStreamRecheck is how often an open flow stream re-validates its session and scope.
var flowStreamRecheck = time.Minute

func (s *Server) handleFlowStream(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	s.sseMu.Lock()
	if s.sseClients >= maxSSEClients || s.ssePerUser[claims.UserID] >= maxSSEPerUser {
		s.sseMu.Unlock()
		writeError(w, http.StatusTooManyRequests, "too many live stream connections (close other console tabs)")
		return
	}
	s.sseClients++
	s.ssePerUser[claims.UserID]++
	s.sseMu.Unlock()
	defer func() {
		s.sseMu.Lock()
		s.sseClients--
		if s.ssePerUser[claims.UserID]--; s.ssePerUser[claims.UserID] <= 0 {
			delete(s.ssePerUser, claims.UserID)
		}
		s.sseMu.Unlock()
	}()

	// Long-lived stream: lift the server-wide write timeout for this response only.
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	scope := scopeFor(claims)
	ch := s.store.SubscribeFlows()
	defer s.store.UnsubscribeFlows(ch)

	_, _ = fmt.Fprintf(w, "retry: 5000\nevent: connected\ndata: {\"status\":\"live\"}\n\n")
	flusher.Flush()

	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()
	// Re-validate the session periodically so revoked/expired sessions stop receiving data.
	recheck := time.NewTicker(flowStreamRecheck)
	defer recheck.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-recheck.C:
			fresh, _, err := s.getClaims(r)
			if err != nil {
				_, _ = fmt.Fprint(w, "event: session_expired\ndata: {}\n\n")
				flusher.Flush()
				return
			}
			// Role and group changes (users and service accounts) apply to the open stream as well.
			scope = scopeFor(fresh)
		case flow, ok := <-ch:
			if !ok {
				return
			}
			if scope != nil && !scope.anyOf(flow.GroupIDs) {
				continue
			}
			b, _ := json.Marshal(flow)
			if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) handleExportAudit(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if scopeFor(claims) != nil {
		writeError(w, http.StatusForbidden, "RBAC Policy: the complete audit trail is available to InfoSec Approvers, Super Admins and Auditors")
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="aegis-audit-%s.jsonl"`, time.Now().UTC().Format("20060102-150405")))
	// Long-running download: lift the server-wide write timeout for this response only.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	if err := s.store.ExportAudit(r.Context(), w, s.cfg.AuditLogPath); err != nil {
		s.log.Warn("audit export interrupted", "error", err)
	}
}

func (s *Server) handleReviewRequest(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var body store.ReviewOptions
	if !decodeJSON(w, r, &body) {
		return
	}
	req, rules, err := s.store.ReviewAccessRequest(r.PathValue("id"), body, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	var first *models.PolicyRule
	if len(rules) > 0 {
		first = &rules[0]
	}
	writeJSON(w, http.StatusOK, map[string]any{"request": req, "rule": first, "rules": nonNil(rules)})
}

func (s *Server) handleStartSession(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var body struct {
		Name            string `json:"name"`
		Description     string `json:"description"`
		ServerID        string `json:"server_id"`
		DurationMinutes int    `json:"duration_minutes"`
		Mode            string `json:"mode"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	sess, err := s.store.StartLearningSession(body.Name, body.Description, body.ServerID, body.DurationMinutes, body.Mode, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, sess)
}

func (s *Server) handleStopSession(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	sess, err := s.store.StopLearningSession(r.PathValue("id"), claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sess)
}

func (s *Server) handlePublishSession(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var body store.SessionPublish
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.RulePrefix == "" {
		body.RulePrefix = "Session-Policy"
	}
	set, rules, err := s.store.PublishSessionRules(r.PathValue("id"), body, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"published_count": len(rules), "policy_set": set, "published": set.Draft == nil})
}

// handleSimulateSessionFlows injects canned sample traffic into a learning session. It only
// exists for demonstrations and is disabled outside AEGIS_DEMO_MODE.
func (s *Server) handleSimulateSessionFlows(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !s.store.DemoMode() {
		writeError(w, http.StatusForbidden, "Traffic simulation is only available in demo mode (AEGIS_DEMO_MODE=true)")
		return
	}
	var body struct {
		Scenario string `json:"scenario"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	sess, ok := s.store.GetSession(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "Session not found")
		return
	}
	if !auth.CanApproveForGroups(claims, sess.GroupIDs) {
		writeError(w, http.StatusForbidden, "RBAC Policy: Insufficient permissions for this session's server groups")
		return
	}
	if !sess.Recording(time.Now()) {
		writeError(w, http.StatusConflict, "The learning session is no longer recording")
		return
	}
	flows := demoSessionFlows(sess, body.Scenario)
	s.store.RecordFlowBatch(flows)
	writeJSON(w, http.StatusOK, map[string]any{"recorded": len(flows)})
}

func (s *Server) handleAddTLSBypass(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var rule models.TLSBypassRule
	if !decodeJSON(w, r, &rule) {
		return
	}
	created, err := s.store.AddTLSBypass(rule, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleToggleTLSBypass(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if err := s.store.ToggleTLSBypass(r.PathValue("id"), body.Enabled, claims); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleDeleteTLSBypass(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if err := s.store.DeleteTLSBypass(r.PathValue("id"), claims); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleUpdateEntra(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var cfg models.EntraIDConfig
	if !decodeJSON(w, r, &cfg) {
		return
	}
	if err := s.store.UpdateEntraConfig(cfg, claims); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.store.SSOSettings(s.cfg.PublicURL).Public())
}

func (s *Server) handleUpdateNotifications(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var cfg models.NotificationConfig
	if !decodeJSON(w, r, &cfg) {
		return
	}
	if err := s.store.UpdateNotificationConfig(cfg, claims); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.notifier.GetConfig().Public())
}

func (s *Server) handleTestNotification(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !s.requireSystem(w, claims) {
		return
	}
	testReq := models.AccessRequest{
		ID:                   fmt.Sprintf("req-test-%d", time.Now().Unix()%10000),
		ServerIP:             "192.0.2.15",
		ServerHostname:       "test-runner.example",
		GroupIDs:             []string{"test-group"},
		RequestedURL:         "https://github.com/example/project/releases/download/v1.0/artifact.tar.gz",
		Host:                 "github.com",
		Path:                 "/example/project/releases/download/v1.0/artifact.tar.gz",
		Method:               "GET",
		Requester:            claims.Username,
		Reason:               "Webhook verification test for Microsoft Teams (Adaptive Card) & Slack (Block Kit).",
		RequestedScope:       "prefix_with_objects",
		SuggestedHostPattern: "github.com",
		SuggestedPathPattern: "/example/**",
		FollowRedirects:      true,
		Duration:             "24h",
		Verified:             true,
	}
	s.notifier.NotifyAccessRequest(testReq)
	writeJSON(w, http.StatusOK, map[string]any{"status": "queued", "logs": s.notifier.GetLogs()})
}

// handleSimulateProxyRequest is a side-effect-free policy simulator ("what would happen if server
// X requested URL Y?"). Outside demo mode it never records flows, mints redirect grants or touches
// learning sessions.
func (s *Server) handleSimulateProxyRequest(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var body struct {
		ServerIP      string `json:"server_ip"`
		ProxyAuthUser string `json:"proxy_auth_user"`
		Method        string `json:"method"`
		FullURL       string `json:"full_url"`
		UserAgent     string `json:"user_agent"`
		SimulateRedir bool   `json:"simulate_redirect"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	parsed, err := url.Parse(strings.TrimSpace(body.FullURL))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || len(body.FullURL) > 4096 {
		writeError(w, http.StatusBadRequest, "full_url must be an absolute http(s) URL")
		return
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	body.Method = strings.ToUpper(strings.TrimSpace(body.Method))
	if body.Method == "" {
		body.Method = "GET"
	}
	if body.UserAgent == "" {
		body.UserAgent = "curl/8.5.0"
	}
	port := 0
	if p := parsed.Port(); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}

	res := s.store.Evaluate(engine.EvaluationRequest{
		ServerIP: body.ServerIP, ProxyAuthUser: body.ProxyAuthUser, Method: body.Method, Scheme: parsed.Scheme,
		Host: parsed.Hostname(), Port: port, Path: path, FullURL: body.FullURL, UserAgent: body.UserAgent,
	})
	if scope := scopeFor(claims); scope != nil && !scope.anyOf(res.GroupIDs) {
		// Team Leads simulate their own servers only; unknown and foreign sources get the same answer.
		writeError(w, http.StatusNotFound, "no server of your groups has this address or proxy user")
		return
	}
	mutate := s.store.DemoMode() && (auth.CanManageSystem(claims) || auth.CanApproveForGroups(claims, res.GroupIDs))

	statusCode := 200
	redirectLoc := ""
	if res.Verdict == models.VerdictAuthFailed {
		statusCode = 407
	} else if !res.Allowed {
		statusCode = 403
	} else if body.SimulateRedir && res.FollowRedirects && strings.EqualFold(parsed.Hostname(), "github.com") {
		statusCode = 302
		redirectLoc = "https://objects.githubusercontent.com/github-production-release-asset-2e65be/9981234/release-artifact.tar.gz"
	}

	flow := models.TrafficFlow{
		ID:                fmt.Sprintf("flw-sim-%d", time.Now().UnixNano()),
		Timestamp:         time.Now().UTC(),
		ServerIP:          body.ServerIP,
		ServerID:          res.ServerID,
		ServerHostname:    res.ServerHostname,
		GroupIDs:          res.GroupIDs,
		ProxyAuthUser:     body.ProxyAuthUser,
		Method:            body.Method,
		Scheme:            parsed.Scheme,
		Host:              engine.NormalizeHost(parsed.Host),
		Path:              path,
		FullURL:           body.FullURL,
		UserAgent:         body.UserAgent,
		Verdict:           res.Verdict,
		MatchedRuleID:     res.MatchedRuleID,
		MatchedRuleName:   res.MatchedRuleName,
		RedirectParentURL: res.RedirectParentURL,
		RedirectLocation:  redirectLoc,
		StatusCode:        statusCode,
		LatencyMs:         19,
		TLSIntercepted:    !res.TLSBypass,
		FollowRedirects:   res.FollowRedirects,
		SessionID:         res.SessionID,
		BlockReason:       res.BlockReason,
		ThreatCategory:    res.ThreatCategory,
		ThreatSource:      res.ThreatSource,
		ThreatIndicator:   res.ThreatIndicator,
		SecurityFlags:     res.SecurityFlags,
	}
	if mutate {
		flow = s.store.RecordFlow(flow)
	}

	var childFlow *models.TrafficFlow
	if redirectLoc != "" {
		uChild, _ := url.Parse(redirectLoc)
		childEval := s.store.Evaluate(engine.EvaluationRequest{
			ServerIP: body.ServerIP, ProxyAuthUser: body.ProxyAuthUser, Method: "GET", Scheme: "https",
			Host: uChild.Host, Path: uChild.Path, FullURL: redirectLoc, UserAgent: body.UserAgent,
		})
		verdict, ruleName := childEval.Verdict, childEval.MatchedRuleName
		if !mutate && childEval.Verdict == models.VerdictBlocked && childEval.BlockReason == "default_deny" {
			// Dry run: no grant was minted, so show what the redirect lineage would produce.
			verdict, ruleName = models.VerdictRedirectObject, res.MatchedRuleName+" (Object Redirect)"
		}
		cf := models.TrafficFlow{
			ID: fmt.Sprintf("flw-sim-%d", time.Now().UnixNano()), Timestamp: time.Now().UTC(),
			ServerIP: body.ServerIP, ServerID: childEval.ServerID, ServerHostname: childEval.ServerHostname,
			GroupIDs: childEval.GroupIDs, ProxyAuthUser: body.ProxyAuthUser, Method: "GET", Scheme: uChild.Scheme,
			Host: uChild.Host, Path: uChild.Path, FullURL: redirectLoc, UserAgent: body.UserAgent,
			Verdict: verdict, MatchedRuleID: childEval.MatchedRuleID, MatchedRuleName: ruleName,
			RedirectParentURL: body.FullURL, StatusCode: 200, LatencyMs: 98, TLSIntercepted: true, SessionID: childEval.SessionID,
		}
		if mutate {
			cf = s.store.RecordFlow(cf)
		}
		childFlow = &cf
	}

	cliOutput := ""
	if !res.Allowed {
		// Only a demo-mode simulation by someone who may act for the server gets a real (verifiable)
		// block token; otherwise anyone could mint "verified" access requests for any server.
		blockToken := "simulated-block-token"
		if mutate && res.Verdict != models.VerdictAuthFailed {
			blockToken, _ = auth.SignBlockToken(s.cfg.DataPlaneKey, auth.BlockClaims{
				ServerIP: body.ServerIP, ServerID: res.ServerID, URL: body.FullURL, Method: body.Method, TraceID: flow.ID, Verdict: res.Verdict,
			})
		}
		cliOutput = renderCLIBlock(s.cfg.PublicURL, s.cfg.DashboardURL, res, statusCode, body.ServerIP, body.Method, body.FullURL, flow.ID, blockToken)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"evaluation": res,
		"flow":       flow,
		"child_flow": childFlow,
		"cli_output": cliOutput,
		"dry_run":    !mutate,
	})
}

// renderCLIBlock mirrors the terminal block message produced by the data-plane.
func renderCLIBlock(publicURL, dashboardURL string, res engine.EvaluationResult, status int, serverIP, method, fullURL, traceID, blockToken string) string {
	payload, _ := json.Marshal(map[string]string{
		"block_token":     blockToken,
		"requester":       "admin@" + res.ServerHostname,
		"reason":          "ENTER_REASON_HERE",
		"requested_scope": "prefix_with_objects",
		"duration":        "24h",
	})
	reason := res.MatchedRuleName
	if reason == "" {
		reason = "No matching path/object whitelist rule (default deny)"
	}
	selfService := fmt.Sprintf(` 🚀 1. REQUEST ACCESS IN BROWSER (Self-Service Block Portal):
    %s/?portal=block&bt=%s

 💻 2. REQUEST ACCESS DIRECTLY VIA CLI (Headless Server One-Liner):
    curl -sX POST %s/api/public/requests \
      -H "Content-Type: application/json" \
      -d %s
`, dashboardURL, url.QueryEscape(blockToken), publicURL, shellQuoteSingle(string(payload)))
	if res.Verdict == models.VerdictAuthFailed {
		selfService = " 🔑 " + authFailedHelp + "\n"
	} else if models.IsSecurityVerdict(res.Verdict) && res.Verdict != models.VerdictPolicyBlocked {
		selfService = " ⛔ This destination was blocked by threat protection. Self-service requests are disabled;\n    contact InfoSec with the Trace ID above if you believe this is a false positive.\n"
	}
	return fmt.Sprintf(`================================================================================
 🛡️  AEGISPROXY ENTERPRISE ZERO-TRUST GATEWAY — ACCESS BLOCKED (HTTP %d)
================================================================================
 Server Hostname : %s (%s)
 Server Groups   : %s
 Blocked URL     : [%s] %s
 Trace ID        : %s
 Policy Verdict  : %s — %s
--------------------------------------------------------------------------------
%s
 🔐 3. INSTALL SSL/TLS ROOT CA CERTIFICATE ON THIS SERVER (compare the installer's SHA-256 with
    the AegisProxy console, TLS & CA, before running it):
    curl -fsSLo aegis-ca-install.sh %s/api/public/ca/install-linux.sh && sha256sum aegis-ca-install.sh
    sudo bash aegis-ca-install.sh
================================================================================`,
		status, res.ServerHostname, serverIP, strings.Join(res.GroupIDs, ", "), method, fullURL, traceID,
		res.Verdict, reason, selfService, publicURL)
}

// authFailedHelp is the data-plane's AUTH_FAILED_HELP (data-plane/aegis_dp/blockpage.py).
const authFailedHelp = `The proxy credentials sent by this client (Proxy-Authorization) are not valid: the token is unknown, was
    rotated or is mistyped, the username does not belong to it, or this server's group requires the proxy
    token. The request was not attributed to the source address. Set the proxy URL of this server to
    http://<proxy-user>:<proxy-token>@<proxy-host>:<port> with the token shown when the server was onboarded
    (console: Servers -> server -> Rotate token issues a new one), or remove the credentials if this server
    is identified by its address.`

// handleVerifyAudit checks every hash and link of the complete audit trail (not only the window
// kept in memory). Evidence for auditors; may take a while on large trails.
func (s *Server) handleVerifyAudit(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if scopeFor(claims) != nil {
		writeError(w, http.StatusForbidden, "RBAC Policy: audit verification is available to InfoSec Approvers, Super Admins and Auditors")
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	res := s.store.VerifyCompleteAudit(r.Context(), s.cfg.AuditLogPath)
	if !res.OK {
		s.log.Error("audit trail verification failed", "error", res.Error, "events", res.Events)
	}
	writeJSON(w, http.StatusOK, auditVerificationJSON(res))
}

func auditVerificationJSON(res store.AuditVerification) map[string]any {
	out := map[string]any{"valid": res.OK, "events_checked": res.Events, "error": res.Error,
		"first_id": res.FirstID, "last_id": res.LastID, "legacy_events": res.Legacy, "scope": "complete",
		"starts_at_genesis": res.StartsAtGenesis, "head_matches": res.HeadMatches,
		"checkpoint_matches": res.CheckpointMatches, "checkpoint_events": res.CheckpointEvents,
		"legacy_pending": res.LegacyPending}
	if res.LegacyPending {
		out["legacy_head"] = res.LegacyHead
	}
	return out
}

// handleAcceptLegacyAudit trusts the unkeyed (pre-2.1) prefix sealed as pending at the upgrade, after
// a Super Admin compared it with an independent copy: the request repeats the number of legacy
// events and the hash of the last one. Audited, and raises a high-severity alert.
func (s *Server) handleAcceptLegacyAudit(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var body struct {
		LegacyEvents *int   `json:"legacy_events"`
		LegacyHead   string `json:"legacy_head"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.LegacyEvents == nil || body.LegacyHead == "" {
		writeError(w, http.StatusBadRequest, "legacy_events and legacy_head (the event hash of the last legacy event) are required")
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	res, err := s.store.AcceptLegacyAudit(r.Context(), s.cfg.AuditLogPath, *body.LegacyEvents, body.LegacyHead, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, auditVerificationJSON(res))
}

// handleAuditRetention re-seals the start of the trail after the operator removed old generations
// (Super Admin; the remaining trail must verify, and the change is an audit event).
func (s *Server) handleAuditRetention(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	res, err := s.store.ApplyAuditRetention(r.Context(), s.cfg.AuditLogPath, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": res.OK, "events_checked": res.Events, "first_id": res.FirstID,
		"last_id": res.LastID, "starts_at_genesis": res.StartsAtGenesis})
}
