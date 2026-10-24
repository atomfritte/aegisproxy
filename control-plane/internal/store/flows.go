package store

import (
	"aegisproxy/control-plane/internal/export"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/models"
)

const maxFlowBatch = 1000

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s
}

func clipList(in []string, maxItems, maxLen int) []string {
	if len(in) > maxItems {
		in = in[:maxItems]
	}
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, clip(v, maxLen))
	}
	return out
}

func validFlowID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// sanitizeFlow bounds every attacker-influenced field (URLs, user agents and hostnames come
// straight from proxied traffic) before it is stored, rendered in the UI or forwarded to webhooks.
func sanitizeFlow(f models.TrafficFlow, now time.Time, i int) models.TrafficFlow {
	if !validFlowID(f.ID) {
		f.ID = fmt.Sprintf("flw-%d-%d", now.UnixNano(), i)
	}
	if f.Timestamp.IsZero() || f.Timestamp.After(now.Add(5*time.Minute)) {
		f.Timestamp = now
	}
	f.ServerIP = clip(f.ServerIP, 64)
	f.ServerID = clip(f.ServerID, 128)
	f.ServerHostname = clip(oneLine(f.ServerHostname), 255)
	f.GroupIDs = clipList(f.GroupIDs, 32, 64)
	f.ProxyAuthUser = clip(oneLine(f.ProxyAuthUser), 128)
	// Never store secrets that may be embedded as "user:token".
	if u, _, ok := strings.Cut(f.ProxyAuthUser, ":"); ok {
		f.ProxyAuthUser = u
	}
	f.Method = clip(strings.ToUpper(f.Method), 16)
	f.Scheme = clip(strings.ToLower(f.Scheme), 8)
	f.Host = clip(engine.NormalizeHost(f.Host), 255)
	f.Path = clip(oneLine(f.Path), 2048)
	f.FullURL = clip(oneLine(f.FullURL), 4096)
	f.UserAgent = clip(oneLine(f.UserAgent), 512)
	f.Verdict = clip(f.Verdict, 32)
	f.MatchedRuleID = clip(f.MatchedRuleID, 128)
	f.MatchedRuleName = clip(oneLine(f.MatchedRuleName), 256)
	f.RedirectParentURL = clip(oneLine(f.RedirectParentURL), 4096)
	f.RedirectLocation = clip(oneLine(f.RedirectLocation), 4096)
	f.SessionID = clip(f.SessionID, 64)
	f.BlockToken = ""
	f.BlockReason = clip(f.BlockReason, 64)
	f.ThreatCategory = clip(f.ThreatCategory, 64)
	f.ThreatSource = clip(oneLine(f.ThreatSource), 128)
	f.ThreatIndicator = clip(oneLine(f.ThreatIndicator), 512)
	f.SecurityFlags = clipList(oneLines(f.SecurityFlags), 16, 128)
	f.ContentSHA256 = clip(strings.ToLower(f.ContentSHA256), 64)
	f.ContentType = clip(oneLine(f.ContentType), 128)
	f.FileType = clip(f.FileType, 32)
	f.AVResult = clip(f.AVResult, 32)
	f.AVSignature = clip(oneLine(f.AVSignature), 256)
	f.DLPFindings = clipList(oneLines(f.DLPFindings), 16, 64)
	f.ResolvedIP = clip(f.ResolvedIP, 64)
	f.DataPlaneID = clip(f.DataPlaneID, 64)
	if f.LatencyMs < 0 {
		f.LatencyMs = 0
	}
	if f.BytesSent < 0 {
		f.BytesSent = 0
	}
	if f.BytesReceived < 0 {
		f.BytesReceived = 0
	}
	return f
}

func (s *Store) RecordFlow(flow models.TrafficFlow) models.TrafficFlow {
	res := s.RecordFlowBatch([]models.TrafficFlow{flow})
	if len(res) > 0 {
		return res[0]
	}
	return flow
}

func (s *Store) RecordFlowBatch(flows []models.TrafficFlow) []models.TrafficFlow {
	if len(flows) == 0 {
		return nil
	}
	if len(flows) > maxFlowBatch {
		flows = flows[:maxFlowBatch]
	}
	now := time.Now().UTC()
	out := make([]models.TrafficFlow, len(flows))
	touchedSessions := make(map[string]bool)

	s.mu.RLock()
	ruleFollowMap := make(map[string]bool, len(s.state.Rules))
	redirectHosts := make(map[string][]string)
	for _, r := range s.state.Rules {
		if r.Enabled && strings.EqualFold(r.Action, "ALLOW") {
			ruleFollowMap[r.ID] = r.FollowRedirects
			if len(r.RedirectHosts) > 0 {
				redirectHosts[r.ID] = slices.Clone(r.RedirectHosts)
			}
		}
	}
	burstThreshold := s.state.SecurityPolicy.BlockedBurstThreshold
	s.mu.RUnlock()

	for i, flow := range flows {
		flow = sanitizeFlow(flow, now, i)
		if flow.ServerID == "" || len(flow.GroupIDs) == 0 {
			srvID, srvHost, groups := s.ResolveServer(flow.ServerIP, flow.ProxyAuthUser)
			flow.ServerID = srvID
			flow.ServerHostname = srvHost
			flow.GroupIDs = groups
		}
		if s.opts.DemoMode && flow.BytesReceived == 0 && flow.BytesSent == 0 {
			flow.BytesSent, flow.BytesReceived = EstimateFlowBytes(flow)
		}
		// Only mint a 302 redirect grant from LEARNING_ALLOWED or from ALLOWED flows whose rule has
		// FollowRedirects. Never chain from REDIRECT_OBJECT_ALLOWED (single-hop cap).
		if flow.RedirectLocation != "" {
			if flow.Verdict == models.VerdictLearningAllowed {
				s.engine.RegisterRedirectGrant(flow.ServerIP, flow.RedirectLocation, flow.FullURL, flow.MatchedRuleID, flow.MatchedRuleName, nil)
			} else if flow.Verdict == models.VerdictAllowed && ruleFollowMap[flow.MatchedRuleID] {
				s.engine.RegisterRedirectGrant(flow.ServerIP, flow.RedirectLocation, flow.FullURL, flow.MatchedRuleID, flow.MatchedRuleName,
					redirectHosts[flow.MatchedRuleID])
			}
		}
		if flow.SessionID != "" {
			touchedSessions[flow.SessionID] = true
		}
		out[i] = flow
	}

	var newEvents, touchedEvents []models.SecurityEvent
	statDeltas := map[string]RuleStat{}
	s.mu.Lock()
	for _, flow := range out {
		if flow.MatchedRuleID != "" {
			if s.bumpRuleStatLocked(flow.MatchedRuleID, flow.BytesSent+flow.BytesReceived) {
				d := statDeltas[flow.MatchedRuleID]
				statDeltas[flow.MatchedRuleID] = RuleStat{Hits: d.Hits + 1, Bytes: d.Bytes + flow.BytesSent + flow.BytesReceived}
			}
		}
		for _, ev := range securityEventsForFlow(flow) {
			created, isNew := s.upsertSecurityEventLocked(ev)
			touchedEvents = append(touchedEvents, created)
			if isNew {
				newEvents = append(newEvents, created)
			}
		}
		if !models.IsAllowedVerdict(flow.Verdict) && flow.Verdict != models.VerdictSimulatedDryRun {
			if burstThreshold > 0 && s.bursts.hit(flow.ServerID, burstThreshold, now) {
				ev := models.SecurityEvent{
					Type: models.SecurityEventBlockBurst, Severity: "high", Action: "detected",
					ServerID: flow.ServerID, ServerIP: flow.ServerIP, ServerHostname: flow.ServerHostname,
					GroupIDs: flow.GroupIDs, Host: flow.Host,
					Detail: fmt.Sprintf("%d+ blocked requests within one minute — possible malware beaconing, misconfiguration or scanning", burstThreshold),
				}
				created, isNew := s.upsertSecurityEventLocked(ev)
				touchedEvents = append(touchedEvents, created)
				if isNew {
					newEvents = append(newEvents, created)
				}
			}
		}
	}

	reversed := make([]models.TrafficFlow, len(out))
	for i := range out {
		reversed[i] = out[len(out)-1-i]
	}
	s.state.Flows = append(reversed, s.state.Flows...)
	if len(s.state.Flows) > maxFlows {
		s.state.Flows = s.state.Flows[:maxFlows]
	}

	if len(touchedSessions) > 0 {
		s.recompileSessionsLocked(touchedSessions)
	}
	if len(newEvents) > 0 {
		s.markDirtyLocked() // new security events are saved promptly
	} else {
		s.markTelemetryDirtyLocked()
	}
	notifyCfg := s.state.NotifyConfig
	s.mu.Unlock()

	if s.telemetry != nil {
		s.telemetry.add(out, touchedEvents, statDeltas)
	}

	for _, flow := range out {
		s.traffic.add(flow)
		s.broadcastFlow(flow)
		s.opts.Exporter.Publish(export.FlowEvent(flow))
	}
	for _, ev := range newEvents {
		s.opts.Exporter.Publish(export.SecurityEvent(ev))
	}
	if s.notifier != nil && notifyCfg.NotifySecurityEvents {
		for _, ev := range newEvents {
			if ev.Severity == "critical" || ev.Severity == "high" {
				s.notifier.NotifySecurityEvent(ev)
			}
		}
	}
	for _, ev := range newEvents {
		s.log.Warn("security event", "type", ev.Type, "severity", ev.Severity, "action", ev.Action,
			"server", ev.ServerHostname, "server_ip", ev.ServerIP, "host", ev.Host, "detail", ev.Detail, "source", ev.Source)
	}
	return out
}

func threatSeverity(category string) string {
	switch category {
	case "botnet_c2", "ransomware", "malware", "compromised_host":
		return "critical"
	case "phishing", "hijacked_network", "threat_intel":
		return "high"
	}
	return "medium"
}

// securityEventsForFlow derives threat-protection events from a recorded flow.
func securityEventsForFlow(f models.TrafficFlow) []models.SecurityEvent {
	base := models.SecurityEvent{
		ServerID: f.ServerID, ServerIP: f.ServerIP, ServerHostname: f.ServerHostname, GroupIDs: f.GroupIDs,
		Method: f.Method, Host: f.Host, URL: f.FullURL, Verdict: f.Verdict, FlowID: f.ID,
	}
	var out []models.SecurityEvent
	add := func(typ, sev, action, detail, indicator, source string) {
		ev := base
		ev.Type, ev.Severity, ev.Action, ev.Detail, ev.Indicator, ev.Source = typ, sev, action, detail, indicator, source
		out = append(out, ev)
	}
	switch f.Verdict {
	case models.VerdictThreatBlocked:
		add(models.SecurityEventThreat, threatSeverity(f.ThreatCategory), "blocked",
			fmt.Sprintf("Destination matched threat intelligence (%s)", f.ThreatCategory), f.ThreatIndicator, f.ThreatSource)
	case models.VerdictMalwareBlocked:
		detail := "Downloaded content matched a malware signature"
		if f.AVSignature != "" {
			detail = "Malware detected: " + f.AVSignature
		}
		add(models.SecurityEventMalware, "critical", "blocked", detail, f.ContentSHA256, firstNonEmpty(f.ThreatSource, "ClamAV"))
	case models.VerdictDLPBlocked:
		src := "DLP"
		if slices.ContainsFunc(f.DLPFindings, func(x string) bool { return strings.HasPrefix(x, "icap:") }) {
			src = "ICAP DLP"
		}
		add(models.SecurityEventDLP, "high", "blocked",
			"Outbound request contained credentials/secrets: "+strings.Join(f.DLPFindings, ", "), "", src)
	case models.VerdictFileTypeBlocked:
		add(models.SecurityEventFileType, "medium", "blocked", "Blocked download of file type "+f.FileType, f.ContentSHA256, "Download control")
	case models.VerdictQuarantined:
		add(models.SecurityEventQuarantine, "high", "blocked", "Egress attempt from a quarantined server", f.Host, "Quarantine")
	case models.VerdictPolicyBlocked:
		switch f.BlockReason {
		case "malformed_path", "malformed_host", "host_mismatch", "sni_mismatch", "raw_tcp", "dns_rebinding", "forbidden_destination":
			add(models.SecurityEventPolicy, "medium", "blocked", firstNonEmpty(f.MatchedRuleName, f.BlockReason), "", "Protocol guard")
		case "undecodable_content", "partial_content":
			// Content that cannot be inspected (unknown or broken encoding, byte ranges) is blocked.
			add(models.SecurityEventPolicy, "medium", "blocked", firstNonEmpty(f.MatchedRuleName, "Content could not be inspected ("+f.BlockReason+")"), f.ContentSHA256, "Content inspection")
		case "internal_error", "unevaluated":
			// The worker failed closed; frequent occurrences point to a bug or an attack on the parser.
			add(models.SecurityEventPolicy, "high", "blocked", firstNonEmpty(f.MatchedRuleName, "Data-plane failed closed ("+f.BlockReason+")"), f.Host, "Data-plane")
		}
	}
	for _, flag := range f.SecurityFlags {
		kind, val, _ := strings.Cut(flag, ":")
		switch kind {
		case "THREAT_MONITOR":
			add(models.SecurityEventThreat, threatSeverity(val), "detected",
				"Allowed request matched threat intelligence (monitor mode): "+val, f.ThreatIndicator, f.ThreatSource)
		case "DLP":
			src := "DLP"
			if strings.HasPrefix(val, "icap:") {
				src = "ICAP DLP"
			}
			add(models.SecurityEventDLP, "high", "detected", "Credentials/secrets detected in outbound request (monitor mode): "+val, "", src)
		case "AV_FOUND":
			add(models.SecurityEventMalware, "critical", "detected", "Malware detected (monitor mode): "+val, f.ContentSHA256, scanEngine(val))
		case "PUNYCODE":
			add(models.SecurityEventPunycode, "low", "detected", "Internationalized (punycode) domain accessed — check for homograph spoofing", f.Host, "Homograph guard")
		case "AV_ERROR":
			add(models.SecurityEventAVError, "medium", "detected", "Content scan failed: "+val, "", scanEngine(val))
		}
	}
	return out
}

// scanEngine names the engine behind a data-plane scan flag value ("YARA: rule", "icap: timeout", …).
func scanEngine(val string) string {
	switch v := strings.ToLower(val); {
	case strings.HasPrefix(v, "yara"):
		return "YARA"
	case strings.HasPrefix(v, "icap"):
		return "ICAP"
	default:
		return "ClamAV"
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// upsertSecurityEventLocked de-duplicates identical events within 15 minutes by incrementing
// a counter instead of flooding the event list (and the notification channels).
func (s *Store) upsertSecurityEventLocked(ev models.SecurityEvent) (models.SecurityEvent, bool) {
	now := time.Now().UTC()
	limit := min(len(s.state.SecurityEvents), 200)
	for i := 0; i < limit; i++ {
		e := &s.state.SecurityEvents[i]
		if now.Sub(e.Timestamp) > 15*time.Minute {
			break
		}
		if e.Type == ev.Type && e.ServerID == ev.ServerID && e.Host == ev.Host && e.Action == ev.Action && e.Detail == ev.Detail {
			e.Count++
			return *e, false
		}
	}
	ev.ID = newRandomID("sev")
	ev.Timestamp = now
	ev.Count = 1
	s.state.SecurityEvents = append([]models.SecurityEvent{ev}, s.state.SecurityEvents...)
	if len(s.state.SecurityEvents) > maxSecurityEvents {
		s.state.SecurityEvents = s.state.SecurityEvents[:maxSecurityEvents]
	}
	return ev, true
}

// burstDetector counts blocked requests per server in one-minute windows.
type burstDetector struct {
	mu      sync.Mutex
	windows map[string]*burstWindow
}

type burstWindow struct {
	minute    int64
	count     int
	alertedAt time.Time
}

func newBurstDetector() *burstDetector {
	return &burstDetector{windows: make(map[string]*burstWindow)}
}

// hit returns true exactly once when a server crosses the threshold (re-armed after 10 minutes).
func (b *burstDetector) hit(serverID string, threshold int, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	minute := now.Unix() / 60
	w := b.windows[serverID]
	if w == nil {
		if len(b.windows) > 50_000 {
			b.windows = make(map[string]*burstWindow)
		}
		w = &burstWindow{minute: minute}
		b.windows[serverID] = w
	}
	if w.minute != minute {
		w.minute = minute
		w.count = 0
	}
	w.count++
	if w.count == threshold && now.Sub(w.alertedAt) > 10*time.Minute {
		w.alertedAt = now
		return true
	}
	return false
}

func oneLines(v []string) []string {
	for i := range v {
		v[i] = oneLine(v[i])
	}
	return v
}
