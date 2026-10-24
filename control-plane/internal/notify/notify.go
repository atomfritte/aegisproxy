package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/netguard"
)

func isDisallowedIP(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() || addr.IsUnspecified() || netip.MustParsePrefix("100.64.0.0/10").Contains(addr)
}

func ValidateWebhookURL(rawURL string) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid webhook URL")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("webhook URL must use https:// scheme")
	}
	if u.User != nil {
		return fmt.Errorf("webhook URL must not contain credentials")
	}
	host := strings.TrimRight(strings.ToLower(u.Hostname()), ".")
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".internal.corp") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return fmt.Errorf("SSRF Policy: internal or loopback webhook hosts are forbidden")
	}
	if addr, err := netip.ParseAddr(host); err == nil && isDisallowedIP(addr) {
		return fmt.Errorf("SSRF Policy: private, loopback, and cloud metadata IPs (%s) are forbidden", host)
	}
	return nil
}

// isPlaceholderWebhook recognizes the documentation/demo URLs shipped with demo data so that no
// traffic is sent to them.
func isPlaceholderWebhook(u string) bool {
	return strings.Contains(u, "example.com") || strings.Contains(u, "hooks.slack.com/services/T00000000") ||
		strings.Contains(u, "enterprise.webhook.office.com")
}

type job struct {
	channel, eventType, title, summary, payload, webhookURL string
	enabled                                                 bool
}

type Dispatcher struct {
	mu     sync.RWMutex
	config models.NotificationConfig
	logs   []models.NotificationLog
	client *http.Client
	queue  chan job
	urgent chan job // security alerts: delivered first, never crowded out by request notifications
	log    *slog.Logger
}

func NewDispatcher(cfg models.NotificationConfig, logger *slog.Logger) *Dispatcher {
	if logger == nil {
		logger = slog.Default()
	}
	// SSRF guard: direct connections are checked on the resolved address; through HTTPS_PROXY the
	// webhook host is checked before it is handed to the proxy (the proxy itself is trusted).
	guard := &netguard.ProxyGuard{Proxy: http.ProxyFromEnvironment, Blocked: isDisallowedIP, What: "SSRF Guard: webhook host",
		Dialer: &net.Dialer{Timeout: 3 * time.Second}}
	transport := &http.Transport{
		Proxy:                 guard.ProxyFunc,
		DialContext:           guard.DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	d := &Dispatcher{
		config: cfg,
		logs:   make([]models.NotificationLog, 0, 100),
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		queue:  make(chan job, 256),
		urgent: make(chan job, 256),
		log:    logger.With("component", "notify"),
	}
	go d.worker()
	return d
}

func (d *Dispatcher) worker() {
	for {
		select {
		case j := <-d.urgent:
			d.deliver(j)
			continue
		default:
		}
		select {
		case j := <-d.urgent:
			d.deliver(j)
		case j := <-d.queue:
			d.deliver(j)
		}
	}
}

func (d *Dispatcher) GetConfig() models.NotificationConfig {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.config
}

func (d *Dispatcher) UpdateConfig(cfg models.NotificationConfig) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.config = cfg
}

func (d *Dispatcher) GetLogs() []models.NotificationLog {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]models.NotificationLog, len(d.logs))
	copy(out, d.logs)
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s + "…"
}

// slackEscape neutralizes Slack mrkdwn control sequences in untrusted text
// (prevents <!channel> mentions and <http://evil|innocent> link spoofing).
func slackEscape(s string) string {
	s = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "`", "'").Replace(s)
	return truncate(s, 1500)
}

// teamsEscape neutralizes Markdown in Adaptive Card TextBlocks (prevents link injection).
func teamsEscape(s string) string {
	s = strings.NewReplacer("[", "\\[", "]", "\\]", "(", "\\(", ")", "\\)", "*", "\\*", "_", "\\_", "<", "&lt;", ">", "&gt;").Replace(s)
	return truncate(s, 1500)
}

func (d *Dispatcher) NotifyAccessRequest(req models.AccessRequest) {
	cfg := d.GetConfig()
	approvalURL := fmt.Sprintf("%s/requests/%s", strings.TrimRight(cfg.DashboardBaseURL, "/"), url.PathEscape(req.ID))
	verified := "✅ verified by proxy"
	if !req.Verified {
		verified = "⚠️ UNVERIFIED (self-reported)"
	}

	teamsPayload := adaptiveCard("🛡️ AegisProxy: Outbound Access Request", "Attention", []map[string]string{
		{"title": "Server:", "value": teamsEscape(fmt.Sprintf("%s (%s) — %s", req.ServerHostname, req.ServerIP, verified))},
		{"title": "Server Groups:", "value": teamsEscape(strings.Join(req.GroupIDs, ", "))},
		{"title": "Blocked URL:", "value": teamsEscape(fmt.Sprintf("[%s] %s", req.Method, req.RequestedURL))},
		{"title": "Suggested Rule:", "value": teamsEscape(fmt.Sprintf("%s%s (Follow Redirects: %v)", req.SuggestedHostPattern, req.SuggestedPathPattern, req.FollowRedirects))},
		{"title": "Requester:", "value": teamsEscape(req.Requester)},
		{"title": "Duration / Scope:", "value": teamsEscape(fmt.Sprintf("%s (%s)", req.Duration, req.RequestedScope))},
		{"title": "Justification:", "value": teamsEscape(req.Reason)},
	}, "Review & Approve in AegisProxy Console", approvalURL)
	teamsJSON, _ := json.MarshalIndent(teamsPayload, "", "  ")
	d.enqueue(job{channel: "teams", eventType: "ACCESS_REQUEST_CREATED",
		title:   truncate(fmt.Sprintf("Access Request from %s for %s", req.ServerHostname, req.Host), 200),
		summary: truncate(fmt.Sprintf("[%s] %s — Reason: %s (by %s)", req.Method, req.RequestedURL, req.Reason, req.Requester), 500),
		payload: string(teamsJSON), enabled: cfg.TeamsEnabled, webhookURL: string(cfg.TeamsWebhookURL)})

	slackPayload := map[string]any{
		"channel": cfg.SlackChannel,
		"text":    fmt.Sprintf("🛡️ Outbound Access Request from `%s` for `%s`", slackEscape(req.ServerHostname), slackEscape(req.RequestedURL)),
		"blocks": []map[string]any{
			{"type": "header", "text": map[string]string{"type": "plain_text", "text": "🛡️ AegisProxy: Outbound Access Request"}},
			{"type": "section", "fields": []map[string]string{
				{"type": "mrkdwn", "text": fmt.Sprintf("*Server:*\n`%s` (`%s`)\n%s", slackEscape(req.ServerHostname), slackEscape(req.ServerIP), verified)},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Requester:*\n%s", slackEscape(req.Requester))},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Blocked URL:*\n`%s %s`", slackEscape(req.Method), slackEscape(req.RequestedURL))},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Suggested Rule:*\n`%s%s`", slackEscape(req.SuggestedHostPattern), slackEscape(req.SuggestedPathPattern))},
			}},
			{"type": "section", "text": map[string]string{"type": "mrkdwn", "text": fmt.Sprintf("*Business / Technical Justification:*\n> %s", slackEscape(req.Reason))}},
			{"type": "actions", "elements": []map[string]any{
				{"type": "button", "text": map[string]string{"type": "plain_text", "text": "Open in Rule Editor & Approve"}, "style": "primary", "url": approvalURL},
			}},
		},
	}
	slackJSON, _ := json.MarshalIndent(slackPayload, "", "  ")
	d.enqueue(job{channel: "slack", eventType: "ACCESS_REQUEST_CREATED",
		title:   truncate(fmt.Sprintf("Slack Alert: %s -> %s", req.ServerHostname, req.Host), 200),
		summary: truncate(fmt.Sprintf("%s requested %s%s (%s): %q", req.Requester, req.SuggestedHostPattern, req.SuggestedPathPattern, req.Duration, req.Reason), 500),
		payload: string(slackJSON), enabled: cfg.SlackEnabled, webhookURL: string(cfg.SlackWebhookURL)})
}

// NotifySecurityEvent alerts the SecOps channels about high/critical threat-protection events.
func (d *Dispatcher) NotifySecurityEvent(ev models.SecurityEvent) {
	cfg := d.GetConfig()
	link := fmt.Sprintf("%s/threats/events/%s", strings.TrimRight(cfg.DashboardBaseURL, "/"), url.PathEscape(ev.ID))
	title := fmt.Sprintf("🚨 AegisProxy %s: %s %s", strings.ToUpper(ev.Severity), ev.Type, ev.Action)

	teamsPayload := adaptiveCard(title, "Attention", []map[string]string{
		{"title": "Server:", "value": teamsEscape(fmt.Sprintf("%s (%s)", ev.ServerHostname, ev.ServerIP))},
		{"title": "Destination:", "value": teamsEscape(firstNonEmpty(ev.URL, ev.Host))},
		{"title": "Detail:", "value": teamsEscape(ev.Detail)},
		{"title": "Indicator / Source:", "value": teamsEscape(strings.TrimSpace(ev.Indicator + " " + ev.Source))},
	}, "Investigate in AegisProxy", link)
	teamsJSON, _ := json.MarshalIndent(teamsPayload, "", "  ")
	d.enqueue(job{channel: "teams", eventType: "SECURITY_EVENT", title: truncate(title, 200),
		summary: truncate(fmt.Sprintf("%s on %s: %s", ev.Type, ev.ServerHostname, ev.Detail), 500),
		payload: string(teamsJSON), enabled: cfg.TeamsEnabled, webhookURL: string(cfg.TeamsWebhookURL)})

	slackPayload := map[string]any{
		"channel": cfg.SlackChannel,
		"text":    slackEscape(title),
		"blocks": []map[string]any{
			{"type": "header", "text": map[string]string{"type": "plain_text", "text": truncate(title, 140)}},
			{"type": "section", "fields": []map[string]string{
				{"type": "mrkdwn", "text": fmt.Sprintf("*Server:*\n`%s` (`%s`)", slackEscape(ev.ServerHostname), slackEscape(ev.ServerIP))},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Destination:*\n`%s`", slackEscape(firstNonEmpty(ev.URL, ev.Host)))},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Detail:*\n%s", slackEscape(ev.Detail))},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Indicator / Source:*\n%s %s", slackEscape(ev.Indicator), slackEscape(ev.Source))},
			}},
			{"type": "actions", "elements": []map[string]any{
				{"type": "button", "text": map[string]string{"type": "plain_text", "text": "Investigate"}, "style": "danger", "url": link},
			}},
		},
	}
	slackJSON, _ := json.MarshalIndent(slackPayload, "", "  ")
	d.enqueue(job{channel: "slack", eventType: "SECURITY_EVENT", title: truncate(title, 200),
		summary: truncate(fmt.Sprintf("%s on %s: %s", ev.Type, ev.ServerHostname, ev.Detail), 500),
		payload: string(slackJSON), enabled: cfg.SlackEnabled, webhookURL: string(cfg.SlackWebhookURL)})
}

// NotifyChangeRequest asks reviewers to look at a policy change (four-eyes review).
func (d *Dispatcher) NotifyChangeRequest(cr models.ChangeRequest) {
	cfg := d.GetConfig()
	link := fmt.Sprintf("%s/changes/%s", strings.TrimRight(cfg.DashboardBaseURL, "/"), url.PathEscape(cr.ID))
	impact := "not computed"
	if cr.Impact != nil {
		impact = fmt.Sprintf("%d newly allowed, %d newly blocked of %d recorded requests", cr.Impact.NewlyAllowed, cr.Impact.NewlyBlocked, cr.Impact.FlowsEvaluated)
	}
	changes := ""
	if cr.Diff != nil {
		changes = fmt.Sprintf("+%d / -%d / ~%d rules", cr.Diff.Added, cr.Diff.Removed, cr.Diff.Modified)
	}
	d.simple("CHANGE_REQUEST_SUBMITTED", "📝 AegisProxy: Policy change awaiting review", "Accent", [][2]string{
		{"Policy set:", cr.PolicySetName},
		{"Change:", cr.Title},
		{"Rules:", changes},
		{"Impact (recorded traffic):", impact},
		{"Submitted by:", cr.SubmittedBy},
	}, "Review change", link)
}

// NotifyRequestDecision informs the channel that an access request was decided.
func (d *Dispatcher) NotifyRequestDecision(req models.AccessRequest) {
	cfg := d.GetConfig()
	link := fmt.Sprintf("%s/requests/%s", strings.TrimRight(cfg.DashboardBaseURL, "/"), url.PathEscape(req.ID))
	icon, color := "✅", "Good"
	if req.Status != "approved" {
		icon, color = "⛔", "Attention"
	}
	expires := "permanent"
	if req.ExpiresAt != nil {
		expires = req.ExpiresAt.UTC().Format(time.RFC3339)
	}
	d.simple("ACCESS_REQUEST_"+strings.ToUpper(req.Status), fmt.Sprintf("%s AegisProxy: access request %s", icon, req.Status), color, [][2]string{
		{"Server:", fmt.Sprintf("%s (%s)", req.ServerHostname, req.ServerIP)},
		{"Destination:", req.SuggestedHostPattern + req.SuggestedPathPattern},
		{"Requester:", req.Requester},
		{"Decision by:", req.ReviewedBy},
		{"Comment:", req.ReviewComment},
		{"Access expires:", expires},
	}, "Open request", link)
}

// NotifyDigest posts the daily summary of open work.
func (d *Dispatcher) NotifyDigest(pending, overdue, changes, recert, quarantined, expiring int) {
	cfg := d.GetConfig()
	base := strings.TrimRight(cfg.DashboardBaseURL, "/")
	d.simple("DAILY_DIGEST", "📋 AegisProxy: daily summary", "Accent", [][2]string{
		{"Access requests pending:", fmt.Sprintf("%d (%d over SLA)", pending, overdue)},
		{"Policy changes awaiting review:", fmt.Sprint(changes)},
		{"Policy sets overdue for recertification:", fmt.Sprint(recert)},
		{"Temporary access expiring within 24 h:", fmt.Sprint(expiring)},
		{"Quarantined servers:", fmt.Sprint(quarantined)},
	}, "Open console", base+"/")
}

// simple sends a fact list to Teams and Slack.
func (d *Dispatcher) simple(eventType, title, color string, facts [][2]string, actionTitle, link string) {
	cfg := d.GetConfig()
	teamsFacts := make([]map[string]string, 0, len(facts))
	slackFields := make([]map[string]string, 0, len(facts))
	var summary []string
	for _, f := range facts {
		if strings.TrimSpace(f[1]) == "" {
			continue
		}
		teamsFacts = append(teamsFacts, map[string]string{"title": f[0], "value": teamsEscape(f[1])})
		slackFields = append(slackFields, map[string]string{"type": "mrkdwn", "text": fmt.Sprintf("*%s*\n%s", slackEscape(f[0]), slackEscape(f[1]))})
		summary = append(summary, f[0]+" "+f[1])
	}
	teamsJSON, _ := json.MarshalIndent(adaptiveCard(title, color, teamsFacts, actionTitle, link), "", "  ")
	d.enqueue(job{channel: "teams", eventType: eventType, title: truncate(title, 200), summary: truncate(strings.Join(summary, " · "), 500),
		payload: string(teamsJSON), enabled: cfg.TeamsEnabled, webhookURL: string(cfg.TeamsWebhookURL)})
	if len(slackFields) > 10 {
		slackFields = slackFields[:10]
	}
	slackJSON, _ := json.MarshalIndent(map[string]any{
		"channel": cfg.SlackChannel,
		"text":    slackEscape(title),
		"blocks": []map[string]any{
			{"type": "header", "text": map[string]string{"type": "plain_text", "text": truncate(title, 140)}},
			{"type": "section", "fields": slackFields},
			{"type": "actions", "elements": []map[string]any{
				{"type": "button", "text": map[string]string{"type": "plain_text", "text": actionTitle}, "url": link},
			}},
		},
	}, "", "  ")
	d.enqueue(job{channel: "slack", eventType: eventType, title: truncate(title, 200), summary: truncate(strings.Join(summary, " · "), 500),
		payload: string(slackJSON), enabled: cfg.SlackEnabled, webhookURL: string(cfg.SlackWebhookURL)})
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func adaptiveCard(title, color string, facts []map[string]string, actionTitle, actionURL string) map[string]any {
	return map[string]any{
		"type": "message",
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content": map[string]any{
				"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
				"type":    "AdaptiveCard",
				"version": "1.4",
				"body": []map[string]any{
					{"type": "TextBlock", "size": "Large", "weight": "Bolder", "color": color, "text": title, "wrap": true},
					{"type": "FactSet", "facts": facts},
				},
				"actions": []map[string]any{{"type": "Action.OpenUrl", "title": actionTitle, "url": actionURL}},
			},
		}},
	}
}

func (d *Dispatcher) enqueue(j job) {
	q := d.queue
	if j.eventType != "ACCESS_REQUEST_CREATED" {
		q = d.urgent
	}
	select {
	case q <- j:
	default:
		d.record(j, false, "Dropped: notification queue full")
		d.log.Warn("notification queue full; dropping message", "channel", j.channel, "event", j.eventType)
	}
}

func (d *Dispatcher) deliver(j job) {
	statusNote := "Recorded in Notification Log (no webhook configured)"
	delivered := false

	switch {
	case !j.enabled:
		statusNote = "Channel disabled (payload logged only)"
	case strings.TrimSpace(j.webhookURL) == "":
		statusNote = "No webhook URL configured (payload logged only)"
	case isPlaceholderWebhook(j.webhookURL):
		statusNote = "Placeholder/demo webhook URL (payload logged only)"
	default:
		if err := ValidateWebhookURL(j.webhookURL); err != nil {
			statusNote = fmt.Sprintf("Blocked by SSRF Guard: %v", err)
			break
		}
		req, err := http.NewRequest(http.MethodPost, j.webhookURL, bytes.NewBufferString(j.payload))
		if err != nil {
			statusNote = "Invalid webhook request"
			break
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "AegisProxy-Notifier/2.0")
		resp, err := d.client.Do(req)
		if err != nil {
			// The webhook URL is the credential (Teams/Slack embed the token in the path): name the
			// host only and drop the URL net/http quotes in its error.
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Err
			}
			dest := models.MaskURL(j.webhookURL)
			statusNote = fmt.Sprintf("Webhook HTTP error (%s): %v", dest, err)
			d.log.Warn("webhook delivery failed", "channel", j.channel, "destination", dest, "error", err)
			break
		}
		_ = resp.Body.Close()
		statusNote = fmt.Sprintf("Webhook delivered (HTTP %d)", resp.StatusCode)
		delivered = resp.StatusCode >= 200 && resp.StatusCode < 300
	}
	d.record(j, delivered, statusNote)
}

func (d *Dispatcher) record(j job, delivered bool, note string) {
	entry := models.NotificationLog{
		ID:          fmt.Sprintf("notif-%d", time.Now().UnixNano()),
		Channel:     j.channel,
		EventType:   j.eventType,
		Title:       j.title,
		Summary:     j.summary,
		PayloadJSON: j.payload,
		Delivered:   delivered,
		StatusNote:  note,
		Timestamp:   time.Now().UTC(),
	}
	d.mu.Lock()
	d.logs = append([]models.NotificationLog{entry}, d.logs...)
	if len(d.logs) > 100 {
		d.logs = d.logs[:100]
	}
	d.mu.Unlock()
}
