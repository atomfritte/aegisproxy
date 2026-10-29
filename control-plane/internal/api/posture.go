package api

import (
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/sealed"
)

// PostureCheck is one item of the security posture report.
type PostureCheck struct {
	ID          string `json:"id"`
	Category    string `json:"category"` // identity | data | detection | governance | platform
	Title       string `json:"title"`
	Status      string `json:"status"` // pass | warn | fail | info
	Detail      string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
	DocLink     string `json:"doc_link,omitempty"`
	// DocURL is DocLink resolved against AEGIS_DOCS_URL (when configured).
	DocURL string `json:"doc_url,omitempty"`
}

func (s *Server) handlePosture(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !s.requireSystem(w, claims) {
		return
	}
	checks := s.postureChecks()
	score, weight := 0, 0
	for _, c := range checks {
		switch c.Status {
		case "pass":
			score += 2
			weight += 2
		case "warn":
			score++
			weight += 2
		case "fail":
			weight += 2
		}
	}
	pct := 100
	if weight > 0 {
		pct = score * 100 / weight
	}
	writeJSON(w, http.StatusOK, map[string]any{"score": pct, "checks": checks, "generated_at": time.Now().UTC()})
}

func (s *Server) postureChecks() []PostureCheck {
	snap := s.store.GetSnapshot()
	now := time.Now()
	var out []PostureCheck
	add := func(id, cat, title, status, detail, fix, doc string) {
		c := PostureCheck{ID: id, Category: cat, Title: title, Status: status, Detail: detail, Remediation: fix, DocLink: doc}
		if doc != "" && s.cfg.DocsURL != "" {
			c.DocURL = strings.TrimRight(s.cfg.DocsURL, "/") + "/" + strings.TrimPrefix(doc, "docs/")
		}
		out = append(out, c)
	}
	pass := func(ok bool, failStatus string) string {
		if ok {
			return "pass"
		}
		return failStatus
	}

	// Platform
	https := strings.HasPrefix(s.cfg.PublicURL, "https://") || s.cfg.TLSCertFile != ""
	add("tls", "platform", "Console and API served over HTTPS", pass(https, "fail"), s.cfg.PublicURL,
		"Terminate TLS at the ingress/reverse proxy and set AEGIS_PUBLIC_URL to the https URL.", "docs/security.md#hardening-checklist")
	add("demo", "platform", "Demo mode disabled", pass(!s.store.DemoMode(), "fail"), "AEGIS_DEMO_MODE",
		"Never run demo mode with real data: it seeds public demo credentials.", "docs/configuration.md")
	s.encryptionPostureCheck(add)
	if _, err := os.Stat(filepath.Join(s.cfg.DataDir, "secrets", "initial-admin-password")); err == nil {
		add("bootstrap-file", "identity", "Initial admin password file removed", "warn", "secrets/initial-admin-password still exists",
			"Sign in, change the password and delete the file.", "docs/operations.md#day-one-checklist")
	} else {
		add("bootstrap-file", "identity", "Initial admin password file removed", "pass", "", "", "")
	}
	add("metrics", "platform", "Metrics endpoint protected", pass(s.cfg.MetricsToken != "", "info"), "AEGIS_METRICS_TOKEN",
		"Set a bearer token for /metrics or restrict it at the network level.", "docs/configuration.md")
	s.trustedProxyPostureCheck(add)
	if s.caMgr != nil {
		left := time.Until(s.caMgr.NotAfter)
		st := "pass"
		if left < 30*24*time.Hour {
			st = "fail"
		} else if left < 90*24*time.Hour {
			st = "warn"
		}
		add("ca-validity", "platform", "Interception CA validity", st, "valid until "+s.caMgr.NotAfter.Format("2006-01-02")+" ("+s.caMgr.Issuer+")",
			"Renew the CA (gen-csr / import-ca with the corporate PKI) before it expires.", "docs/operations.md#rotating-secrets-and-the-ca")
	}

	// Identity
	ssoDetail := "not configured"
	if snap.EntraConfig.Enabled {
		ssoDetail = map[string]string{"entra": "Microsoft Entra ID", "oidc": "OpenID Connect"}[s.store.SSOSettings(s.cfg.PublicURL).Provider]
	}
	add("sso", "identity", "Single sign-on (MFA, conditional access) enabled", pass(snap.EntraConfig.Enabled, "warn"),
		ssoDetail, "Connect Entra ID or another OIDC provider and map IdP groups to roles.", "docs/identity.md")
	add("local-login", "identity", "Password login limited to break-glass accounts", pass(!snap.EntraConfig.AllowLocalLogin && snap.EntraConfig.Enabled, "warn"),
		"", "After enabling SSO, disable password login (break-glass Super Admins keep access).", "docs/identity.md#break-glass-accounts")
	superAdmins, breakGlass := 0, 0
	var stale []string
	for _, u := range snap.Users {
		if u.Disabled {
			continue
		}
		if u.Role == models.RoleSuperAdmin {
			superAdmins++
		}
		if u.BreakGlass {
			breakGlass++
		}
		last := u.CreatedAt
		if u.LastLoginAt != nil {
			last = *u.LastLoginAt
		}
		if now.Sub(last) > 90*24*time.Hour {
			stale = append(stale, u.Username)
		}
	}
	add("super-admins", "identity", "Number of Super Admins (2-5)", pass(superAdmins >= 2 && superAdmins <= 5, "warn"),
		itoa(superAdmins)+" active",
		"Keep at least two (availability) and at most five (least privilege) Super Admins.", "docs/security.md#roles-rbac")
	add("break-glass", "identity", "Break-glass account available (1-2)", pass(breakGlass >= 1 && breakGlass <= 2, "warn"), itoa(breakGlass)+" accounts",
		"Keep one or two break-glass Super Admins with long random passwords in a safe.", "docs/identity.md#break-glass-accounts")
	add("stale-users", "identity", "No accounts unused for 90 days", pass(len(stale) == 0, "warn"), strings.Join(stale, ", "),
		"Disable or delete unused accounts (SSO users are revoked automatically when removed from the IdP group).", "")
	var expiring, unrestricted []string
	for _, sa := range s.store.ServiceAccounts() {
		if sa.Disabled {
			continue
		}
		if sa.ExpiresAt.Sub(now) < 14*24*time.Hour {
			expiring = append(expiring, sa.Name)
		}
		if len(sa.AllowedCIDRs) == 0 {
			unrestricted = append(unrestricted, sa.Name)
		}
	}
	add("sa-expiry", "identity", "No API keys expiring within 14 days", pass(len(expiring) == 0, "warn"), strings.Join(expiring, ", "),
		"Rotate the keys of these service accounts and extend their expiry.", "docs/identity.md#service-accounts")
	add("sa-cidr", "identity", "API keys restricted to source networks", pass(len(unrestricted) == 0, "info"), strings.Join(unrestricted, ", "),
		"Restrict service accounts to the addresses of the automation that uses them.", "docs/identity.md#service-accounts")

	// Governance
	add("four-eyes", "governance", "Four-eyes review for policy changes", pass(snap.Governance.RequirePolicyReview, "warn"), "",
		"Enable require_policy_review in Settings → Governance.", "docs/policy-management.md#publishing-and-four-eyes-review")
	overdue := 0
	for _, set := range snap.PolicySets {
		if set.ReviewState == "overdue" {
			overdue++
		}
	}
	add("recertification", "governance", "Policy sets recertified on time", pass(overdue == 0, "warn"), itoa(overdue)+" overdue",
		"Open the overdue sets and recertify or retire them.", "docs/policy-management.md#recertification")
	catchAll := 0
	for _, rule := range snap.Rules {
		if rule.Enabled && strings.EqualFold(rule.Action, "ALLOW") && strings.TrimSpace(rule.HostPattern) == "*" {
			catchAll++
		}
	}
	add("catch-all", "governance", "No catch-all ALLOW rules", pass(catchAll == 0, "fail"), itoa(catchAll)+" rules",
		"Replace '*' allow rules with explicit destinations.", "")
	s.auditPostureChecks(add)

	// Detection
	p := snap.SecurityPolicy
	add("threat-intel", "detection", "Threat intelligence blocking", pass(p.ThreatIntelMode == "block", "warn"), "mode "+p.ThreatIntelMode,
		"Set threat intelligence to block.", "docs/threat-protection.md")
	scanners := []string{}
	if p.AVEnabled {
		scanners = append(scanners, "ClamAV")
	}
	if p.ICAPRespmodURL != "" {
		scanners = append(scanners, "ICAP")
	}
	if p.YARAMode != "off" && len(s.store.YaraRuleSets()) > 0 {
		scanners = append(scanners, "YARA")
	}
	add("malware-scanning", "detection", "Downloads scanned for malware", pass(len(scanners) > 0, "fail"), strings.Join(scanners, ", "),
		"Enable ClamAV and/or connect your antivirus engine via ICAP.", "docs/threat-protection.md")
	if p.AVEnabled || p.ICAPRespmodURL != "" {
		open := []string{}
		if p.AVEnabled && p.AVFailMode != "closed" {
			open = append(open, "ClamAV")
		}
		if p.ICAPRespmodURL != "" && p.ICAPFailMode != "closed" {
			open = append(open, "ICAP")
		}
		add("scan-fail-closed", "detection", "Downloads blocked while a scanner is unavailable (fail-closed)", pass(len(open) == 0, "warn"),
			strings.Join(open, ", ")+" fail open",
			"Fail-open lets downloads through unscanned during an engine outage. Set the fail mode to closed where availability allows.",
			"docs/threat-protection.md")
		// An enforcing scanner with oversize "allow" delivers everything above the scan limit unscanned: an attacker
		// only has to pad a file. Monitor-only scanning never blocks anyway, so that stays informational.
		avEnforces := (p.AVEnabled && p.AVMode != "monitor") || (p.ICAPRespmodURL != "" && p.ICAPMode != "monitor")
		oversizeStatus := "info"
		if avEnforces {
			oversizeStatus = "warn"
		}
		add("scan-oversize", "detection", "Downloads above the scan limit are blocked", pass(p.AVOversizeAction == "block", oversizeStatus),
			"oversize action "+p.AVOversizeAction+", scan limit "+strconv.FormatInt(p.AVMaxScanBytes, 10)+" bytes",
			"Files above the scan limit pass unscanned (flagged AV_UNSCANNED:oversize) with \"allow\": set av_oversize_action to block, or raise av_max_scan_bytes.",
			"docs/threat-protection.md")
	}
	add("dlp", "detection", "Data loss prevention active", pass(p.DLPMode != "off" || p.ICAPReqmodURL != "", "warn"), "mode "+p.DLPMode, "", "docs/threat-protection.md#data-loss-prevention")
	if p.DLPMode == "block" || (p.ICAPReqmodURL != "" && p.ICAPMode != "monitor") {
		add("dlp-oversize", "detection", "Uploads above the DLP scan limit are blocked", pass(p.DLPOversizeAction == "block", "warn"),
			"oversize action "+p.DLPOversizeAction+", scan limit "+strconv.FormatInt(p.DLPMaxScanBytes, 10)+" bytes",
			"Only the first dlp_max_scan_bytes of an upload are scanned; with \"allow\" a secret placed beyond them leaves (flagged DLP_UNSCANNED:oversize). Set dlp_oversize_action to block (413), or raise dlp_max_scan_bytes.",
			"docs/threat-protection.md#data-loss-prevention")
	}
	failing := []string{}
	if ti := s.store.ThreatIntel(); ti != nil {
		for _, f := range ti.FeedsWithStatus(s.store.ThreatFeedConfigs()) {
			if f.Enabled && f.LastError != "" && (f.LastSuccessAt == nil || now.Sub(*f.LastSuccessAt) > 24*time.Hour) {
				failing = append(failing, f.Name)
			}
		}
	}
	add("feeds", "detection", "Threat-intelligence sources up to date", pass(len(failing) == 0, "warn"), strings.Join(failing, ", "),
		"Check connectivity and credentials of the failing sources.", "docs/threat-protection.md")
	healthy := 0
	for _, dp := range s.DataPlanes() {
		if dp.Healthy {
			healthy++
		}
	}
	add("workers", "platform", "Data-plane workers reporting", pass(healthy > 0, "warn"), itoa(healthy)+" healthy", "", "docs/operations.md#monitoring")
	s.workerFreshnessChecks(add)
	return out
}

type postureAdd func(id, cat, title, status, detail, fix, doc string)

// trustedProxyPostureCheck: only the reverse proxy can assert client addresses. Loopback is shared by every
// local account and a broad range by every host in it; without the proxy secret each of them can choose the
// address used for CIDR-bound API keys, sign-in throttling and the audit trail.
func (s *Server) trustedProxyPostureCheck(add postureAdd) {
	const title = "Client addresses asserted only by the reverse proxy"
	doc := "docs/configuration.md#trusted-proxies-and-sign-in-throttling"
	if len(s.cfg.TrustedProxies) == 0 && len(s.cfg.TrustedProxyHosts) == 0 {
		add("trusted-proxies", "platform", title, "pass", "no trusted proxies: the TCP peer is the client", "", doc)
		return
	}
	if s.cfg.TrustedProxySecret != "" {
		add("trusted-proxies", "platform", title, "pass", "trusted proxies authenticate with AEGIS_TRUSTED_PROXY_SECRET", "", doc)
		return
	}
	var shared []string
	for _, p := range s.cfg.TrustedProxies {
		if broadProxyRange(p) {
			shared = append(shared, p.String())
		}
	}
	if len(shared) == 0 {
		add("trusted-proxies", "platform", title, "pass", "trusted proxies listed by address or name", "", doc)
		return
	}
	add("trusted-proxies", "platform", title, "warn", "AEGIS_TRUSTED_PROXIES trusts "+strings.Join(shared, ", ")+" without a proxy secret",
		"Loopback is shared by every local account and a broad range by every host in it: set AEGIS_TRUSTED_PROXY_SECRET and let the proxy send it in "+
			proxyAuthHeader+", or trust only the proxy's own address or name (AEGIS_TRUSTED_PROXY_HOSTS).", doc)
}

// broadProxyRange: a trusted prefix of loopback addresses, or one at least as large as a /16 (IPv4) or /48 (IPv6).
func broadProxyRange(p netip.Prefix) bool {
	if p.Addr().IsLoopback() {
		return true
	}
	if p.Addr().Is4() {
		return p.Bits() <= 16
	}
	return p.Bits() <= 48
}

// encryptionPostureCheck: secrets at rest are encrypted, with a key kept outside the data directory.
func (s *Server) encryptionPostureCheck(add postureAdd) {
	const title = "Secrets encrypted at rest"
	switch {
	case !sealed.Enabled():
		add("encryption", "data", title, "fail", "secrets are stored unencrypted",
			"Set AEGIS_ENCRYPTION_KEY (required in cluster mode).", "docs/security.md")
	case s.cfg.EncryptionKeyInDataDir:
		// Encrypted, but the key sits next to the data: a copy of DATA_DIR decrypts the secrets and
		// the audit chain key, which defeats the keyed audit hash chain.
		add("encryption", "data", title, "warn", "AES-256-GCM key "+sealed.KeyID()+" — but the key is stored in the data directory (the generated secrets/encryption.key, or AEGIS_ENCRYPTION_KEY_FILE pointing into DATA_DIR), so anyone who can read DATA_DIR can decrypt the secrets and the audit chain key",
			"Provide AEGIS_ENCRYPTION_KEY or AEGIS_ENCRYPTION_KEY_FILE from a secret store outside DATA_DIR (Kubernetes/Docker secret, systemd credential, vault agent); move the key there and delete it from DATA_DIR.",
			"docs/operations.md#encryption-key")
	default:
		add("encryption", "data", title, "pass", "AES-256-GCM key "+sealed.KeyID()+" provided from outside the data directory", "", "docs/security.md")
	}
}

// auditSinkStale: an audit sink that has not delivered for this long while failing does not count as
// forwarding the trail.
const auditSinkStale = 15 * time.Minute

// auditPostureChecks: the audit trail is forwarded, intact (verified completely), trusted end to end
// and writable.
func (s *Server) auditPostureChecks(add postureAdd) {
	// Only an exported copy (with its AUDIT_CHECKPOINT records) reveals a rollback of the state and
	// the audit log together, so production installations must forward the audit stream, and a
	// destination that does not take it does not count.
	status := map[string]models.ExportSinkStatus{}
	for _, st := range s.exporter.Status() {
		status[st.ID] = st
	}
	configured, delivering := 0, 0
	var failing []string
	for _, sink := range s.store.ExportSinks() {
		if !sink.Enabled || !slices.Contains(sink.Streams, models.StreamAudit) {
			continue
		}
		configured++
		st, running := status[sink.ID]
		if !running || st.State == "ok" || st.State == "idle" || st.LastSuccessAt != nil && time.Since(*st.LastSuccessAt) < auditSinkStale {
			delivering++ // not running yet: the configuration is being applied
			continue
		}
		msg := sink.Name + ": " + st.State
		if st.LastError != "" {
			msg += " (" + st.LastError + ")"
		}
		if st.LastSuccessAt != nil {
			msg += ", last delivery " + st.LastSuccessAt.UTC().Format(time.RFC3339)
		}
		failing = append(failing, msg)
	}
	exportStatus := "fail"
	if s.store.DemoMode() {
		exportStatus = "warn"
	}
	exportDetail := "without an exported copy a rollback of state and audit log together cannot be detected"
	switch {
	case delivering > 0:
		exportStatus, exportDetail = "pass", itoa(delivering)+" destination(s) receive the audit stream"
		if len(failing) > 0 {
			exportDetail += "; failing: " + strings.Join(failing, "; ")
		}
	case configured > 0:
		exportDetail = "the audit stream is configured but no destination receives it: " + strings.Join(failing, "; ")
	}
	add("audit-export", "governance", "Audit trail forwarded to a SIEM", exportStatus, exportDetail,
		"Add a log export destination with the audit stream (Settings → Integrations → Log export) and make sure it delivers (Log export status).", "docs/log-export.md")
	audit := s.store.AuditStatus()
	full := s.store.AuditFullCheck()
	n, err := s.store.VerifyAuditChain()
	verified := itoa(n) + " events verified (in-memory window)"
	if full.Interval > 0 && full.At != nil && full.OK {
		verified = itoa(full.Events) + " events verified completely at " + full.At.Format(time.RFC3339)
	}
	switch {
	case audit.Integrity != "":
		add("audit-chain", "governance", "Audit hash chain intact", "fail", audit.Integrity,
			"Investigate tampering: compare with the exported audit trail and restore the data from a backup taken before the violation.", "docs/operations.md#audit-trail")
	case err != nil:
		add("audit-chain", "governance", "Audit hash chain intact", "fail", err.Error(), "Investigate tampering; compare with the exported audit trail.", "docs/operations.md#audit-trail")
	case full.Interval > 0 && full.At != nil && !full.OK:
		add("audit-chain", "governance", "Audit hash chain intact", "fail", "complete verification ("+full.Trigger+", "+full.At.Format(time.RFC3339)+") failed: "+full.Error,
			"Compare the trail with the exported copy. A missing start is expected only until a retention point is applied; a trail that cannot be read must be made readable again (permissions, disk).", "docs/operations.md#audit-trail")
	case audit.LegacyPending:
		add("audit-chain", "governance", "Audit hash chain intact", "fail",
			itoa(audit.LegacyEvents)+" unkeyed (pre-2.1) events up to "+audit.LegacyHead+" are not trusted until a Super Admin accepts them",
			"Compare the legacy events with the trail exported before the upgrade, then accept them (Audit trail → Verify hash chain → Review and accept). If this installation already ran 2.1, the audit chain key and anchor were removed: do not accept, restore from a backup.",
			"docs/operations.md#audit-trail")
	case full.Interval > 0 && full.At == nil:
		add("audit-chain", "governance", "Audit hash chain intact", "warn", verified+"; the complete verification of the trail has not finished yet",
			"Wait for the complete verification started at start-up (large trails take a while), or run it: Audit trail → Verify hash chain.", "docs/operations.md#audit-trail")
	case full.Interval > 0 && time.Since(*full.At) > 2*full.Interval+time.Hour:
		add("audit-chain", "governance", "Audit hash chain intact", "warn", verified+"; the last complete verification is overdue (AEGIS_AUDIT_VERIFY_INTERVAL "+full.Interval.String()+")",
			"Check the control-plane log for the complete verification of the audit trail.", "docs/operations.md#audit-trail")
	case audit.LegacyEvents > 0:
		// Pre-2.1 events use the unkeyed hash; a Super Admin accepted them as the prefix before the cutover.
		add("audit-chain", "governance", "Audit hash chain intact", "warn", verified+"; "+itoa(audit.LegacyEvents)+" accepted legacy events (pre-2.1, unkeyed hash) before the sealed cutover",
			"Keep an archived copy of the legacy part of the trail (exported before the upgrade) as independent evidence.", "docs/operations.md#audit-trail")
	default:
		add("audit-chain", "governance", "Audit hash chain intact", "pass", verified, "", "")
	}
	if !audit.Writable {
		// File storage refuses changes meanwhile; in a cluster the database stays the trail of record.
		status := "fail"
		if s.store.StorageName() != "file" {
			status = "pass"
		}
		add("audit-log", "governance", "Audit log writable", status, audit.Error,
			"Free disk space or fix the audit log file (no symbolic link or FIFO); changes resume automatically.", "docs/operations.md#audit-trail")
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// workerFreshnessChecks covers the reporting workers' stale-policy limit (AEGIS_POLICY_MAX_AGE) and telemetry loss.
func (s *Server) workerFreshnessChecks(add func(id, cat, title, status, detail, fix, doc string)) {
	var unknown, noLimit, stale, lossy []string
	healthy := 0
	for _, dp := range s.DataPlanes() {
		if !dp.Healthy {
			continue
		}
		healthy++
		switch {
		case dp.PolicyMaxAgeSeconds < 0:
			unknown = append(unknown, dp.ID)
		case dp.PolicyMaxAgeSeconds == 0:
			noLimit = append(noLimit, dp.ID)
		case dp.PolicyAgeSeconds > dp.PolicyMaxAgeSeconds:
			stale = append(stale, dp.ID)
		}
		if dp.FlowsDroppedTotal > 0 {
			lossy = append(lossy, dp.ID+" ("+strconv.FormatInt(dp.FlowsDroppedTotal, 10)+")")
		}
	}
	if healthy == 0 {
		return
	}
	list := func(ids []string) string {
		if len(ids) > 5 {
			return strings.Join(ids[:5], ", ") + " and " + itoa(len(ids)-5) + " more"
		}
		return strings.Join(ids, ", ")
	}
	const fix = "Set AEGIS_POLICY_MAX_AGE on every worker (e.g. 10m): a worker cut off from the control-plane longer than that " +
		"refuses new connections instead of enforcing a policy that may revoke nothing any more."
	switch {
	case len(stale) > 0:
		add("worker-policy-age", "platform", "Workers enforce a current policy", "fail", "policy older than the limit: "+list(stale),
			"These workers fail closed (503 policy_stale). Check their connection to the control-plane.", "docs/configuration.md#data-plane-mitmproxy-worker")
	case len(noLimit) > 0 || len(unknown) > 0:
		detail := ""
		if len(noLimit) > 0 {
			detail = "no AEGIS_POLICY_MAX_AGE: " + list(noLimit)
		}
		if len(unknown) > 0 {
			detail = strings.TrimPrefix(detail+"; not reported (older worker): "+list(unknown), "; ")
		}
		add("worker-policy-age", "platform", "Workers enforce a current policy", "warn", detail, fix, "docs/configuration.md#data-plane-mitmproxy-worker")
	default:
		add("worker-policy-age", "platform", "Workers enforce a current policy", "pass", itoa(healthy)+" workers with a policy age limit", "", "")
	}
	cpLost := int64(0)
	for _, n := range s.store.FlowDrops() {
		cpLost += n
	}
	detail := ""
	if len(lossy) > 0 {
		detail = "workers: " + list(lossy)
	}
	if cpLost > 0 {
		detail = strings.TrimPrefix(detail+"; control-plane: "+strconv.FormatInt(cpLost, 10), "; ")
	}
	status := "pass"
	if detail != "" {
		status = "warn"
	}
	add("telemetry-loss", "data", "Traffic records delivered completely", status, detail,
		"Records were lost (counts since the worker or control-plane started). Enable the worker flow spool (AEGIS_FLOW_SPOOL_DIR) "+
			"on persistent storage and check aegis_dp_flows_dropped_total / aegis_flows_dropped_total by reason.",
		"docs/operations.md#traffic-telemetry-delivery")
}
