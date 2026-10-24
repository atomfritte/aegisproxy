package api

import (
	"net/http"
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
	add("encryption", "data", "Secrets encrypted at rest", pass(sealed.Enabled(), "fail"), "AES-256-GCM key "+sealed.KeyID(),
		"Set AEGIS_ENCRYPTION_KEY (required in cluster mode).", "docs/security.md")
	if _, err := os.Stat(filepath.Join(s.cfg.DataDir, "secrets", "initial-admin-password")); err == nil {
		add("bootstrap-file", "identity", "Initial admin password file removed", "warn", "secrets/initial-admin-password still exists",
			"Sign in, change the password and delete the file.", "docs/operations.md#day-one-checklist")
	} else {
		add("bootstrap-file", "identity", "Initial admin password file removed", "pass", "", "", "")
	}
	add("metrics", "platform", "Metrics endpoint protected", pass(s.cfg.MetricsToken != "", "info"), "AEGIS_METRICS_TOKEN",
		"Set a bearer token for /metrics or restrict it at the network level.", "docs/configuration.md")
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
	auditExport := false
	for _, sink := range s.store.ExportSinks() {
		if sink.Enabled && slices.Contains(sink.Streams, models.StreamAudit) {
			auditExport = true
		}
	}
	add("audit-export", "governance", "Audit trail forwarded to a SIEM", pass(auditExport, "warn"), "",
		"Add a log export destination with the audit stream (Settings → Integrations → Log export).", "docs/log-export.md")
	audit := s.store.AuditStatus()
	if n, err := s.store.VerifyAuditChain(); err != nil {
		add("audit-chain", "governance", "Audit hash chain intact", "fail", err.Error(), "Investigate tampering; compare with the exported audit trail.", "docs/security.md")
	} else if audit.LegacyEvents > 0 {
		// Pre-2.1 events use the unkeyed hash; they are accepted only before the sealed cutover.
		add("audit-chain", "governance", "Audit hash chain intact", "warn", itoa(n)+" events verified; "+itoa(audit.LegacyEvents)+" legacy events (pre-2.1, unkeyed hash) before the sealed cutover",
			"Keep an archived copy of the legacy part of the trail (exported before the upgrade) as independent evidence.", "docs/operations.md#audit-trail")
	} else {
		add("audit-chain", "governance", "Audit hash chain intact", "pass", itoa(n)+" events verified", "", "")
	}
	if !audit.Writable {
		// File storage refuses changes meanwhile; in a cluster the database stays the trail of record.
		add("audit-log", "governance", "Audit log writable", pass(s.store.StorageName() != "file", "fail"), audit.Error,
			"Free disk space or fix the audit log file (no symbolic link or FIFO); changes resume automatically.", "docs/operations.md#audit-trail")
	}

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
		add("scan-oversize", "detection", "Downloads above the scan limit are blocked", pass(p.AVOversizeAction == "block", "info"),
			"oversize action "+p.AVOversizeAction, "Large files pass unscanned with \"allow\"; raise the scan limit or block oversize downloads for sensitive groups.",
			"docs/threat-protection.md")
	}
	add("dlp", "detection", "Data loss prevention active", pass(p.DLPMode != "off" || p.ICAPReqmodURL != "", "warn"), "mode "+p.DLPMode, "", "docs/threat-protection.md#data-loss-prevention")
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
	return out
}

func itoa(n int) string { return strconv.Itoa(n) }
