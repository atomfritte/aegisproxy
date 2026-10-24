package store

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"

	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/threatintel"
)

var allowedMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "*"}

// DLPDetectors lists the detector IDs implemented by the data-plane.
var DLPDetectors = []string{
	"private_key", "aws_access_key", "aws_secret_key", "github_token", "gitlab_token", "slack_token",
	"slack_webhook", "google_api_key", "stripe_key", "azure_storage_key", "npm_token", "pypi_token",
	"credit_card", "unix_shadow",
}

// FileTypes lists the file type IDs the data-plane can detect via magic bytes / extensions.
var FileTypes = []string{
	"pe", "elf", "macho", "java_class", "msi_ole", "script", "jar", "apk", "zip", "archive", "office_macro", "iso",
}

func DefaultSecurityPolicy() models.SecurityPolicy {
	return models.SecurityPolicy{
		ThreatIntelMode:          "block",
		AVEnabled:                true,
		AVMode:                   "block",
		AVFailMode:               "open",
		AVMaxScanBytes:           25 << 20,
		AVOversizeAction:         "allow",
		DLPMode:                  "monitor",
		DLPMaxScanBytes:          1 << 20,
		DLPOversizeAction:        "allow",
		DLPDetectors:             append([]string(nil), DLPDetectors...),
		BlockedFileTypes:         []string{},
		BlockIPLiterals:          true,
		BlockPrivateDestinations: true,
		BlockRawTCP:              true,
		AllowedPorts:             []int{80, 443},
		PunycodeMode:             "monitor",
		MaxUploadBytes:           0,
		BlockedBurstThreshold:    30,
		ICAPMode:                 "block",
		ICAPFailMode:             "open",
		ICAPTimeoutSeconds:       30,
		ICAPMaxBytes:             25 << 20,
		ICAPAllowModified:        true,
		YARAMode:                 "off",
		YARAMaxBytes:             25 << 20,
		TelemetryQueryRedaction:  RedactSensitive,
	}
}

func validICAPURL(field, raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "icap" && u.Scheme != "icaps") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || len(raw) > 300 {
		return fmt.Errorf("%s must look like icap://host:1344/service or icaps://host:11344/service", field)
	}
	if a, err := netip.ParseAddr(u.Hostname()); err == nil && (a.IsLinkLocalUnicast() || a.IsUnspecified()) {
		return fmt.Errorf("%s must not point to a link-local address", field)
	}
	return nil
}

func hasCtl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func checkText(field, v string, maxLen int, required bool) error {
	if required && strings.TrimSpace(v) == "" {
		return fmt.Errorf("%s is required", field)
	}
	if len(v) > maxLen {
		return fmt.Errorf("%s must be at most %d characters", field, maxLen)
	}
	if hasCtl(strings.ReplaceAll(strings.ReplaceAll(v, "\n", ""), "\t", "")) {
		return fmt.Errorf("%s contains control characters", field)
	}
	return nil
}

// ValidateHostPattern accepts "example.com", "*.example.com", an IP literal or "*".
func ValidateHostPattern(p string) (string, error) {
	h := strings.ToLower(strings.TrimSpace(p))
	h = strings.TrimSuffix(h, ".")
	if h == "*" {
		return h, nil
	}
	if h == "" {
		return "", errors.New("host pattern is required")
	}
	if strings.ContainsAny(h, "/:@ ?#") {
		if a, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
			return a.String(), nil
		}
		return "", fmt.Errorf("host pattern %q must be a bare hostname (no scheme, port or path)", p)
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return a.String(), nil
	}
	check := h
	if strings.HasPrefix(h, "*.") {
		check = strings.TrimPrefix(h, "*.")
	}
	if strings.Contains(check, "*") {
		return "", fmt.Errorf("host pattern %q: wildcards are only allowed as a leading '*.' label", p)
	}
	if _, ok := threatintel.NormalizeDomain(check); !ok {
		if check != "localhost" {
			return "", fmt.Errorf("host pattern %q is not a valid hostname", p)
		}
	}
	return h, nil
}

func validatePathPattern(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" || p == "*" {
		return "/**", nil
	}
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("path pattern %q must start with '/'", p)
	}
	if len(p) > 1024 || hasCtl(p) || strings.ContainsAny(p, " \\") {
		return "", fmt.Errorf("path pattern %q contains invalid characters", p)
	}
	if _, ok := engine.CanonicalizePath(strings.ReplaceAll(p, "*", "x")); !ok {
		return "", fmt.Errorf("path pattern %q is malformed", p)
	}
	return p, nil
}

func validateCompanion(c string) (string, error) {
	c = strings.TrimSpace(c)
	host, path := c, "/**"
	if i := strings.IndexByte(c, '/'); i >= 0 {
		host, path = c[:i], c[i:]
	}
	h, err := ValidateHostPattern(host)
	if err != nil {
		return "", fmt.Errorf("companion rule %q: %w", c, err)
	}
	if h == "*" {
		return "", fmt.Errorf("companion rule %q: catch-all host is not allowed", c)
	}
	p, err := validatePathPattern(path)
	if err != nil {
		return "", fmt.Errorf("companion rule %q: %w", c, err)
	}
	return h + p, nil
}

// validateRedirectHosts normalizes the optional redirect target allowlist of a rule (nil when empty).
func validateRedirectHosts(list []string) ([]string, error) {
	if len(list) > 20 {
		return nil, errors.New("at most 20 redirect hosts are allowed")
	}
	var out []string
	for _, raw := range list {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		h, err := ValidateHostPattern(raw)
		if err != nil {
			return nil, fmt.Errorf("redirect host: %w", err)
		}
		if h == "*" {
			return nil, errors.New("redirect host: '*' is the default (leave the list empty)")
		}
		if !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	return out, nil
}

// normalizeAndValidateRuleLocked validates a policy rule against the current fleet.
func (s *Store) normalizeAndValidateRuleLocked(r *models.PolicyRule, actorRole models.Role) error {
	if err := checkText("name", r.Name, 200, true); err != nil {
		return err
	}
	if err := checkText("description", r.Description, 2000, false); err != nil {
		return err
	}
	r.Action = strings.ToUpper(strings.TrimSpace(r.Action))
	if r.Action == "" {
		r.Action = "ALLOW"
	}
	if r.Action != "ALLOW" && r.Action != "BLOCK" {
		return errors.New("action must be ALLOW or BLOCK")
	}
	h, err := ValidateHostPattern(r.HostPattern)
	if err != nil {
		return err
	}
	if h == "*" && r.Action == "ALLOW" && actorRole != models.RoleSuperAdmin {
		return errors.New("only Super Admins may create catch-all (*) ALLOW rules")
	}
	r.HostPattern = h
	if r.PathPattern, err = validatePathPattern(r.PathPattern); err != nil {
		return err
	}
	if len(r.Methods) == 0 {
		r.Methods = []string{"GET", "HEAD"}
	}
	methods := make([]string, 0, len(r.Methods))
	for _, m := range r.Methods {
		m = strings.ToUpper(strings.TrimSpace(m))
		if !slices.Contains(allowedMethods, m) {
			return fmt.Errorf("unsupported HTTP method %q", m)
		}
		if !slices.Contains(methods, m) {
			methods = append(methods, m)
		}
	}
	r.Methods = methods
	if len(r.CompanionRules) > 20 {
		return errors.New("at most 20 companion rules are allowed")
	}
	comps := make([]string, 0, len(r.CompanionRules))
	for _, c := range r.CompanionRules {
		if strings.TrimSpace(c) == "" {
			continue
		}
		v, err := validateCompanion(c)
		if err != nil {
			return err
		}
		comps = append(comps, v)
	}
	r.CompanionRules = comps
	if r.RedirectHosts, err = validateRedirectHosts(r.RedirectHosts); err != nil {
		return err
	}
	if err := s.validateScopeLocked(r.GroupIDs, r.ServerIDs); err != nil {
		return err
	}
	if len(r.GroupIDs) == 0 && len(r.ServerIDs) == 0 {
		return errors.New("rule must target at least one server group or server")
	}
	if r.ExpiresAt != nil && r.ExpiresAt.Before(time.Now().Add(-time.Minute)) {
		return errors.New("expires_at must be in the future")
	}
	if r.GroupIDs == nil {
		r.GroupIDs = []string{}
	}
	if r.ServerIDs == nil {
		r.ServerIDs = []string{}
	}
	return nil
}

func (s *Store) validateScopeLocked(groupIDs, serverIDs []string) error {
	if len(groupIDs) > 100 || len(serverIDs) > 1000 {
		return errors.New("too many scope entries")
	}
	for _, g := range groupIDs {
		if g == "*" {
			continue
		}
		if !slices.ContainsFunc(s.state.Groups, func(x models.ServerGroup) bool { return x.ID == g }) {
			return fmt.Errorf("unknown server group %q", g)
		}
	}
	for _, id := range serverIDs {
		if id == "*" {
			continue
		}
		if !slices.ContainsFunc(s.state.Servers, func(x models.Server) bool { return x.ID == id }) {
			return fmt.Errorf("unknown server %q", id)
		}
	}
	return nil
}

func (s *Store) validateTLSBypassLocked(b *models.TLSBypassRule) error {
	p, err := ValidateHostPattern(b.Pattern)
	if err != nil {
		return err
	}
	if p == "*" || isBroadWildcard(p) {
		return errors.New("TLS bypass patterns must not be catch-all or top-level-domain wildcards")
	}
	b.Pattern = p
	if strings.HasPrefix(p, "*.") {
		b.MatchType = "wildcard"
	} else {
		b.MatchType = "exact"
	}
	if err := checkText("reason", b.Reason, 1000, true); err != nil {
		return err
	}
	if err := checkText("category", b.Category, 120, false); err != nil {
		return err
	}
	if b.ExpiresAt != nil && b.ExpiresAt.Before(time.Now()) {
		return errors.New("expires_at must be in the future")
	}
	return s.validateScopeLocked(b.GroupIDs, b.ServerIDs)
}

func isBroadWildcard(p string) bool {
	if !strings.HasPrefix(p, "*.") {
		return false
	}
	labels := strings.Split(strings.TrimPrefix(p, "*."), ".")
	return len(labels) < 2 || (len(labels) == 2 && len(labels[0]) <= 3 && len(labels[1]) == 2)
}

func validateMode(field, v string, allowed ...string) error {
	if !slices.Contains(allowed, v) {
		return fmt.Errorf("%s must be one of %v", field, allowed)
	}
	return nil
}

func validateSecurityPolicy(p *models.SecurityPolicy, groups []models.ServerGroup) error {
	if err := validateMode("threat_intel_mode", p.ThreatIntelMode, "off", "monitor", "block"); err != nil {
		return err
	}
	if err := validateMode("av_mode", p.AVMode, "monitor", "block"); err != nil {
		return err
	}
	if err := validateMode("av_fail_mode", p.AVFailMode, "open", "closed"); err != nil {
		return err
	}
	if err := validateMode("av_oversize_action", p.AVOversizeAction, "allow", "block"); err != nil {
		return err
	}
	if err := validateMode("dlp_mode", p.DLPMode, "off", "monitor", "block"); err != nil {
		return err
	}
	if p.DLPOversizeAction == "" {
		p.DLPOversizeAction = "allow" // clients that predate the field
	}
	if err := validateMode("dlp_oversize_action", p.DLPOversizeAction, "allow", "block"); err != nil {
		return err
	}
	if err := validateMode("punycode_mode", p.PunycodeMode, "off", "monitor", "block"); err != nil {
		return err
	}
	if p.ICAPMode == "" {
		p.ICAPMode, p.ICAPFailMode, p.ICAPTimeoutSeconds, p.ICAPMaxBytes = "block", "open", 30, 25<<20
	}
	if p.YARAMode == "" {
		p.YARAMode, p.YARAMaxBytes = "off", 25<<20
	}
	if err := validateMode("icap_mode", p.ICAPMode, "monitor", "block"); err != nil {
		return err
	}
	if err := validateMode("icap_fail_mode", p.ICAPFailMode, "open", "closed"); err != nil {
		return err
	}
	if err := validateMode("yara_mode", p.YARAMode, "off", "monitor", "block"); err != nil {
		return err
	}
	if p.TelemetryQueryRedaction == "" {
		p.TelemetryQueryRedaction = RedactSensitive // clients that predate the field
	}
	if err := validateMode("telemetry_query_redaction", p.TelemetryQueryRedaction, RedactNone, RedactSensitive, RedactAll); err != nil {
		return err
	}
	if err := validICAPURL("icap_respmod_url", p.ICAPRespmodURL); err != nil {
		return err
	}
	if err := validICAPURL("icap_reqmod_url", p.ICAPReqmodURL); err != nil {
		return err
	}
	if p.ICAPTimeoutSeconds < 1 || p.ICAPTimeoutSeconds > 600 {
		return errors.New("icap_timeout_seconds must be between 1 and 600")
	}
	if p.ICAPMaxBytes < 1<<20 || p.ICAPMaxBytes > 2<<30 || p.YARAMaxBytes < 1<<20 || p.YARAMaxBytes > 2<<30 {
		return errors.New("icap_max_bytes and yara_max_bytes must be between 1 MiB and 2 GiB")
	}
	if len(p.ICAPCACertPEM) > 64<<10 || (strings.TrimSpace(p.ICAPCACertPEM) != "" && !strings.Contains(p.ICAPCACertPEM, "BEGIN CERTIFICATE")) {
		return errors.New("icap_ca_cert_pem must be a PEM certificate")
	}
	if p.AVMaxScanBytes < 1<<20 || p.AVMaxScanBytes > 2<<30 {
		return errors.New("av_max_scan_bytes must be between 1 MiB and 2 GiB")
	}
	if p.DLPMaxScanBytes < 4<<10 || p.DLPMaxScanBytes > 64<<20 {
		return errors.New("dlp_max_scan_bytes must be between 4 KiB and 64 MiB")
	}
	if p.MaxUploadBytes < 0 {
		return errors.New("max_upload_bytes must not be negative")
	}
	if p.BlockedBurstThreshold < 0 || p.BlockedBurstThreshold > 100_000 {
		return errors.New("blocked_burst_threshold out of range")
	}
	for _, d := range p.DLPDetectors {
		if !slices.Contains(DLPDetectors, d) {
			return fmt.Errorf("unknown DLP detector %q", d)
		}
	}
	checkTypes := func(list []string) error {
		for _, t := range list {
			if !slices.Contains(FileTypes, t) {
				return fmt.Errorf("unknown file type %q", t)
			}
		}
		return nil
	}
	if err := checkTypes(p.BlockedFileTypes); err != nil {
		return err
	}
	for gid, list := range p.GroupBlockedFileTypes {
		if !slices.ContainsFunc(groups, func(g models.ServerGroup) bool { return g.ID == gid }) {
			return fmt.Errorf("unknown server group %q in group_blocked_file_types", gid)
		}
		if err := checkTypes(list); err != nil {
			return err
		}
	}
	if len(p.AllowedPorts) == 0 {
		return errors.New("allowed_ports must not be empty")
	}
	for _, port := range p.AllowedPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid port %d", port)
		}
	}
	if p.DLPDetectors == nil {
		p.DLPDetectors = []string{}
	}
	if p.BlockedFileTypes == nil {
		p.BlockedFileTypes = []string{}
	}
	return nil
}

func validateIndicator(ind *models.Indicator) error {
	v := strings.TrimSpace(ind.Value)
	switch ind.Type {
	case "domain":
		d, ok := threatintel.NormalizeDomain(strings.TrimPrefix(v, "*."))
		if !ok {
			return errors.New("invalid domain")
		}
		ind.Value = d
	case "url":
		u, ok := threatintel.NormalizeURL(v)
		if !ok {
			return errors.New("invalid URL (absolute http/https URL required)")
		}
		ind.Value = u
	case "ip":
		a, err := netip.ParseAddr(v)
		if err != nil {
			return errors.New("invalid IP address")
		}
		ind.Value = a.Unmap().String()
	case "cidr":
		p, err := netip.ParsePrefix(v)
		if err != nil || p.Bits() < 8 {
			return errors.New("invalid CIDR (prefix length must be >= 8)")
		}
		ind.Value = p.Masked().String()
	case "sha256":
		h, ok := threatintel.NormalizeHash(v)
		if !ok {
			return errors.New("invalid SHA-256 hash")
		}
		ind.Value = h
	default:
		return errors.New("type must be one of domain, url, ip, cidr, sha256")
	}
	if ind.Category == "" {
		ind.Category = "custom"
	}
	if err := checkText("category", ind.Category, 64, true); err != nil {
		return err
	}
	return checkText("reason", ind.Reason, 1000, true)
}

func validateException(ex *models.ThreatException) error {
	ind := models.Indicator{Type: ex.Type, Value: ex.Value, Category: "exception", Reason: ex.Reason}
	if ex.Type == "cidr" {
		return errors.New("exceptions support domain, url, ip and sha256")
	}
	if err := validateIndicator(&ind); err != nil {
		return err
	}
	ex.Value = ind.Value
	return nil
}
