package store

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
)

const (
	maxPackageRules     = 500
	maxPackageApprovals = 200_000
	maxPackageBlocks    = 50_000
)

var errPackagesNeedSystem = errors.New("RBAC Policy: only InfoSec Approvers and Super Admins can change the package firewall")

// DefaultPackageFirewall is the initial configuration: every ecosystem off, a conservative cooldown,
// the public registries pre-filled, and the default advisory sources enabled.
func DefaultPackageFirewall() models.PackageFirewall {
	eco := func(hosts, fileHosts []string, upstream string) models.PackageEcosystemSettings {
		return models.PackageEcosystemSettings{Mode: models.PackageModeOff, Hosts: hosts, FileHosts: fileHosts, GroupIDs: []string{"*"}, Upstream: upstream}
	}
	return models.PackageFirewall{
		Settings: models.PackageSettings{
			Ecosystems: map[string]models.PackageEcosystemSettings{
				models.EcosystemNPM:       eco([]string{"registry.npmjs.org", "registry.yarnpkg.com"}, nil, "https://registry.npmjs.org"),
				models.EcosystemPyPI:      eco([]string{"pypi.org"}, []string{"files.pythonhosted.org"}, "https://pypi.org"),
				models.EcosystemNuGet:     eco([]string{"api.nuget.org"}, nil, "https://api.nuget.org"),
				models.EcosystemPSGallery: eco([]string{"www.powershellgallery.com"}, []string{"psg-prod-eastus.azureedge.net", "psg-prod-centralus.azureedge.net"}, "https://www.powershellgallery.com"),
			},
			DefaultCooldownHours:  72,
			AutoRequestDiscovered: true,
			ReauditHours:          24,
			WatchHours:            6,
			RevokeOnSeverity:      models.RiskCritical,
			MaxGraphSize:          4000,
			Sandbox: models.PackageSandboxConfig{
				Enabled: true, Scenarios: []string{"static", "install", "load"},
				TimeoutSeconds: 120, MaxArtifactBytes: 512 << 20, Required: false,
			},
			Audit:              DefaultPackageAuditSources(),
			PythonEnvironments: defaultPythonEnvironments(),
		},
	}
}

// mergePackageAuditDefaultsLocked adds advisory sources introduced after the stored configuration was
// written, keeping the operator's enabled/token choices for the sources that already exist.
func mergePackageAuditDefaultsLocked(p *models.PackageSettings) {
	have := map[string]bool{}
	for _, a := range p.Audit {
		have[a.ID] = true
	}
	for _, def := range DefaultPackageAuditSources() {
		if !have[def.ID] {
			def.Enabled = false // a newly shipped source stays off until the operator enables it
			p.Audit = append(p.Audit, def)
		}
	}
	if p.Sandbox.TimeoutSeconds == 0 {
		p.Sandbox = DefaultPackageFirewall().Settings.Sandbox
	}
}

// DefaultPackageAuditSources lists the advisory / reputation sources enabled out of the box.
func DefaultPackageAuditSources() []models.PackageAuditSource {
	return []models.PackageAuditSource{
		{ID: "osv", Enabled: true},       // OSV.dev — covers every ecosystem, no token
		{ID: "npm", Enabled: true},       // npm registry audit (bulk advisory endpoint)
		{ID: "pypi", Enabled: true},      // PyPI JSON API vulnerabilities (OSV-backed)
		{ID: "nuget", Enabled: true},     // NuGet vulnerability index
		{ID: "github", Enabled: false},   // GitHub Advisory Database (GraphQL; needs a token)
		{ID: "depsdev", Enabled: true},   // deps.dev (advisories, scorecard, provenance signals)
		{ID: "ossindex", Enabled: false}, // Sonatype OSS Index (optional account)
	}
}

func defaultPythonEnvironments() []map[string]string {
	return []map[string]string{
		{"python_version": "3.12", "python_full_version": "3.12.7", "os_name": "posix", "sys_platform": "linux", "platform_system": "Linux", "platform_machine": "x86_64", "implementation_name": "cpython"},
		{"python_version": "3.12", "python_full_version": "3.12.7", "os_name": "posix", "sys_platform": "linux", "platform_system": "Linux", "platform_machine": "aarch64", "implementation_name": "cpython"},
		{"python_version": "3.12", "python_full_version": "3.12.7", "os_name": "nt", "sys_platform": "win32", "platform_system": "Windows", "platform_machine": "AMD64", "implementation_name": "cpython"},
		{"python_version": "3.12", "python_full_version": "3.12.7", "os_name": "posix", "sys_platform": "darwin", "platform_system": "Darwin", "platform_machine": "arm64", "implementation_name": "cpython"},
	}
}

// PackageFirewall returns a copy of the package firewall configuration (tokens redacted).
func (s *Store) PackageFirewall() models.PackageFirewall {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return clonePackageFirewall(s.state.Packages, true)
}

func clonePackageFirewall(p models.PackageFirewall, redact bool) models.PackageFirewall {
	out := models.PackageFirewall{Settings: p.Settings}
	out.Settings.Ecosystems = map[string]models.PackageEcosystemSettings{}
	for k, v := range p.Settings.Ecosystems {
		v.Hosts = append([]string(nil), v.Hosts...)
		v.FileHosts = append([]string(nil), v.FileHosts...)
		v.GroupIDs = append([]string(nil), v.GroupIDs...)
		out.Settings.Ecosystems[k] = v
	}
	out.Settings.Audit = make([]models.PackageAuditSource, len(p.Settings.Audit))
	for i, a := range p.Settings.Audit {
		a.HasToken = a.Token != ""
		if redact {
			a.Token = ""
		}
		out.Settings.Audit[i] = a
	}
	out.Settings.Sandbox.Scenarios = append([]string(nil), p.Settings.Sandbox.Scenarios...)
	out.Rules = make([]models.PackageRule, len(p.Rules))
	for i, r := range p.Rules {
		out.Rules[i] = clonePackageRule(r)
	}
	out.Approvals = append([]models.PackageApproval(nil), p.Approvals...)
	out.Blocks = append([]models.PackageBlock(nil), p.Blocks...)
	return out
}

func clonePackageRule(r models.PackageRule) models.PackageRule {
	r.Ecosystems = append([]string(nil), r.Ecosystems...)
	r.Packages = append([]string(nil), r.Packages...)
	r.GroupIDs = append([]string(nil), r.GroupIDs...)
	r.UpdateTypes = append([]string(nil), r.UpdateTypes...)
	r.Licenses = append([]string(nil), r.Licenses...)
	return r
}

// UpdatePackageSettings replaces the firewall settings (not rules/approvals/blocks).
func (s *Store) UpdatePackageSettings(in models.PackageSettings, actor *auth.TokenClaims) (models.PackageFirewall, error) {
	if !auth.CanManageSystem(actor) {
		return models.PackageFirewall{}, errPackagesNeedSystem
	}
	err := s.withWrite(func() error {
		merged, err := mergePackageSettings(s.state.Packages.Settings, in)
		if err != nil {
			return err
		}
		s.state.Packages.Settings = merged
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "PACKAGE_SETTINGS_UPDATED", Category: "SECURITY",
			EntityType: "package_firewall", EntityID: "global", EntityName: "Package firewall",
			Summary: packageSettingsSummary(merged),
		})
		s.saveLocked()
		return nil
	})
	if err != nil {
		return models.PackageFirewall{}, err
	}
	return s.PackageFirewall(), nil
}

func packageSettingsSummary(p models.PackageSettings) string {
	modes := make([]string, 0, len(p.Ecosystems))
	for _, e := range models.Ecosystems {
		if es, ok := p.Ecosystems[e]; ok {
			modes = append(modes, e+"="+es.Mode)
		}
	}
	return fmt.Sprintf("%s cooldown=%dh reaudit=%dh watch=%dh revoke>=%s sandbox=%v/%v auto_request=%v",
		strings.Join(modes, " "), p.DefaultCooldownHours, p.ReauditHours, p.WatchHours, p.RevokeOnSeverity,
		p.Sandbox.Enabled, p.Sandbox.Required, p.AutoRequestDiscovered)
}

// mergePackageSettings validates in and carries over sealed tokens the API redacts (empty token with
// HasToken means "keep the stored one").
func mergePackageSettings(cur, in models.PackageSettings) (models.PackageSettings, error) {
	if in.Ecosystems == nil {
		in.Ecosystems = map[string]models.PackageEcosystemSettings{}
	}
	for name, es := range in.Ecosystems {
		if !models.ValidEcosystem(name) {
			return cur, fmt.Errorf("unknown ecosystem %q", name)
		}
		switch es.Mode {
		case models.PackageModeOff, models.PackageModeMonitor, models.PackageModeEnforce:
		default:
			return cur, fmt.Errorf("%s: mode must be off, monitor or enforce", name)
		}
		if len(es.GroupIDs) == 0 {
			es.GroupIDs = []string{"*"}
		}
		if strings.TrimSpace(es.Upstream) == "" {
			return cur, fmt.Errorf("%s: an upstream registry URL is required", name)
		}
		if !strings.HasPrefix(es.Upstream, "https://") && !strings.HasPrefix(es.Upstream, "http://") {
			return cur, fmt.Errorf("%s: upstream must be an http(s) URL", name)
		}
		es.Upstream = strings.TrimRight(es.Upstream, "/")
		if len(es.Hosts) == 0 {
			return cur, fmt.Errorf("%s: at least one registry host is required", name)
		}
		in.Ecosystems[name] = es
	}
	if in.DefaultCooldownHours < 0 || in.DefaultCooldownHours > 24*365 {
		return cur, errors.New("default cooldown must be between 0 and 8760 hours")
	}
	if in.MaxGraphSize <= 0 || in.MaxGraphSize > 100_000 {
		in.MaxGraphSize = 4000
	}
	switch in.RevokeOnSeverity {
	case "", "malware", models.RiskCritical, models.RiskHigh:
	default:
		return cur, errors.New("revoke_on_severity must be empty, malware, critical or high")
	}
	// Carry over sealed tokens for sources whose token was redacted on the way out.
	byID := map[string]models.PackageAuditSource{}
	for _, a := range cur.Audit {
		byID[a.ID] = a
	}
	for i, a := range in.Audit {
		if a.Token == "" && a.HasToken {
			a.Token = byID[a.ID].Token
		}
		a.HasToken = a.Token != ""
		in.Audit[i] = a
	}
	if in.Sandbox.TimeoutSeconds <= 0 || in.Sandbox.TimeoutSeconds > 3600 {
		in.Sandbox.TimeoutSeconds = 120
	}
	if in.Sandbox.MaxArtifactBytes <= 0 {
		in.Sandbox.MaxArtifactBytes = 512 << 20
	}
	if len(in.Sandbox.Scenarios) == 0 {
		in.Sandbox.Scenarios = []string{"static", "install", "load"}
	}
	return in, nil
}

// --- Rules ---

// SavePackageRule creates or updates a rule (ID set = update).
func (s *Store) SavePackageRule(in models.PackageRule, actor *auth.TokenClaims) (models.PackageRule, error) {
	if !auth.CanManageSystem(actor) {
		return models.PackageRule{}, errPackagesNeedSystem
	}
	err := s.withWrite(func() error {
		if err := validatePackageRule(&in); err != nil {
			return err
		}
		now := time.Now().UTC()
		if in.ID == "" {
			if len(s.state.Packages.Rules) >= maxPackageRules {
				return errors.New("too many package rules")
			}
			in.ID = newRandomID("prule")
			in.CreatedAt, in.CreatedBy = now, actor.Username
			in.UpdatedAt, in.UpdatedBy = now, actor.Username
			s.state.Packages.Rules = append(s.state.Packages.Rules, in)
		} else {
			idx := -1
			for i, r := range s.state.Packages.Rules {
				if r.ID == in.ID {
					idx = i
					break
				}
			}
			if idx < 0 {
				return errors.New("rule not found")
			}
			in.CreatedAt, in.CreatedBy = s.state.Packages.Rules[idx].CreatedAt, s.state.Packages.Rules[idx].CreatedBy
			in.UpdatedAt, in.UpdatedBy = now, actor.Username
			s.state.Packages.Rules[idx] = in
		}
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "PACKAGE_RULE_SAVED", Category: "SECURITY",
			EntityType: "package_rule", EntityID: in.ID, EntityName: in.Name,
			Summary: fmt.Sprintf("Rule %q: action=%s trigger=%s cooldown=%dh priority=%d", in.Name, in.Action, in.Trigger, in.MinAgeHours, in.Priority),
		})
		s.saveLocked()
		return nil
	})
	if err != nil {
		return models.PackageRule{}, err
	}
	return clonePackageRule(in), nil
}

func validatePackageRule(r *models.PackageRule) error {
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" {
		return errors.New("a rule name is required")
	}
	switch r.Action {
	case models.PackageRuleAutoApprove, models.PackageRuleReview, models.PackageRuleBlock:
	default:
		return errors.New("action must be auto_approve, review or block")
	}
	if r.Trigger == "" {
		r.Trigger = models.PackageTriggerAny
	}
	if r.Trigger != models.PackageTriggerAny && r.Trigger != models.PackageTriggerUpdates {
		return errors.New("trigger must be any or updates")
	}
	for _, e := range r.Ecosystems {
		if !models.ValidEcosystem(e) {
			return fmt.Errorf("unknown ecosystem %q", e)
		}
	}
	switch r.MaxSeverity {
	case "", models.RiskNone, models.RiskLow, models.RiskMedium, models.RiskHigh:
	default:
		return errors.New("max_severity must be empty, none, low, medium or high")
	}
	if r.MinAgeHours < 0 || r.MinAgeHours > 24*365 {
		return errors.New("min_age_hours must be between 0 and 8760")
	}
	if len(r.GroupIDs) == 0 {
		r.GroupIDs = []string{"*"}
	}
	return nil
}

// DeletePackageRule removes a rule.
func (s *Store) DeletePackageRule(id string, actor *auth.TokenClaims) error {
	if !auth.CanManageSystem(actor) {
		return errPackagesNeedSystem
	}
	return s.withWrite(func() error {
		idx := -1
		for i, r := range s.state.Packages.Rules {
			if r.ID == id {
				idx = i
				break
			}
		}
		if idx < 0 {
			return errors.New("rule not found")
		}
		name := s.state.Packages.Rules[idx].Name
		s.state.Packages.Rules = append(s.state.Packages.Rules[:idx], s.state.Packages.Rules[idx+1:]...)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "PACKAGE_RULE_DELETED", Category: "SECURITY",
			EntityType: "package_rule", EntityID: id, EntityName: name, Summary: "Deleted package rule " + name,
		})
		s.saveLocked()
		return nil
	})
}

// TogglePackageRule flips a rule's enabled flag.
func (s *Store) TogglePackageRule(id string, actor *auth.TokenClaims) (models.PackageRule, error) {
	if !auth.CanManageSystem(actor) {
		return models.PackageRule{}, errPackagesNeedSystem
	}
	var out models.PackageRule
	err := s.withWrite(func() error {
		for i := range s.state.Packages.Rules {
			if s.state.Packages.Rules[i].ID == id {
				s.state.Packages.Rules[i].Enabled = !s.state.Packages.Rules[i].Enabled
				s.state.Packages.Rules[i].UpdatedAt, s.state.Packages.Rules[i].UpdatedBy = time.Now().UTC(), actor.Username
				out = clonePackageRule(s.state.Packages.Rules[i])
				s.saveLocked()
				return nil
			}
		}
		return errors.New("rule not found")
	})
	return out, err
}

// --- Blocks ---

// AddPackageBlock blocks versions of a package.
func (s *Store) AddPackageBlock(b models.PackageBlock, actor *auth.TokenClaims) (models.PackageBlock, error) {
	if !auth.CanManageSystem(actor) {
		return models.PackageBlock{}, errPackagesNeedSystem
	}
	err := s.withWrite(func() error {
		if !models.ValidEcosystem(b.Ecosystem) {
			return fmt.Errorf("unknown ecosystem %q", b.Ecosystem)
		}
		b.Name = strings.TrimSpace(b.Name)
		if b.Name == "" || b.Name == "*" {
			return errors.New("a package name is required")
		}
		if strings.TrimSpace(b.Versions) == "" {
			b.Versions = "*"
		}
		if len(s.state.Packages.Blocks) >= maxPackageBlocks {
			return errors.New("too many package blocks")
		}
		b.ID = newRandomID("pblk")
		b.CreatedAt = time.Now().UTC()
		b.CreatedBy = actor.Username
		if b.Source == "" {
			b.Source = "manual"
		}
		s.state.Packages.Blocks = append(s.state.Packages.Blocks, b)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "PACKAGE_BLOCKED", Category: "SECURITY",
			EntityType: "package_block", EntityID: b.ID, EntityName: b.Ecosystem + ":" + b.Name,
			Summary: fmt.Sprintf("Blocked %s %s %s (%s)", b.Ecosystem, b.Name, b.Versions, b.Reason),
		})
		// A block revokes matching active approvals for cause.
		s.revokeForBlockLocked(b, actor.Username)
		s.saveLocked()
		return nil
	})
	return b, err
}

// DeletePackageBlock removes a block.
func (s *Store) DeletePackageBlock(id string, actor *auth.TokenClaims) error {
	if !auth.CanManageSystem(actor) {
		return errPackagesNeedSystem
	}
	return s.withWrite(func() error {
		idx := -1
		for i, b := range s.state.Packages.Blocks {
			if b.ID == id {
				idx = i
				break
			}
		}
		if idx < 0 {
			return errors.New("block not found")
		}
		b := s.state.Packages.Blocks[idx]
		s.state.Packages.Blocks = append(s.state.Packages.Blocks[:idx], s.state.Packages.Blocks[idx+1:]...)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "PACKAGE_BLOCK_REMOVED", Category: "SECURITY",
			EntityType: "package_block", EntityID: id, EntityName: b.Ecosystem + ":" + b.Name,
			Summary: fmt.Sprintf("Removed block on %s %s %s", b.Ecosystem, b.Name, b.Versions),
		})
		s.saveLocked()
		return nil
	})
}

// --- approvals ---

// ApproveRequestGraph approves every not-yet-approved, not-blocked node of a request's graph for the
// request's groups and marks the request approved. Returns the number of approvals created.
func (s *Store) ApproveRequestGraph(reqID, actor, role, note string, groupOverride []string) (int, error) {
	created := 0
	err := s.withWrite(func() error {
		ridx := -1
		for i := range s.state.PackageWork.Requests {
			if s.state.PackageWork.Requests[i].ID == reqID {
				ridx = i
				break
			}
		}
		if ridx < 0 {
			return errors.New("request not found")
		}
		req := &s.state.PackageWork.Requests[ridx]
		groups := req.GroupIDs
		if len(groupOverride) > 0 {
			groups = groupOverride
		}
		if len(groups) == 0 {
			groups = []string{"*"}
		}
		now := time.Now().UTC()
		for _, n := range req.Graph {
			if s.isBlockedLocked(n.Ecosystem, n.Name, n.Version) {
				continue
			}
			if s.activeApprovalLocked(n.Ecosystem, n.Name, n.Version, groups) != nil {
				continue
			}
			via := "dependency"
			if n.Root {
				via = "manual"
			}
			risk := ""
			if n.Assessment != nil {
				risk = n.Assessment.Risk
			}
			ap := models.PackageApproval{
				ID: newRandomID("pappr"), Ecosystem: n.Ecosystem, Name: n.Name, DisplayName: n.DisplayName,
				Version: n.Version, Files: n.Files, GroupIDs: append([]string(nil), groups...),
				Status: "approved", Via: via, RequestID: reqID, ApprovedBy: actor, ApprovedAt: now,
				Reason: note, Risk: risk, PublishedAt: n.PublishedAt,
				Unanalyzed: n.Assessment == nil || n.Assessment.Sandbox == nil,
			}
			if n.Root {
				ap.RequiredBy = ""
			} else if len(n.RequiredBy) > 0 {
				ap.RequiredBy = n.RequiredBy[0].Parent
			}
			s.state.Packages.Approvals = append(s.state.Packages.Approvals, ap)
			created++
		}
		req.Status = models.PackageReqApproved
		req.Decision = "approve"
		req.DecidedBy, req.DecidedAt, req.DecisionNote = actor, &now, note
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor, ActorRole: role, Action: "PACKAGE_REQUEST_APPROVED", Category: "SECURITY",
			EntityType: "package_request", EntityID: reqID, EntityName: req.Ecosystem + ":" + req.Name + "@" + req.Version,
			Summary: approvalSummary(req, created),
		})
		s.saveLocked() // approvals change the data-plane bundle
		return nil
	})
	return created, err
}

func approvalSummary(req *models.PackageRequest, created int) string {
	return req.Ecosystem + " " + req.Name + "@" + req.Version + ": approved " +
		itoa(created) + " package version(s) for " + strings.Join(req.GroupIDs, ",")
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

// isBlockedLocked reports whether a version is on the block list.
func (s *Store) isBlockedLocked(ecosystem, name, version string) bool {
	nn := normalizePackageName(ecosystem, name)
	for _, b := range s.state.Packages.Blocks {
		if b.Ecosystem == ecosystem && normalizePackageName(ecosystem, b.Name) == nn && versionInBlock(ecosystem, version, b.Versions) {
			return true
		}
	}
	return false
}

// activeApprovalLocked returns an active approval covering the version for all of the given groups.
func (s *Store) activeApprovalLocked(ecosystem, name, version string, groups []string) *models.PackageApproval {
	now := time.Now().UTC()
	for i := range s.state.Packages.Approvals {
		a := &s.state.Packages.Approvals[i]
		if a.Ecosystem != ecosystem || a.Name != name || a.Version != version || !a.Active(now) {
			continue
		}
		if groupsCovered(a.GroupIDs, groups) {
			return a
		}
	}
	return nil
}

// groupsCovered reports whether have (an approval's groups) covers every group in want.
func groupsCovered(have, want []string) bool {
	if containsStr(have, "*") {
		return true
	}
	set := map[string]bool{}
	for _, g := range have {
		set[g] = true
	}
	for _, g := range want {
		if g == "*" || !set[g] {
			return false
		}
	}
	return len(want) > 0
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// RevokePackageApproval revokes an approval for cause.
func (s *Store) RevokePackageApproval(id, actor, role, reason string) error {
	return s.withWrite(func() error {
		for i := range s.state.Packages.Approvals {
			a := &s.state.Packages.Approvals[i]
			if a.ID != id {
				continue
			}
			if a.Status == "revoked" {
				return nil
			}
			now := time.Now().UTC()
			a.Status, a.RevokedAt, a.RevokedBy, a.RevokeReason = "revoked", &now, actor, reason
			s.appendAuditLocked(models.AuditEvent{
				Actor: actor, ActorRole: role, Action: "PACKAGE_APPROVAL_REVOKED", Category: "SECURITY",
				EntityType: "package_approval", EntityID: id, EntityName: a.Ecosystem + ":" + a.Name + "@" + a.Version,
				Summary: "Revoked approval: " + reason,
			})
			s.saveLocked()
			return nil
		}
		return errors.New("approval not found")
	})
}

// ExtendPackageApproval sets or clears an approval's expiry.
func (s *Store) ExtendPackageApproval(id, actor, role string, expiresAt *time.Time) error {
	return s.withWrite(func() error {
		for i := range s.state.Packages.Approvals {
			a := &s.state.Packages.Approvals[i]
			if a.ID != id {
				continue
			}
			a.ExpiresAt = expiresAt
			s.appendAuditLocked(models.AuditEvent{
				Actor: actor, ActorRole: role, Action: "PACKAGE_APPROVAL_EXTENDED", Category: "SECURITY",
				EntityType: "package_approval", EntityID: id, EntityName: a.Ecosystem + ":" + a.Name + "@" + a.Version,
				Summary: "Updated approval expiry",
			})
			s.saveLocked()
			return nil
		}
		return errors.New("approval not found")
	})
}

// PackageApproval returns one approval by ID.
func (s *Store) PackageApproval(id string) (models.PackageApproval, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.state.Packages.Approvals {
		if a.ID == id {
			return a, true
		}
	}
	return models.PackageApproval{}, false
}

// revokeForBlockLocked revokes active approvals that a new block covers.
func (s *Store) revokeForBlockLocked(b models.PackageBlock, actor string) {
	now := time.Now().UTC()
	for i := range s.state.Packages.Approvals {
		a := &s.state.Packages.Approvals[i]
		if a.Status != "approved" || a.Ecosystem != b.Ecosystem || a.Name != normalizePackageName(b.Ecosystem, b.Name) {
			continue
		}
		if b.Versions != "*" && !versionInBlock(b.Ecosystem, a.Version, b.Versions) {
			continue
		}
		a.Status = "revoked"
		a.RevokedAt, a.RevokedBy, a.RevokeReason = &now, actor, "blocked: "+b.Reason
	}
}

// --- read accessors ---

// PackageApprovals returns the approvals, newest first.
func (s *Store) PackageApprovals() []models.PackageApproval {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]models.PackageApproval(nil), s.state.Packages.Approvals...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].ApprovedAt.After(out[j].ApprovedAt) })
	return out
}

// PackageRules returns the rules ordered by priority.
func (s *Store) PackageRules() []models.PackageRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.PackageRule, len(s.state.Packages.Rules))
	for i, r := range s.state.Packages.Rules {
		out[i] = clonePackageRule(r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out
}

// PackageBlocks returns the block list.
func (s *Store) PackageBlocks() []models.PackageBlock {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]models.PackageBlock(nil), s.state.Packages.Blocks...)
}

// PackageBundle builds the compact package-firewall view the data-plane enforces. nil when no
// ecosystem is in monitor or enforce mode (the gate stays off).
func (s *Store) PackageBundle(consoleURL string) map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	settings := s.state.Packages.Settings
	ecoOut := map[string]any{}
	anyOn := false
	for name, es := range settings.Ecosystems {
		if es.Mode == models.PackageModeMonitor || es.Mode == models.PackageModeEnforce {
			anyOn = true
		}
		ecoOut[name] = map[string]any{
			"mode": es.Mode, "hosts": es.Hosts, "file_hosts": es.FileHosts, "group_ids": es.GroupIDs,
		}
	}
	if !anyOn {
		return nil
	}
	now := time.Now().UTC()
	// approved[eco][name][version] = {"g": groups, "files": {filename: {sha256,sha512}}}
	approved := map[string]map[string]map[string]any{}
	for _, a := range s.state.Packages.Approvals {
		if !a.Active(now) {
			continue
		}
		files := map[string]any{}
		for _, f := range a.Files {
			dig := map[string]string{}
			if f.SHA256 != "" {
				dig["sha256"] = f.SHA256
			}
			if f.SHA512 != "" {
				dig["sha512"] = f.SHA512
			}
			files[artifactKey(a.Ecosystem, f.Filename)] = dig
		}
		byName := approved[a.Ecosystem]
		if byName == nil {
			byName = map[string]map[string]any{}
			approved[a.Ecosystem] = byName
		}
		byVer := byName[a.Name]
		if byVer == nil {
			byVer = map[string]any{}
			byName[a.Name] = byVer
		}
		byVer[a.Version] = map[string]any{"g": a.GroupIDs, "files": files}
	}
	blocked := map[string]map[string]map[string]string{}
	for _, b := range s.state.Packages.Blocks {
		byName := blocked[b.Ecosystem]
		if byName == nil {
			byName = map[string]map[string]string{}
			blocked[b.Ecosystem] = byName
		}
		name := normalizePackageName(b.Ecosystem, b.Name)
		ver := byName[name]
		if ver == nil {
			ver = map[string]string{}
			byName[name] = ver
		}
		ver[b.Versions] = b.Reason
	}
	return map[string]any{
		"enabled":            true,
		"console_url":        consoleURL,
		"max_metadata_bytes": int64(64 << 20),
		"max_verify_bytes":   settings.Sandbox.MaxArtifactBytes,
		"ecosystems":         ecoOut,
		"approved":           approved,
		"blocked":            blocked,
	}
}

// artifactKey lowercases NuGet / PowerShell Gallery file names (their URLs are case-insensitive); npm
// and PyPI file names are matched as published.
func artifactKey(ecosystem, filename string) string {
	switch ecosystem {
	case models.EcosystemNuGet, models.EcosystemPSGallery:
		return strings.ToLower(filename)
	}
	return filename
}
