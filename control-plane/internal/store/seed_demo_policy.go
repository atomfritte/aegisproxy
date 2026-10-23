package store

import (
	"slices"
	"time"

	"aegisproxy/control-plane/internal/models"
)

// seedDemoPolicyLocked organizes the demo rules into policy sets and adds showcase data for the
// policy-management features (labels, a dynamic group, branded block pages, an open change request).
func (s *Store) seedDemoPolicyLocked(now time.Time) {
	s.state.Governance = DefaultGovernance()
	s.state.RuleStats = map[string]RuleStat{}
	byID := map[string]models.PolicyRule{}
	for _, r := range s.state.Rules {
		if r.HitCount > 0 {
			s.state.RuleStats[r.ID] = RuleStat{Hits: r.HitCount, Bytes: r.TotalBytes}
		}
		r = cloneRule(r)
		r.GroupIDs, r.ServerIDs, r.HitCount, r.TotalBytes = []string{}, []string{}, 0, 0
		byID[r.ID] = r
	}
	pick := func(ids ...string) []models.PolicyRule {
		var out []models.PolicyRule
		for _, id := range ids {
			if r, ok := byID[id]; ok {
				out = append(out, r)
			}
		}
		return out
	}
	guard := func(id, name, host, desc string) models.PolicyRule {
		return models.PolicyRule{ID: id, Version: 1, Name: name, Description: desc, Action: "BLOCK", HostPattern: host, PathPattern: "/**",
			Methods: []string{"*"}, CompanionRules: []string{}, CreatedBy: "infosec", ApprovedBy: "admin", Enabled: true, CreatedAt: now.Add(-45 * 24 * time.Hour)}
	}
	ago := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	day := 24 * time.Hour

	sets := []models.PolicySet{
		{ID: "ps-global-guardrails", Kind: models.PolicySetKindBaseline, Version: 3, PublishedAt: ago(12 * day), PublishedBy: "infosec",
			CreatedAt: now.Add(-60 * day), CreatedBy: "infosec", LastReviewedAt: ago(12 * day), LastReviewedBy: "admin",
			PolicySetSpec: models.PolicySetSpec{Name: "Global guardrails", Description: "Destinations that are never allowed for any server: paste sites, anonymous file drops and tunnelling services frequently used for data exfiltration and command-and-control.",
				OwnerTeam: "Information Security", Tags: []string{"baseline", "exfiltration"}, Priority: 100, Enabled: true, GroupIDs: []string{}, ServerIDs: []string{}, ReviewIntervalDays: 90,
				Rules: []models.PolicyRule{
					guard("rule-guard-paste", "Block paste sites", "pastebin.com", "Paste sites are a common exfiltration channel."),
					guard("rule-guard-ngrok", "Block ngrok tunnels", "*.ngrok.io", "Reverse tunnels bypass inbound controls."),
					guard("rule-guard-transfer", "Block anonymous file drops", "transfer.sh", "Anonymous upload services."),
				}}},
		{ID: "ps-os-updates", Kind: models.PolicySetKindStandard, Version: 2, PublishedAt: ago(30 * day), PublishedBy: "infosec",
			CreatedAt: now.Add(-90 * day), CreatedBy: "admin", LastReviewedAt: ago(100 * day), LastReviewedBy: "infosec",
			PolicySetSpec: models.PolicySetSpec{Name: "Linux OS updates", Description: "Official distribution mirrors for unattended security updates.",
				OwnerTeam: "Core Linux Operations", Tags: []string{"patching"}, Priority: 50, Enabled: true,
				GroupIDs: []string{"grp-linux-core", "grp-ci-runners", "grp-k8s-prod", "grp-ai-gpu"}, ServerIDs: []string{}, ReviewIntervalDays: 90,
				Rules: pick("rule-ubuntu-security")}},
		{ID: "ps-dev-tooling", Kind: models.PolicySetKindStandard, Version: 4, PublishedAt: ago(10 * day), PublishedBy: "infosec",
			CreatedAt: now.Add(-40 * day), CreatedBy: "teamlead", LastReviewedAt: ago(10 * day), LastReviewedBy: "infosec",
			PolicySetSpec: models.PolicySetSpec{Name: "Developer tooling", Description: "Source and container registries for build runners and Kubernetes nodes.",
				OwnerTeam: "DevOps & Release Engineering", Tags: []string{"ci", "containers"}, Priority: 20, Enabled: true,
				GroupIDs: []string{"grp-ci-runners", "grp-k8s-prod"}, ServerIDs: []string{}, ReviewIntervalDays: 90,
				Rules: pick("rule-gh-microsoft", "rule-docker-library")}},
		{ID: "ps-ai-models", Kind: models.PolicySetKindStandard, Version: 1, PublishedAt: ago(5 * day), PublishedBy: "infosec",
			CreatedAt: now.Add(-6 * day), CreatedBy: "teamlead", LastReviewedAt: ago(5 * day), LastReviewedBy: "infosec",
			PolicySetSpec: models.PolicySetSpec{Name: "AI model sources", Description: "Verified model weights for the GPU cluster.",
				OwnerTeam: "Applied AI Infrastructure", Tags: []string{"ml"}, Priority: 10, Enabled: true,
				GroupIDs: []string{"grp-ai-gpu"}, ServerIDs: []string{}, ReviewIntervalDays: 30,
				Rules: pick("rule-hf-metallama")}},
	}
	for _, set := range sets {
		for v := 1; v <= set.Version; v++ {
			spec := cloneSpec(set.PolicySetSpec)
			summary := "Published"
			if v < set.Version && len(spec.Rules) > 1 {
				spec.Rules = spec.Rules[:len(spec.Rules)-1]
				summary = "Earlier version"
			}
			s.state.PolicyVersions = append(s.state.PolicyVersions, models.PolicySetVersion{PolicySetID: set.ID, Version: v, Spec: spec,
				PublishedBy: set.PublishedBy, PublishedAt: set.PublishedAt.Add(-time.Duration(set.Version-v) * 3 * day), Summary: summary})
		}
	}
	s.state.PolicySets = sets
	s.state.ChangeRequests = []models.ChangeRequest{}

	// Labels and a dynamic (label-selected) compliance group with its own block page.
	labels := map[string]map[string]string{
		"srv-ci-runner-01":   {"env": "infra", "os": "linux", "tier": "build"},
		"srv-ci-runner-02":   {"env": "infra", "os": "linux", "tier": "build"},
		"srv-k8s-worker-104": {"env": "prod", "os": "linux", "tier": "platform"},
		"srv-linux-app-312":  {"env": "prod", "os": "linux", "tier": "app", "compliance": "pci"},
		"srv-gpu-node-04":    {"env": "staging", "os": "linux", "tier": "ml"},
		"srv-win-erp-09":     {"env": "prod", "os": "windows", "tier": "app", "compliance": "pci"},
		"srv-db-vault-01":    {"env": "prod", "os": "linux", "tier": "data"},
	}
	for i := range s.state.Servers {
		srv := &s.state.Servers[i]
		srv.Labels = labels[srv.ID]
		srv.OwnerTeam = srv.Department
		created := now.Add(-120 * day)
		srv.CreatedAt = &created
	}
	s.state.Groups = append(s.state.Groups, models.ServerGroup{
		ID: "grp-pci-scope", Name: "PCI DSS scope", Description: "Dynamic group: every server labelled compliance=pci (cardholder data environment).",
		Environment: "prod", OwnerTeam: "Governance, Risk & Compliance", Color: "#BE185D", CIDRs: []string{},
		MatchLabels: map[string]string{"compliance": "pci"}, BlockPageTemplateID: "bp-pci",
	})

	corp := DefaultBlockPageTemplate()
	corp.Name, corp.CompanyName = "Enterprise Corp", "Enterprise Corp"
	corp.Support = models.SupportContact{Label: "IT Service Desk", Email: "servicedesk@enterprise.corp", Phone: "+49 30 1234 5678", URL: "https://servicedesk.enterprise.corp/egress"}
	corp.Links = []models.LinkItem{{Label: "Egress policy", URL: "https://wiki.enterprise.corp/security/egress"}, {Label: "Request status", URL: "https://servicedesk.enterprise.corp/my-requests"}}
	corp.FooterText = "{company} Information Security · Outbound access is logged and reviewed."
	pci := DefaultBlockPageTemplate()
	pci.ID, pci.IsDefault, pci.Name, pci.CompanyName = "bp-pci", false, "PCI zone", "Enterprise Corp"
	pci.PrimaryColor, pci.AccentColor, pci.Theme = "#BE185D", "#B91C1C", "light"
	pci.Title = "Blocked: PCI DSS cardholder data environment"
	pci.Message = "{hostname} is part of the PCI DSS scope. Outbound connections are restricted to approved payment processors and patch sources.\n\nTemporary access needs a change ticket and is reviewed by GRC."
	pci.AllowedScopes, pci.AllowedDurations = []string{"exact_path"}, []string{"1h", "24h"}
	pci.ShowSuggestedRule = false
	pci.Support = models.SupportContact{Label: "GRC on-call", Email: "grc@enterprise.corp"}
	pci.FooterText = "PCI DSS v4.0 requirement 1.4 — all outbound traffic from the CDE is denied by default."
	s.state.BlockPages = []models.BlockPageTemplate{corp, pci}

	// An open change request awaiting four-eyes review.
	s.computeEffectiveGroupsLocked()
	s.compileRulesLocked()
	if i := s.setIndexLocked("ps-ai-models"); i >= 0 {
		set := &s.state.PolicySets[i]
		spec := cloneSpec(set.PolicySetSpec)
		spec.Rules = append(spec.Rules, models.PolicyRule{ID: "rule-pytorch-wheels", Version: 1, Name: "PyTorch wheels (CUDA 12.4)",
			Description: "Official PyTorch wheel index for CUDA 12.4 builds.", Action: "ALLOW", HostPattern: "download.pytorch.org", PathPattern: "/whl/cu124/**",
			Methods: []string{"GET", "HEAD"}, CompanionRules: []string{}, CreatedBy: "teamlead", ApprovedBy: "teamlead", Enabled: true, CreatedAt: now.Add(-3 * time.Hour)})
		diff := DiffSpecs(set.PolicySetSpec, spec)
		impact := simulate(s.simulationInputLocked(set.ID, &spec))
		cr := models.ChangeRequest{ID: "cr-demo-1001", PolicySetID: set.ID, PolicySetName: set.Name, Title: "Add PyTorch CUDA 12.4 wheel index",
			Description: "The training images move to PyTorch 2.5 (CHG-50117). Only the cu124 wheel path is opened.", Status: "open",
			BaseVersion: set.Version, Spec: spec, Diff: &diff, Impact: &impact, SubmittedBy: "teamlead", SubmittedAt: now.Add(-3 * time.Hour),
			Reviews: []models.ChangeReview{{Reviewer: "auditor", Role: string(models.RoleAuditorOperator), Decision: "comment",
				Comment: "Please confirm the wheel index is pinned to cu124 only.", At: now.Add(-2 * time.Hour)}}}
		set.Draft = &models.PolicySetDraft{Spec: cloneSpec(spec), BaseVersion: set.Version, Status: "in_review", ChangeRequestID: cr.ID, UpdatedBy: "teamlead", UpdatedAt: cr.SubmittedAt}
		s.state.ChangeRequests = append(s.state.ChangeRequests, cr)
	}
	for i := range s.state.Requests {
		r := &s.state.Requests[i]
		due := r.CreatedAt.Add(time.Duration(s.state.Governance.RequestSLAHours) * time.Hour)
		r.DueAt = &due
		if r.Comments == nil {
			r.Comments = []models.RequestComment{}
		}
	}
	// Assignments must be actionable: teamlead leads grp-ci-runners (req-1001), req-1002 targets prod K8s.
	if i := slices.IndexFunc(s.state.Requests, func(r models.AccessRequest) bool { return r.ID == "req-1001" }); i >= 0 {
		s.state.Requests[i].AssignedTo = "teamlead"
		s.state.Requests[i].Comments = append(s.state.Requests[i].Comments, models.RequestComment{Author: "infosec",
			Text: "Assigned to the CI platform lead for a business justification check.", At: now.Add(-20 * time.Minute)})
	}
	if i := slices.IndexFunc(s.state.Requests, func(r models.AccessRequest) bool { return r.ID == "req-1002" }); i >= 0 {
		s.state.Requests[i].AssignedTo = "infosec"
		s.state.Requests[i].Comments = append(s.state.Requests[i].Comments, models.RequestComment{Author: "infosec",
			Text: "Taking this one; CHG-49201 is approved in the CAB.", At: now.Add(-15 * time.Minute)})
	}
	s.state.Rules = nil
	s.compileRulesLocked()
}
