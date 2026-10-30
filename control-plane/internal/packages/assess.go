package packages

import (
	"context"
	"fmt"
	"sort"
	"time"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/packages/advisory"
	"aegisproxy/control-plane/internal/packages/registry"
)

// Assess evaluates one version: advisories across the enabled sources, signature and provenance
// verification, and the install-script signal. The sandbox behavior result is merged in separately by
// the caller once an analysis job completes (MergeSandbox), because it runs asynchronously.
func (s *Service) Assess(ctx context.Context, ecosystem, name, version string) (*models.PackageAssessment, error) {
	ad := s.adapter(ecosystem)
	if ad == nil {
		return nil, fmt.Errorf("unsupported ecosystem %q", ecosystem)
	}
	vm, err := ad.Version(ctx, s.client, s.upstream(ecosystem), name, version)
	if err != nil {
		return nil, err
	}
	return s.assessVersion(ctx, ecosystem, vm)
}

// assessVersion builds an assessment from an already-fetched version metadata.
func (s *Service) assessVersion(ctx context.Context, ecosystem string, vm *registry.VersionMeta) (*models.PackageAssessment, error) {
	a := &models.PackageAssessment{
		Ecosystem: ecosystem, Name: vm.Name, Version: vm.Version, PublishedAt: vm.PublishedAt,
		HasInstallScripts: vm.HasInstallScripts, UpdatedAt: time.Now().UTC(),
	}
	// Advisories.
	sources := s.enabledSources(ecosystem)
	q := []advisory.Query{{Ecosystem: ecosystem, Name: vm.DisplayName, Version: vm.Version}}
	for _, src := range sources {
		res, err := src.Lookup(ctx, q)
		if err != nil {
			a.Partial = true
			s.log.Warn("advisory source failed", "source", src.ID(), "ecosystem", ecosystem, "error", err)
			continue
		}
		a.Sources = append(a.Sources, src.ID())
		if len(res) == 1 {
			a.Advisories = append(a.Advisories, res[0]...)
		}
	}
	dedupeAdvisories(a)

	// Signature and provenance.
	if s.verifier != nil {
		a.Signature = s.verifier.VerifySignature(ctx, ecosystem, vm)
		a.Provenance = s.verifier.VerifyProvenance(ctx, ecosystem, vm)
	} else {
		a.Signature = models.PackageVerification{Status: "unchecked"}
		a.Provenance = models.PackageVerification{Status: "unchecked"}
	}

	s.deriveFindingsAndRisk(a, vm)
	return a, nil
}

// MergeSandbox folds a completed sandbox summary and its findings into an assessment and recomputes
// the overall risk.
func (s *Service) MergeSandbox(a *models.PackageAssessment, res *models.PackageSandboxResult, findings []models.PackageFinding) {
	a.Sandbox = res
	// Replace any previous sandbox findings, keep the rest.
	kept := a.Findings[:0]
	for _, f := range a.Findings {
		if f.Source != "sandbox" {
			kept = append(kept, f)
		}
	}
	a.Findings = append(kept, findings...)
	sortFindings(a.Findings)
	a.UpdatedAt = time.Now().UTC()
	a.Risk, a.Summary = overallRisk(a)
}

// deriveFindingsAndRisk turns advisories, verification and install signals into findings + overall risk.
func (s *Service) deriveFindingsAndRisk(a *models.PackageAssessment, vm *registry.VersionMeta) {
	a.Findings = a.Findings[:0]
	for _, adv := range a.Advisories {
		if adv.Withdrawn {
			continue
		}
		cat := "advisory"
		title := adv.ID
		if adv.Malware {
			cat = "malware"
			title = "Malicious package: " + adv.ID
		}
		a.Findings = append(a.Findings, models.PackageFinding{
			ID: adv.ID, Severity: adv.Severity, Category: cat, Title: title, Detail: adv.Summary, Source: "advisory",
		})
	}
	if vm.Deprecated {
		a.Findings = append(a.Findings, models.PackageFinding{
			ID: "PKG-DEPRECATED", Severity: models.RiskLow, Category: "deprecated",
			Title: "Version is deprecated", Source: "static",
		})
	}
	if vm.Yanked {
		a.Findings = append(a.Findings, models.PackageFinding{
			ID: "PKG-YANKED", Severity: models.RiskLow, Category: "yanked",
			Title: "Version is yanked / unlisted", Source: "static",
		})
	}
	if a.HasInstallScripts {
		a.Findings = append(a.Findings, models.PackageFinding{
			ID: "PKG-INSTALL-SCRIPTS", Severity: models.RiskInfo, Category: "install-hook",
			Title: "Declares install/build scripts", Source: "static",
		})
	}
	if a.Signature.Status == "failed" {
		a.Findings = append(a.Findings, models.PackageFinding{
			ID: "PKG-SIG-FAILED", Severity: models.RiskHigh, Category: "signature",
			Title: "Signature verification failed", Detail: a.Signature.Detail, Source: "signature",
		})
	}
	if a.Provenance.Status == "failed" {
		a.Findings = append(a.Findings, models.PackageFinding{
			ID: "PKG-PROV-FAILED", Severity: models.RiskHigh, Category: "signature",
			Title: "Provenance verification failed", Detail: a.Provenance.Detail, Source: "signature",
		})
	}
	sortFindings(a.Findings)
	a.Risk, a.Summary = overallRisk(a)
}

// overallRisk is the highest finding severity, with a one-line summary.
func overallRisk(a *models.PackageAssessment) (string, string) {
	risk := models.RiskNone
	for _, f := range a.Findings {
		if models.RiskRank(f.Severity) > models.RiskRank(risk) {
			risk = f.Severity
		}
	}
	for _, adv := range a.Advisories {
		if adv.Malware {
			return models.RiskCritical, "Reported as a malicious package"
		}
	}
	switch {
	case len(a.Advisories) > 0:
		return risk, fmt.Sprintf("%d advisory finding(s); highest severity %s", len(a.Advisories), risk)
	case a.Sandbox != nil && a.Sandbox.CanaryHits > 0:
		return maxRisk(risk, models.RiskHigh), "Sandbox: accessed decoy credentials"
	case risk == models.RiskNone && a.Partial:
		return models.RiskUnknown, "No findings, but some checks did not complete"
	case risk == models.RiskNone:
		return models.RiskNone, summaryClean(a)
	default:
		return risk, fmt.Sprintf("Highest finding severity %s", risk)
	}
}

func summaryClean(a *models.PackageAssessment) string {
	if len(a.Sources) == 0 {
		return "No checks ran"
	}
	return "No findings with these checks: " + joinSources(a.Sources)
}

func joinSources(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}

func maxRisk(a, b string) string {
	if models.RiskRank(a) >= models.RiskRank(b) {
		return a
	}
	return b
}

func dedupeAdvisories(a *models.PackageAssessment) {
	if len(a.Advisories) < 2 {
		return
	}
	// Collapse by ID and by alias so the same CVE from two sources appears once (highest severity wins).
	byKey := map[string]int{}
	var out []models.PackageAdvisory
	keyOf := func(adv models.PackageAdvisory) string {
		if len(adv.Aliases) > 0 {
			sort.Strings(adv.Aliases)
			return adv.Aliases[0]
		}
		return adv.ID
	}
	for _, adv := range a.Advisories {
		k := keyOf(adv)
		if i, ok := byKey[k]; ok {
			if models.RiskRank(adv.Severity) > models.RiskRank(out[i].Severity) {
				out[i].Severity = adv.Severity
			}
			out[i].Malware = out[i].Malware || adv.Malware
			continue
		}
		byKey[k] = len(out)
		out = append(out, adv)
	}
	sort.SliceStable(out, func(i, j int) bool { return models.RiskRank(out[i].Severity) > models.RiskRank(out[j].Severity) })
	a.Advisories = out
}
