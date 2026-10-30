package packages

import (
	"fmt"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/packages/pkgver"
)

// RuleInput is everything a rule needs to decide about one version.
type RuleInput struct {
	Ecosystem    string
	Name         string
	Version      string
	PublishedAt  *time.Time
	Prerelease   bool
	Deprecated   bool
	License      string
	Assessment   *models.PackageAssessment
	HasInstall   bool
	IsUpdate     bool // a prior version of this package is already approved
	SignatureOK  bool
	ProvenanceOK bool
	SandboxDone  bool
}

// RuleDecision is the outcome of evaluating the rules against a version.
type RuleDecision struct {
	Action   string // auto_approve | review | block
	RuleID   string
	RuleName string
	Reason   string
}

// EvaluateRules runs the ordered rules against a version and returns the first matching decision.
// No matching rule means review (a human decides). now is injected for determinism.
func EvaluateRules(rules []models.PackageRule, settings models.PackageSettings, in RuleInput, now time.Time) RuleDecision {
	ordered := append([]models.PackageRule(nil), rules...)
	// Stable priority order (lower number first).
	for i := 1; i < len(ordered); i++ {
		for j := i; j > 0 && ordered[j].Priority < ordered[j-1].Priority; j-- {
			ordered[j], ordered[j-1] = ordered[j-1], ordered[j]
		}
	}
	for _, r := range ordered {
		if !r.Enabled || !ruleMatches(r, in) {
			continue
		}
		switch r.Action {
		case models.PackageRuleBlock:
			return RuleDecision{Action: models.PackageRuleBlock, RuleID: r.ID, RuleName: r.Name, Reason: "matched block rule"}
		case models.PackageRuleReview:
			return RuleDecision{Action: models.PackageRuleReview, RuleID: r.ID, RuleName: r.Name, Reason: "matched review rule"}
		case models.PackageRuleAutoApprove:
			if reason := autoApproveBlocked(r, settings, in, now); reason != "" {
				// The rule matched but its conditions are not met: hold for review with the reason.
				return RuleDecision{Action: models.PackageRuleReview, RuleID: r.ID, RuleName: r.Name, Reason: reason}
			}
			return RuleDecision{Action: models.PackageRuleAutoApprove, RuleID: r.ID, RuleName: r.Name, Reason: "auto-approved by rule"}
		}
	}
	return RuleDecision{Action: models.PackageRuleReview, Reason: "no matching rule"}
}

// ruleMatches checks the rule's selectors (ecosystem, package globs, trigger).
func ruleMatches(r models.PackageRule, in RuleInput) bool {
	if len(r.Ecosystems) > 0 && !contains(r.Ecosystems, in.Ecosystem) {
		return false
	}
	if len(r.Packages) > 0 {
		matched := false
		for _, pat := range r.Packages {
			if pkgver.MatchPackagePattern(pat, in.Name, in.Ecosystem) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if r.Trigger == models.PackageTriggerUpdates && !in.IsUpdate {
		return false
	}
	return true
}

// autoApproveBlocked returns a human-readable reason when an auto_approve rule's conditions are not
// satisfied (so the version is held for review), or "" when the version may be approved automatically.
func autoApproveBlocked(r models.PackageRule, settings models.PackageSettings, in RuleInput, now time.Time) string {
	// Cooldown (Karenz): a version must have been public for min_age_hours.
	minAge := r.MinAgeHours
	if minAge == 0 {
		minAge = settings.DefaultCooldownHours
	}
	if minAge > 0 {
		if in.PublishedAt == nil {
			return "publication time unknown; cannot confirm the cooldown"
		}
		age := now.Sub(*in.PublishedAt)
		if age < time.Duration(minAge)*time.Hour {
			remain := time.Duration(minAge)*time.Hour - age
			return fmt.Sprintf("in cooldown: %s of %dh remaining", roundDur(remain), minAge)
		}
	}
	if r.ExcludePrerelease && in.Prerelease {
		return "prerelease versions are excluded"
	}
	if r.ExcludeDeprecated && in.Deprecated {
		return "deprecated versions are excluded"
	}
	// Advisory severity and malware.
	if in.Assessment != nil {
		for _, adv := range in.Assessment.Advisories {
			if adv.Malware {
				return "reported as malicious"
			}
		}
		maxSev := r.MaxSeverity
		if maxSev == "" {
			maxSev = models.RiskNone
		}
		worst := worstAdvisory(in.Assessment)
		if models.RiskRank(worst) > models.RiskRank(maxSev) {
			return fmt.Sprintf("advisory severity %s exceeds the allowed %s", worst, maxSev)
		}
		// critical always blocks an auto-approve regardless of max_severity.
		if models.RiskRank(worst) >= models.RiskRank(models.RiskCritical) {
			return "critical advisory"
		}
		if r.MaxRisk != "" && models.RiskRank(in.Assessment.Risk) > models.RiskRank(r.MaxRisk) {
			return fmt.Sprintf("overall risk %s exceeds the allowed %s", in.Assessment.Risk, r.MaxRisk)
		}
	}
	if r.RequireSignature && !in.SignatureOK {
		return "a verified signature is required"
	}
	if r.RequireProvenance && !in.ProvenanceOK {
		return "verified provenance is required"
	}
	if r.RequireSandbox && !in.SandboxDone {
		return "a completed sandbox analysis is required"
	}
	if settings.Sandbox.Required && !in.SandboxDone {
		return "sandbox analysis has not completed"
	}
	if !r.AllowInstallScripts && in.HasInstall {
		return "declares install/build scripts (not allowed by the rule)"
	}
	if len(r.Licenses) > 0 && !licenseAllowed(r.Licenses, in.License) {
		return fmt.Sprintf("license %q is not in the allow list", in.License)
	}
	return ""
}

func worstAdvisory(a *models.PackageAssessment) string {
	worst := models.RiskNone
	for _, adv := range a.Advisories {
		if adv.Withdrawn {
			continue
		}
		if models.RiskRank(adv.Severity) > models.RiskRank(worst) {
			worst = adv.Severity
		}
	}
	return worst
}

func licenseAllowed(allowed []string, license string) bool {
	if license == "" {
		return false
	}
	for _, a := range allowed {
		if strings.EqualFold(a, license) {
			return true
		}
	}
	return false
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func roundDur(d time.Duration) time.Duration { return d.Round(time.Hour) }
