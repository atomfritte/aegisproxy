// Package advisory queries vulnerability and malware sources for package versions. Sources are
// pluggable; OSV.dev is the default and covers npm, PyPI and NuGet without a token.
package advisory

import (
	"context"

	"aegisproxy/control-plane/internal/models"
)

// Query identifies one package version to look up.
type Query struct {
	Ecosystem string
	Name      string // display name as published (OSV matches the registry's name form)
	Version   string // normalized version
}

// Source is one advisory / reputation provider.
type Source interface {
	// ID is the models.PackageAuditSource identifier (osv, github, npm, pypi, nuget, depsdev, ossindex).
	ID() string
	// Supports reports whether the source covers an ecosystem.
	Supports(ecosystem string) bool
	// Lookup returns the advisories for each query (same order and length as queries). An error means
	// the source did not answer; callers mark the assessment partial rather than treating it as clean.
	Lookup(ctx context.Context, queries []Query) ([][]models.PackageAdvisory, error)
}

// severityFromCVSS maps a CVSS base score to a coarse level.
func severityFromCVSS(score float64) string {
	switch {
	case score <= 0:
		return models.RiskUnknown
	case score < 4.0:
		return models.RiskLow
	case score < 7.0:
		return models.RiskMedium
	case score < 9.0:
		return models.RiskHigh
	default:
		return models.RiskCritical
	}
}

// normalizeSeverity maps the common database severity words to our levels.
func normalizeSeverity(s string) string {
	switch s {
	case "LOW", "low":
		return models.RiskLow
	case "MODERATE", "moderate", "MEDIUM", "medium":
		return models.RiskMedium
	case "HIGH", "high":
		return models.RiskHigh
	case "CRITICAL", "critical":
		return models.RiskCritical
	}
	return ""
}
