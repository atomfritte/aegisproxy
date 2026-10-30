package models

import (
	"time"

	"aegisproxy/control-plane/internal/sealed"
)

// Package firewall (3.0): transparent approval of registry packages. Clients keep using the public registries
// through the proxy; the data-plane filters the registry metadata down to approved versions and lets only approved,
// hash-pinned artifacts through. Packages are never stored or re-hosted: analysis downloads go into a disposable
// sandbox only.

const (
	EcosystemNPM       = "npm"
	EcosystemPyPI      = "pypi"
	EcosystemNuGet     = "nuget"
	EcosystemPSGallery = "psgallery"
)

// Ecosystems lists the supported package ecosystems in display order.
var Ecosystems = []string{EcosystemNPM, EcosystemPyPI, EcosystemNuGet, EcosystemPSGallery}

// ValidEcosystem reports whether e is a supported ecosystem identifier.
func ValidEcosystem(e string) bool {
	for _, x := range Ecosystems {
		if x == e {
			return true
		}
	}
	return false
}

// Enforcement modes of an ecosystem.
const (
	PackageModeOff     = "off"     // registry traffic follows the ordinary egress rules only
	PackageModeMonitor = "monitor" // egress rules decide; package requests are recorded and discovered
	PackageModeEnforce = "enforce" // metadata filtered to approved versions, only approved artifacts delivered
)

// Decisions of the data-plane package gate (FlowPackage.Decision).
const (
	PackageDecisionApproved     = "approved"      // approved artifact delivered (hash verified)
	PackageDecisionFiltered     = "filtered"      // metadata delivered with unapproved versions removed
	PackageDecisionNotApproved  = "not_approved"  // no approval for this package/version and client
	PackageDecisionBlocked      = "blocked"       // explicitly blocked (block list, revoked for cause)
	PackageDecisionHashMismatch = "hash_mismatch" // the registry served bytes that differ from the pinned hash
	PackageDecisionMonitor      = "monitor"       // monitor mode: recorded, not enforced
	PackageDecisionService      = "service"       // harmless registry service endpoint (keys, ping, audit)
)

// Severity / risk levels shared by findings, advisories and assessments (ascending).
const (
	RiskNone     = "none"
	RiskInfo     = "info"
	RiskLow      = "low"
	RiskMedium   = "medium"
	RiskHigh     = "high"
	RiskCritical = "critical"
	RiskUnknown  = "unknown"
)

// RiskRank orders risk levels; unknown ranks like medium (it is not a clean result).
func RiskRank(r string) int {
	switch r {
	case RiskNone, "":
		return 0
	case RiskInfo:
		return 1
	case RiskLow:
		return 2
	case RiskMedium, RiskUnknown:
		return 3
	case RiskHigh:
		return 4
	case RiskCritical:
		return 5
	}
	return 3
}

// FlowPackage is the package a registry request referred to (data-plane telemetry, TrafficFlow.Package).
type FlowPackage struct {
	Ecosystem       string `json:"ecosystem"`
	Name            string `json:"name"`              // normalized name
	Version         string `json:"version,omitempty"` // normalized version (artifacts)
	Kind            string `json:"kind"`              // metadata | artifact | service
	Decision        string `json:"decision"`
	Filename        string `json:"filename,omitempty"`
	SHA256          string `json:"sha256,omitempty"` // hex digest of the delivered artifact
	SHA512          string `json:"sha512,omitempty"` // base64 digest of the delivered artifact
	HiddenVersions  int    `json:"hidden_versions,omitempty"`
	VisibleVersions int    `json:"visible_versions,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

// PackageSettings configures the package firewall (part of the configuration document).
type PackageSettings struct {
	Ecosystems map[string]PackageEcosystemSettings `json:"ecosystems"`
	// DefaultCooldownHours is the waiting period (Karenz) after publication used by new rules and shown for
	// versions that no rule covers.
	DefaultCooldownHours int `json:"default_cooldown_hours"`
	// AutoRequestDiscovered opens a package request (and starts its analysis) for packages a client tried to
	// download but that are not approved; rules may then approve them without a human.
	AutoRequestDiscovered bool `json:"auto_request_discovered"`
	// ReauditHours re-checks every approved version against the advisory sources (0 = off).
	ReauditHours int `json:"reaudit_hours"`
	// WatchHours looks for new upstream versions of approved packages and evaluates them against the rules (0 = off).
	WatchHours int `json:"watch_hours"`
	// RevokeOnSeverity revokes approvals automatically when a new advisory of at least this severity (or malware)
	// affects them: "" (never), malware, critical, high.
	RevokeOnSeverity string `json:"revoke_on_severity"`
	// MaxGraphSize bounds dependency resolution (nodes per request).
	MaxGraphSize int                  `json:"max_graph_size"`
	Sandbox      PackageSandboxConfig `json:"sandbox"`
	Audit        []PackageAuditSource `json:"audit_sources"`
	// PythonEnvironments are the PEP 508 marker environments dependencies are resolved for (union).
	PythonEnvironments []map[string]string `json:"python_environments,omitempty"`
	// NuGetFrameworks limits the NuGet dependency groups considered (empty = every group).
	NuGetFrameworks []string `json:"nuget_frameworks,omitempty"`
}

// PackageEcosystemSettings configures one ecosystem.
type PackageEcosystemSettings struct {
	Mode string `json:"mode"` // off | monitor | enforce
	// Hosts serve registry metadata and artifacts; FileHosts serve artifacts only (files.pythonhosted.org, CDNs).
	Hosts     []string `json:"hosts"`
	FileHosts []string `json:"file_hosts,omitempty"`
	// GroupIDs are the server groups the gate applies to; ["*"] = every client, including unregistered sources.
	GroupIDs []string `json:"group_ids"`
	// Upstream is the registry base URL used for metadata, resolution and analysis.
	Upstream string `json:"upstream"`
}

// PackageSandboxConfig configures the behavior analysis of artifacts in the sandbox workers.
type PackageSandboxConfig struct {
	Enabled bool `json:"enabled"`
	// Scenarios run per artifact: static (unpack and inspect), install (install hooks), load (import the module).
	Scenarios        []string `json:"scenarios"`
	TimeoutSeconds   int      `json:"timeout_seconds"`
	MaxArtifactBytes int64    `json:"max_artifact_bytes"`
	// Required: an approval needs a completed analysis; manual approvals of unanalyzed versions need an InfoSec
	// Approver or Super Admin and are flagged.
	Required bool `json:"required"`
}

// PackageAuditSource is one advisory / reputation source (osv, npm, pypi, nuget, depsdev, github, ossindex,
// socket, snyk). Tokens are sealed at rest and never returned by the API.
type PackageAuditSource struct {
	ID       string        `json:"id"`
	Enabled  bool          `json:"enabled"`
	Token    sealed.String `json:"token,omitempty"`
	HasToken bool          `json:"has_token,omitempty"`
	// Account is the OSS Index user name or the Snyk organization ID.
	Account string `json:"account,omitempty"`
	URL     string `json:"url,omitempty"` // base URL override (mirror / on-premises instance)
}

// PackageFilePin is an artifact pinned by an approval.
type PackageFilePin struct {
	Filename string `json:"filename"`
	SHA256   string `json:"sha256,omitempty"` // hex
	SHA512   string `json:"sha512,omitempty"` // base64 (npm integrity, NuGet / PowerShell Gallery package hash)
	Size     int64  `json:"size,omitempty"`
	URL      string `json:"url,omitempty"`
}

// PackageApproval permits one version of a package for a set of server groups.
type PackageApproval struct {
	ID          string           `json:"id"`
	Ecosystem   string           `json:"ecosystem"`
	Name        string           `json:"name"` // normalized
	DisplayName string           `json:"display_name,omitempty"`
	Version     string           `json:"version"` // normalized
	Files       []PackageFilePin `json:"files"`
	GroupIDs    []string         `json:"group_ids"` // ["*"] = every client the ecosystem applies to
	Status      string           `json:"status"`    // approved | revoked
	Via         string           `json:"via"`       // manual | rule | dependency
	RuleID      string           `json:"rule_id,omitempty"`
	RequestID   string           `json:"request_id,omitempty"`
	RequiredBy  string           `json:"required_by,omitempty"` // root package (name@version) that pulled it in
	ApprovedBy  string           `json:"approved_by"`
	ApprovedAt  time.Time        `json:"approved_at"`
	ExpiresAt   *time.Time       `json:"expires_at,omitempty"`
	Reason      string           `json:"reason,omitempty"`
	Risk        string           `json:"risk,omitempty"` // assessment at approval time
	PublishedAt *time.Time       `json:"published_at,omitempty"`
	// Unanalyzed: approved without a completed sandbox analysis (override).
	Unanalyzed   bool       `json:"unanalyzed,omitempty"`
	RevokedBy    string     `json:"revoked_by,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	RevokeReason string     `json:"revoke_reason,omitempty"`
}

// Active reports whether the approval currently permits downloads.
func (a PackageApproval) Active(now time.Time) bool {
	return a.Status == "approved" && (a.ExpiresAt == nil || now.Before(*a.ExpiresAt))
}

// PackageBlock denies versions of a package regardless of approvals (explicit block list).
type PackageBlock struct {
	ID        string    `json:"id"`
	Ecosystem string    `json:"ecosystem"`
	Name      string    `json:"name"`     // normalized; "*" is not allowed
	Versions  string    `json:"versions"` // "*" or a version range in the ecosystem's syntax
	Reason    string    `json:"reason"`
	Source    string    `json:"source"` // manual | advisory | sandbox
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// Package rule actions and triggers.
const (
	PackageRuleAutoApprove = "auto_approve"
	PackageRuleReview      = "review"
	PackageRuleBlock       = "block"
	PackageTriggerAny      = "any"     // any version of a matching package
	PackageTriggerUpdates  = "updates" // only new versions of packages that already have an approved version
)

// PackageRule decides automatically about versions (ordered by priority, first match wins; no match = review).
type PackageRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Enabled     bool     `json:"enabled"`
	Priority    int      `json:"priority"`
	Ecosystems  []string `json:"ecosystems"` // empty = all
	Packages    []string `json:"packages"`   // name globs ("*", "@corp/*", "microsoft.extensions.*")
	GroupIDs    []string `json:"group_ids"`  // scope of approvals created by the rule (["*"] = all)
	Action      string   `json:"action"`
	Trigger     string   `json:"trigger"`
	// UpdateTypes restricts the updates trigger to patch / minor / major steps (empty = all).
	UpdateTypes []string `json:"update_types,omitempty"`
	// MinAgeHours is the waiting period (Karenz) a version must have been public before the rule approves it.
	MinAgeHours int `json:"min_age_hours"`
	// MaxSeverity is the highest advisory severity tolerated (none, low, medium, high); critical and malware
	// always fail an auto_approve rule.
	MaxSeverity string `json:"max_severity"`
	// MaxRisk is the highest overall assessment tolerated (behavior, install hooks, signatures, advisories).
	MaxRisk             string    `json:"max_risk"`
	RequireSignature    bool      `json:"require_signature"`  // registry / repository signature verified
	RequireProvenance   bool      `json:"require_provenance"` // Sigstore provenance verified
	RequireSandbox      bool      `json:"require_sandbox"`    // completed sandbox analysis
	AllowInstallScripts bool      `json:"allow_install_scripts"`
	Licenses            []string  `json:"licenses,omitempty"` // allowed SPDX identifiers (empty = any)
	ExcludePrerelease   bool      `json:"exclude_prerelease"`
	ExcludeDeprecated   bool      `json:"exclude_deprecated"`
	CreatedBy           string    `json:"created_by,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedBy           string    `json:"updated_by,omitempty"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// PackageFirewall is the package firewall section of the configuration document.
type PackageFirewall struct {
	Settings  PackageSettings   `json:"settings"`
	Rules     []PackageRule     `json:"rules"`
	Approvals []PackageApproval `json:"approvals"`
	Blocks    []PackageBlock    `json:"blocks"`
}
