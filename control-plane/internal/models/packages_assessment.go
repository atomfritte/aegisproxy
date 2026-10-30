package models

import "time"

// PackageAssessment is the cached risk assessment of one exact package version. It is reused across
// requests while its inputs hold and re-evaluated when a new advisory, rule or sandbox result applies.
type PackageAssessment struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	// Risk is the overall level (none … critical) and Summary the one-line reason.
	Risk    string `json:"risk"`
	Summary string `json:"summary,omitempty"`
	// Advisories are the known-vulnerability / malware findings across the configured sources.
	Advisories []PackageAdvisory `json:"advisories,omitempty"`
	// Signature and Provenance record what was verified (see PackageVerification).
	Signature  PackageVerification `json:"signature"`
	Provenance PackageVerification `json:"provenance"`
	// Sandbox is the behavior analysis outcome (nil = not run / not applicable).
	Sandbox *PackageSandboxResult `json:"sandbox,omitempty"`
	// Findings are the notable sandbox / static findings, most severe first.
	Findings []PackageFinding `json:"findings,omitempty"`
	// HasInstallScripts flags install/build code (npm lifecycle, PyPI sdist build, MSBuild, PS scripts).
	HasInstallScripts bool `json:"has_install_scripts,omitempty"`
	// AgeHours is the version's age at assessment time (for cooldown / Karenz display).
	PublishedAt *time.Time `json:"published_at,omitempty"`
	// Sources lists the advisory sources that actually answered (for "no findings with these checks").
	Sources   []string  `json:"sources,omitempty"`
	Partial   bool      `json:"partial,omitempty"` // some source or the sandbox did not complete
	UpdatedAt time.Time `json:"updated_at"`
}

// PackageAdvisory is one advisory affecting a version.
type PackageAdvisory struct {
	ID       string   `json:"id"`       // e.g. GHSA-…, CVE-…, PYSEC-…, MAL-…
	Source   string   `json:"source"`   // osv | github | npm | pypi | nuget | depsdev | ossindex
	Severity string   `json:"severity"` // none … critical
	Malware  bool     `json:"malware,omitempty"`
	Summary  string   `json:"summary"`
	URL      string   `json:"url,omitempty"`
	Aliases  []string `json:"aliases,omitempty"`
	CVSS     float64  `json:"cvss,omitempty"`
	// Withdrawn advisories are kept for context but do not raise the risk.
	Withdrawn bool `json:"withdrawn,omitempty"`
}

// PackageVerification is the outcome of a signature or provenance check.
type PackageVerification struct {
	Status string `json:"status"` // verified | unsigned | failed | unchecked
	// Kind and Identity describe what was verified (e.g. "npm-registry" key id, Sigstore identity).
	Kind     string `json:"kind,omitempty"`
	Identity string `json:"identity,omitempty"` // e.g. the Fulcio SAN / source repository
	KeyID    string `json:"key_id,omitempty"`
	Detail   string `json:"detail,omitempty"`
	// SourceRepo / Commit / Workflow come from a verified SLSA provenance.
	SourceRepo string `json:"source_repo,omitempty"`
	Commit     string `json:"commit,omitempty"`
	Workflow   string `json:"workflow,omitempty"`
}

// PackageSandboxResult is the summary of a sandbox analysis stored with an assessment.
type PackageSandboxResult struct {
	JobID      string    `json:"job_id"`
	Status     string    `json:"status"` // completed | failed | running | queued | skipped
	Driver     string    `json:"driver,omitempty"`
	StartedAt  time.Time `json:"started_at,omitempty"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	// URLs and Hosts the package tried to reach (deduplicated across phases) — the user-facing
	// "which web addresses does it contact" answer.
	URLs     []string `json:"urls,omitempty"`
	Hosts    []string `json:"hosts,omitempty"`
	DNSNames []string `json:"dns_names,omitempty"`
	// SyscallCounts is the aggregate system-call histogram across phases.
	SyscallCounts map[string]int64 `json:"syscall_counts,omitempty"`
	Processes     []string         `json:"processes,omitempty"` // argv of spawned processes
	FilesWritten  []string         `json:"files_written,omitempty"`
	SecretsRead   []string         `json:"secrets_read,omitempty"`
	CanaryHits    int              `json:"canary_hits,omitempty"`
	// ReportKey locates the full stored report (sandbox report store).
	ReportKey string `json:"report_key,omitempty"`
	Error     string `json:"error,omitempty"`
}

// PackageFinding is a notable finding shown in the review UI.
type PackageFinding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	Source   string `json:"source"` // advisory | signature | sandbox | static | policy
}

// PackageAlert is a package-firewall event delivered to the notification channels (Slack / Teams /
// webhook). The re-audit loop raises it when a new advisory or malware verdict affects an approved
// version — whether or not the approval was auto-revoked — so SecOps hears about it instead of only
// the log.
type PackageAlert struct {
	Action     string   `json:"action"`    // revoked | advisory | malware
	Ecosystem  string   `json:"ecosystem"` // npm | pypi | nuget | psgallery
	Name       string   `json:"name"`      // display name
	Version    string   `json:"version"`
	Severity   string   `json:"severity"`             // none … critical
	Summary    string   `json:"summary,omitempty"`    // one-line reason
	Advisories []string `json:"advisories,omitempty"` // advisory identifiers (CVE / GHSA / MAL-…)
	Reason     string   `json:"reason,omitempty"`     // what triggered the alert (e.g. "re-audit")
	ApprovalID string   `json:"approval_id,omitempty"`
	// Servers is how many servers were observed pulling this version in the retained flow telemetry
	// (-1 = not looked up). It lets the alert say how far an affected version has already spread.
	Servers int `json:"servers"`
}

// AnalysisJobState values.
const (
	AnalysisQueued    = "queued"
	AnalysisRunning   = "running"
	AnalysisCompleted = "completed"
	AnalysisFailed    = "failed"
)

// AnalysisJob is a queued/finished sandbox analysis of one artifact (tracked by the control-plane,
// claimed by sandbox workers). The heavy report is stored separately by ReportKey.
type AnalysisJob struct {
	ID         string     `json:"id"`
	Ecosystem  string     `json:"ecosystem"`
	Name       string     `json:"name"`
	Version    string     `json:"version"`
	Filename   string     `json:"filename"`
	URL        string     `json:"url"`
	SHA256     string     `json:"sha256,omitempty"`
	SHA512     string     `json:"sha512,omitempty"`
	Scenarios  []string   `json:"scenarios"`
	State      string     `json:"state"`
	Worker     string     `json:"worker,omitempty"`
	Attempts   int        `json:"attempts"`
	CreatedAt  time.Time  `json:"created_at"`
	LeasedAt   *time.Time `json:"leased_at,omitempty"`
	LeaseUntil *time.Time `json:"lease_until,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	ReportKey  string     `json:"report_key,omitempty"`
	Error      string     `json:"error,omitempty"`
}
