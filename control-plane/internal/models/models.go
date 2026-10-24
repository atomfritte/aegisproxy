package models

import (
	"strings"
	"time"

	"aegisproxy/control-plane/internal/sealed"
)

type Role string

const (
	RoleSuperAdmin      Role = "SUPER_ADMIN"
	RoleInfoSecApprover Role = "INFOSEC_APPROVER"
	RoleTeamLead        Role = "TEAM_LEAD_APPROVER"
	RoleAuditorOperator Role = "OPERATOR_AUDITOR"
)

func (r Role) Valid() bool {
	switch r {
	case RoleSuperAdmin, RoleInfoSecApprover, RoleTeamLead, RoleAuditorOperator:
		return true
	}
	return false
}

// Flow verdicts shared by the control-plane, the data-plane and the UI.
const (
	VerdictAllowed          = "ALLOWED"
	VerdictBlocked          = "BLOCKED"
	VerdictLearningAllowed  = "LEARNING_ALLOWED"
	VerdictRedirectObject   = "REDIRECT_OBJECT_ALLOWED"
	VerdictTLSBypass        = "TLS_BYPASS"
	VerdictThreatBlocked    = "THREAT_BLOCKED"
	VerdictMalwareBlocked   = "MALWARE_BLOCKED"
	VerdictDLPBlocked       = "DLP_BLOCKED"
	VerdictFileTypeBlocked  = "FILETYPE_BLOCKED"
	VerdictPolicyBlocked    = "POLICY_BLOCKED"
	VerdictQuarantined      = "QUARANTINED"
	VerdictSimulatedDryRun  = "SIMULATED"
	SecurityEventThreat     = "THREAT_INTEL"
	SecurityEventMalware    = "MALWARE"
	SecurityEventDLP        = "DLP"
	SecurityEventFileType   = "FILE_TYPE"
	SecurityEventPolicy     = "POLICY"
	SecurityEventAnomaly    = "ANOMALY"
	SecurityEventPunycode   = "PUNYCODE"
	SecurityEventAVSkipped  = "AV_UNSCANNED"
	SecurityEventAVError    = "AV_ERROR"
	SecurityEventBlockBurst = "BLOCK_BURST"
	SecurityEventQuarantine = "QUARANTINE"
)

// IsAllowedVerdict reports whether traffic with this verdict was forwarded upstream.
func IsAllowedVerdict(v string) bool {
	switch v {
	case VerdictAllowed, VerdictLearningAllowed, VerdictRedirectObject, VerdictTLSBypass:
		return true
	}
	return false
}

// IsSecurityVerdict reports whether a verdict was produced by a threat-protection engine
// (as opposed to the default-deny whitelist).
func IsSecurityVerdict(v string) bool {
	switch v {
	case VerdictThreatBlocked, VerdictMalwareBlocked, VerdictDLPBlocked, VerdictFileTypeBlocked, VerdictPolicyBlocked, VerdictQuarantined:
		return true
	}
	return false
}

type User struct {
	ID            string   `json:"id"`
	Username      string   `json:"username"`
	DisplayName   string   `json:"display_name"`
	Email         string   `json:"email"`
	PasswordHash  string   `json:"password_hash,omitempty"`
	Role          Role     `json:"role"`
	AuthProvider  string   `json:"auth_provider"`
	AllowedGroups []string `json:"allowed_groups"`
	Department    string   `json:"department"`
	Disabled      bool     `json:"disabled,omitempty"`
	// DisabledByAdmin marks a manual lock-out: unlike an automatic SSO deprovisioning it is not
	// lifted by the next single sign-on.
	DisabledByAdmin bool `json:"disabled_by_admin,omitempty"`
	// BreakGlass accounts may always sign in with a password (emergency access when SSO is down);
	// every such login raises a security alert.
	BreakGlass bool `json:"break_glass,omitempty"`
	// ExternalID links users provisioned by single sign-on to the IdP subject (issuer|sub digest).
	ExternalID string `json:"external_id,omitempty"`
	// SCIM is set for accounts managed by SCIM provisioning (Entra ID, Okta).
	SCIM          *SCIMUser  `json:"scim,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
	PasswordSetAt *time.Time `json:"password_set_at,omitempty"`
	// SessionsNotBefore invalidates every session token issued before this instant
	// (password change/reset, account disable, "sign out everywhere").
	SessionsNotBefore *time.Time `json:"sessions_not_before,omitempty"`
}

// Public returns a copy that is safe to serialize to API clients.
func (u User) Public() User {
	u.PasswordHash = ""
	u.AllowedGroups = append([]string(nil), u.AllowedGroups...)
	if u.SCIM != nil {
		sc := *u.SCIM
		sc.Emails = append([]SCIMEmail(nil), sc.Emails...)
		u.SCIM = &sc
	}
	return u
}

// EntraIDConfig configures single sign-on via OpenID Connect (Microsoft Entra ID or any OIDC
// provider such as Okta, Keycloak, ADFS, Ping or Google Workspace).
type EntraIDConfig struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"` // entra | oidc
	// DisplayName is the label of the login button ("Sign in with …").
	DisplayName     string        `json:"display_name"`
	TenantID        string        `json:"tenant_id"`
	ClientID        string        `json:"client_id"`
	ClientSecret    sealed.String `json:"client_secret,omitempty"` // write-only
	HasClientSecret bool          `json:"has_client_secret,omitempty"`
	IssuerURL       string        `json:"issuer_url"`   // derived for Entra from the tenant
	RedirectURI     string        `json:"redirect_uri"` // default <public URL>/api/auth/sso/callback
	Scopes          []string      `json:"scopes"`
	// UsernameClaim (default preferred_username) and GroupsClaim (default groups; Entra app roles: roles).
	UsernameClaim string `json:"username_claim"`
	GroupsClaim   string `json:"groups_claim"`
	// GroupRoleMap maps IdP groups (Entra: object IDs or app role values) to console roles; the most
	// privileged match wins. Users without a mapped group cannot sign in.
	GroupRoleMap map[string]Role `json:"group_role_map"`
	// GroupScopeMap grants Team Leads server groups based on IdP groups.
	GroupScopeMap map[string][]string `json:"group_scope_map"`
	// AllowLocalLogin keeps password login for all local users; when false only break-glass
	// accounts may sign in with a password.
	AllowLocalLogin bool `json:"allow_local_login"`
	// TokenAuthMethod: "" (auto), client_secret_post, client_secret_basic (e.g. Okta web apps) or
	// private_key_jwt (signed client assertion with the active SSO client key, no shared secret).
	TokenAuthMethod string `json:"token_auth_method,omitempty"`
}

// Public returns the configuration without the client secret.
func (c EntraIDConfig) Public() EntraIDConfig {
	c.HasClientSecret = c.ClientSecret != ""
	c.ClientSecret = ""
	return c
}

type ServerGroup struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	CIDRs       []string `json:"cidrs"`
	ServerCount int      `json:"server_count"`
	Environment string   `json:"environment"`
	OwnerTeam   string   `json:"owner_team"`
	Color       string   `json:"color"`
	// StrictIsolation marks zero-internet tiers: global (unscoped) TLS bypass rules never apply,
	// and learning sessions cannot be started for its members.
	StrictIsolation bool `json:"strict_isolation"`
	// MatchLabels adds every registered server whose labels contain all of these pairs (dynamic group).
	MatchLabels map[string]string `json:"match_labels,omitempty"`
	// BlockPageTemplateID selects the block page shown to servers of this group ("" = default).
	BlockPageTemplateID string `json:"block_page_template_id,omitempty"`
}

type Server struct {
	ID                 string     `json:"id"`
	Hostname           string     `json:"hostname"`
	IP                 string     `json:"ip"`
	SubnetCIDR         string     `json:"subnet_cidr"`
	ProxyAuthUser      string     `json:"proxy_auth_user"`
	ProxyAuthToken     string     `json:"proxy_auth_token,omitempty"` // legacy plaintext; migrated to hash on load, never persisted again
	ProxyAuthTokenHash string     `json:"proxy_auth_token_hash,omitempty"`
	TokenRotatedAt     *time.Time `json:"token_rotated_at,omitempty"`
	// HasProxyToken is set in API responses instead of exposing the token digest.
	HasProxyToken bool      `json:"has_proxy_token,omitempty"`
	GroupIDs      []string  `json:"group_ids"`
	OS            string    `json:"os"`
	Department    string    `json:"department"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	Description   string    `json:"description,omitempty"`
	OwnerTeam     string    `json:"owner_team,omitempty"`
	// Labels (key=value) drive dynamic group membership via ServerGroup.MatchLabels.
	Labels map[string]string `json:"labels,omitempty"`
	// Quarantined servers may not reach any destination (incident response).
	Quarantined      bool       `json:"quarantined,omitempty"`
	QuarantineReason string     `json:"quarantine_reason,omitempty"`
	QuarantinedBy    string     `json:"quarantined_by,omitempty"`
	QuarantinedAt    *time.Time `json:"quarantined_at,omitempty"`
	CreatedAt        *time.Time `json:"created_at,omitempty"`
	// Defender is the matched Microsoft Defender for Endpoint device (when device sync is enabled).
	Defender *DefenderDevice `json:"defender,omitempty"`
	// EffectiveGroupIDs = static GroupIDs + groups whose MatchLabels match (computed, not persisted input).
	EffectiveGroupIDs []string `json:"effective_group_ids,omitempty"`
}

type PolicyRule struct {
	ID              string     `json:"id"`
	Version         int        `json:"version"`
	Name            string     `json:"name"`
	Description     string     `json:"description"`
	Action          string     `json:"action"`
	HostPattern     string     `json:"host_pattern"`
	PathPattern     string     `json:"path_pattern"`
	Methods         []string   `json:"methods"`
	FollowRedirects bool       `json:"follow_redirects"`
	RedirectHosts   []string   `json:"redirect_hosts,omitempty"` // host patterns redirect grants may target; empty = any public host
	CompanionRules  []string   `json:"companion_rules"`
	GroupIDs        []string   `json:"group_ids"`
	ServerIDs       []string   `json:"server_ids"`
	CreatedBy       string     `json:"created_by"`
	ApprovedBy      string     `json:"approved_by"`
	SourceSessionID string     `json:"source_session_id,omitempty"`
	Enabled         bool       `json:"enabled"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       *time.Time `json:"updated_at,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	HitCount        int64      `json:"hit_count"`
	TotalBytes      int64      `json:"total_bytes"`
	// Set attribution of compiled (effective) rules.
	PolicySetID   string `json:"policy_set_id,omitempty"`
	PolicySetName string `json:"policy_set_name,omitempty"`
	// AccessRequestID links rules created by approving an access request.
	AccessRequestID string `json:"access_request_id,omitempty"`
}

// ---------------------------------------------------------------------------
// Policy sets & change management
// ---------------------------------------------------------------------------

const (
	PolicySetKindStandard  = "standard"  // assigned to groups and/or servers
	PolicySetKindBaseline  = "baseline"  // applies to every registered server
	PolicySetKindApprovals = "approvals" // system-managed: approved access requests of one group
)

// PolicySetSpec is the editable content of a policy set (what drafts and change requests carry).
type PolicySetSpec struct {
	Name               string       `json:"name"`
	Description        string       `json:"description"`
	OwnerTeam          string       `json:"owner_team"`
	Tags               []string     `json:"tags"`
	Priority           int          `json:"priority"`
	Enabled            bool         `json:"enabled"`
	GroupIDs           []string     `json:"group_ids"`
	ServerIDs          []string     `json:"server_ids"`
	Rules              []PolicyRule `json:"rules"`
	ReviewIntervalDays int          `json:"review_interval_days"`
}

type PolicySetDraft struct {
	Spec            PolicySetSpec `json:"spec"`
	BaseVersion     int           `json:"base_version"`
	Status          string        `json:"status"` // editing | in_review
	ChangeRequestID string        `json:"change_request_id,omitempty"`
	UpdatedBy       string        `json:"updated_by"`
	UpdatedAt       time.Time     `json:"updated_at"`
}

type PolicySet struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	PolicySetSpec                  // published content
	Version        int             `json:"version"` // 0 = never published
	PublishedAt    *time.Time      `json:"published_at,omitempty"`
	PublishedBy    string          `json:"published_by,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	CreatedBy      string          `json:"created_by"`
	LastReviewedAt *time.Time      `json:"last_reviewed_at,omitempty"`
	LastReviewedBy string          `json:"last_reviewed_by,omitempty"`
	Draft          *PolicySetDraft `json:"draft,omitempty"`
	// Computed for API responses.
	ReviewDueAt *time.Time `json:"review_due_at,omitempty"`
	ReviewState string     `json:"review_state,omitempty"` // ok | due_soon | overdue
}

// PolicySetVersion is an immutable snapshot of a published version.
type PolicySetVersion struct {
	PolicySetID     string        `json:"policy_set_id"`
	Version         int           `json:"version"`
	Spec            PolicySetSpec `json:"spec"`
	PublishedBy     string        `json:"published_by"`
	PublishedAt     time.Time     `json:"published_at"`
	ChangeRequestID string        `json:"change_request_id,omitempty"`
	Summary         string        `json:"summary"`
	Emergency       bool          `json:"emergency,omitempty"`
}

type ChangeReview struct {
	Reviewer string    `json:"reviewer"`
	Role     string    `json:"role"`
	Decision string    `json:"decision"` // approve | reject | comment
	Comment  string    `json:"comment"`
	At       time.Time `json:"at"`
}

// RuleChange is one line of a policy diff.
type RuleChange struct {
	Op     string      `json:"op"` // added | removed | modified
	RuleID string      `json:"rule_id"`
	Before *PolicyRule `json:"before,omitempty"`
	After  *PolicyRule `json:"after,omitempty"`
	Fields []string    `json:"fields,omitempty"`
}

type PolicyDiff struct {
	Metadata []string     `json:"metadata"` // changed set-level fields
	Rules    []RuleChange `json:"rules"`
	Added    int          `json:"added"`
	Removed  int          `json:"removed"`
	Modified int          `json:"modified"`
}

// ImpactSample is one recorded request whose verdict a change would flip.
type ImpactSample struct {
	ServerHostname string `json:"server_hostname"`
	ServerIP       string `json:"server_ip"`
	Method         string `json:"method"`
	URL            string `json:"url"`
	Before         string `json:"before"`
	After          string `json:"after"`
	RuleName       string `json:"rule_name,omitempty"`
}

type ImpactSummary struct {
	FlowsEvaluated  int            `json:"flows_evaluated"`
	NewlyAllowed    int            `json:"newly_allowed"`
	NewlyBlocked    int            `json:"newly_blocked"`
	Unchanged       int            `json:"unchanged"`
	AffectedServers int            `json:"affected_servers"`
	TargetServers   int            `json:"target_servers"` // registered servers the set applies to
	Samples         []ImpactSample `json:"samples"`
	ComputedAt      time.Time      `json:"computed_at"`
}

type ChangeRequest struct {
	ID            string         `json:"id"`
	PolicySetID   string         `json:"policy_set_id"`
	PolicySetName string         `json:"policy_set_name"`
	Title         string         `json:"title"`
	Description   string         `json:"description"`
	Status        string         `json:"status"` // open | approved | rejected | withdrawn | superseded
	BaseVersion   int            `json:"base_version"`
	Spec          PolicySetSpec  `json:"spec"`
	Diff          *PolicyDiff    `json:"diff,omitempty"`
	Impact        *ImpactSummary `json:"impact,omitempty"`
	SubmittedBy   string         `json:"submitted_by"`
	SubmittedAt   time.Time      `json:"submitted_at"`
	Reviews       []ChangeReview `json:"reviews"`
	DecidedBy     string         `json:"decided_by,omitempty"`
	DecidedAt     *time.Time     `json:"decided_at,omitempty"`
	PublishedVer  int            `json:"published_version,omitempty"`
}

// GovernanceSettings controls change management and request handling.
type GovernanceSettings struct {
	// RequirePolicyReview enforces four-eyes approval: policy changes are published only through an
	// approved change request reviewed by someone other than the author.
	RequirePolicyReview       bool `json:"require_policy_review"`
	RequestSLAHours           int  `json:"request_sla_hours"`
	DefaultReviewIntervalDays int  `json:"default_review_interval_days"`
	MaxTemporaryAccessDays    int  `json:"max_temporary_access_days"`
	// DailyDigest posts a daily Teams/Slack summary of overdue requests, pending reviews,
	// recertifications and quarantined servers.
	DailyDigest bool `json:"daily_digest"`
	// PruneExpiredAfterDays removes expired temporary access from approvals sets after this many
	// days (0 = keep forever).
	PruneExpiredAfterDays int        `json:"prune_expired_after_days"`
	LastDigestAt          *time.Time `json:"last_digest_at,omitempty"` // server-maintained
	UpdatedAt             *time.Time `json:"updated_at,omitempty"`
	UpdatedBy             string     `json:"updated_by,omitempty"`
}

// ---------------------------------------------------------------------------
// Block page branding
// ---------------------------------------------------------------------------

type SupportContact struct {
	Label string `json:"label"`
	Email string `json:"email"`
	Phone string `json:"phone"`
	URL   string `json:"url"`
}

type LinkItem struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// BlockPageTemplate customizes what users see when a request is blocked (browser page and CLI text).
type BlockPageTemplate struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	IsDefault   bool   `json:"is_default"`
	CompanyName string `json:"company_name"`
	LogoDataURL string `json:"logo_data_url,omitempty"`
	// Colors (hex) and look.
	PrimaryColor string `json:"primary_color"`
	AccentColor  string `json:"accent_color"`
	Theme        string `json:"theme"` // auto | light | dark
	// Texts (plain text; blank lines separate paragraphs). Empty = built-in defaults.
	Title         string         `json:"title"`
	Message       string         `json:"message"`
	ThreatMessage string         `json:"threat_message"`
	FooterText    string         `json:"footer_text"`
	Support       SupportContact `json:"support"`
	Links         []LinkItem     `json:"links"`
	// Sections and options.
	ShowRequestForm      bool       `json:"show_request_form"`
	ShowCASection        bool       `json:"show_ca_section"`
	ShowTechnicalDetails bool       `json:"show_technical_details"`
	ShowSuggestedRule    bool       `json:"show_suggested_rule"`
	AllowedScopes        []string   `json:"allowed_scopes"`
	AllowedDurations     []string   `json:"allowed_durations"`
	DefaultLocale        string     `json:"default_locale"` // en | de (the browser language wins when supported)
	CLIHeader            string     `json:"cli_header"`
	CLIFooter            string     `json:"cli_footer"`
	UpdatedAt            *time.Time `json:"updated_at,omitempty"`
	UpdatedBy            string     `json:"updated_by,omitempty"`
}

type TLSBypassRule struct {
	ID        string     `json:"id"`
	Pattern   string     `json:"pattern"`
	MatchType string     `json:"match_type"`
	Category  string     `json:"category"`
	Reason    string     `json:"reason"`
	GroupIDs  []string   `json:"group_ids,omitempty"`
	ServerIDs []string   `json:"server_ids,omitempty"`
	Enabled   bool       `json:"enabled"`
	AddedBy   string     `json:"added_by"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type CompiledRuleCandidate struct {
	ID              string   `json:"id"`
	HostPattern     string   `json:"host_pattern"`
	PathPattern     string   `json:"path_pattern"`
	Methods         []string `json:"methods"`
	FollowRedirects bool     `json:"follow_redirects"`
	CompanionRules  []string `json:"companion_rules"`
	SampleURLs      []string `json:"sample_urls"`
	RedirectTargets []string `json:"redirect_targets"`
	HitCount        int      `json:"hit_count"`
	IsRedirectChild bool     `json:"is_redirect_child"`
	Selected        bool     `json:"selected"`
}

type LearningSession struct {
	ID                 string                  `json:"id"`
	Name               string                  `json:"name"`
	Description        string                  `json:"description"`
	ServerID           string                  `json:"server_id"`
	ServerIP           string                  `json:"server_ip"`
	ServerHostname     string                  `json:"server_hostname"`
	GroupIDs           []string                `json:"group_ids"`
	Mode               string                  `json:"mode"`
	Status             string                  `json:"status"`
	StartedBy          string                  `json:"started_by"`
	StartedAt          time.Time               `json:"started_at"`
	ExpiresAt          time.Time               `json:"expires_at"`
	CapturedFlowCount  int                     `json:"captured_flow_count"`
	CompiledCandidates []CompiledRuleCandidate `json:"compiled_candidates"`
}

// Recording reports whether the session still captures traffic (active and not expired).
func (s LearningSession) Recording(now time.Time) bool {
	return s.Status == "active" && now.Before(s.ExpiresAt)
}

type TrafficFlow struct {
	ID                string    `json:"id"`
	Timestamp         time.Time `json:"timestamp"`
	ServerIP          string    `json:"server_ip"`
	ServerID          string    `json:"server_id"`
	ServerHostname    string    `json:"server_hostname"`
	GroupIDs          []string  `json:"group_ids"`
	ProxyAuthUser     string    `json:"proxy_auth_user,omitempty"`
	Method            string    `json:"method"`
	Scheme            string    `json:"scheme"`
	Host              string    `json:"host"`
	Port              int       `json:"port,omitempty"`
	Path              string    `json:"path"`
	FullURL           string    `json:"full_url"`
	UserAgent         string    `json:"user_agent"`
	Verdict           string    `json:"verdict"`
	MatchedRuleID     string    `json:"matched_rule_id,omitempty"`
	MatchedRuleName   string    `json:"matched_rule_name,omitempty"`
	RedirectParentURL string    `json:"redirect_parent_url,omitempty"`
	RedirectLocation  string    `json:"redirect_location,omitempty"`
	StatusCode        int       `json:"status_code"`
	LatencyMs         int64     `json:"latency_ms"`
	BytesSent         int64     `json:"bytes_sent"`
	BytesReceived     int64     `json:"bytes_received"`
	TLSIntercepted    bool      `json:"tls_intercepted"`
	FollowRedirects   bool      `json:"follow_redirects,omitempty"`
	SessionID         string    `json:"session_id,omitempty"`
	BlockToken        string    `json:"block_token,omitempty"`
	// Threat protection telemetry
	BlockReason     string   `json:"block_reason,omitempty"`
	ThreatCategory  string   `json:"threat_category,omitempty"`
	ThreatSource    string   `json:"threat_source,omitempty"`
	ThreatIndicator string   `json:"threat_indicator,omitempty"`
	SecurityFlags   []string `json:"security_flags,omitempty"`
	ContentSHA256   string   `json:"content_sha256,omitempty"`
	ContentType     string   `json:"content_type,omitempty"`
	FileType        string   `json:"file_type,omitempty"`
	AVResult        string   `json:"av_result,omitempty"`
	AVSignature     string   `json:"av_signature,omitempty"`
	DLPFindings     []string `json:"dlp_findings,omitempty"`
	ResolvedIP      string   `json:"resolved_ip,omitempty"`
	DataPlaneID     string   `json:"data_plane_id,omitempty"`
}

type BandwidthSample struct {
	TimeLabel       string  `json:"time_label"`
	MbpsTotal       float64 `json:"mbps_total"`
	MbpsDirectAllow float64 `json:"mbps_direct_allow"`
	MbpsCDNObjects  float64 `json:"mbps_cdn_objects"`
	MbpsTLSBypass   float64 `json:"mbps_tls_bypass"`
	RequestsPerSec  int     `json:"requests_per_sec"`
}

type ServerVolumeEntry struct {
	ServerID       string   `json:"server_id"`
	Hostname       string   `json:"hostname"`
	IP             string   `json:"ip"`
	GroupIDs       []string `json:"group_ids"`
	BytesReceived  int64    `json:"bytes_received"`
	BytesSent      int64    `json:"bytes_sent"`
	TotalBytes     int64    `json:"total_bytes"`
	RequestCount   int64    `json:"request_count"`
	PeakMbps       float64  `json:"peak_mbps"`
	TopDestination string   `json:"top_destination"`
}

type DestinationVolumeEntry struct {
	Host            string `json:"host"`
	PathPattern     string `json:"path_pattern"`
	Category        string `json:"category"`
	TotalBytes      int64  `json:"total_bytes"`
	RequestCount    int64  `json:"request_count"`
	TLSIntercepted  bool   `json:"tls_intercepted"`
	IsRedirectAsset bool   `json:"is_redirect_asset"`
	ParentRuleName  string `json:"parent_rule_name"`
}

type GroupVolumeEntry struct {
	GroupID      string  `json:"group_id"`
	GroupName    string  `json:"group_name"`
	ServerCount  int     `json:"server_count"`
	TotalBytes   int64   `json:"total_bytes"`
	CurrentMbps  float64 `json:"current_mbps"`
	RequestCount int64   `json:"request_count"`
	Color        string  `json:"color"`
}

type BandwidthSummary struct {
	CurrentMbps         float64                  `json:"current_mbps"`
	PeakMbps24h         float64                  `json:"peak_mbps_24h"`
	TotalBytes24h       int64                    `json:"total_bytes_24h"`
	CDNRedirectBytes24h int64                    `json:"cdn_redirect_bytes_24h"`
	TLSBypassBytes24h   int64                    `json:"tls_bypass_bytes_24h"`
	TimeSeries          []BandwidthSample        `json:"time_series"`
	TopServers          []ServerVolumeEntry      `json:"top_servers"`
	TopDestinations     []DestinationVolumeEntry `json:"top_destinations"`
	GroupBreakdown      []GroupVolumeEntry       `json:"group_breakdown"`
}

type AccessRequest struct {
	ID                   string     `json:"id"`
	TraceID              string     `json:"trace_id"`
	ServerIP             string     `json:"server_ip"`
	ServerID             string     `json:"server_id"`
	ServerHostname       string     `json:"server_hostname"`
	GroupIDs             []string   `json:"group_ids"`
	RequestedURL         string     `json:"requested_url"`
	Host                 string     `json:"host"`
	Path                 string     `json:"path"`
	Method               string     `json:"method"`
	UserAgent            string     `json:"user_agent"`
	Requester            string     `json:"requester"`
	Reason               string     `json:"reason"`
	RequestedScope       string     `json:"requested_scope"`
	SuggestedHostPattern string     `json:"suggested_host_pattern"`
	SuggestedPathPattern string     `json:"suggested_path_pattern"`
	FollowRedirects      bool       `json:"follow_redirects"`
	TargetGroupIDs       []string   `json:"target_group_ids"`
	Duration             string     `json:"duration"`
	Status               string     `json:"status"`
	ReviewedBy           string     `json:"reviewed_by,omitempty"`
	ReviewerRole         string     `json:"reviewer_role,omitempty"`
	ReviewComment        string     `json:"review_comment,omitempty"`
	ReviewedAt           *time.Time `json:"reviewed_at,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	CreatedRuleID        string     `json:"created_rule_id,omitempty"`
	// Verified is true when the request carried a block token signed by a data-plane worker,
	// i.e. server identity and URL were attested by the proxy rather than self-reported.
	Verified bool   `json:"verified"`
	SourceIP string `json:"source_ip,omitempty"`
	// Workflow
	AssignedTo     string           `json:"assigned_to,omitempty"`
	DueAt          *time.Time       `json:"due_at,omitempty"`
	Comments       []RequestComment `json:"comments,omitempty"`
	CreatedRuleIDs []string         `json:"created_rule_ids,omitempty"`
	ExpiresAt      *time.Time       `json:"expires_at,omitempty"` // access expiry of an approved request
	RevokedBy      string           `json:"revoked_by,omitempty"`
	RevokedAt      *time.Time       `json:"revoked_at,omitempty"`
}

type RequestComment struct {
	Author string    `json:"author"`
	Text   string    `json:"text"`
	At     time.Time `json:"at"`
}

type NotificationConfig struct {
	TeamsEnabled     bool          `json:"teams_enabled"`
	TeamsWebhookURL  sealed.String `json:"teams_webhook_url"`
	TeamsChannel     string        `json:"teams_channel"`
	SlackEnabled     bool          `json:"slack_enabled"`
	SlackWebhookURL  sealed.String `json:"slack_webhook_url"`
	SlackChannel     string        `json:"slack_channel"`
	DashboardBaseURL string        `json:"dashboard_base_url"`
	// NotifySecurityEvents sends high/critical threat-protection events to the same channels.
	NotifySecurityEvents bool `json:"notify_security_events"`
}

// MaskedSecretMarker marks a redacted secret in API responses; sending it back keeps the stored value.
const MaskedSecretMarker = "••••••"

// MaskURL keeps scheme and host of a secret-bearing URL (webhooks embed their token in the path).
func MaskURL(u string) string {
	if u == "" {
		return ""
	}
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			rest = rest[:j]
		}
		return u[:i+3] + rest + "/" + MaskedSecretMarker
	}
	return MaskedSecretMarker
}

// NotificationConfigView is the API representation of NotificationConfig: webhook URLs masked and
// plain strings (a sealed.String would be serialized as ciphertext).
type NotificationConfigView struct {
	TeamsEnabled         bool   `json:"teams_enabled"`
	TeamsWebhookURL      string `json:"teams_webhook_url"`
	TeamsChannel         string `json:"teams_channel"`
	SlackEnabled         bool   `json:"slack_enabled"`
	SlackWebhookURL      string `json:"slack_webhook_url"`
	SlackChannel         string `json:"slack_channel"`
	DashboardBaseURL     string `json:"dashboard_base_url"`
	NotifySecurityEvents bool   `json:"notify_security_events"`
}

// MaskURLQuery masks all query values of a URL (SAS tokens, signatures and API keys are often passed
// there); sending the masked URL back keeps the stored one.
func MaskURLQuery(raw string) string {
	i := strings.IndexByte(raw, '?')
	if i < 0 {
		return raw
	}
	parts := strings.Split(raw[i+1:], "&")
	for j, p := range parts {
		if k, _, ok := strings.Cut(p, "="); ok {
			parts[j] = k + "=" + MaskedSecretMarker
		}
	}
	return raw[:i+1] + strings.Join(parts, "&")
}

// Public returns the configuration with webhook URLs masked.
func (c NotificationConfig) Public() NotificationConfigView {
	return NotificationConfigView{TeamsEnabled: c.TeamsEnabled, TeamsWebhookURL: MaskURL(string(c.TeamsWebhookURL)), TeamsChannel: c.TeamsChannel,
		SlackEnabled: c.SlackEnabled, SlackWebhookURL: MaskURL(string(c.SlackWebhookURL)), SlackChannel: c.SlackChannel,
		DashboardBaseURL: c.DashboardBaseURL, NotifySecurityEvents: c.NotifySecurityEvents}
}

type NotificationLog struct {
	ID          string    `json:"id"`
	Channel     string    `json:"channel"`
	EventType   string    `json:"event_type"`
	Title       string    `json:"title"`
	Summary     string    `json:"summary"`
	PayloadJSON string    `json:"payload_json"`
	Delivered   bool      `json:"delivered"`
	StatusNote  string    `json:"status_note"`
	Timestamp   time.Time `json:"timestamp"`
}

type AuditEvent struct {
	ID           string      `json:"id"`
	Revision     uint64      `json:"revision"`
	Timestamp    time.Time   `json:"timestamp"`
	Actor        string      `json:"actor"`
	ActorRole    string      `json:"actor_role"`
	Action       string      `json:"action"`
	Category     string      `json:"category"` // "RULE", "APPROVAL", "SESSION", "TLS_BYPASS", "SYSTEM", "SECURITY", "IDENTITY", "FLEET"
	EntityType   string      `json:"entity_type"`
	EntityID     string      `json:"entity_id"`
	EntityName   string      `json:"entity_name"`
	Summary      string      `json:"summary"`
	ScopeGroups  []string    `json:"scope_groups,omitempty"`
	BeforeState  string      `json:"before_state,omitempty"`
	AfterState   string      `json:"after_state,omitempty"`
	RollbackRule *PolicyRule `json:"rollback_rule,omitempty"`
	PrevHash     string      `json:"prev_hash,omitempty"`
	EventHash    string      `json:"event_hash,omitempty"`
	// HashVersion 2: HMAC-SHA256 over a length-prefixed encoding with the installation's audit
	// chain key (stored encrypted), so the chain cannot be recomputed with database access alone.
	// 0: SHA-256 over "|"-joined fields (events written before 2.1).
	HashVersion int `json:"hash_version,omitempty"`
}

// ---------------------------------------------------------------------------
// Threat protection
// ---------------------------------------------------------------------------

// Threat feed formats understood by the threatintel parser.
const (
	FeedFormatDomains = "domains" // one domain per line (also accepts adblock "||domain^" and "*.domain")
	FeedFormatHosts   = "hosts"   // /etc/hosts style "0.0.0.0 domain"
	FeedFormatURLs    = "urls"    // one absolute URL per line
	FeedFormatIPs     = "ips"     // one IP or CIDR per line (";" and "#" comments, Spamhaus DROP compatible)
	FeedFormatSHA256  = "sha256"  // one hex SHA-256 file hash per line
)

type ThreatFeed struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	URL             string `json:"url"`
	Format          string `json:"format"`
	Category        string `json:"category"`
	License         string `json:"license"`
	Enabled         bool   `json:"enabled"`
	Builtin         bool   `json:"builtin"`
	MatchSubdomains bool   `json:"match_subdomains"`
	RefreshMinutes  int    `json:"refresh_minutes"`
	// Optional request header for feeds that require an API key (e.g. "Auth-Key").
	// The value is write-only: it is persisted but never returned by the API.
	AuthHeaderName string `json:"auth_header_name,omitempty"`
	// Structured sources (TAXII 2.1, MISP): indicator age window and an optional private CA.
	LookbackDays    int           `json:"lookback_days,omitempty"`
	CACertPEM       string        `json:"ca_cert_pem,omitempty"`
	AuthHeaderValue sealed.String `json:"auth_header_value,omitempty"`
	HasAuthValue    bool          `json:"has_auth_value,omitempty"`

	LastAttemptAt *time.Time `json:"last_attempt_at,omitempty"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	EntryCount    int        `json:"entry_count"`
	ETag          string     `json:"etag,omitempty"`
	LastModified  string     `json:"last_modified,omitempty"`
	ContentSHA256 string     `json:"content_sha256,omitempty"`
}

// Public returns a copy with secrets redacted.
func (f ThreatFeed) Public() ThreatFeed {
	f.HasAuthValue = f.AuthHeaderValue != ""
	f.AuthHeaderValue = ""
	return f
}

// Indicator is a manually curated IOC (indicator of compromise).
type Indicator struct {
	ID        string     `json:"id"`
	Type      string     `json:"type"` // domain | url | ip | cidr | sha256
	Value     string     `json:"value"`
	Category  string     `json:"category"`
	Reason    string     `json:"reason"`
	Enabled   bool       `json:"enabled"`
	AddedBy   string     `json:"added_by"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// ThreatException suppresses a threat-intel match (false positive handling).
type ThreatException struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // domain | url | ip | sha256
	Value     string    `json:"value"`
	Reason    string    `json:"reason"`
	AddedBy   string    `json:"added_by"`
	CreatedAt time.Time `json:"created_at"`
}

// SecurityPolicy holds the global threat-protection settings enforced by every data-plane worker.
type SecurityPolicy struct {
	// Threat intelligence (domain / URL / IP / file hash blocklists): off | monitor | block
	ThreatIntelMode string `json:"threat_intel_mode"`

	// Antivirus (ClamAV clamd INSTREAM) scanning of downloaded response bodies.
	AVEnabled        bool   `json:"av_enabled"`
	AVMode           string `json:"av_mode"`            // monitor | block
	AVFailMode       string `json:"av_fail_mode"`       // open | closed (scanner unavailable / scan error)
	AVMaxScanBytes   int64  `json:"av_max_scan_bytes"`  // bodies above this size are not scanned
	AVOversizeAction string `json:"av_oversize_action"` // allow | block (bodies too large to scan)

	// Data loss prevention: detect credentials/secrets in outbound request URLs, headers and bodies.
	DLPMode           string   `json:"dlp_mode"` // off | monitor | block
	DLPMaxScanBytes   int64    `json:"dlp_max_scan_bytes"`
	DLPOversizeAction string   `json:"dlp_oversize_action"` // allow | block (uploads above the DLP/ICAP scan limit)
	DLPDetectors      []string `json:"dlp_detectors"`

	// Download control: block executable / script / archive types detected by magic bytes.
	BlockedFileTypes      []string            `json:"blocked_file_types"`
	GroupBlockedFileTypes map[string][]string `json:"group_blocked_file_types,omitempty"`

	// Protocol & destination hygiene.
	BlockIPLiterals          bool   `json:"block_ip_literals"`
	BlockPrivateDestinations bool   `json:"block_private_destinations"`
	BlockRawTCP              bool   `json:"block_raw_tcp"`
	AllowedPorts             []int  `json:"allowed_ports"`
	PunycodeMode             string `json:"punycode_mode"`    // off | monitor | block
	MaxUploadBytes           int64  `json:"max_upload_bytes"` // 0 = unlimited

	// Behavioural anomaly detection: emit a security event when one server exceeds
	// this many blocked requests within one minute (possible malware beaconing). 0 disables.
	BlockedBurstThreshold int `json:"blocked_burst_threshold"`

	// ICAP (RFC 3507) integration with external antivirus / sandbox (RESPMOD) and DLP (REQMOD) engines.
	ICAPRespmodURL     string `json:"icap_respmod_url"` // icap://host:1344/service or icaps://…; "" = off
	ICAPReqmodURL      string `json:"icap_reqmod_url"`
	ICAPMode           string `json:"icap_mode"`      // monitor | block
	ICAPFailMode       string `json:"icap_fail_mode"` // open | closed
	ICAPTimeoutSeconds int    `json:"icap_timeout_seconds"`
	ICAPMaxBytes       int64  `json:"icap_max_bytes"`
	ICAPAllowModified  bool   `json:"icap_allow_modified"` // deliver sanitized content (CDR) returned by the engine
	ICAPTLSSkipVerify  bool   `json:"icap_tls_skip_verify"`
	ICAPCACertPEM      string `json:"icap_ca_cert_pem,omitempty"`

	// YARA rules (managed under Threat protection) applied to downloads.
	YARAMode     string `json:"yara_mode"` // off | monitor | block
	YARAMaxBytes int64  `json:"yara_max_bytes"`

	// Query strings in recorded URLs (traffic telemetry, access log, block pages, exports): none | sensitive
	// (values of credential-like parameters redacted; the default, also for states written before the setting
	// existed) | all (query dropped). Policy evaluation always uses the full URL.
	TelemetryQueryRedaction string `json:"telemetry_query_redaction"`

	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	UpdatedBy string     `json:"updated_by,omitempty"`
}

type SecurityEvent struct {
	ID             string     `json:"id"`
	Timestamp      time.Time  `json:"timestamp"`
	Type           string     `json:"type"`
	Severity       string     `json:"severity"` // critical | high | medium | low
	Action         string     `json:"action"`   // blocked | detected
	ServerID       string     `json:"server_id"`
	ServerIP       string     `json:"server_ip"`
	ServerHostname string     `json:"server_hostname"`
	GroupIDs       []string   `json:"group_ids,omitempty"`
	Method         string     `json:"method,omitempty"`
	Host           string     `json:"host,omitempty"`
	URL            string     `json:"url,omitempty"`
	Verdict        string     `json:"verdict,omitempty"`
	Detail         string     `json:"detail"`
	Indicator      string     `json:"indicator,omitempty"`
	Source         string     `json:"source,omitempty"`
	FlowID         string     `json:"flow_id,omitempty"`
	Count          int        `json:"count"`
	Acknowledged   bool       `json:"acknowledged"`
	AcknowledgedBy string     `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
}

// YaraRuleSet is a named collection of YARA rules applied by the data-plane.
type YaraRuleSet struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Source      string     `json:"source"`
	Enabled     bool       `json:"enabled"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
	UpdatedBy   string     `json:"updated_by,omitempty"`
}

// ThreatIntelStatus summarizes the compiled threat-intel snapshot currently enforced.
type ThreatIntelStatus struct {
	Version     string    `json:"version"`
	CompiledAt  time.Time `json:"compiled_at"`
	Domains     int       `json:"domains"`
	URLs        int       `json:"urls"`
	IPs         int       `json:"ips"`
	CIDRs       int       `json:"cidrs"`
	Hashes      int       `json:"hashes"`
	Exceptions  int       `json:"exceptions"`
	ActiveFeeds int       `json:"active_feeds"`
}

// ---------------------------------------------------------------------------
// Fleet management views
// ---------------------------------------------------------------------------

// DiscoveredSource is a client seen in traffic that is not registered as a server.
type DiscoveredSource struct {
	IP             string    `json:"ip"`
	SuggestedID    string    `json:"suggested_id"`
	ProxyAuthUser  string    `json:"proxy_auth_user,omitempty"`
	MatchedGroups  []string  `json:"matched_groups"` // via group CIDRs
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	Requests       int       `json:"requests"`
	Blocked        int       `json:"blocked"`
	TopHosts       []string  `json:"top_hosts"`
	UserAgentHints []string  `json:"user_agent_hints"`
}

// ServerImportResult reports one row of a bulk import.
type ServerImportResult struct {
	Row      int    `json:"row"`
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	Action   string `json:"action"` // create | update | error
	Error    string `json:"error,omitempty"`
}

type EffectivePolicySet struct {
	ID       string       `json:"id"`
	Name     string       `json:"name"`
	Kind     string       `json:"kind"`
	Version  int          `json:"version"`
	Priority int          `json:"priority"`
	Via      []string     `json:"via"` // "baseline", "group:<id>", "server"
	Rules    []PolicyRule `json:"rules"`
}

// EffectivePolicy is everything that applies to one server, in evaluation terms.
type EffectivePolicy struct {
	Server              Server               `json:"server"`
	EffectiveGroupIDs   []string             `json:"effective_group_ids"`
	DynamicGroupIDs     []string             `json:"dynamic_group_ids"`
	Quarantined         bool                 `json:"quarantined"`
	StrictIsolation     bool                 `json:"strict_isolation"`
	PolicySets          []EffectivePolicySet `json:"policy_sets"`
	BlockRules          int                  `json:"block_rules"`
	AllowRules          int                  `json:"allow_rules"`
	TLSBypass           []TLSBypassRule      `json:"tls_bypass"`
	BlockPageTemplateID string               `json:"block_page_template_id"`
	BlockedFileTypes    []string             `json:"blocked_file_types"`
}

// ---------------------------------------------------------------------------
// Log export (SIEM / observability integrations)
// ---------------------------------------------------------------------------

// Export streams.
const (
	StreamAudit    = "audit"
	StreamTraffic  = "traffic"
	StreamSecurity = "security"
)

// ExportSink forwards audit, traffic and security records to an external system.
type ExportSink struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Type    string   `json:"type"` // syslog | otlp | splunk_hec | elasticsearch | sentinel | datadog | loki | webhook | file
	Enabled bool     `json:"enabled"`
	Streams []string `json:"streams"`
	// Format of each record: json (native), ecs (flat Elastic Common Schema fields), cef, leef.
	// Fixed per type for otlp/sentinel/datadog/loki (structured fields).
	Format string `json:"format"`

	// Filters
	TrafficFilter string `json:"traffic_filter"` // all | blocked | security | allowed
	MinSeverity   string `json:"min_severity"`   // security events: low | medium | high | critical
	RedactQuery   bool   `json:"redact_query"`   // remove URL query strings from traffic records

	// Destination: URL, or host:port for syslog, or a file name for type file.
	Endpoint       string            `json:"endpoint"`
	Transport      string            `json:"transport,omitempty"`       // syslog: udp | tcp | tls
	SyslogProtocol string            `json:"syslog_protocol,omitempty"` // rfc5424 | rfc3164
	SyslogFacility string            `json:"syslog_facility,omitempty"` // local0..local7 | user | daemon | auth | authpriv | security
	SyslogFraming  string            `json:"syslog_framing,omitempty"`  // octet-counting | newline (tcp/tls)
	Index          string            `json:"index,omitempty"`           // Elasticsearch index/data stream or Splunk index; {stream} placeholder
	SourceType     string            `json:"source_type,omitempty"`     // Splunk sourcetype prefix
	Labels         map[string]string `json:"labels,omitempty"`          // static labels/tags/resource attributes (Loki, Datadog, OTLP)
	Username       string            `json:"username,omitempty"`        // basic auth (Elasticsearch, Loki)
	// Microsoft Sentinel / Azure Monitor Logs Ingestion API
	TenantID       string `json:"tenant_id,omitempty"`
	ClientID       string `json:"client_id,omitempty"`
	DCRImmutableID string `json:"dcr_immutable_id,omitempty"`
	StreamName     string `json:"stream_name,omitempty"`
	AuthorityURL   string `json:"authority_url,omitempty"` // default https://login.microsoftonline.com
	// AzureAuth: client_secret (default) | workload_identity (AKS, federated token file) |
	// managed_identity (Azure VM / App Service; optional user-assigned identity client id in ClientID).
	AzureAuth string `json:"azure_auth,omitempty"`

	// TLS
	TLSSkipVerify bool   `json:"tls_skip_verify"`
	CACertPEM     string `json:"ca_cert_pem,omitempty"`
	ClientCertPEM string `json:"client_cert_pem,omitempty"`

	// Write-only secrets (never returned by the API): token / API key / password / HMAC key /
	// client secret, the TLS client key and header values. Empty on update = keep.
	Secret       sealed.String `json:"secret,omitempty"`
	ClientKeyPEM sealed.String `json:"client_key_pem,omitempty"`
	Headers      sealed.Map    `json:"headers,omitempty"`
	ClearSecret  bool          `json:"clear_secret,omitempty"` // request flag, not persisted
	HasSecret    bool          `json:"has_secret,omitempty"`
	HasClientKey bool          `json:"has_client_key,omitempty"`

	// Delivery
	BatchSize    int `json:"batch_size"`
	FlushSeconds int `json:"flush_seconds"`
	SpoolMB      int `json:"spool_mb"`

	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	UpdatedBy string     `json:"updated_by,omitempty"`
}

// MaskSinkEndpoint hides credentials a sink URL may carry: query values always and, for webhooks,
// the path (many webhook receivers embed their token there).
func MaskSinkEndpoint(sinkType, endpoint string) string {
	if sinkType == "webhook" {
		if i := strings.Index(endpoint, "://"); i >= 0 {
			if j := strings.IndexAny(endpoint[i+3:], "/?#"); j >= 0 && endpoint[i+3+j:] != "/" {
				return MaskURL(endpoint)
			}
		}
	}
	return MaskURLQuery(endpoint)
}

// Public returns a copy with secrets redacted (header names are kept, values blanked).
func (s ExportSink) Public() ExportSink {
	s.Endpoint = MaskSinkEndpoint(s.Type, s.Endpoint)
	s.HasSecret, s.HasClientKey = s.Secret != "", s.ClientKeyPEM != ""
	s.Secret, s.ClientKeyPEM, s.ClearSecret = "", "", false
	if s.Headers != nil {
		h := make(sealed.Map, len(s.Headers))
		for k := range s.Headers {
			h[k] = ""
		}
		s.Headers = h
	}
	return s
}

// ExportSinkStatus is the delivery state of a sink on one control-plane node.
type ExportSinkStatus struct {
	ID           string `json:"id"`
	Node         string `json:"node"`
	State        string `json:"state"` // ok | retrying | error | disabled | idle
	Queued       int    `json:"queued"`
	SpoolBytes   int64  `json:"spool_bytes"`
	SpoolRecords int64  `json:"spool_records"`
	Sent         uint64 `json:"sent"`
	Failed       uint64 `json:"failed"`
	Dropped      uint64 `json:"dropped"`
	// DiscardedBatches counts batches the destination rejected permanently (4xx); sinks carrying audit
	// or security records keep them in dead-letter.jsonl in their spool directory.
	DiscardedBatches uint64     `json:"discarded_batches"`
	LastSuccessAt    *time.Time `json:"last_success_at,omitempty"`
	LastError        string     `json:"last_error,omitempty"`
	LastErrorAt      *time.Time `json:"last_error_at,omitempty"`
}

// PolicySetDocument is the portable representation of a policy set (policy as code).
type PolicySetDocument struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	PolicySetSpec
}

// PolicySetBundle is the export/import file format.
type PolicySetBundle struct {
	Format     string              `json:"format"` // aegisproxy.policy-sets/v1
	ExportedAt time.Time           `json:"exported_at"`
	ExportedBy string              `json:"exported_by"`
	PolicySets []PolicySetDocument `json:"policy_sets"`
}

// PolicySetImportResult is the plan/outcome for one imported set.
type PolicySetImportResult struct {
	ID     string      `json:"id"`
	Name   string      `json:"name"`
	Action string      `json:"action"` // create | update | unchanged | skip | error
	Diff   *PolicyDiff `json:"diff,omitempty"`
	Error  string      `json:"error,omitempty"`
}

// ServiceAccount is a non-human identity for automation (SOAR playbooks, CI, Terraform, scripts).
// It authenticates with an API key ("Authorization: Bearer aegis_sa_…"); only the SHA-256 of the
// key is stored.
type ServiceAccount struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Description   string     `json:"description"`
	Role          Role       `json:"role"` // never SUPER_ADMIN
	AllowedGroups []string   `json:"allowed_groups"`
	AllowedCIDRs  []string   `json:"allowed_cidrs"` // empty = any source address
	Disabled      bool       `json:"disabled"`
	KeyPrefix     string     `json:"key_prefix"` // first characters of the key, for identification
	KeyHash       string     `json:"key_hash,omitempty"`
	ExpiresAt     time.Time  `json:"expires_at"`
	KeyRotatedAt  *time.Time `json:"key_rotated_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	CreatedBy     string     `json:"created_by"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP    string     `json:"last_used_ip,omitempty"`
}

// Public removes the key digest.
func (a ServiceAccount) Public() ServiceAccount {
	a.KeyHash = ""
	a.AllowedGroups = append([]string{}, a.AllowedGroups...)
	a.AllowedCIDRs = append([]string{}, a.AllowedCIDRs...)
	return a
}

// ---------------------------------------------------------------------------
// Microsoft Defender for Endpoint integration
// ---------------------------------------------------------------------------

type DefenderConfig struct {
	Enabled         bool          `json:"enabled"`
	TenantID        string        `json:"tenant_id"`
	ClientID        string        `json:"client_id"`
	ClientSecret    sealed.String `json:"client_secret,omitempty"` // write-only
	HasClientSecret bool          `json:"has_client_secret,omitempty"`
	APIBaseURL      string        `json:"api_base_url"`  // commercial (default), GCC, GCC High, DoD endpoints
	AuthorityURL    string        `json:"authority_url"` // default https://login.microsoftonline.com
	// ImportIndicators adds Defender custom indicators (block actions) to the proxy's threat intel.
	ImportIndicators bool     `json:"import_indicators"`
	IndicatorActions []string `json:"indicator_actions"`
	// DeviceSync maps Defender devices to registered servers (risk, isolation) and can quarantine them.
	DeviceSync            bool   `json:"device_sync"`
	QuarantineOnRisk      string `json:"quarantine_on_risk"` // off | high | medium
	QuarantineOnIsolation bool   `json:"quarantine_on_isolation"`
	AutoRelease           bool   `json:"auto_release"` // release Defender-initiated quarantines when the condition clears
	SyncMinutes           int    `json:"sync_minutes"`

	LastSyncAt      *time.Time `json:"last_sync_at,omitempty"`
	LastSyncError   string     `json:"last_sync_error,omitempty"`
	LastSyncDevices int        `json:"last_sync_devices"`
	MatchedServers  int        `json:"matched_servers"`
	UpdatedAt       *time.Time `json:"updated_at,omitempty"`
	UpdatedBy       string     `json:"updated_by,omitempty"`
}

func (c DefenderConfig) Public() DefenderConfig {
	c.HasClientSecret = c.ClientSecret != ""
	c.ClientSecret = ""
	c.IndicatorActions = append([]string{}, c.IndicatorActions...)
	return c
}

// DefenderDevice is the Defender view of a registered server.
type DefenderDevice struct {
	MachineID     string     `json:"machine_id"`
	ComputerName  string     `json:"computer_name"`
	RiskScore     string     `json:"risk_score"`
	ExposureLevel string     `json:"exposure_level"`
	HealthStatus  string     `json:"health_status"`
	Isolated      bool       `json:"isolated"`
	LastSeen      *time.Time `json:"last_seen,omitempty"`
	MatchedBy     string     `json:"matched_by"` // hostname | ip
	SyncedAt      time.Time  `json:"synced_at"`
}

// Public returns the server for API responses: the proxy token digest is replaced by a flag.
func (s Server) Public() Server {
	s.HasProxyToken = s.ProxyAuthTokenHash != ""
	s.ProxyAuthTokenHash = ""
	s.ProxyAuthToken = ""
	return s
}
