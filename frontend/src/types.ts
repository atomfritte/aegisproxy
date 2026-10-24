// JSON models of the control-plane API (source of truth:
// control-plane/internal/models/models.go, snake_case JSON).
//
// Arrays coming from Go may be `null` when empty (e.g. `companion_rules`, `group_ids` of rules
// inside a spec, `security.events`). Always read them with `?? []`.

export type Role = 'SUPER_ADMIN' | 'INFOSEC_APPROVER' | 'TEAM_LEAD_APPROVER' | 'OPERATOR_AUDITOR';

export interface User {
  id: string;
  username: string;
  display_name: string;
  email: string;
  role: Role;
  auth_provider: string;
  allowed_groups: string[] | null;
  department: string;
  created_at: string;
  disabled?: boolean;
  /** Manual lock-out by an administrator (persists across SSO sign-ins); without it a disabled SSO user was deprovisioned by the IdP. */
  disabled_by_admin?: boolean;
  /** Emergency account: may always sign in with a password (Super Admins only); every use raises an alert. */
  break_glass?: boolean;
  /** Set for users provisioned by single sign-on (issuer/subject digest). */
  external_id?: string;
  /** Set for accounts managed by SCIM provisioning (Entra ID, Okta). Their `role` is '' while no SCIM group maps to a role. */
  scim?: ScimUserLink;
  last_login_at?: string;
  password_set_at?: string;
}

/** Provisioning attributes of a SCIM-managed account, as sent by the IdP. */
export interface ScimUserLink {
  user_name: string;
  external_id?: string;
  /** Absent means active. */
  active?: boolean;
  display_name?: string;
  given_name?: string;
  family_name?: string;
  formatted?: string;
  title?: string;
  emails?: Array<{ value: string; type?: string; primary?: boolean }>;
  department?: string;
  /** Deleted by the SCIM client: kept disabled for the audit trail. */
  deleted?: boolean;
  version: number;
  created: string;
  last_modified: string;
}

export type SsoProvider = 'entra' | 'oidc';

export interface PublicMeta {
  product: string;
  version: string;
  demo_mode: boolean;
  public_url: string;
  local_login_enabled: boolean;
  entra_enabled: boolean;
  /** Single sign-on summary for the login page. */
  sso?: {
    enabled: boolean;
    provider: SsoProvider;
    /** Label of the login button ("Sign in with …"). */
    label: string;
    /** Relative to the API base: GET starts the OIDC flow (`?next=/path` returns there). */
    login_url: string;
    local_login_enabled: boolean;
  };
}

export interface LoginResponse {
  user: User;
  expires_at: string;
  token?: string;
}

/** Single sign-on (OpenID Connect: Microsoft Entra ID or any OIDC provider). Super Admins edit. */
export interface EntraIDConfig {
  enabled: boolean;
  provider: SsoProvider | '';
  /** Login button label; default "Microsoft Entra ID" / "Single sign-on". */
  display_name: string;
  tenant_id: string;
  client_id: string;
  /** Write-only: send a new value to replace it, omit/empty keeps the stored one. Never returned. */
  client_secret?: string;
  has_client_secret?: boolean;
  /**
   * Token endpoint client authentication: '' (auto: post when advertised, else basic), client_secret_post,
   * client_secret_basic, or private_key_jwt (signed assertion with the active SSO client key, no secret).
   */
  token_auth_method?: TokenAuthMethod;
  /** Derived from the tenant for Entra when empty. */
  issuer_url: string;
  /** Default <public URL>/api/auth/sso/callback when empty. */
  redirect_uri: string;
  scopes: string[] | null;
  /** Default preferred_username. */
  username_claim: string;
  /** Default groups (Entra app roles: roles). */
  groups_claim: string;
  /** IdP group (Entra: object ID or app role value) → console role; the most privileged match wins. */
  group_role_map: Record<string, Role> | null;
  /** IdP group → server groups a Team Lead may approve for. */
  group_scope_map: Record<string, string[]> | null;
  /** false: only break-glass accounts may sign in with a password. */
  allow_local_login: boolean;
}

export type TokenAuthMethod = '' | 'client_secret_post' | 'client_secret_basic' | 'private_key_jwt';

export interface SsoTestResult {
  ok: boolean;
  issuer: string;
  redirect_uri?: string;
  /** token_endpoint_auth_methods_supported of the provider. */
  token_endpoint_auth_methods?: string[];
  /** Control-plane JWKS URL (private_key_jwt). */
  jwks_uri?: string;
  /** private_key_jwt problems: not advertised by the IdP, no active client key. */
  warnings?: string[];
  note?: string;
  error?: string;
}

// ---------------------------------------------------------------------------
// private_key_jwt client keys and SCIM provisioning
// ---------------------------------------------------------------------------

/** active signs assertions; next is published and waits for activation; retired stays published until published_until. */
export type SsoClientKeyStatus = 'active' | 'next' | 'retired';

/** Public part of a private_key_jwt client key (the private key never leaves the server). */
export interface SsoClientKey {
  /** RFC 7638 JWK thumbprint. */
  kid: string;
  alg: 'RS256' | 'ES256';
  status: SsoClientKeyStatus;
  certificate_pem: string;
  /** base64url SHA-1 certificate thumbprint (Entra ID shows it hex-encoded). */
  x5t: string;
  x5t_s256: string;
  not_after: string;
  created_at: string;
  created_by: string;
  activated_at?: string;
  retired_at?: string;
  published_until?: string;
}

export interface SsoClientKeyList {
  keys: SsoClientKey[];
  jwks_uri: string;
  grace_period_hours: number;
  can_edit: boolean;
}

export interface ScimToken {
  id: string;
  name: string;
  /** aegis_scim_xxxxxx */
  prefix: string;
  created_at: string;
  created_by: string;
  expires_at: string;
  rotated_at?: string;
  last_used_at?: string;
  last_used_ip?: string;
}

export interface ScimStatus {
  enabled: boolean;
  tokens: ScimToken[];
  users: number;
  active_users: number;
  groups: number;
  changes: number;
  last_sync_at?: string;
  last_request_at?: string;
}

export interface ScimSettings {
  status: ScimStatus;
  /** <public URL>/api/scim/v2 — Entra "Tenant URL", Okta "SCIM connector base URL". */
  base_url: string;
  can_edit: boolean;
  /** Setup guide (when AEGIS_DOCS_URL is configured). */
  docs_url?: string;
}

export interface ScimTokenIssued {
  token: ScimToken;
  /** Shown once. */
  secret: string;
  base_url: string;
  note?: string;
}

// ---------------------------------------------------------------------------
// Service accounts (API keys for automation)
// ---------------------------------------------------------------------------

export interface ServiceAccount {
  id: string;
  name: string;
  description: string;
  /** Never SUPER_ADMIN. */
  role: Role;
  allowed_groups: string[];
  /** Empty = any source address. */
  allowed_cidrs: string[];
  disabled: boolean;
  /** First characters of the key (aegis_sa_xxxxxx), for identification. */
  key_prefix: string;
  expires_at: string;
  key_rotated_at?: string;
  created_at: string;
  created_by: string;
  last_used_at?: string;
  last_used_ip?: string;
}

export interface ServiceAccountInput {
  name: string;
  description: string;
  role: Role;
  allowed_groups: string[];
  allowed_cidrs: string[];
  disabled: boolean;
  /** RFC 3339; between 1 hour and 730 days from now (default 365 days). */
  expires_at?: string;
}

export interface ServiceAccountKeyResponse {
  service_account: ServiceAccount;
  /** Shown exactly once. */
  api_key: string;
  note?: string;
}

// ---------------------------------------------------------------------------
// Microsoft Defender for Endpoint
// ---------------------------------------------------------------------------

export type DefenderIndicatorAction = 'Block' | 'AlertAndBlock' | 'BlockAndRemediate' | 'Alert' | 'Audit' | 'Warn';

export interface DefenderConfig {
  enabled: boolean;
  tenant_id: string;
  client_id: string;
  /** Write-only. */
  client_secret?: string;
  has_client_secret?: boolean;
  /** Default https://api.securitycenter.microsoft.com (GCC, GCC High and DoD have their own endpoints). */
  api_base_url: string;
  /** Default https://login.microsoftonline.com */
  authority_url: string;
  import_indicators: boolean;
  indicator_actions: DefenderIndicatorAction[] | null;
  device_sync: boolean;
  quarantine_on_risk: 'off' | 'high' | 'medium' | '';
  quarantine_on_isolation: boolean;
  auto_release: boolean;
  sync_minutes: number;
  last_sync_at?: string;
  last_sync_error?: string;
  last_sync_devices: number;
  matched_servers: number;
  updated_at?: string;
  updated_by?: string;
}

export interface DefenderResponse {
  config: DefenderConfig;
  can_edit: boolean;
  /** Required application permissions (WindowsDefenderATP API). */
  permissions: string[];
}

export interface DefenderTestResult {
  ok: boolean;
  indicators?: number;
  indicators_error?: string;
  devices?: number;
  devices_error?: string;
}

/** Defender view of a registered server (device sync). */
export interface DefenderDevice {
  machine_id: string;
  computer_name: string;
  /** None | Informational | Low | Medium | High */
  risk_score: string;
  /** None | Low | Medium | High */
  exposure_level: string;
  /** Active | Inactive | ImpairedCommunication | NoSensorData … */
  health_status: string;
  isolated: boolean;
  last_seen?: string;
  matched_by: 'hostname' | 'ip' | string;
  synced_at: string;
}

// ---------------------------------------------------------------------------
// Security posture
// ---------------------------------------------------------------------------

export type PostureStatus = 'pass' | 'warn' | 'fail' | 'info';

export interface PostureCheck {
  id: string;
  /** identity | data | detection | governance | platform */
  category: string;
  title: string;
  status: PostureStatus;
  detail: string;
  remediation?: string;
  /** Repository documentation path, e.g. docs/security.md#hardening-checklist */
  doc_link?: string;
  /** doc_link resolved against AEGIS_DOCS_URL, when the operator configured one. */
  doc_url?: string;
}

export interface PostureReport {
  score: number;
  checks: PostureCheck[] | null;
  generated_at: string;
}

// ---------------------------------------------------------------------------
// Policy as code
// ---------------------------------------------------------------------------

export interface PolicySetDocument extends PolicySetSpec {
  id: string;
  kind: PolicySetKind;
}

export interface PolicySetBundle {
  /** aegisproxy.policy-sets/v1 */
  format: string;
  exported_at: string;
  exported_by: string;
  policy_sets: PolicySetDocument[];
}

export interface PolicySetImportResult {
  id: string;
  name: string;
  action: 'create' | 'update' | 'unchanged' | 'skip' | 'error';
  diff?: PolicyDiff | null;
  error?: string;
}

export interface PolicySetImportResponse {
  dry_run: boolean;
  results: PolicySetImportResult[] | null;
  error?: string;
}

// ---------------------------------------------------------------------------
// Public portal
// ---------------------------------------------------------------------------

/** GET /api/public/request-options?bt=<token> — what the self-service form offers for this server. */
export interface PublicRequestOptions {
  verified: boolean;
  server_hostname: string;
  url: string;
  verdict: string;
  request_form: boolean;
  allowed_scopes: string[] | null;
  allowed_durations: string[] | null;
  company_name: string;
  support: SupportContact;
  default_locale: string;
}

// ---------------------------------------------------------------------------
// Fleet
// ---------------------------------------------------------------------------

export interface ServerGroup {
  id: string;
  name: string;
  description: string;
  cidrs: string[] | null;
  server_count: number;
  environment: string;
  owner_team: string;
  color: string;
  strict_isolation: boolean;
  /** Dynamic membership: every registered server whose labels contain all pairs (`*` = any value). */
  match_labels?: Record<string, string>;
  /** Block page template for servers of this group ("" = default). */
  block_page_template_id?: string;
}

export interface Server {
  id: string;
  hostname: string;
  ip: string;
  subnet_cidr: string;
  proxy_auth_user: string;
  /** True when a proxy token is configured (neither the token nor its digest is ever returned). */
  has_proxy_token?: boolean;
  token_rotated_at?: string;
  group_ids: string[] | null;
  os: string;
  department: string;
  last_seen_at: string;
  description?: string;
  owner_team?: string;
  labels?: Record<string, string>;
  quarantined?: boolean;
  quarantine_reason?: string;
  quarantined_by?: string;
  quarantined_at?: string;
  created_at?: string;
  /** Matched Microsoft Defender for Endpoint device (device sync). */
  defender?: DefenderDevice | null;
  /** Static group_ids + dynamic groups whose match_labels match (computed). */
  effective_group_ids?: string[];
}

export interface OnboardingSnippets {
  linux: string;
  windows: string;
  proxy_url: string;
  no_proxy: string;
  proxy_address: string;
}

export interface RotateTokenResponse {
  server: Server;
  proxy_auth_user: string;
  token: string;
  proxy_url_hint: string;
  onboarding: OnboardingSnippets;
  note: string;
}

export interface DiscoveredSource {
  ip: string;
  suggested_id: string;
  proxy_auth_user?: string;
  matched_groups: string[] | null;
  first_seen: string;
  last_seen: string;
  requests: number;
  blocked: number;
  top_hosts: string[] | null;
  user_agent_hints: string[] | null;
}

export interface ServerImportResult {
  row: number;
  id: string;
  hostname: string;
  action: 'create' | 'update' | 'error';
  error?: string;
}

export interface ServerImportResponse {
  dry_run: boolean;
  results: ServerImportResult[];
  error?: string;
}

export interface EffectivePolicySet {
  id: string;
  name: string;
  kind: PolicySetKind;
  version: number;
  priority: number;
  /** "baseline", "group:<id>", "server" */
  via: string[];
  rules: PolicyRule[];
}

export interface EffectivePolicy {
  server: Server;
  effective_group_ids: string[];
  dynamic_group_ids: string[] | null;
  quarantined: boolean;
  strict_isolation: boolean;
  policy_sets: EffectivePolicySet[] | null;
  block_rules: number;
  allow_rules: number;
  tls_bypass: TLSBypassRule[] | null;
  block_page_template_id: string;
  blocked_file_types: string[] | null;
}

// ---------------------------------------------------------------------------
// Rules & policy sets
// ---------------------------------------------------------------------------

export type RuleAction = 'ALLOW' | 'BLOCK';

export interface PolicyRule {
  id: string;
  version?: number;
  name: string;
  description: string;
  action: RuleAction;
  host_pattern: string;
  path_pattern: string;
  methods: string[] | null;
  follow_redirects: boolean;
  /** Hosts redirect grants of this rule may target (patterns); absent/empty = any public host. */
  redirect_hosts?: string[] | null;
  companion_rules: string[] | null;
  /** Only set on compiled (effective) rules; rules inside a set carry no scope. */
  group_ids: string[] | null;
  server_ids: string[] | null;
  created_by: string;
  approved_by: string;
  source_session_id?: string;
  enabled: boolean;
  created_at: string;
  updated_at?: string;
  expires_at?: string;
  hit_count: number;
  total_bytes?: number;
  policy_set_id?: string;
  policy_set_name?: string;
  /** Links rules created by approving an access request. */
  access_request_id?: string;
}

/** A rule as sent to PUT /draft and POST /policy-sets (server fields are optional). */
export type RuleInput = Pick<
  PolicyRule,
  'name' | 'description' | 'action' | 'host_pattern' | 'path_pattern' | 'follow_redirects' | 'enabled'
> & {
  id?: string;
  methods: string[];
  companion_rules: string[];
  redirect_hosts?: string[] | null;
  expires_at?: string;
} & Partial<Omit<PolicyRule, 'methods' | 'companion_rules'>>;

export type PolicySetKind = 'baseline' | 'standard' | 'approvals';
export type ReviewState = 'ok' | 'due_soon' | 'overdue';

export interface PolicySetSpec {
  name: string;
  description: string;
  owner_team: string;
  tags: string[] | null;
  priority: number;
  enabled: boolean;
  group_ids: string[] | null;
  server_ids: string[] | null;
  rules: PolicyRule[] | null;
  review_interval_days: number;
}

/** Spec as sent by the console (rules may be new and lack server fields). */
export interface PolicySetSpecInput {
  name: string;
  description: string;
  owner_team: string;
  tags: string[];
  priority: number;
  enabled: boolean;
  group_ids: string[];
  server_ids: string[];
  rules: RuleInput[];
  review_interval_days: number;
}

export interface PolicySetDraft {
  spec: PolicySetSpec;
  base_version: number;
  status: 'editing' | 'in_review';
  change_request_id?: string;
  updated_by: string;
  updated_at: string;
}

export interface PolicySet extends PolicySetSpec {
  id: string;
  kind: PolicySetKind;
  /** 0 = never published */
  version: number;
  published_at?: string;
  published_by?: string;
  created_at: string;
  created_by: string;
  last_reviewed_at?: string;
  last_reviewed_by?: string;
  draft?: PolicySetDraft | null;
  review_due_at?: string;
  review_state?: ReviewState;
}

/** Version summary (GET /versions, GET /policy-sets/{id}). */
export interface PolicySetVersionSummary {
  version: number;
  published_by: string;
  published_at: string;
  change_request_id?: string;
  summary: string;
  emergency?: boolean;
  rules: number;
}

/** Full version (GET /versions/{n}). */
export interface PolicySetVersion {
  policy_set_id: string;
  version: number;
  spec: PolicySetSpec;
  published_by: string;
  published_at: string;
  change_request_id?: string;
  summary: string;
  emergency?: boolean;
}

export interface PolicySetDetail {
  policy_set: PolicySet;
  versions: PolicySetVersionSummary[];
  change_requests: ChangeRequest[];
  draft_diff: PolicyDiff | null;
}

export type RuleChangeOp = 'added' | 'removed' | 'modified';

export interface RuleChange {
  op: RuleChangeOp;
  rule_id: string;
  before?: PolicyRule;
  after?: PolicyRule;
  fields?: string[];
}

export interface PolicyDiff {
  /** Changed set-level fields (name, description, owner_team, tags, priority, enabled, group_ids, server_ids, review_interval_days). */
  metadata: string[] | null;
  rules: RuleChange[] | null;
  added: number;
  removed: number;
  modified: number;
}

export interface ImpactSample {
  server_hostname: string;
  server_ip: string;
  method: string;
  url: string;
  before: string;
  after: string;
  rule_name?: string;
}

export interface ImpactSummary {
  flows_evaluated: number;
  newly_allowed: number;
  newly_blocked: number;
  unchanged: number;
  affected_servers: number;
  /** Registered servers the set applies to. */
  target_servers: number;
  samples: ImpactSample[] | null;
  computed_at: string;
}

export type ReviewDecision = 'approve' | 'reject' | 'comment';

export interface ChangeReview {
  reviewer: string;
  role: string;
  decision: ReviewDecision;
  comment: string;
  at: string;
}

export type ChangeRequestStatus = 'open' | 'approved' | 'rejected' | 'withdrawn' | 'superseded';

export interface ChangeRequest {
  id: string;
  policy_set_id: string;
  policy_set_name: string;
  title: string;
  description: string;
  status: ChangeRequestStatus;
  base_version: number;
  spec: PolicySetSpec;
  diff?: PolicyDiff | null;
  impact?: ImpactSummary | null;
  submitted_by: string;
  submitted_at: string;
  reviews: ChangeReview[] | null;
  decided_by?: string;
  decided_at?: string;
  published_version?: number;
}

export interface GovernanceSettings {
  /** Four-eyes review: policy changes are published only through an approved change request. */
  require_policy_review: boolean;
  request_sla_hours: number;
  default_review_interval_days: number;
  max_temporary_access_days: number;
  /** Daily Teams/Slack summary (overdue requests, pending reviews, recertifications, expiring access, quarantine). */
  daily_digest?: boolean;
  /** Days after expiry until temporary access rules are removed from approvals sets (0 = keep, max 3650). */
  prune_expired_after_days?: number;
  /** Server-maintained: when the last daily digest was sent. */
  last_digest_at?: string;
  updated_at?: string;
  updated_by?: string;
}

// ---------------------------------------------------------------------------
// Block pages
// ---------------------------------------------------------------------------

export interface SupportContact {
  label: string;
  email: string;
  phone: string;
  url: string;
}

export interface LinkItem {
  label: string;
  url: string;
}

export interface BlockPageTemplate {
  id: string;
  name: string;
  is_default: boolean;
  company_name: string;
  logo_data_url?: string;
  primary_color: string;
  accent_color: string;
  theme: 'auto' | 'light' | 'dark';
  title: string;
  message: string;
  threat_message: string;
  footer_text: string;
  support: SupportContact;
  links: LinkItem[] | null;
  show_request_form: boolean;
  show_ca_section: boolean;
  show_technical_details: boolean;
  show_suggested_rule: boolean;
  allowed_scopes: string[] | null;
  allowed_durations: string[] | null;
  default_locale: 'en' | 'de' | string;
  cli_header: string;
  cli_footer: string;
  updated_at?: string;
  updated_by?: string;
}

export interface BlockPagesResponse {
  templates: BlockPageTemplate[];
  default_template_id: string;
  /** group id -> template id */
  group_templates: Record<string, string>;
  locales: string[];
  variables: string[];
}

export interface BlockPagePreview {
  html: string;
  cli: string;
}

// ---------------------------------------------------------------------------
// TLS, sessions, flows
// ---------------------------------------------------------------------------

export interface TLSBypassRule {
  id: string;
  pattern: string;
  match_type: string;
  category: string;
  reason: string;
  group_ids?: string[];
  server_ids?: string[];
  enabled: boolean;
  added_by: string;
  created_at: string;
  expires_at?: string;
}

export interface CompiledRuleCandidate {
  id: string;
  host_pattern: string;
  path_pattern: string;
  methods: string[];
  follow_redirects: boolean;
  companion_rules: string[];
  sample_urls: string[];
  redirect_targets: string[];
  hit_count: number;
  is_redirect_child: boolean;
  selected: boolean;
}

export interface LearningSession {
  id: string;
  name: string;
  description: string;
  server_id: string;
  server_ip: string;
  server_hostname: string;
  group_ids: string[];
  mode: 'record_and_allow' | 'record_only';
  status: 'active' | 'completed' | 'published' | 'stopped';
  started_by: string;
  started_at: string;
  expires_at: string;
  captured_flow_count: number;
  compiled_candidates: CompiledRuleCandidate[];
}

export interface SessionPublishRequest {
  candidates: CompiledRuleCandidate[];
  rule_prefix: string;
  policy_set_id?: string;
  new_set_name?: string;
  target_group_ids?: string[];
  target_server_ids?: string[];
  publish?: boolean;
}

export interface SessionPublishResponse {
  published_count: number;
  policy_set: PolicySet;
  published: boolean;
}

export type FlowVerdict =
  | 'ALLOWED'
  | 'BLOCKED'
  | 'LEARNING_ALLOWED'
  | 'REDIRECT_OBJECT_ALLOWED'
  | 'TLS_BYPASS'
  | 'THREAT_BLOCKED'
  | 'MALWARE_BLOCKED'
  | 'DLP_BLOCKED'
  | 'FILETYPE_BLOCKED'
  | 'POLICY_BLOCKED'
  | 'QUARANTINED'
  | 'SIMULATED';

export interface TrafficFlow {
  id: string;
  timestamp: string;
  server_ip: string;
  server_id: string;
  server_hostname: string;
  group_ids: string[];
  proxy_auth_user?: string;
  method: string;
  scheme: string;
  host: string;
  path: string;
  full_url: string;
  user_agent: string;
  port?: number;
  verdict: FlowVerdict;
  matched_rule_id?: string;
  matched_rule_name?: string;
  redirect_parent_url?: string;
  redirect_location?: string;
  status_code: number;
  latency_ms: number;
  bytes_sent?: number;
  bytes_received?: number;
  tls_intercepted: boolean;
  follow_redirects?: boolean;
  session_id?: string;
  /** Data-plane-signed block token (present on blocked flows recorded by a worker). */
  block_token?: string;
  block_reason?: string;
  threat_category?: string;
  threat_source?: string;
  threat_indicator?: string;
  security_flags?: string[];
  content_sha256?: string;
  content_type?: string;
  file_type?: string;
  /** clean | infected | error | skipped | ... (free-form, set by the data-plane) */
  av_result?: string;
  av_signature?: string;
  dlp_findings?: string[];
  resolved_ip?: string;
  data_plane_id?: string;
}

export interface SimulateRequestBody {
  server_ip: string;
  proxy_auth_user?: string;
  method: string;
  full_url: string;
  user_agent?: string;
  simulate_redirect?: boolean;
}

export interface SimulateRequestResponse {
  evaluation: Record<string, any>;
  flow: TrafficFlow;
  child_flow: TrafficFlow | null;
  cli_output: string;
  dry_run: boolean;
}

// ---------------------------------------------------------------------------
// Bandwidth
// ---------------------------------------------------------------------------

export interface BandwidthSample {
  time_label: string;
  mbps_total: number;
  mbps_direct_allow: number;
  mbps_cdn_objects: number;
  mbps_tls_bypass: number;
  requests_per_sec: number;
}

export interface ServerVolumeEntry {
  server_id: string;
  hostname: string;
  ip: string;
  group_ids: string[];
  bytes_received: number;
  bytes_sent: number;
  total_bytes: number;
  request_count: number;
  peak_mbps: number;
  top_destination: string;
}

export interface DestinationVolumeEntry {
  host: string;
  path_pattern: string;
  category: string;
  total_bytes: number;
  request_count: number;
  tls_intercepted: boolean;
  is_redirect_asset: boolean;
  parent_rule_name: string;
}

export interface GroupVolumeEntry {
  group_id: string;
  group_name: string;
  server_count: number;
  total_bytes: number;
  current_mbps: number;
  request_count: number;
  color: string;
}

export interface BandwidthSummary {
  current_mbps: number;
  peak_mbps_24h: number;
  total_bytes_24h: number;
  cdn_redirect_bytes_24h: number;
  tls_bypass_bytes_24h: number;
  time_series: BandwidthSample[];
  top_servers: ServerVolumeEntry[];
  top_destinations: DestinationVolumeEntry[];
  group_breakdown: GroupVolumeEntry[];
}

// ---------------------------------------------------------------------------
// Access requests
// ---------------------------------------------------------------------------

export type AccessScope = 'exact_path' | 'prefix_with_objects' | 'domain' | 'learning_session_15m';
/** Requested durations (public form): 1h 24h 7d permanent; grant durations add 8h 30d 90d. */
export type AccessDuration = '1h' | '8h' | '24h' | '7d' | '30d' | '90d' | 'permanent';
export type AccessRequestStatus = 'pending' | 'approved' | 'rejected' | 'revoked';

export interface RequestComment {
  author: string;
  text: string;
  at: string;
}

export interface AccessRequest {
  id: string;
  trace_id: string;
  server_ip: string;
  server_id: string;
  server_hostname: string;
  group_ids: string[];
  requested_url: string;
  host: string;
  path: string;
  method: string;
  user_agent: string;
  requester: string;
  reason: string;
  requested_scope: AccessScope;
  suggested_host_pattern: string;
  suggested_path_pattern: string;
  follow_redirects: boolean;
  target_group_ids: string[];
  duration: AccessDuration;
  status: AccessRequestStatus;
  reviewed_by?: string;
  reviewer_role?: string;
  review_comment?: string;
  reviewed_at?: string;
  created_at: string;
  created_rule_id?: string;
  /** True when the request carried a data-plane-signed block token (server identity attested). */
  verified: boolean;
  source_ip?: string;
  assigned_to?: string;
  /** SLA deadline */
  due_at?: string;
  comments?: RequestComment[] | null;
  created_rule_ids?: string[] | null;
  /** Access expiry of an approved request. */
  expires_at?: string;
  revoked_by?: string;
  revoked_at?: string;
}

export interface ReviewAccessRequestBody {
  approve: boolean;
  comment: string;
  host_pattern?: string;
  path_pattern?: string;
  follow_redirects?: boolean;
  target_group_ids?: string[];
  duration?: AccessDuration | '';
  methods?: string[];
}

export interface BulkReviewResult {
  id: string;
  status?: string;
  error?: string;
}

export interface PublicAccessRequestBody {
  block_token?: string;
  requester: string;
  reason: string;
  requested_scope: AccessScope;
  duration: AccessDuration;
  requested_url?: string;
  method?: string;
  trace_id?: string;
  server_ip?: string;
}

// ---------------------------------------------------------------------------
// Notifications & audit
// ---------------------------------------------------------------------------

export interface NotificationConfig {
  teams_enabled: boolean;
  teams_webhook_url: string;
  teams_channel: string;
  slack_enabled: boolean;
  slack_webhook_url: string;
  slack_channel: string;
  dashboard_base_url: string;
  notify_security_events: boolean;
}

export interface NotificationLog {
  id: string;
  channel: 'teams' | 'slack';
  event_type: string;
  title: string;
  summary: string;
  payload_json: string;
  delivered: boolean;
  status_note: string;
  timestamp: string;
}

export type AuditCategory =
  | 'RULE'
  | 'POLICY'
  | 'APPROVAL'
  | 'SESSION'
  | 'TLS_BYPASS'
  | 'SYSTEM'
  | 'SECURITY'
  | 'IDENTITY'
  | 'FLEET';

export interface AuditEvent {
  id: string;
  revision: number;
  timestamp: string;
  actor: string;
  actor_role: string;
  action: string;
  category: AuditCategory;
  entity_type: string;
  entity_id: string;
  entity_name: string;
  summary: string;
  scope_groups?: string[];
  before_state?: string;
  after_state?: string;
  /** Legacy (pre-2.1) field; rollback now uses policy set versions. */
  rollback_rule?: PolicyRule;
  prev_hash?: string;
  event_hash?: string;
}

export interface AuditVerifyResult {
  valid: boolean;
  events_checked: number;
  error?: string;
}

export interface UserInput {
  id?: string;
  username: string;
  display_name: string;
  email: string;
  role: Role;
  allowed_groups: string[];
  department: string;
  disabled: boolean;
  break_glass?: boolean;
  password?: string;
}

// ---------------------------------------------------------------------------
// Threat protection
// ---------------------------------------------------------------------------

export type ThreatMode = 'off' | 'monitor' | 'block';

export interface SecurityPolicy {
  threat_intel_mode: ThreatMode;
  av_enabled: boolean;
  av_mode: 'monitor' | 'block';
  av_fail_mode: 'open' | 'closed';
  av_max_scan_bytes: number;
  av_oversize_action: 'allow' | 'block';
  dlp_mode: ThreatMode;
  dlp_max_scan_bytes: number;
  /** Uploads above the DLP / ICAP REQMOD scan limit (absent in older responses = allow). */
  dlp_oversize_action?: 'allow' | 'block';
  dlp_detectors: string[];
  blocked_file_types: string[];
  group_blocked_file_types?: Record<string, string[]>;
  block_ip_literals: boolean;
  block_private_destinations: boolean;
  block_raw_tcp: boolean;
  allowed_ports: number[];
  punycode_mode: ThreatMode;
  /** 0 = unlimited */
  max_upload_bytes: number;
  /** 0 disables burst detection */
  blocked_burst_threshold: number;
  /** ICAP (RFC 3507): icap://host:1344/service or icaps://…; "" = off. RESPMOD scans downloads. */
  icap_respmod_url: string;
  /** REQMOD inspects uploads (DLP engines). */
  icap_reqmod_url: string;
  icap_mode: 'monitor' | 'block';
  icap_fail_mode: 'open' | 'closed';
  icap_timeout_seconds: number;
  icap_max_bytes: number;
  /** Deliver sanitized content (CDR) returned by the engine. */
  icap_allow_modified: boolean;
  icap_tls_skip_verify: boolean;
  icap_ca_cert_pem?: string;
  /** YARA rule sets (Threat protection → YARA) applied to downloads. */
  yara_mode: ThreatMode;
  yara_max_bytes: number;
  updated_at?: string;
  updated_by?: string;
}

/** Lists (domains … sha256), structured sources (TAXII 2.1, MISP) and the Defender-managed feed (mde). */
export type FeedFormat = 'domains' | 'hosts' | 'urls' | 'ips' | 'sha256' | 'taxii21' | 'misp' | 'mde';

export interface ThreatFeed {
  id: string;
  name: string;
  description: string;
  url: string;
  format: FeedFormat;
  category: string;
  license: string;
  enabled: boolean;
  builtin: boolean;
  match_subdomains: boolean;
  refresh_minutes: number;
  auth_header_name?: string;
  /** Write-only: only sent when the operator types a new value. */
  auth_header_value?: string;
  has_auth_value?: boolean;
  /** TAXII / MISP: indicator age window in days (0 = default 90). */
  lookback_days?: number;
  /** TAXII / MISP: private CA (PEM) of the source. */
  ca_cert_pem?: string;
  last_attempt_at?: string;
  last_success_at?: string;
  last_error?: string;
  entry_count: number;
  last_modified?: string;
  content_sha256?: string;
}

export type IndicatorType = 'domain' | 'url' | 'ip' | 'cidr' | 'sha256';

export interface Indicator {
  id: string;
  type: IndicatorType;
  value: string;
  category: string;
  reason: string;
  enabled: boolean;
  added_by: string;
  created_at: string;
  expires_at?: string;
}

export interface ThreatException {
  id: string;
  type: 'domain' | 'url' | 'ip' | 'sha256';
  value: string;
  reason: string;
  added_by: string;
  created_at: string;
}

export type SecuritySeverity = 'critical' | 'high' | 'medium' | 'low';

export interface SecurityEvent {
  id: string;
  timestamp: string;
  /** THREAT_INTEL | MALWARE | DLP | FILE_TYPE | POLICY | ANOMALY | PUNYCODE | AV_UNSCANNED | AV_ERROR | BLOCK_BURST | QUARANTINE */
  type: string;
  severity: SecuritySeverity;
  action: 'blocked' | 'detected';
  server_id: string;
  server_ip: string;
  server_hostname: string;
  group_ids?: string[];
  method?: string;
  host?: string;
  url?: string;
  verdict?: string;
  detail: string;
  indicator?: string;
  source?: string;
  flow_id?: string;
  count: number;
  acknowledged: boolean;
  acknowledged_by?: string;
  acknowledged_at?: string;
}

export interface ThreatIntelStatus {
  version: string;
  compiled_at: string;
  domains: number;
  urls: number;
  ips: number;
  cidrs: number;
  hashes: number;
  exceptions: number;
  active_feeds: number;
}

export interface ThreatLookupMatch {
  type: string;
  indicator: string;
  category: string;
  source_id: string;
  source_name: string;
}

export interface ThreatLookupResult {
  value: string;
  malicious: boolean;
  matches: ThreatLookupMatch[] | null;
  version: string;
}

export interface DataPlaneStatus {
  id: string;
  version: string;
  remote_ip: string;
  last_seen_at: string;
  bundle_revision: string;
  threat_intel_version: string;
  /** 'yes' | 'no' | '' (unknown) */
  clamav_available: string;
  /** ok | idle (no rule sets) | unavailable (no engine) | error:<message> ("error:N of M rule sets failed: <set>: <msg> (…); …" when only some failed) | '' (old worker) */
  yara_status?: string;
  /** disabled | respmod=ok,reqmod=down | … | '' (old worker) */
  icap_status?: string;
  healthy: boolean;
}

/** YARA rule set (GET /api/security/yara). */
export interface YaraRuleSet {
  id: string;
  name: string;
  description: string;
  source: string;
  enabled: boolean;
  created_at: string;
  updated_at?: string;
  updated_by?: string;
}

export interface YaraResponse {
  rule_sets: YaraRuleSet[] | null;
  data_planes: DataPlaneStatus[] | null;
}

export interface SecurityState {
  policy: SecurityPolicy;
  feeds: ThreatFeed[];
  indicators: Indicator[];
  exceptions: ThreatException[];
  events: SecurityEvent[];
  threat_intel: ThreatIntelStatus;
  dlp_detectors: string[];
  file_types: string[];
}

export interface DashboardStats {
  allowed: number;
  blocked: number;
  bypass: number;
  learning: number;
  threats: number;
  open_security_events: number;
}

/** Work-queue counters of GET /api/state (missing keys mean 0). */
export interface OverviewCounters {
  pending_requests?: number;
  overdue_requests?: number;
  assigned_to_me?: number;
  open_change_requests?: number;
  changes_to_review?: number;
  recertification_overdue?: number;
  recertification_due_soon?: number;
  drafts?: number;
  quarantined_servers?: number;
  stale_servers?: number;
}

/** GET /api/state — the console state. `flows` is absent with ?exclude_flows=1. */
export interface DashboardState {
  revision?: number;
  version: string;
  demo_mode: boolean;
  me?: User;
  fleet_total_servers: number;
  groups: ServerGroup[];
  servers: Server[];
  /** Effective (compiled) rules with policy_set_id / policy_set_name / hit_count. */
  rules: PolicyRule[];
  policy_sets: PolicySet[];
  change_requests: ChangeRequest[];
  governance: GovernanceSettings;
  block_pages: BlockPageTemplate[];
  overview: OverviewCounters;
  proxy_address: string;
  tls_bypass: TLSBypassRule[];
  sessions: LearningSession[];
  requests: AccessRequest[];
  flows: TrafficFlow[];
  users: User[];
  entra_config: EntraIDConfig;
  notify_config: NotificationConfig;
  notification_logs: NotificationLog[];
  audit_events: AuditEvent[];
  bandwidth: BandwidthSummary;
  stats: DashboardStats;
  data_planes: DataPlaneStatus[];
  security: SecurityState;
}

export type ConsoleState = DashboardState;

export interface CAInfo {
  subject: string;
  issuer: string;
  serial: string;
  not_before: string;
  not_after: string;
  fingerprint: string;
  pem_content: string;
  download_crt: string;
  download_pem: string;
  download_der: string;
  linux_script: string;
  windows_script?: string;
  public_url?: string;
  /** SHA-256 of the installers as served, and copy-paste commands that verify it before running them. */
  linux_script_sha256?: string;
  windows_script_sha256?: string;
  linux_command?: string;
  windows_command?: string;
}

// ---------------------------------------------------------------------------
// Log export (SIEM / observability destinations) — /api/integrations/exports
// ---------------------------------------------------------------------------

export type ExportStream = 'audit' | 'traffic' | 'security';

export type AzureAuth = 'client_secret' | 'managed_identity' | 'workload_identity';

export interface ExportSink {
  id: string;
  name: string;
  /** syslog | otlp | splunk_hec | elasticsearch | sentinel | datadog | loki | webhook | file */
  type: string;
  enabled: boolean;
  streams: ExportStream[];
  /** json | ecs | cef | leef */
  format: string;
  traffic_filter: 'all' | 'blocked' | 'security' | 'allowed';
  min_severity: SecuritySeverity;
  redact_query: boolean;
  endpoint: string;
  transport?: string;
  syslog_protocol?: string;
  syslog_facility?: string;
  syslog_framing?: string;
  index?: string;
  source_type?: string;
  labels?: Record<string, string>;
  username?: string;
  tenant_id?: string;
  client_id?: string;
  dcr_immutable_id?: string;
  stream_name?: string;
  authority_url?: string;
  /** Sentinel: client_secret (app registration), managed_identity (Azure VM/VMSS) or workload_identity (AKS). */
  azure_auth?: AzureAuth;
  tls_skip_verify: boolean;
  ca_cert_pem?: string;
  client_cert_pem?: string;
  /** write-only */
  secret?: string;
  client_key_pem?: string;
  headers?: Record<string, string>;
  clear_secret?: boolean;
  has_secret?: boolean;
  has_client_key?: boolean;
  batch_size: number;
  flush_seconds: number;
  spool_mb: number;
  updated_at?: string;
  updated_by?: string;
}

export interface ExportSinkStatus {
  id: string;
  node: string;
  state: 'ok' | 'retrying' | 'error' | 'disabled' | 'idle';
  queued: number;
  spool_bytes: number;
  spool_records: number;
  sent: number;
  failed: number;
  dropped: number;
  last_success_at?: string;
  last_error?: string;
  last_error_at?: string;
}

/** Catalog entry describing a destination type (GET /api/integrations/exports → types[]). */
export interface ExportSinkType {
  type?: string;
  id?: string;
  label: string;
  description: string;
  formats: string[] | null;
  endpoint_hint: string;
  secret_label: string;
  fields: string[] | null;
}

export interface ExportsResponse {
  sinks: ExportSink[];
  status: ExportSinkStatus[];
  types: ExportSinkType[];
  export_dir: string;
  can_edit: boolean;
}
