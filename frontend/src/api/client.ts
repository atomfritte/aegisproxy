// Typed client for every endpoint in docs/api.md. All functions throw ApiError (with the
// server's `error` message) on non-2xx responses; show it with toast.error(err).
//
//   import { api } from '../api';
//   const set = await api.policySets.get('ps-1');

import { apiDelete, apiJSON, apiPost, apiPut, apiUrl, qs, seg } from './http';
import type {
  AccessDuration,
  AccessRequest,
  AuditVerifyResult,
  BlockPagePreview,
  BlockPagesResponse,
  BlockPageTemplate,
  BulkReviewResult,
  CAInfo,
  ChangeRequest,
  DashboardState,
  DefenderConfig,
  DefenderResponse,
  DefenderTestResult,
  DiscoveredSource,
  EffectivePolicy,
  EntraIDConfig,
  ExportSink,
  ExportsResponse,
  GovernanceSettings,
  ImpactSummary,
  Indicator,
  LearningSession,
  LoginResponse,
  NotificationConfig,
  NotificationLog,
  PackageApproval,
  PackageApprovalDetail,
  PackageApprovalsPage,
  PackageBlock,
  PackageDecisionInput,
  PackageLookupResult,
  PackageReceiversResponse,
  PackageRequest,
  PackageRequestInput,
  PackageRule,
  PackageSettings,
  PackagesOverview,
  PolicyDiff,
  PolicyRule,
  PolicySetBundle,
  PolicySetImportResponse,
  PolicySet,
  PolicySetDetail,
  PolicySetKind,
  PolicySetSpecInput,
  PolicySetVersion,
  PolicySetVersionSummary,
  PublicAccessRequestBody,
  PostureReport,
  PublicMeta,
  PublicRequestOptions,
  ReviewAccessRequestBody,
  ReviewDecision,
  RotateTokenResponse,
  SandboxReport,
  ScimSettings,
  ScimTokenIssued,
  SecurityPolicy,
  Server,
  ServerGroup,
  ServiceAccount,
  ServiceAccountInput,
  ServiceAccountKeyResponse,
  ServerImportResponse,
  SessionPublishRequest,
  SessionPublishResponse,
  SimulateRequestBody,
  SimulateRequestResponse,
  SsoClientKey,
  SsoClientKeyList,
  SsoTestResult,
  ThreatException,
  ThreatFeed,
  ThreatLookupResult,
  TLSBypassRule,
  User,
  UserInput,
  YaraResponse,
  YaraRuleSet,
} from '../types';

type Status = { status: string };

/** Diff references: a version number, 'published', 'draft' or 'empty'. */
export type DiffRef = number | 'published' | 'draft' | 'empty';

export const api = {
  // -------------------------------------------------------------------------
  // Operational / public
  // (data-plane endpoints /api/dataplane/* are worker-only and intentionally not wrapped;
  //  /metrics needs the Prometheus token)
  // -------------------------------------------------------------------------
  ops: {
    healthz: () => apiJSON<unknown>('/healthz'),
    readyz: () => apiJSON<{ status: string; revision: number; storage: string }>('/readyz'),
  },
  public: {
    meta: () => apiJSON<PublicMeta>('/api/public/meta'),
    caInfo: () => apiJSON<CAInfo>('/api/public/ca/info'),
    caDownloadUrl: (format: 'crt' | 'pem' | 'der') => apiUrl(`/api/public/ca/aegis-ca.${format}`),
    linuxInstallerUrl: () => apiUrl('/api/public/ca/install-linux.sh'),
    windowsInstallerUrl: () => apiUrl('/api/public/ca/install-windows.ps1'),
    /** 201 created / 200 duplicate pending */
    createRequest: (body: PublicAccessRequestBody) =>
      apiPost<{ message: string; request: Partial<AccessRequest> }>('/api/public/requests', body),
    /** Scopes / durations the self-service form offers for the server of a block token (or the caller's IP). */
    requestOptions: (bt?: string) => apiJSON<PublicRequestOptions>(`/api/public/request-options${qs({ bt })}`),
  },

  // -------------------------------------------------------------------------
  // Session
  // -------------------------------------------------------------------------
  auth: {
    login: (username: string, password: string) => apiPost<LoginResponse>('/api/auth/login', { username, password }),
    logout: () => apiPost<Status>('/api/auth/logout'),
    me: () => apiJSON<{ user: User; expires_at: string }>('/api/auth/me'),
    changePassword: (current_password: string, new_password: string) =>
      apiPost<Status>('/api/auth/password', { current_password, new_password }),
    /** Full-page navigation target that starts single sign-on; `next` is a local console path. */
    ssoLoginUrl: (next?: string) => apiUrl(`/api/auth/sso/login${qs({ next: next && next !== '/' ? next : undefined })}`),
  },

  // -------------------------------------------------------------------------
  // State & live data
  // -------------------------------------------------------------------------
  state: {
    get: (opts: { excludeFlows?: boolean } = {}) =>
      apiJSON<DashboardState>(`/api/state${opts.excludeFlows ? '?exclude_flows=1' : ''}`),
    flowStreamUrl: () => apiUrl('/api/flows/stream'),
  },
  simulate: {
    request: (body: SimulateRequestBody) => apiPost<SimulateRequestResponse>('/api/simulate/request', body),
  },
  rules: {
    /** Effective (compiled) rules. */
    list: () => apiJSON<PolicyRule[]>('/api/rules'),
  },

  // -------------------------------------------------------------------------
  // Policy sets & change management
  // -------------------------------------------------------------------------
  policySets: {
    list: () => apiJSON<PolicySet[]>('/api/policy-sets'),
    get: (id: string) => apiJSON<PolicySetDetail>(`/api/policy-sets/${seg(id)}`),
    /** Creates a set whose content is in `draft` (version 0). */
    create: (kind: Exclude<PolicySetKind, 'approvals'>, spec: PolicySetSpecInput) =>
      apiPost<PolicySet>('/api/policy-sets', { kind, spec }),
    remove: (id: string, reason: string) => apiDelete<Status>(`/api/policy-sets/${seg(id)}${qs({ reason })}`),
    /** Replaces the draft (send rule ids back unchanged). 400 while in review. */
    saveDraft: (id: string, spec: PolicySetSpecInput) => apiPut<PolicySet>(`/api/policy-sets/${seg(id)}/draft`, { spec }),
    discardDraft: (id: string) => apiDelete<Status>(`/api/policy-sets/${seg(id)}/draft`),
    /** 409 when four-eyes review is required (unless emergency by a Super Admin, comment >= 10 chars). */
    publish: (id: string, body: { comment: string; emergency?: boolean }) =>
      apiPost<PolicySet>(`/api/policy-sets/${seg(id)}/publish`, { emergency: false, ...body }),
    submit: (id: string, body: { title: string; description: string }) =>
      apiPost<ChangeRequest>(`/api/policy-sets/${seg(id)}/submit`, body),
    /** Impact against recorded traffic; default spec: draft, else published. */
    simulate: (id: string, spec?: PolicySetSpecInput) =>
      apiPost<ImpactSummary>(`/api/policy-sets/${seg(id)}/simulate`, spec ? { spec } : {}),
    diff: (id: string, from?: DiffRef, to?: DiffRef) =>
      apiJSON<PolicyDiff>(`/api/policy-sets/${seg(id)}/diff${qs({ from, to })}`),
    versions: (id: string) => apiJSON<PolicySetVersionSummary[]>(`/api/policy-sets/${seg(id)}/versions`),
    version: (id: string, version: number) =>
      apiJSON<PolicySetVersion>(`/api/policy-sets/${seg(id)}/versions/${version}`),
    /** Published directly, or prepared as a draft when review is required (`published: false`). */
    rollback: (id: string, version: number, comment: string) =>
      apiPost<{ policy_set: PolicySet; published: boolean }>(`/api/policy-sets/${seg(id)}/rollback`, {
        version,
        comment,
      }),
    recertify: (id: string, comment: string) => apiPost<PolicySet>(`/api/policy-sets/${seg(id)}/recertify`, { comment }),
    /** Policy as code: published content of all (or the given) sets as a JSON bundle download. */
    exportUrl: (ids: string[] = []) => apiUrl(`/api/policy-sets/export${ids.length ? `?${ids.map((id) => `id=${encodeURIComponent(id)}`).join('&')}` : ''}`),
    exportBundle: () => apiJSON<PolicySetBundle>('/api/policy-sets/export'),
    /**
     * Plans (dry run) or applies a bundle; changes land in drafts. All-or-nothing: 422 with per-set
     * results (thrown as ApiError, results in err.data.results).
     */
    importBundle: (bundle: PolicySetBundle, dryRun: boolean) =>
      apiPost<PolicySetImportResponse>('/api/policy-sets/import', { dry_run: dryRun, bundle }),
  },
  changeRequests: {
    list: (status?: string) => apiJSON<ChangeRequest[]>(`/api/change-requests${qs({ status })}`),
    get: (id: string) => apiJSON<ChangeRequest>(`/api/change-requests/${seg(id)}`),
    /** Approval publishes. 409 + `change_request` when superseded. */
    review: (id: string, decision: ReviewDecision, comment: string) =>
      apiPost<ChangeRequest>(`/api/change-requests/${seg(id)}/review`, { decision, comment }),
    withdraw: (id: string) => apiPost<Status>(`/api/change-requests/${seg(id)}/withdraw`),
  },
  governance: {
    get: () => apiJSON<GovernanceSettings>('/api/settings/governance'),
    update: (g: GovernanceSettings) => apiPut<GovernanceSettings>('/api/settings/governance', g),
  },

  // -------------------------------------------------------------------------
  // Access requests
  // -------------------------------------------------------------------------
  requests: {
    review: (id: string, body: ReviewAccessRequestBody) =>
      apiPost<{ request: AccessRequest; rule: PolicyRule | null; rules: PolicyRule[] }>(
        `/api/requests/${seg(id)}/review`,
        body
      ),
    bulkReview: (ids: string[], approve: boolean, comment: string) =>
      apiPost<{ results: BulkReviewResult[] }>('/api/requests/bulk-review', { ids, approve, comment }),
    comment: (id: string, text: string) => apiPost<AccessRequest>(`/api/requests/${seg(id)}/comments`, { text }),
    /** assignee = username, '' unassigns */
    assign: (id: string, assignee: string) => apiPost<AccessRequest>(`/api/requests/${seg(id)}/assign`, { assignee }),
    extend: (id: string, duration: AccessDuration) =>
      apiPost<AccessRequest>(`/api/requests/${seg(id)}/extend`, { duration }),
    revoke: (id: string, reason: string) => apiPost<AccessRequest>(`/api/requests/${seg(id)}/revoke`, { reason }),
  },

  // -------------------------------------------------------------------------
  // Learning sessions
  // -------------------------------------------------------------------------
  sessions: {
    start: (body: {
      name: string;
      description: string;
      server_id: string;
      duration_minutes: number;
      mode: LearningSession['mode'];
    }) => apiPost<LearningSession>('/api/sessions', body),
    stop: (id: string) => apiPost<LearningSession>(`/api/sessions/${seg(id)}/stop`),
    publish: (id: string, body: SessionPublishRequest) =>
      apiPost<SessionPublishResponse>(`/api/sessions/${seg(id)}/publish`, body),
    /** Demo mode only: injects canned sample traffic. */
    simulateTraffic: (id: string, scenario: string) =>
      apiPost<{ recorded: number }>(`/api/sessions/${seg(id)}/simulate`, { scenario }),
  },

  // -------------------------------------------------------------------------
  // Fleet
  // -------------------------------------------------------------------------
  servers: {
    list: () => apiJSON<Server[]>('/api/servers'),
    /** Register / update (full replace: send labels, description, owner_team, group_ids ...). */
    upsert: (srv: Partial<Server> & { id: string; hostname: string }) => apiPost<Server>('/api/servers', srv),
    remove: (id: string) => apiDelete<Status>(`/api/servers/${seg(id)}`),
    rotateToken: (id: string) => apiPost<RotateTokenResponse>(`/api/servers/${seg(id)}/rotate-token`),
    quarantine: (id: string, quarantined: boolean, reason: string) =>
      apiPost<Server>(`/api/servers/${seg(id)}/quarantine`, { quarantined, reason }),
    effectivePolicy: (id: string) => apiJSON<EffectivePolicy>(`/api/servers/${seg(id)}/effective-policy`),
    discovered: () => apiJSON<DiscoveredSource[]>('/api/servers/discovered'),
    /** All-or-nothing; 422 with per-row errors (thrown as ApiError, rows in err.data.results). */
    importCsv: (csv: string, dryRun: boolean) =>
      apiPost<ServerImportResponse>('/api/servers/import', { dry_run: dryRun, csv }),
    importRows: (servers: Partial<Server>[], dryRun: boolean) =>
      apiPost<ServerImportResponse>('/api/servers/import', { dry_run: dryRun, servers }),
    exportUrl: (format: 'csv' | 'json' = 'csv') => apiUrl(`/api/servers/export${qs({ format })}`),
  },
  groups: {
    upsert: (g: Partial<ServerGroup> & { id: string; name: string }) => apiPost<ServerGroup>('/api/groups', g),
    remove: (id: string) => apiDelete<Status>(`/api/groups/${seg(id)}`),
  },

  // -------------------------------------------------------------------------
  // Block pages
  // -------------------------------------------------------------------------
  blockPages: {
    list: () => apiJSON<BlockPagesResponse>('/api/block-pages'),
    create: (t: Partial<BlockPageTemplate>) => apiPost<BlockPageTemplate>('/api/block-pages', t),
    update: (id: string, t: Partial<BlockPageTemplate>) => apiPut<BlockPageTemplate>(`/api/block-pages/${seg(id)}`, t),
    remove: (id: string) => apiDelete<Status>(`/api/block-pages/${seg(id)}`),
    /** Renders an unsaved template with sample data (use in <iframe sandbox srcdoc>). */
    preview: (template: Partial<BlockPageTemplate>, locale: string, variant: 'request' | 'threat') =>
      apiPost<BlockPagePreview>('/api/block-pages/preview', { template, locale, variant }),
    previewUrl: (id: string, opts: { locale?: string; variant?: 'request' | 'threat'; format?: 'html' | 'cli' } = {}) =>
      apiUrl(`/api/block-pages/${seg(id)}/preview${qs(opts)}`),
  },

  // -------------------------------------------------------------------------
  // Log export (SIEM destinations)
  // -------------------------------------------------------------------------
  exports: {
    /** InfoSec: destinations (secrets redacted), per-replica status and the type catalog. */
    list: () => apiJSON<ExportsResponse>('/api/integrations/exports'),
    /** Super Admin */
    create: (sink: Partial<ExportSink>) => apiPost<ExportSink>('/api/integrations/exports', sink),
    /** Super Admin. Empty secret / client_key_pem / header values keep the stored values. */
    update: (id: string, sink: Partial<ExportSink>) => apiPut<ExportSink>(`/api/integrations/exports/${seg(id)}`, sink),
    remove: (id: string) => apiDelete<Status>(`/api/integrations/exports/${seg(id)}`),
    /** Sends one synthetic audit record with the (possibly unsaved) configuration. */
    test: (sink: Partial<ExportSink>) => apiPost<{ ok: boolean; error?: string }>('/api/integrations/exports/test', sink),
  },

  // -------------------------------------------------------------------------
  // Other administration
  // -------------------------------------------------------------------------
  tlsBypass: {
    add: (rule: Partial<TLSBypassRule>) => apiPost<TLSBypassRule>('/api/tls-bypass', rule),
    toggle: (id: string, enabled: boolean) => apiPost<Status>(`/api/tls-bypass/${seg(id)}/toggle`, { enabled }),
    remove: (id: string) => apiDelete<Status>(`/api/tls-bypass/${seg(id)}`),
  },
  settings: {
    /** Single sign-on configuration (Super Admin). Returns the normalized config without the secret. */
    entra: (cfg: EntraIDConfig) => apiPost<EntraIDConfig>('/api/settings/entra', cfg),
    /** OIDC discovery + JWKS check for the submitted (or stored) issuer; failures come back as ok:false. */
    ssoTest: (cfg?: Partial<EntraIDConfig>) => apiPost<SsoTestResult>('/api/settings/sso/test', cfg ?? {}),
    /** private_key_jwt client keys (public parts; any role may list, Super Admins manage). */
    ssoClientKeys: () => apiJSON<SsoClientKeyList>('/api/settings/sso/client-keys'),
    /** First key becomes active, later keys are staged ("next") unless activate is set. */
    generateSsoClientKey: (alg: 'RS256' | 'ES256', activate = false) =>
      apiPost<{ key: SsoClientKey; jwks_uri: string }>('/api/settings/sso/client-keys', { alg, activate }),
    /** Rotation: the staged key signs from now on; the previous key is retired (published for the grace period). */
    activateSsoClientKey: (kid: string) => apiPost<{ key: SsoClientKey }>(`/api/settings/sso/client-keys/${seg(kid)}/activate`),
    deleteSsoClientKey: (kid: string) => apiDelete<Status>(`/api/settings/sso/client-keys/${seg(kid)}`),
    /** Download link (session cookie) of a key's self-signed certificate (Entra: Certificates & secrets → Upload). */
    ssoClientCertificateUrl: (kid?: string, format: 'pem' | 'cer' = 'pem') => apiUrl(`/api/settings/sso/client-certificate${qs({ kid, format })}`),
    /** SCIM provisioning status (InfoSec / Super Admin). */
    scim: () => apiJSON<ScimSettings>('/api/settings/scim'),
    /** Super Admin. */
    updateScim: (enabled: boolean) => apiPost<ScimSettings>('/api/settings/scim', { enabled }),
    /** Super Admin; the token is returned once. */
    createScimToken: (name: string, expiresAt?: string) => apiPost<ScimTokenIssued>('/api/settings/scim/tokens', { name, expires_at: expiresAt }),
    /** The previous token value stops working immediately. */
    rotateScimToken: (id: string) => apiPost<ScimTokenIssued>(`/api/settings/scim/tokens/${seg(id)}/rotate`),
    revokeScimToken: (id: string) => apiDelete<Status>(`/api/settings/scim/tokens/${seg(id)}`),
    notifications: (cfg: NotificationConfig) => apiPost<NotificationConfig>('/api/settings/notifications', cfg),
    testNotification: () => apiPost<{ status: string; logs: NotificationLog[] }>('/api/settings/notifications/test'),
  },
  audit: {
    verify: () => apiJSON<AuditVerifyResult>('/api/audit/verify'),
    exportUrl: () => apiUrl('/api/audit/export'),
    /** Super Admin: accepts the pending pre-2.1 prefix; count and last hash must match exactly (audited, raises an alert). */
    acceptLegacy: (legacyEvents: number, legacyHead: string) =>
      apiPost<AuditVerifyResult>('/api/audit/anchor/accept-legacy', { legacy_events: legacyEvents, legacy_head: legacyHead }),
  },
  users: {
    /** Super Admin. A temporary password is returned once for new local users. */
    upsert: (u: UserInput) => apiPost<{ user: User; temporary_password?: string }>('/api/users', u),
    remove: (id: string) => apiDelete<Status>(`/api/users/${seg(id)}`),
    resetPassword: (id: string) => apiPost<{ temporary_password: string }>(`/api/users/${seg(id)}/reset-password`),
  },
  security: {
    updatePolicy: (p: SecurityPolicy) => apiPost<SecurityPolicy>('/api/security/policy', p),
    upsertFeed: (f: Partial<ThreatFeed>) => apiPost<ThreatFeed>('/api/security/feeds', f),
    deleteFeed: (id: string) => apiDelete<Status>(`/api/security/feeds/${seg(id)}`),
    /** id omitted = refresh all */
    refreshFeeds: (id?: string) => apiPost<Status>('/api/security/feeds/refresh', id ? { id } : {}),
    addIndicator: (i: Partial<Indicator>) => apiPost<Indicator>('/api/security/indicators', i),
    deleteIndicator: (id: string) => apiDelete<Status>(`/api/security/indicators/${seg(id)}`),
    addException: (x: Partial<ThreatException>) => apiPost<ThreatException>('/api/security/exceptions', x),
    deleteException: (id: string) => apiDelete<Status>(`/api/security/exceptions/${seg(id)}`),
    ackEvent: (id: string) => apiPost<Status>(`/api/security/events/${seg(id)}/ack`),
    lookup: (value: string) => apiPost<ThreatLookupResult>('/api/security/lookup', { value }),
  },
  yara: {
    /** Rule sets plus the data-plane heartbeats (yara_status per worker). */
    list: () => apiJSON<YaraResponse>('/api/security/yara'),
    create: (rs: Partial<YaraRuleSet>) => apiPost<YaraRuleSet>('/api/security/yara', rs),
    update: (id: string, rs: Partial<YaraRuleSet>) => apiPut<YaraRuleSet>(`/api/security/yara/${seg(id)}`, rs),
    remove: (id: string) => apiDelete<Status>(`/api/security/yara/${seg(id)}`),
  },

  // -------------------------------------------------------------------------
  // Identity & integrations
  // -------------------------------------------------------------------------
  serviceAccounts: {
    /** InfoSec / Super Admin. */
    list: () => apiJSON<ServiceAccount[]>('/api/service-accounts'),
    /** Super Admin; the API key is returned once. */
    create: (input: ServiceAccountInput) => apiPost<ServiceAccountKeyResponse>('/api/service-accounts', input),
    update: (id: string, input: ServiceAccountInput) => apiPut<ServiceAccount>(`/api/service-accounts/${seg(id)}`, input),
    /** The previous key stops working immediately. */
    rotate: (id: string) => apiPost<ServiceAccountKeyResponse>(`/api/service-accounts/${seg(id)}/rotate`),
    remove: (id: string) => apiDelete<Status>(`/api/service-accounts/${seg(id)}`),
  },
  defender: {
    /** InfoSec / Super Admin (can_edit: Super Admin). */
    get: () => apiJSON<DefenderResponse>('/api/integrations/defender'),
    /** Super Admin. Empty client_secret keeps the stored one. */
    update: (cfg: DefenderConfig) => apiPut<DefenderConfig>('/api/integrations/defender', cfg),
    /** Checks credentials and permissions (indicators + devices) with the submitted or stored config. */
    test: (cfg?: Partial<DefenderConfig>) => apiPost<DefenderTestResult>('/api/integrations/defender/test', cfg ?? {}),
    /** Device sync now (502 with the Defender error), then refreshes the indicator feed. */
    sync: () => apiPost<{ config: DefenderConfig }>('/api/integrations/defender/sync'),
  },
  system: {
    /** InfoSec / Super Admin. */
    posture: () => apiJSON<PostureReport>('/api/system/posture'),
  },

  // -------------------------------------------------------------------------
  // Package firewall (3.0) — /api/packages/*
  // Reads: any signed-in role. Writes (settings, rules, blocks, approvals,
  // decisions, reanalyze): InfoSec Approver or Super Admin (`canManageSystem`).
  // -------------------------------------------------------------------------
  packages: {
    /** Ecosystem modes, counts, sandbox worker status, recent decisions and the current settings. */
    overview: () => apiJSON<PackagesOverview>('/api/packages/overview'),
    settings: {
      /** Replaces PackageSettings. Advisory-source tokens are write-only (sent only when typed). */
      update: (s: PackageSettings) => apiPost<PackageSettings>('/api/packages/settings', s),
    },
    rules: {
      list: () => apiJSON<{ rules: PackageRule[] }>('/api/packages/rules').then((r) => r.rules ?? []),
      create: (r: Partial<PackageRule>) => apiPost<PackageRule>('/api/packages/rules', r),
      update: (id: string, r: Partial<PackageRule>) => apiPut<PackageRule>(`/api/packages/rules/${seg(id)}`, r),
      delete: (id: string) => apiDelete<Status>(`/api/packages/rules/${seg(id)}`),
      toggle: (id: string, enabled: boolean) => apiPost<PackageRule>(`/api/packages/rules/${seg(id)}/toggle`, { enabled }),
    },
    blocks: {
      list: () => apiJSON<{ blocks: PackageBlock[] }>('/api/packages/blocks').then((r) => r.blocks ?? []),
      add: (b: Partial<PackageBlock>) => apiPost<PackageBlock>('/api/packages/blocks', b),
      delete: (id: string) => apiDelete<Status>(`/api/packages/blocks/${seg(id)}`),
    },
    approvals: {
      /** Paged, newest first. Returns `{ approvals, cursor? }`. */
      list: (params: { ecosystem?: string; status?: string; q?: string; cursor?: string } = {}) =>
        apiJSON<PackageApprovalsPage>(`/api/packages/approvals${qs(params)}`),
      get: (id: string) => apiJSON<PackageApprovalDetail>(`/api/packages/approvals/${seg(id)}`),
      revoke: (id: string, reason: string) => apiPost<PackageApproval>(`/api/packages/approvals/${seg(id)}/revoke`, { reason }),
      /** `expires_at`: RFC 3339, or '' to make the approval permanent. */
      extend: (id: string, expires_at: string) => apiPost<PackageApproval>(`/api/packages/approvals/${seg(id)}/extend`, { expires_at }),
    },
    requests: {
      list: (params: { status?: string; ecosystem?: string; mine?: boolean } = {}) =>
        apiJSON<{ requests: PackageRequest[] }>(`/api/packages/requests${qs(params)}`).then((r) => r.requests ?? []),
      /** One request with the full resolved graph and per-node assessment. */
      get: (id: string) => apiJSON<{ request: PackageRequest }>(`/api/packages/requests/${seg(id)}`).then((r) => r.request),
      /** Opens a request; resolution + analysis start asynchronously. */
      create: (body: PackageRequestInput) => apiPost<PackageRequest>('/api/packages/requests', body),
      /** Review; approve creates the graph's approvals. */
      decide: (id: string, body: PackageDecisionInput) => apiPost<PackageRequest>(`/api/packages/requests/${seg(id)}/decision`, body),
      /** Re-run resolution + analysis (new advisories / rules). */
      reanalyze: (id: string) => apiPost<PackageRequest>(`/api/packages/requests/${seg(id)}/reanalyze`),
    },
    /** Live assessment preview for the request wizard (no request is created). */
    lookup: (params: { ecosystem: string; name: string; version?: string }) =>
      apiJSON<PackageLookupResult>(`/api/packages/lookup${qs(params)}`),
    analysis: {
      /** The full sandbox report of one analysis (URLs, syscalls, processes, files, findings). */
      get: (jobId: string) => apiJSON<SandboxReport>(`/api/packages/analysis/${seg(jobId)}`),
    },
    /** Which servers obtained a package — backed by the `package` field on flow telemetry. */
    receivers: (params: { ecosystem: string; name: string; version?: string; sha256?: string }) =>
      apiJSON<PackageReceiversResponse>(`/api/packages/receivers${qs(params)}`),
  },
};

export type Api = typeof api;
