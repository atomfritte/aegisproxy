import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Link2,
  Lock,
  Plus,
  PlugZap,
  Siren,
  Trash2,
  UserCog,
  Users,
  XCircle,
} from 'lucide-react';
import { api, publicBaseUrl } from '../../../api';
import { useConsole, useConsoleState, usePermissions } from '../../../data/AppData';
import { ROLE_LABELS } from '../../../data/permissions';
import { useSession } from '../../../data/session';
import { cn } from '../../../lib/cn';
import { Link, useNavigationBlocker } from '../../../lib/router';
import type { EntraIDConfig, Role, SsoProvider, SsoTestResult, TokenAuthMethod } from '../../../types';
import {
  Badge,
  Button,
  Callout,
  Card,
  CardHeader,
  CopyButton,
  Field,
  HelpTip,
  IconButton,
  Input,
  MultiSelect,
  RadioCards,
  RelativeTime,
  Select,
  StatusChip,
  Switch,
  TagInput,
  useToast,
} from '../../../ui';
import { ProviderLogo } from '../../../components/common/ProviderLogo';
import { SecretField } from '../../../components/common/Secrets';
import { ScimCard } from './ScimCard';
import { SaveBar, SectionTitle } from './shared';
import { SsoClientKeysPanel } from './SsoClientKeysPanel';

const ROLES: Role[] = ['SUPER_ADMIN', 'INFOSEC_APPROVER', 'TEAM_LEAD_APPROVER', 'OPERATOR_AUDITOR'];
const DEFAULT_SCOPES = ['openid', 'profile', 'email'];
const CLAIM_RE = /^[A-Za-z0-9_.:/-]{1,128}$/;
const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
type TokenAuth = TokenAuthMethod;
const TOKEN_AUTH: TokenAuth[] = ['', 'client_secret_post', 'client_secret_basic', 'private_key_jwt'];

interface Form {
  enabled: boolean;
  provider: SsoProvider;
  display_name: string;
  tenant_id: string;
  client_id: string;
  client_secret: string;
  token_auth_method: TokenAuth;
  issuer_url: string;
  redirect_uri: string;
  scopes: string[];
  username_claim: string;
  groups_claim: string;
  roles: Array<{ group: string; role: Role }>;
  scopesMap: Array<{ group: string; groups: string[] }>;
  allow_local_login: boolean;
}

function toForm(c: EntraIDConfig | undefined): Form {
  return {
    enabled: !!c?.enabled,
    provider: c?.provider === 'oidc' ? 'oidc' : 'entra',
    display_name: c?.display_name ?? '',
    tenant_id: c?.tenant_id ?? '',
    client_id: c?.client_id ?? '',
    client_secret: '',
    token_auth_method: TOKEN_AUTH.includes(c?.token_auth_method ?? '') ? (c?.token_auth_method ?? '') : '',
    issuer_url: c?.issuer_url ?? '',
    redirect_uri: c?.redirect_uri ?? '',
    scopes: c?.scopes?.length ? [...c.scopes] : [],
    username_claim: c?.username_claim ?? '',
    groups_claim: c?.groups_claim ?? '',
    roles: Object.entries(c?.group_role_map ?? {}).map(([group, role]) => ({ group, role })),
    scopesMap: Object.entries(c?.group_scope_map ?? {}).map(([group, groups]) => ({ group, groups: [...(groups ?? [])] })),
    allow_local_login: c ? c.allow_local_login : true,
  };
}

function toPayload(f: Form): EntraIDConfig {
  const roles: Record<string, Role> = {};
  for (const r of f.roles) if (r.group.trim()) roles[r.group.trim()] = r.role;
  const scopes: Record<string, string[]> = {};
  for (const s of f.scopesMap) if (s.group.trim()) scopes[s.group.trim()] = [...s.groups];
  const out: EntraIDConfig = {
    enabled: f.enabled,
    provider: f.provider,
    display_name: f.display_name.trim(),
    tenant_id: f.provider === 'entra' ? f.tenant_id.trim() : '',
    client_id: f.client_id.trim(),
    token_auth_method: f.token_auth_method,
    issuer_url: f.issuer_url.trim(),
    redirect_uri: f.redirect_uri.trim(),
    scopes: f.scopes.length ? [...f.scopes] : null,
    username_claim: f.username_claim.trim(),
    groups_claim: f.groups_claim.trim(),
    group_role_map: roles,
    group_scope_map: scopes,
    allow_local_login: f.allow_local_login,
  };
  if (f.client_secret && f.token_auth_method !== 'private_key_jwt') out.client_secret = f.client_secret;
  return out;
}

/** Comparable form without the write-only secret. */
const fingerprint = (f: Form) => JSON.stringify({ ...toPayload(f), client_secret: undefined });

const entraIssuer = (tenant: string) => `https://login.microsoftonline.com/${tenant || '<tenant-id>'}/v2.0`;

function validate(f: Form) {
  const e: Partial<Record<'tenant_id' | 'client_id' | 'issuer_url' | 'redirect_uri' | 'roles' | 'username_claim' | 'groups_claim' | 'client_secret', string>> = {};
  if (f.provider === 'entra' && f.tenant_id.trim() && !GUID_RE.test(f.tenant_id.trim()))
    e.tenant_id = 'The Directory (tenant) ID is a GUID such as 72f988bf-86f1-41af-91ab-2d7cd011db47 — domain names are not accepted.';
  if (f.enabled && f.provider === 'entra' && !f.tenant_id.trim() && !f.issuer_url.trim()) e.tenant_id = 'Required to enable single sign-on.';
  if (f.enabled && !f.client_id.trim()) e.client_id = 'Required to enable single sign-on.';
  const iss = f.issuer_url.trim();
  if (iss && !/^https:\/\/[^\s/?#]+[^\s?#]*$/i.test(iss) && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(\/[^\s?#]*)?$/i.test(iss))
    e.issuer_url = 'An https:// URL without query string, e.g. https://idp.corp.example/realms/aegis.';
  if (f.enabled && f.provider === 'oidc' && !iss) e.issuer_url = 'Required for generic OpenID Connect providers.';
  const ru = f.redirect_uri.trim();
  if (ru && !/\/api\/auth\/sso\/callback$/.test(ru.split('?')[0])) e.redirect_uri = 'Must end with /api/auth/sso/callback (https, or http on localhost).';
  if (f.enabled && f.roles.filter((r) => r.group.trim()).length === 0) e.roles = 'Map at least one IdP group to a role — users without a mapped group cannot sign in.';
  if (f.username_claim.trim() && !CLAIM_RE.test(f.username_claim.trim())) e.username_claim = 'Letters, digits and . _ : / - only.';
  if (f.groups_claim.trim() && !CLAIM_RE.test(f.groups_claim.trim())) e.groups_claim = 'Letters, digits and . _ : / - only.';
  if (/[\r\n]/.test(f.client_secret)) e.client_secret = 'The secret must be a single line.';
  return e;
}

/** Settings → Single sign-on: OpenID Connect (Entra ID or any OIDC IdP), role mapping, break-glass. */
export const SsoSection: React.FC = () => {
  const state = useConsoleState();
  const { refresh } = useConsole();
  const perms = usePermissions();
  const { meta } = useSession();
  const toast = useToast();
  const ro = !perms.isSuperAdmin;
  const stored = state.entra_config;
  const serverKey = JSON.stringify(stored);
  const base = useMemo(() => toForm(stored), [serverKey]); // eslint-disable-line react-hooks/exhaustive-deps
  const [f, setF] = useState<Form>(base);
  const [saving, setSaving] = useState(false);
  const [attempted, setAttempted] = useState(false);
  const [testing, setTesting] = useState(false);
  const [test, setTest] = useState<(SsoTestResult & { at: number }) | null>(null);
  const [advanced, setAdvanced] = useState(false);
  const [savedAt, setSavedAt] = useState(0);
  const dirty = fingerprint(f) !== fingerprint(base) || !!f.client_secret;
  // adopt server changes (refresh, other admins) unless the form has local edits
  const prevBase = useRef(base);
  useEffect(() => {
    if (fingerprint(f) === fingerprint(prevBase.current) && !f.client_secret) setF(base);
    prevBase.current = base;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [base]);
  useNavigationBlocker(dirty && !ro, 'Discard unsaved single sign-on settings?');

  const set = (p: Partial<Form>) => setF((x) => ({ ...x, ...p }));
  const errors = validate(f);
  const invalid = Object.values(errors).some(Boolean);
  const err = (k: keyof typeof errors) => (attempted || k === 'tenant_id' || k === 'issuer_url' || k === 'redirect_uri' ? errors[k] : undefined);
  const advancedInvalid = !!(errors.redirect_uri || errors.username_claim || errors.groups_claim || (f.provider === 'entra' && errors.issuer_url));
  const showAdvanced = advanced || advancedInvalid;

  const publicUrl = publicBaseUrl(meta?.public_url);
  const defaultRedirect = `${publicUrl}/api/auth/sso/callback`;
  const redirect = f.redirect_uri.trim() || defaultRedirect;
  const effectiveIssuer = f.issuer_url.trim() || (f.provider === 'entra' ? entraIssuer(f.tenant_id.trim()) : '');
  const label = f.display_name.trim() || (f.provider === 'entra' ? 'Microsoft Entra ID' : 'Single sign-on');

  const users = state.users ?? [];
  const breakGlass = users.filter((u) => u.break_glass);
  const usableBreakGlass = breakGlass.filter((u) => !u.disabled && u.role === 'SUPER_ADMIN' && u.auth_provider === 'local');
  const ssoUsers = users.filter((u) => u.auth_provider === 'oidc');
  const groupOptions = state.groups.map((g) => ({ value: g.id, label: g.name, color: g.color, description: g.id }));
  const dupRoles = f.roles.map((r) => r.group.trim()).filter((g, i, a) => g && a.indexOf(g) !== i);

  const save = async () => {
    setAttempted(true);
    if (invalid) return;
    setSaving(true);
    try {
      await api.settings.entra(toPayload(f));
      await refresh();
      setF((x) => ({ ...x, client_secret: '' }));
      setSavedAt(Date.now());
      setAttempted(false);
      toast.success(f.enabled ? `Single sign-on saved — “Sign in with ${label}” is live` : 'Single sign-on settings saved');
    } catch (e) {
      toast.error(e, { title: 'Single sign-on settings not saved' });
    } finally {
      setSaving(false);
    }
  };

  const runTest = async () => {
    setTesting(true);
    try {
      const r = await api.settings.ssoTest({
        provider: f.provider,
        tenant_id: f.provider === 'entra' ? f.tenant_id.trim() : '',
        issuer_url: effectiveIssuer.includes('<tenant-id>') ? '' : effectiveIssuer,
        client_id: f.client_id.trim(),
        redirect_uri: f.redirect_uri.trim(),
        token_auth_method: f.token_auth_method,
      });
      setTest({ ...r, at: Date.now() });
    } catch (e) {
      setTest({ ok: false, issuer: effectiveIssuer, error: e instanceof Error ? e.message : String(e), at: Date.now() });
    } finally {
      setTesting(false);
    }
  };

  const status = stored?.enabled ? (
    <StatusChip tone="success" label="Enabled" />
  ) : (
    <StatusChip tone="neutral" label="Not enabled" />
  );

  return (
    <>
      <SectionTitle
        title="Single sign-on"
        description="Let administrators sign in with your identity provider over OpenID Connect — Microsoft Entra ID or any OIDC provider such as Okta, Keycloak, Ping or ADFS. MFA and conditional access stay with the IdP; console roles follow IdP groups."
        actions={status}
      />
      <div className="grid items-start gap-5 2xl:grid-cols-[minmax(0,1fr)_340px]">
        <div className="min-w-0 space-y-5">
          {ro && (
            <Callout tone="neutral" icon={Lock}>
              Only Super Admins can change single sign-on: whoever controls the group mapping controls who becomes an administrator.
            </Callout>
          )}

          <fieldset disabled={ro} className="min-w-0 space-y-5">
            <Card>
              <CardHeader icon={Link2} title="Identity provider" description="The application you register in the IdP for AegisProxy." divider />
              <div className="space-y-5 p-[var(--card-p)]">
                <Switch
                  checked={f.enabled}
                  onChange={(v) => set({ enabled: v })}
                  label="Enable single sign-on"
                  description={`The sign-in page shows “Sign in with ${label}”. Users are created on their first sign-in.`}
                />
                <RadioCards<SsoProvider>
                  aria-label="Identity provider type"
                  className="sm:grid-cols-2"
                  value={f.provider}
                  onChange={(v) => set({ provider: v })}
                  options={[
                    { value: 'entra', title: 'Microsoft Entra ID', description: 'Azure AD app registration; issuer derived from the tenant.' },
                    { value: 'oidc', title: 'Generic OpenID Connect', description: 'Okta, Keycloak, Ping, ADFS, Google Workspace, Auth0 …' },
                  ]}
                />
                <div className="grid gap-4 md:grid-cols-2">
                  {f.provider === 'entra' ? (
                    <Field label="Directory (tenant) ID" required={f.enabled} error={err('tenant_id')} hint="A GUID: Entra admin center → Overview → Tenant ID.">
                      <Input mono value={f.tenant_id} onChange={(e) => set({ tenant_id: e.target.value })} placeholder="00000000-0000-0000-0000-000000000000" spellCheck={false} />
                    </Field>
                  ) : (
                    <Field label="Issuer URL" required={f.enabled} error={err('issuer_url')} hint="Discovery is read from <issuer>/.well-known/openid-configuration.">
                      <Input mono value={f.issuer_url} onChange={(e) => set({ issuer_url: e.target.value })} placeholder="https://idp.corp.example/realms/aegis" spellCheck={false} />
                    </Field>
                  )}
                  <Field label="Application (client) ID" required={f.enabled} error={err('client_id')}>
                    <Input mono value={f.client_id} onChange={(e) => set({ client_id: e.target.value })} placeholder={f.provider === 'entra' ? '00000000-0000-0000-0000-000000000000' : 'aegisproxy-console'} spellCheck={false} />
                  </Field>
                  {f.token_auth_method === 'private_key_jwt' ? (
                    <Field label="Client secret" hint="Not used: the control plane authenticates with a JWT signed by its client key (below).">
                      <div className="flex min-h-[var(--control-h)] items-center gap-2 rounded-md border border-border bg-surface-2 px-3 text-[13px] text-fg-muted">
                        <Lock className="h-4 w-4 shrink-0" aria-hidden />
                        {stored?.has_client_secret ? 'A stored secret is kept but never sent' : 'No secret needed'}
                      </div>
                    </Field>
                  ) : (
                    <SecretField
                      label="Client secret"
                      stored={!!stored?.has_client_secret}
                      value={f.client_secret}
                      onChange={(v) => set({ client_secret: v })}
                      error={err('client_secret')}
                      resetKey={savedAt}
                      disabled={ro}
                      optional={!stored?.has_client_secret}
                      hint={stored?.has_client_secret ? 'Stored encrypted and never shown. Replace it before it expires in the IdP.' : 'Confidential (web) clients need one. Sign-in also uses PKCE. Write-only.'}
                    />
                  )}
                  <Field
                    label="Client authentication"
                    hint={
                      f.token_auth_method === 'client_secret_basic'
                        ? 'Secret sent in the Authorization header (required by e.g. Okta web apps).'
                        : f.token_auth_method === 'client_secret_post'
                          ? 'Secret sent in the token request body.'
                          : f.token_auth_method === 'private_key_jwt'
                            ? 'Signed client assertion (RFC 7523) — no shared secret. Entra ID: certificate credential; Keycloak/Okta: JWKS URL.'
                            : 'Uses client_secret_post when the IdP advertises it, otherwise client_secret_basic.'
                    }
                  >
                    <Select
                      value={f.token_auth_method}
                      onChange={(e) => set({ token_auth_method: e.target.value as TokenAuth })}
                      options={[
                        { value: '', label: 'Automatic' },
                        { value: 'client_secret_post', label: 'client_secret_post (request body)' },
                        { value: 'client_secret_basic', label: 'client_secret_basic (HTTP Basic)' },
                        { value: 'private_key_jwt', label: 'private_key_jwt (signed JWT, no secret)' },
                      ]}
                    />
                  </Field>
                  <Field label="Button label" optional hint={`Shown as “Sign in with ${label}”.`}>
                    <Input value={f.display_name} onChange={(e) => set({ display_name: e.target.value })} placeholder={f.provider === 'entra' ? 'Microsoft Entra ID' : 'Corporate SSO'} maxLength={80} />
                  </Field>
                </div>

                {f.token_auth_method === 'private_key_jwt' && <SsoClientKeysPanel provider={f.provider} ro={ro} inUse={stored?.token_auth_method === 'private_key_jwt'} />}

                <div>
                  <div className="mb-1.5 flex items-center gap-1.5">
                    <span className="label">Redirect URI</span>
                    <HelpTip content="Register exactly this URI in the IdP application (platform: Web). The IdP sends users back here after sign-in." />
                  </div>
                  <div className={cn('flex items-center gap-1 rounded-md border py-1 pl-3 pr-1', errors.redirect_uri ? 'border-danger-border bg-danger-soft' : 'border-border bg-surface-2')}>
                    <code className="min-w-0 flex-1 font-mono text-[12.5px] text-fg [overflow-wrap:anywhere]" data-testid="sso-redirect-uri">
                      {redirect}
                    </code>
                    <CopyButton text={redirect} label="Copy redirect URI" />
                  </div>
                  {errors.redirect_uri && <p className="mt-1.5 text-[12px] text-danger">{errors.redirect_uri} Fix it under Advanced or clear it to use the default.</p>}
                </div>

                <button
                  type="button"
                  onClick={() => setAdvanced((v) => !v)}
                  aria-expanded={showAdvanced}
                  className="flex items-center gap-1.5 text-[13px] font-medium text-accent hover:underline"
                >
                  {showAdvanced ? <ChevronDown className="h-4 w-4" aria-hidden /> : <ChevronRight className="h-4 w-4" aria-hidden />}
                  Advanced: issuer, redirect URI, scopes and claims
                </button>
                {showAdvanced && (
                  <div className="grid gap-4 rounded-lg border border-border bg-surface-2 p-4 md:grid-cols-2">
                    {f.provider === 'entra' && (
                      <Field label="Issuer URL" optional error={err('issuer_url')} hint={`Default ${entraIssuer(f.tenant_id.trim())}`}>
                        <Input mono value={f.issuer_url} onChange={(e) => set({ issuer_url: e.target.value })} placeholder={entraIssuer(f.tenant_id.trim())} spellCheck={false} />
                      </Field>
                    )}
                    <Field label="Redirect URI override" optional error={err('redirect_uri')} hint="Leave empty to use the public URL of the control plane.">
                      <Input mono value={f.redirect_uri} onChange={(e) => set({ redirect_uri: e.target.value })} placeholder={defaultRedirect} spellCheck={false} />
                    </Field>
                    <Field label="Scopes" optional hint="Default openid profile email. Press Enter after each scope.">
                      <TagInput value={f.scopes} onChange={(v) => set({ scopes: v })} mono placeholder={DEFAULT_SCOPES.join(' ')} validate={(t) => (CLAIM_RE.test(t) ? null : `“${t}” is not a valid scope`)} suggestions={['openid', 'profile', 'email', 'offline_access', 'groups']} max={20} />
                    </Field>
                    <Field label="Username claim" optional error={err('username_claim')} hint="Default preferred_username (UPNs become user.name).">
                      <Input mono value={f.username_claim} onChange={(e) => set({ username_claim: e.target.value })} placeholder="preferred_username" spellCheck={false} />
                    </Field>
                    <Field label="Groups claim" optional error={err('groups_claim')} hint={f.provider === 'entra' ? 'Default groups. Use roles for Entra app roles.' : 'Default groups.'}>
                      <Input mono value={f.groups_claim} onChange={(e) => set({ groups_claim: e.target.value })} placeholder="groups" spellCheck={false} />
                    </Field>
                  </div>
                )}

                <div className="flex flex-col gap-3 border-t border-border pt-4 sm:flex-row sm:items-start">
                  <Button icon={PlugZap} loading={testing} onClick={runTest} disabled={f.provider === 'entra' ? !f.tenant_id.trim() && !f.issuer_url.trim() : !f.issuer_url.trim()}>
                    Test connection
                  </Button>
                  <p className="text-[12.5px] leading-5 text-fg-muted sm:pt-1.5">
                    Fetches the OpenID discovery document of <span className="font-mono text-fg [overflow-wrap:anywhere]">{effectiveIssuer || 'the issuer'}</span>. Nothing is sent to the IdP besides this request; nobody is signed in.
                  </p>
                </div>
                {test && (
                  <div aria-live="polite">
                    {test.ok ? (
                      <Callout tone={test.warnings?.length ? 'warning' : 'success'} icon={CheckCircle2} title="The identity provider is reachable">
                        The discovery document of <span className="font-mono [overflow-wrap:anywhere]">{test.issuer}</span> was loaded and its endpoints are valid. Register{' '}
                        <span className="font-mono [overflow-wrap:anywhere]">{test.redirect_uri || redirect}</span> as redirect URI, then sign in once in a private window to verify the group mapping.
                        {!!test.warnings?.length && (
                          <ul className="mt-1.5 list-disc pl-5 text-[12.5px] text-fg" data-testid="sso-test-warnings">
                            {test.warnings.map((w) => (
                              <li key={w}>{w}</li>
                            ))}
                          </ul>
                        )}
                      </Callout>
                    ) : (
                      <Callout tone="danger" icon={XCircle} title="The connection test failed" action={<Button size="sm" onClick={runTest} loading={testing}>Retry</Button>}>
                        <span className="block">The control plane could not load the OpenID configuration{test.issuer ? <> of <span className="font-mono [overflow-wrap:anywhere]">{test.issuer}</span></> : null}.</span>
                        <span className="mt-1 block font-mono text-[12px] text-fg [overflow-wrap:anywhere]" data-testid="sso-test-error">
                          {test.error || 'Unknown error'}
                        </span>
                        <span className="mt-1 block text-[12px]">Check the tenant ID or issuer URL, outbound HTTPS from the control plane (proxy, firewall) and the IdP certificate.</span>
                      </Callout>
                    )}
                  </div>
                )}
              </div>
            </Card>

            <Card>
              <CardHeader
                icon={UserCog}
                title="Role mapping"
                description="IdP groups that grant console roles. When a user is in several mapped groups, the most privileged role wins."
                divider
              />
              <div className="space-y-3 p-[var(--card-p)]">
                {f.roles.length === 0 && (
                  <p className="rounded-md border border-dashed border-border-strong px-3 py-3 text-[12.5px] text-fg-subtle">
                    No mappings yet. Users without a mapped group cannot sign in with single sign-on.
                  </p>
                )}
                {f.roles.map((r, i) => (
                  <div key={i} className="flex items-start gap-2">
                    <div className="min-w-0 flex-1">
                      <Input
                        mono
                        aria-label={`IdP group ${i + 1}`}
                        value={r.group}
                        placeholder={f.provider === 'entra' ? 'Group object ID or app role' : 'aegis-admins'}
                        aria-invalid={dupRoles.includes(r.group.trim()) || undefined}
                        onChange={(e) => set({ roles: f.roles.map((x, j) => (j === i ? { ...x, group: e.target.value } : x)) })}
                      />
                      {dupRoles.includes(r.group.trim()) && <p className="mt-1 text-[11.5px] text-danger">Mapped twice — only the last mapping is kept.</p>}
                    </div>
                    <Select
                      aria-label={`Role for IdP group ${i + 1}`}
                      className="w-[42%] max-w-[220px] shrink-0"
                      value={r.role}
                      onChange={(e) => set({ roles: f.roles.map((x, j) => (j === i ? { ...x, role: e.target.value as Role } : x)) })}
                      options={ROLES.map((x) => ({ value: x, label: ROLE_LABELS[x] }))}
                    />
                    {!ro && <IconButton icon={Trash2} label="Remove mapping" variant="danger-ghost" onClick={() => set({ roles: f.roles.filter((_, j) => j !== i) })} />}
                  </div>
                ))}
                {errors.roles && attempted && <p className="text-[12px] text-danger">{errors.roles}</p>}
                {!ro && (
                  <Button size="sm" variant="ghost" icon={Plus} onClick={() => set({ roles: [...f.roles, { group: '', role: 'OPERATOR_AUDITOR' }] })}>
                    Add mapping
                  </Button>
                )}

                <div className="border-t border-border pt-4">
                  <div className="mb-2 flex items-center gap-1.5">
                    <span className="label">Team Lead scopes</span>
                    <HelpTip content="Team Leads approve requests and edit policy sets only for these server groups. A user in several IdP groups gets the union." />
                  </div>
                  {f.scopesMap.length === 0 && <p className="mb-2 text-[12.5px] text-fg-subtle">No scope mappings — Team Leads from SSO cannot approve anything until one exists.</p>}
                  <div className="space-y-2">
                    {f.scopesMap.map((s, i) => (
                      <div key={i} className="flex flex-col gap-2 sm:flex-row sm:items-start">
                        <Input
                          mono
                          aria-label={`IdP group for scope ${i + 1}`}
                          className="sm:w-[40%]"
                          value={s.group}
                          placeholder="aegis-team-ci"
                          onChange={(e) => set({ scopesMap: f.scopesMap.map((x, j) => (j === i ? { ...x, group: e.target.value } : x)) })}
                        />
                        <div className="flex min-w-0 flex-1 items-start gap-2">
                          <MultiSelect
                            aria-label={`Server groups for scope ${i + 1}`}
                            className="min-w-0 flex-1"
                            value={s.groups}
                            onChange={(v) => set({ scopesMap: f.scopesMap.map((x, j) => (j === i ? { ...x, groups: v } : x)) })}
                            options={groupOptions}
                            placeholder="Server groups"
                            disabled={ro}
                          />
                          {!ro && <IconButton icon={Trash2} label="Remove scope mapping" variant="danger-ghost" onClick={() => set({ scopesMap: f.scopesMap.filter((_, j) => j !== i) })} />}
                        </div>
                      </div>
                    ))}
                  </div>
                  {!ro && (
                    <Button size="sm" variant="ghost" icon={Plus} className="mt-2" onClick={() => set({ scopesMap: [...f.scopesMap, { group: '', groups: [] }] })}>
                      Add scope mapping
                    </Button>
                  )}
                </div>
              </div>
            </Card>

            <Card>
              <CardHeader icon={Siren} title="Password sign-in and break-glass access" divider />
              <div className="space-y-4 p-[var(--card-p)]">
                <Switch
                  checked={f.allow_local_login}
                  onChange={(v) => set({ allow_local_login: v })}
                  label="Allow password sign-in for all local accounts"
                  description="Turn off once single sign-on works: only break-glass accounts may then use a password."
                />
                {!f.allow_local_login && (
                  <Callout tone={usableBreakGlass.length ? 'warning' : 'danger'} title={usableBreakGlass.length ? 'Password sign-in limited to break-glass accounts' : 'No usable break-glass account'}>
                    {usableBreakGlass.length
                      ? 'The sign-in page hides the password form behind “Use a local account”. Every break-glass sign-in is audited and raises a security alert.'
                      : 'Mark at least one active local Super Admin with a password as break-glass before disabling password sign-in — otherwise nobody can get in when the IdP is down.'}
                  </Callout>
                )}
                <div>
                  <div className="mb-2 flex items-center justify-between gap-2">
                    <span className="label">Break-glass accounts</span>
                    <Link to="/settings/identity" className="text-[12.5px] font-medium text-accent hover:underline">
                      Manage in Identity &amp; access
                    </Link>
                  </div>
                  {breakGlass.length === 0 ? (
                    <p className="text-[12.5px] text-fg-subtle">None yet. Edit a local Super Admin and turn on “Break-glass account”.</p>
                  ) : (
                    <ul className="divide-y divide-border rounded-md border border-border">
                      {breakGlass.map((u) => (
                        <li key={u.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-[13px]">
                          <span className="min-w-0 flex-1 truncate font-medium text-fg">
                            {u.display_name} <span className="font-normal text-fg-subtle">@{u.username}</span>
                          </span>
                          {u.disabled ? <StatusChip tone="danger" label="Disabled" /> : <StatusChip tone="success" label="Active" />}
                          <span className="text-[12px] text-fg-subtle">{u.last_login_at ? <RelativeTime value={u.last_login_at} prefix="last sign-in" /> : 'never signed in'}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            </Card>
          </fieldset>

          {perms.canManageSystem && <ScimCard provider={f.provider} mappedGroups={f.roles.filter((r) => r.group.trim()).length} />}

          {!ro && (
            <SaveBar
              dirty={dirty}
              saving={saving}
              onSave={save}
              onReset={() => {
                setF(base);
                setAttempted(false);
              }}
              note={attempted && invalid ? 'Fix the highlighted fields.' : undefined}
            />
          )}
        </div>

        <aside className="min-w-0 space-y-5 2xl:sticky 2xl:top-[72px]">
          <Card>
            <CardHeader title="Register the application" description="Copy this redirect URI into the IdP application (platform: Web)." />
            <div className="space-y-4 p-[var(--card-p)] pt-3">
              <div className="flex items-center gap-1 rounded-md border border-border bg-surface-2 py-1 pl-3 pr-1">
                <code className="min-w-0 flex-1 font-mono text-[12px] text-fg [overflow-wrap:anywhere]">{redirect}</code>
                <CopyButton text={redirect} label="Copy redirect URI" />
              </div>
              {f.provider === 'entra' ? (
                <ol className="list-decimal space-y-2 pl-5 text-[12.5px] leading-5 text-fg-muted marker:text-fg-subtle">
                  <li>
                    Entra admin center → <span className="text-fg">App registrations → New registration</span>, single tenant, redirect URI type <span className="text-fg">Web</span>.
                  </li>
                  <li>
                    <span className="text-fg">Certificates &amp; secrets</span>: create a client secret and paste it here (note its expiry) — or choose{' '}
                    <code className="font-mono text-fg">private_key_jwt</code> and upload the generated certificate instead (no secret).
                  </li>
                  <li>
                    <span className="text-fg">Token configuration → Add groups claim</span> (security groups, emit as group IDs) — or define app roles and set the groups claim to{' '}
                    <code className="font-mono text-fg">roles</code>.
                  </li>
                  <li>Copy the tenant ID and application (client) ID, map group object IDs to roles, test and enable.</li>
                </ol>
              ) : (
                <ol className="list-decimal space-y-2 pl-5 text-[12.5px] leading-5 text-fg-muted marker:text-fg-subtle">
                  <li>
                    Create a confidential OIDC client (Keycloak client, Okta web app, Ping application) with the authorization code flow and the redirect URI above.
                  </li>
                  <li>
                    Add a <code className="font-mono text-fg">groups</code> claim to the ID token (Keycloak: group membership mapper; Okta: groups claim filter).
                  </li>
                  <li>Paste the issuer URL, client ID and secret, map groups to roles, test and enable.</li>
                </ol>
              )}
            </div>
          </Card>
          <Card>
            <CardHeader icon={Users} title="Provisioning" />
            <ul className="space-y-2.5 p-[var(--card-p)] pt-3 text-[12.5px] leading-5 text-fg-muted">
              <li>
                <span className="font-medium text-fg">Just in time.</span> Accounts are created on the first sign-in; role and Team Lead scope are synchronized from the IdP groups at every sign-in.
              </li>
              <li>
                <span className="font-medium text-fg">SCIM.</span> With provisioning enabled, Entra ID or Okta create and deactivate accounts ahead of the first sign-in and push groups; roles follow
                the pushed groups and offboarding revokes sessions at once.
              </li>
              <li>
                <span className="font-medium text-fg">Deprovisioning without SCIM.</span> When a user loses every mapped group, the next sign-in attempt is denied and the console account is disabled. To
                revoke access immediately, disable the user in Identity &amp; access as well.
              </li>
              <li>
                <span className="font-medium text-fg">Local passwords.</span> SSO users have no password; only local accounts can use the password form.
              </li>
            </ul>
            <div className="flex flex-wrap items-center gap-2 border-t border-border px-[var(--card-p)] py-3 text-[12.5px]">
              <Badge tone="info">{ssoUsers.length}</Badge>
              <span className="text-fg-muted">{ssoUsers.length === 1 ? 'SSO account' : 'SSO accounts'}</span>
              {ssoUsers.some((u) => u.scim) && (
                <>
                  <Badge tone="violet">{ssoUsers.filter((u) => u.scim && !u.scim.deleted).length}</Badge>
                  <span className="text-fg-muted">managed by SCIM</span>
                </>
              )}
            </div>
          </Card>
          {stored?.enabled && (
            <Card>
              <div className="flex items-start gap-3 p-[var(--card-p)]">
                <ProviderLogo provider={stored.provider || 'entra'} className="mt-0.5 h-5 w-5" />
                <div className="min-w-0 text-[12.5px] leading-5 text-fg-muted">
                  <p className="font-medium text-fg">Sign-in page</p>
                  <p>
                    Shows “Sign in with {stored.display_name || (stored.provider === 'oidc' ? 'Single sign-on' : 'Microsoft Entra ID')}”
                    {stored.allow_local_login ? ' above the password form.' : '; the password form is reserved for break-glass accounts.'}
                  </p>
                </div>
              </div>
            </Card>
          )}
        </aside>
      </div>
    </>
  );
};

export const ssoSummaryLabel = (c?: EntraIDConfig | null) =>
  c?.display_name || (c?.provider === 'oidc' ? 'Single sign-on' : 'Microsoft Entra ID');

/** Small badge used in user lists: how the account signs in. */
export const AuthProviderBadge: React.FC<{ provider: string; className?: string }> = ({ provider, className }) =>
  provider === 'oidc' ? (
    <Badge tone="info" className={cn(className)}>
      SSO
    </Badge>
  ) : null;
