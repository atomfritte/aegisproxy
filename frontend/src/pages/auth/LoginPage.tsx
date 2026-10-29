import React, { useState } from 'react';
import { ChevronDown, ChevronRight, ExternalLink, KeyRound, LogIn, Siren, User as UserIcon } from 'lucide-react';
import { api } from '../../api';
import { useSession } from '../../data/session';
import { cn } from '../../lib/cn';
import { useDocumentTitle } from '../../lib/hooks';
import { navigate, useLocation, useSearchParams } from '../../lib/router';
import { LogoMark } from '../../shell/Logo';
import { buttonClass, Button, Callout, Field, Input, PatternText } from '../../ui';
import { ProviderLogo } from '../../components/common/ProviderLogo';

const DEMO_ACCOUNTS = [
  { u: 'admin', p: 'admin123', label: 'Super Admin' },
  { u: 'infosec', p: 'infosec123', label: 'InfoSec Approver' },
  { u: 'teamlead', p: 'teamlead123', label: 'Team Lead (CI, AI)' },
  { u: 'auditor', p: 'auditor123', label: 'Auditor (read-only)' },
];

// A few illustrative decisions for the brand panel (static, not live data).
const LEDGER = [
  { host: 'github.com', path: '/acme/**', verdict: 'Allowed', ok: true, from: 'ci-runner-fra01' },
  { host: 'pastebin.com', path: '/**', verdict: 'Blocked', ok: false, from: 'linux-app-312' },
  { host: 'download.pytorch.org', path: '/whl/cu124/**', verdict: 'Allowed', ok: true, from: 'gpu-node-04' },
  { host: '*.ngrok.io', path: '', verdict: 'Blocked', ok: false, from: 'win-erp-09' },
];

/** Friendly text for the `sso_error` codes of GET /api/auth/sso/callback. */
export function ssoErrorMessage(code: string): { title: string; text: string } {
  if (code.startsWith('idp_')) {
    const idp = code.slice(4);
    if (idp === 'access_denied')
      return { title: 'Sign-in was cancelled', text: 'The identity provider denied or cancelled the sign-in. Try again, or ask your administrator to assign you to the AegisProxy application.' };
    if (idp === 'consent_required' || idp === 'interaction_required')
      return { title: 'Consent or additional sign-in required', text: 'The identity provider needs consent or another sign-in step for AegisProxy. Ask your administrator to grant admin consent for the application.' };
    if (idp === 'login_required') return { title: 'Sign-in required', text: 'The identity provider asked you to sign in again. Start the single sign-on again.' };
    return { title: 'The identity provider reported an error', text: `The identity provider rejected the sign-in (${idp.replace(/_/g, ' ')}). Try again or contact your administrator.` };
  }
  switch (code) {
    case 'account_disabled':
      return { title: 'Your account is disabled', text: 'Your account was disabled by an administrator. Contact your AegisProxy administrator.' };
    case 'account_link':
      return {
        title: 'Your account could not be linked',
        text: 'An account was provisioned for your user name, but its identifier does not match your sign-in. Ask your administrator to map the SCIM externalId to your immutable user ID in the identity provider.',
      };
    case 'not_authorized':
      return {
        title: 'Your account has no AegisProxy role',
        text: 'You signed in successfully, but none of your groups is mapped to a console role. Ask your administrator to add you to a group that grants access.',
      };
    case 'group_overage':
      return {
        title: 'Too many groups in your token',
        text: 'Your account is in more groups than the identity provider puts into a token. Ask your administrator to assign groups to the application or to use app roles.',
      };
    case 'session':
      return { title: 'The sign-in expired', text: 'The sign-in took longer than 10 minutes or was started in another browser window. Please start again.' };
    case 'state':
      return { title: 'The sign-in could not be verified', text: 'The response did not match the sign-in that was started in this browser (possible tampering). Please start again.' };
    case 'disabled':
      return { title: 'Single sign-on is turned off', text: 'An administrator disabled single sign-on. Use your local account or contact your administrator.' };
    case 'configuration':
      return { title: 'Single sign-on is not configured correctly', text: 'The identity provider settings are incomplete or invalid. Contact your administrator.' };
    case 'provider_unreachable':
      return { title: 'The identity provider is unreachable', text: 'AegisProxy could not reach the identity provider. Try again in a moment.' };
    case 'token':
      return { title: 'The sign-in could not be completed', text: 'The identity provider did not accept the authorization code (for example a wrong client secret). Contact your administrator.' };
    case 'id_token':
      return { title: 'The identity token was rejected', text: 'The token from the identity provider failed validation (signature, audience or clock skew). Contact your administrator.' };
    case 'provisioning':
      return { title: 'Your console account could not be set up', text: 'Single sign-on succeeded, but the console account could not be created or is disabled. Contact your administrator.' };
    default:
      return { title: 'Single sign-on failed', text: 'The sign-in could not be completed. Try again or contact your administrator.' };
  }
}

/** Sign-in page: single sign-on (when configured) and local accounts; SSO error messages. */
export const LoginPage: React.FC = () => {
  useDocumentTitle('Sign in');
  const { meta, login, loggingIn, loginError } = useSession();
  const { pathname, search } = useLocation();
  const [params, setParams] = useSearchParams();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const ssoError = params.get('sso_error');
  const sso = meta?.sso?.enabled ? meta.sso : null;
  const localEnabled = meta ? meta.local_login_enabled : true;
  const [showLocal, setShowLocal] = useState(false);
  const localVisible = !sso || localEnabled || showLocal;
  // return to the requested page after single sign-on (local paths only; the server checks again)
  const next = pathname === '/login' || pathname === '/' ? '' : `${pathname}${search.replace(/([?&])sso_error=[^&]*&?/, '$1').replace(/[?&]$/, '')}`;
  const ssoHref = sso ? api.auth.ssoLoginUrl(next || undefined) : '';

  const submit = async (u: string, p: string) => {
    if (ssoError) setParams({ sso_error: null });
    const err = await login(u, p);
    if (!err) setPassword('');
  };

  const passwordForm = (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        submit(username, password);
      }}
    >
      <Field label="Username">
        <Input icon={UserIcon} required autoComplete="username" autoFocus={!sso} value={username} onChange={(e) => setUsername(e.target.value)} />
      </Field>
      <Field label="Password">
        <Input icon={KeyRound} type="password" required autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
      </Field>
      {loginError && (
        <Callout tone="danger" className="py-2.5">
          {loginError}
          {sso && /use single sign-on/i.test(loginError) && (
            <span className="mt-1 block text-[12px]">Use “Sign in with {sso.label || 'single sign-on'}” above unless you hold a break-glass account.</span>
          )}
        </Callout>
      )}
      <Button type="submit" variant={sso ? 'secondary' : 'primary'} size="lg" fullWidth loading={loggingIn} icon={LogIn}>
        {sso && !localEnabled ? 'Sign in with break-glass account' : 'Sign in'}
      </Button>
    </form>
  );

  return (
    <div className="flex min-h-screen bg-bg">
      {/* Brand panel */}
      <section className="relative hidden w-[46%] max-w-[640px] flex-col justify-between overflow-hidden bg-sidebar p-10 text-sidebar-fg lg:flex">
        <div className="flex items-center gap-3">
          <LogoMark className="h-9 w-9" />
          <div className="leading-tight">
            <div className="text-[15px] font-semibold text-white">AegisProxy</div>
            <div className="text-[12px] text-sidebar-muted">Enterprise{meta?.version ? ` ${meta.version}` : ''}</div>
          </div>
        </div>

        <div>
          <h1 className="max-w-[420px] text-[28px] font-semibold leading-[1.2] tracking-[-0.02em] text-white">
            Every outbound connection from your servers, decided by policy.
          </h1>
          <p className="mt-3 max-w-[420px] text-[14px] leading-6 text-sidebar-muted">
            Default-deny egress with versioned policy sets, four-eyes review and a tamper-evident audit trail.
          </p>
          <ul className="mt-8 space-y-2" aria-label="Example policy decisions">
            {LEDGER.map((l) => (
              <li key={l.host} className="flex items-center gap-3 rounded-lg border border-sidebar-border bg-white/[0.03] px-3.5 py-2.5">
                <span className={l.ok ? 'h-2 w-2 shrink-0 rounded-full bg-success-solid' : 'h-2 w-2 shrink-0 rounded-full bg-danger-solid'} aria-hidden />
                <span className="min-w-0 flex-1">
                  <PatternText host={l.host} path={l.path} inverse />
                </span>
                <span className="hidden text-[12px] text-sidebar-muted xl:inline">{l.from}</span>
                <span className={l.ok ? 'text-[12px] font-medium text-[#47CD89]' : 'text-[12px] font-medium text-[#F97066]'}>{l.verdict}</span>
              </li>
            ))}
          </ul>
        </div>

        <p className="text-[12px] text-sidebar-muted">Zero-trust egress proxy and control plane</p>
      </section>

      {/* Form */}
      <main className="flex flex-1 items-center justify-center px-4 py-10 sm:px-8">
        <div className="w-full max-w-[400px]">
          <div className="mb-8 flex items-center gap-3 lg:hidden">
            <LogoMark className="h-9 w-9" />
            <div className="leading-tight">
              <div className="text-[15px] font-semibold text-fg">AegisProxy</div>
              <div className="text-[12px] text-fg-subtle">Enterprise{meta?.version ? ` ${meta.version}` : ''}</div>
            </div>
          </div>

          <h2 className="text-[22px] font-semibold tracking-[-0.01em] text-fg">Sign in to the console</h2>
          <p className="mt-1 text-[13.5px] text-fg-muted">
            {sso ? `Use your ${sso.label || 'organization'} account.` : 'Use your local AegisProxy account.'}
          </p>

          {ssoError && (
            <Callout tone="danger" className="mt-5" title={ssoErrorMessage(ssoError).title}>
              <span className="block" data-testid="sso-error">
                {ssoErrorMessage(ssoError).text}
              </span>
              <span className="mt-1 block text-[12px] text-fg-subtle">
                Error code: <code className="font-mono">{ssoError}</code>
              </span>
            </Callout>
          )}

          {sso && (
            <div className="mt-6">
              <a
                href={ssoHref}
                onClick={() => ssoError && setParams({ sso_error: null })}
                className={cn(buttonClass('primary', 'lg', 'w-full gap-2.5'))}
                data-testid="sso-login"
              >
                <span className="flex h-6 w-6 items-center justify-center rounded bg-white">
                  <ProviderLogo provider={sso.provider} className={sso.provider === 'oidc' ? 'text-[rgb(43,74,203)]' : undefined} />
                </span>
                Sign in with {sso.label || 'single sign-on'}
              </a>
              <p className="mt-2 text-center text-[12px] text-fg-subtle">You are redirected to your identity provider and back.</p>
            </div>
          )}

          {meta && !sso && !meta.local_login_enabled && (
            <Callout tone="warning" className="mt-5">
              Local password sign-in is disabled for this deployment. Contact your administrator if you cannot sign in.
            </Callout>
          )}

          {sso && localEnabled && (
            <div className="my-6 flex items-center gap-3 text-[12px] text-fg-subtle" aria-hidden>
              <span className="h-px flex-1 bg-border" />
              or with a local account
              <span className="h-px flex-1 bg-border" />
            </div>
          )}

          {sso && !localEnabled && (
            <div className="mt-8 border-t border-border pt-5">
              <button
                type="button"
                onClick={() => setShowLocal((v) => !v)}
                aria-expanded={showLocal}
                aria-controls="local-login"
                className="flex items-center gap-1.5 text-[13px] font-medium text-fg-muted hover:text-fg"
              >
                {showLocal ? <ChevronDown className="h-4 w-4" aria-hidden /> : <ChevronRight className="h-4 w-4" aria-hidden />}
                Use a local account
                <span className="font-normal text-fg-subtle">(break-glass)</span>
              </button>
              {showLocal && (
                <div id="local-login" className="mt-4 space-y-4">
                  <Callout tone="warning" icon={Siren} className="py-2.5">
                    Emergency access only. Password sign-in is limited to break-glass accounts; every use is audited and alerts the security team.
                  </Callout>
                  {passwordForm}
                </div>
              )}
            </div>
          )}

          {localVisible && !(sso && !localEnabled) && <div className={sso ? '' : 'mt-6'}>{passwordForm}</div>}

          {meta?.demo_mode && (
            <div className="mt-8 border-t border-border pt-6">
              <p className="text-[12.5px] font-medium text-fg">Demo accounts</p>
              <p className="mt-0.5 text-[12px] text-fg-subtle">Demo mode only. Sign in as one of the seeded roles.</p>
              <div className="mt-3 grid grid-cols-2 gap-2">
                {DEMO_ACCOUNTS.map((d) => (
                  <button
                    key={d.u}
                    type="button"
                    disabled={loggingIn}
                    onClick={() => submit(d.u, d.p)}
                    className="rounded-lg border border-border bg-surface px-3 py-2 text-left transition-colors hover:border-accent-border hover:bg-accent-soft disabled:opacity-60"
                  >
                    <div className="font-mono text-[12.5px] font-semibold text-accent">{d.u}</div>
                    <div className="truncate text-[11.5px] text-fg-subtle">{d.label}</div>
                  </button>
                ))}
              </div>
            </div>
          )}

          <div className="mt-8 flex flex-wrap items-center justify-between gap-3 border-t border-border pt-5 text-[12.5px]">
            <button type="button" onClick={() => navigate('/?portal=block')} className="inline-flex items-center gap-1.5 font-medium text-accent hover:underline">
              <ExternalLink className="h-3.5 w-3.5" aria-hidden />
              Block page and root CA download
            </button>
            {meta?.version && <span className="text-fg-subtle">{meta.product || 'AegisProxy'} {meta.version}</span>}
          </div>
        </div>
      </main>
    </div>
  );
};
