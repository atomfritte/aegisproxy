import React, { useEffect, useMemo, useState } from 'react';
import {
  ArrowLeft,
  CheckCircle2,
  Clock,
  Download,
  FileKey,
  Fingerprint,
  Moon,
  RotateCcw,
  Send,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Sun,
  Terminal,
  TriangleAlert,
} from 'lucide-react';
import { api, apiFetch, publicBaseUrl } from '../../api';
import { cn } from '../../lib/cn';
import { formatDate } from '../../lib/format';
import { useAsync, useDocumentTitle } from '../../lib/hooks';
import { useTheme } from '../../lib/theme';
import { useSession } from '../../data/session';
import { LogoMark } from '../../shell/Logo';
import type { AccessScope, PublicMeta } from '../../types';
import { Badge, Button, buttonClass, Callout, CodeBlock, CopyButton, Field, Input, PatternText, Select, Spinner, Textarea } from '../../ui';
import { CaValidityBadge } from '../security/tls/RootCaCard';
import { TRUST_OS, TrustOs, trustSnippet } from '../security/tls/ca';
import {
  decodeBlockToken,
  DURATIONS,
  METHODS,
  NO_SELF_SERVICE_VERDICTS,
  parseNotOffered,
  PortalDuration,
  SCOPES,
  SubmitResult,
  VERDICT_LABELS,
} from './portalModel';

/** Values used to prefill the portal when it is opened from inside the admin console. */
export interface PortalPrefill {
  ip?: string;
  url?: string;
  trace?: string;
  /** Data-plane-signed block token ("bt"), attests server identity and URL. */
  bt?: string;
}

interface Props {
  meta: PublicMeta | null;
  /** null = read ?bt=, ?url=, ?ip=, ?trace= from the page URL */
  prefill?: PortalPrefill | null;
  onSwitchToAdmin?: () => void;
  onRequestSubmitted?: () => void;
}

const DEMO_DEFAULTS = {
  url: 'https://github.com/hashicorp/terraform/releases/download/v1.9.8/terraform_1.9.8_linux_amd64.zip',
  trace: 'flw-live-105',
  requester: 'devops-oncall@enterprise.corp',
  reason: 'Required for the release pipeline dependency download on the server fleet (change ticket CHG-50812).',
};

const Card: React.FC<{ className?: string; children: React.ReactNode }> = ({ className, children }) => (
  <section className={cn('min-w-0 rounded-xl border border-border bg-surface shadow-card', className)}>{children}</section>
);

const Detail: React.FC<{ label: string; className?: string; children: React.ReactNode }> = ({ label, className, children }) => (
  <div className={cn('min-w-0', className)}>
    <dt className="text-[12px] font-medium text-fg-subtle">{label}</dt>
    <dd className="mt-1 min-w-0 text-[13px] text-fg">{children}</dd>
  </div>
);

/** Self-service block portal (anonymous): what was blocked, request access, trust the root CA. */
export const PublicBlockPortal: React.FC<Props> = ({ meta, prefill = null, onSwitchToAdmin, onRequestSubmitted }) => {
  useDocumentTitle('Request access');
  const { resolvedTheme, setTheme } = useTheme();
  const { user } = useSession();
  const source = useMemo<PortalPrefill>(() => {
    if (prefill) return prefill;
    const params = new URLSearchParams(window.location.search);
    return {
      ip: params.get('ip') || undefined,
      url: params.get('url') || undefined,
      trace: params.get('trace') || undefined,
      bt: params.get('bt') || undefined,
    };
  }, [prefill]);

  const blockToken = (source.bt || '').trim();
  const claims = useMemo(() => (blockToken ? decodeBlockToken(blockToken) : null), [blockToken]);
  const hasToken = blockToken !== '';
  const tokenExpired = !!claims?.exp && claims.exp * 1000 < Date.now();
  const verdict = claims?.v || '';
  const noSelfService = NO_SELF_SERVICE_VERDICTS.includes(verdict);

  const [blockedURL, setBlockedURL] = useState(claims?.url || source.url || '');
  const [method, setMethod] = useState((claims?.m || 'GET').toUpperCase());
  const traceId = claims?.tid || source.trace || '';
  const serverIP = claims?.ip || '';
  const [requester, setRequester] = useState('');
  const [scope, setScope] = useState<AccessScope>('prefix_with_objects');
  const [duration, setDuration] = useState<PortalDuration>('24h');
  const [reason, setReason] = useState('');
  const [allowedScopes, setAllowedScopes] = useState<string[] | null>(null);
  const [allowedDurations, setAllowedDurations] = useState<string[] | null>(null);
  const [formOffered, setFormOffered] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState<SubmitResult | null>(null);
  const [error, setError] = useState<{ message: string; narrowed?: 'scope' | 'duration' } | null>(null);
  const [touched, setTouched] = useState(false);
  const [os, setOs] = useState<TrustOs>('ubuntu');
  const { data: ca } = useAsync(() => api.public.caInfo(), []);

  // Re-sync when the portal is reopened with a different flow.
  useEffect(() => {
    setBlockedURL(claims?.url || source.url || '');
    setMethod((claims?.m || 'GET').toUpperCase());
    setSubmitted(null);
    setError(null);
  }, [source, claims]);

  // Scopes, durations and whether self-service is offered come from the block page template of the
  // server (GET /api/public/request-options). Without it the full catalog is shown and the server
  // narrows the options on submit.
  useEffect(() => {
    let cancelled = false;
    api.public
      .requestOptions(blockToken || undefined)
      .then((o) => {
        if (cancelled) return;
        const scopes = o.allowed_scopes ?? [];
        const durations = o.allowed_durations ?? [];
        setAllowedScopes(scopes);
        setAllowedDurations(durations);
        setFormOffered(o.request_form);
        setScope((cur) => (scopes.includes(cur) ? cur : ((SCOPES.find((x) => scopes.includes(x.value))?.value ?? cur) as AccessScope)));
        setDuration((cur) => (durations.includes(cur) ? cur : (DURATIONS.find((x) => durations.includes(x.value))?.value ?? cur)));
      })
      .catch(() => {
        // invalid/expired token or rate limit: keep the catalog; the token state is shown separately
      });
    return () => {
      cancelled = true;
    };
  }, [blockToken]);

  // Demo deployments keep the familiar showcase values; production starts empty.
  useEffect(() => {
    if (!meta?.demo_mode || hasToken) return;
    setBlockedURL((v) => v || DEMO_DEFAULTS.url);
    setRequester((v) => v || DEMO_DEFAULTS.requester);
    setReason((v) => v || DEMO_DEFAULTS.reason);
  }, [meta?.demo_mode, hasToken]);

  const scopeOptions = SCOPES.filter((s) => !allowedScopes || allowedScopes.includes(s.value));
  const durationOptions = DURATIONS.filter((d) => !allowedDurations || allowedDurations.includes(d.value));
  const nothingOffered =
    !formOffered ||
    (allowedScopes && SCOPES.filter((x) => allowedScopes.includes(x.value)).length === 0) ||
    (allowedDurations && DURATIONS.filter((x) => allowedDurations.includes(x.value)).length === 0);

  const urlError = !hasToken && touched && !/^https?:\/\/[^\s/]+/i.test(blockedURL.trim()) ? 'Enter the full blocked URL, starting with https:// or http://.' : null;
  const requesterError = touched && !requester.trim() ? 'Tell the reviewers who needs access.' : null;
  const reasonError = touched && reason.trim().length < 10 ? 'Explain why the server needs this destination (at least 10 characters).' : null;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if ((!hasToken && !/^https?:\/\/[^\s/]+/i.test(blockedURL.trim())) || !requester.trim() || reason.trim().length < 10) return;
    setSubmitting(true);
    setError(null);
    try {
      const body: Record<string, string> = {
        requester: requester.trim(),
        reason: reason.trim(),
        requested_scope: scope,
        duration,
      };
      if (hasToken) body.block_token = blockToken;
      else {
        body.requested_url = blockedURL.trim();
        body.method = method;
        if (traceId) body.trace_id = traceId;
      }
      const res = await apiFetch('/api/public/requests', { method: 'POST', body: JSON.stringify(body) });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const msg: string = data?.error || res.statusText || 'The request could not be submitted.';
        const narrow = parseNotOffered(msg);
        if (narrow?.field === 'scope') {
          setAllowedScopes(narrow.allowed);
          if (narrow.allowed[0]) setScope(narrow.allowed[0] as AccessScope);
        } else if (narrow?.field === 'duration') {
          setAllowedDurations(narrow.allowed);
          const pick = DURATIONS.find((d) => narrow.allowed.includes(d.value));
          if (pick) setDuration(pick.value);
        }
        setError({ message: msg, narrowed: narrow?.field });
      } else {
        setSubmitted({ message: data.message, request: data.request, duplicate: res.status === 200 });
        onRequestSubmitted?.();
      }
    } catch (err) {
      setError({ message: err instanceof Error ? err.message : 'Network error — check the connection to the control plane.' });
    } finally {
      setSubmitting(false);
    }
  };

  const reset = () => {
    setSubmitted(null);
    setError(null);
    setTouched(false);
    if (!meta?.demo_mode) setReason('');
  };

  const base = publicBaseUrl(meta?.public_url || ca?.public_url);
  const product = meta?.product || 'AegisProxy';

  let heading = 'Request outbound access';
  let lead =
    'Outbound connections from managed servers are denied by default. Describe what the server needs; the responsible team reviews the request and you can retry once it is approved.';
  if (hasToken && noSelfService) {
    heading = verdict === 'QUARANTINED' ? 'This server is quarantined' : 'Blocked by threat protection';
    lead =
      verdict === 'QUARANTINED'
        ? 'The security team has isolated this server. All outbound connections are denied until it is released.'
        : 'The destination matched a threat-protection control (malware, phishing, command-and-control or data loss prevention). Self-service access is not available for this kind of block.';
  } else if (hasToken || source.url) {
    heading = 'This destination is not on the allow list';
  }

  return (
    <div className="min-h-screen bg-bg text-fg">
      <header className="border-b border-border bg-surface">
        <div className="mx-auto flex h-14 max-w-[1120px] items-center gap-3 px-4 sm:px-6">
          <LogoMark className="h-8 w-8 shrink-0" />
          <div className="min-w-0 leading-tight">
            <div className="truncate text-[14px] font-semibold text-fg">{product}</div>
            <div className="truncate text-[11.5px] text-fg-subtle">Self-service portal</div>
          </div>
          <div className="ml-auto flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => setTheme(resolvedTheme === 'dark' ? 'light' : 'dark')}
              aria-label={resolvedTheme === 'dark' ? 'Use light theme' : 'Use dark theme'}
              className="flex h-9 w-9 items-center justify-center rounded-md text-fg-muted hover:bg-surface-3 hover:text-fg"
            >
              {resolvedTheme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>
            {onSwitchToAdmin && (
              <Button size="sm" variant="secondary" icon={ArrowLeft} onClick={onSwitchToAdmin}>
                <span className="hidden sm:inline">{user ? 'Back to console' : 'Sign in to console'}</span>
                <span className="sm:hidden">{user ? 'Console' : 'Sign in'}</span>
              </Button>
            )}
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1120px] px-4 pb-14 pt-6 sm:px-6 sm:pt-10">
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_360px] lg:items-start">
          <div className="min-w-0 space-y-6">
            {/* What happened */}
            <Card>
              <div className="p-5 sm:p-7">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone="danger" size="md" icon={noSelfService ? ShieldX : ShieldAlert}>
                    HTTP 403 · {noSelfService ? 'Blocked by threat protection' : 'Outbound access blocked'}
                  </Badge>
                </div>
                <h1 className="mt-4 text-[22px] font-semibold leading-tight tracking-[-0.01em] text-fg sm:text-[26px]">{heading}</h1>
                <p className="mt-2 max-w-[620px] text-[13.5px] leading-6 text-fg-muted">{lead}</p>

                {(hasToken || source.url || traceId) && (
                  <dl className="mt-5 grid gap-4 rounded-lg border border-border bg-surface-2 p-4 sm:grid-cols-2">
                    {(hasToken ? claims?.url : source.url) && (
                      <Detail label="Blocked URL" className="sm:col-span-2">
                        <span className="flex min-w-0 items-start gap-2">
                          <span className="mt-px shrink-0 rounded border border-border bg-surface px-1.5 font-mono text-[11px] font-semibold leading-5 text-fg-muted">
                            {(hasToken ? claims?.m || 'GET' : method).toUpperCase()}
                          </span>
                          <span className="min-w-0 break-all font-mono text-[12.5px] leading-5">{hasToken ? claims?.url : source.url}</span>
                        </span>
                      </Detail>
                    )}
                    <Detail label="Server">
                      {serverIP ? <span className="font-mono text-[12.5px]">{serverIP}</span> : <span className="text-fg-muted">Detected from this connection</span>}
                    </Detail>
                    {verdict && <Detail label="Reason">{VERDICT_LABELS[verdict] || verdict}</Detail>}
                    {traceId && (
                      <Detail label="Trace ID">
                        <span className="flex items-center gap-1">
                          <span className="truncate font-mono text-[12.5px]">{traceId}</span>
                          <CopyButton text={traceId} label="Copy trace ID" size="xs" />
                        </span>
                      </Detail>
                    )}
                  </dl>
                )}

                <div className="mt-4">
                  {hasToken && tokenExpired ? (
                    <Callout tone="warning" title="This link has expired">
                      Block links are valid for 24 hours. Run the blocked command again and open the new link it prints.
                    </Callout>
                  ) : hasToken ? (
                    <div className="flex items-start gap-2.5 text-[12.5px] leading-5 text-fg-muted">
                      <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-success" aria-hidden />
                      <span>
                        <span className="font-medium text-fg">Verified by the proxy.</span> The server identity and URL come from a signed block token and cannot be
                        changed. Reviewers see the request as verified.
                      </span>
                    </div>
                  ) : (
                    <Callout tone="warning" title="Unverified request">
                      This page was opened without a block token, so the server identity is taken from the network connection this request is sent from. Reviewers
                      see it as self-reported. For a verified request, open the link printed in the blocked terminal output or browser page.
                    </Callout>
                  )}
                </div>
              </div>
            </Card>

            {/* Request access */}
            <Card>
              <div className="border-b border-border px-5 py-4 sm:px-7">
                <h2 className="text-[16px] font-semibold text-fg">{noSelfService ? 'What you can do' : submitted ? 'Request received' : 'Request access'}</h2>
                {!noSelfService && !submitted && (
                  <p className="mt-0.5 text-[13px] text-fg-muted">The responsible team is notified in Microsoft Teams or Slack and reviews your request.</p>
                )}
              </div>
              <div className="p-5 sm:p-7">
                {noSelfService ? (
                  <div className="space-y-4">
                    <Callout tone="danger" title="Self-service is not available">
                      Contact the security team and quote the trace ID{traceId ? ` ${traceId}` : ''}. If you believe this is a false positive, they can add an
                      exception after reviewing the event.
                    </Callout>
                  </div>
                ) : submitted ? (
                  <div className="space-y-5">
                    <div className="flex items-start gap-3">
                      <span className={cn('flex h-10 w-10 shrink-0 items-center justify-center rounded-full', submitted.duplicate ? 'bg-info-soft text-info' : 'bg-success-soft text-success')}>
                        {submitted.duplicate ? <Clock className="h-5 w-5" aria-hidden /> : <CheckCircle2 className="h-5 w-5" aria-hidden />}
                      </span>
                      <div className="min-w-0">
                        <p className="text-[15px] font-semibold text-fg">{submitted.duplicate ? 'This request is already pending' : 'Your request was submitted'}</p>
                        <p className="mt-0.5 text-[13px] leading-5 text-fg-muted">{submitted.message}</p>
                      </div>
                    </div>
                    <dl className="grid gap-4 rounded-lg border border-border bg-surface-2 p-4 sm:grid-cols-2">
                      <Detail label="Request ID">
                        <span className="flex items-center gap-1">
                          <span className="truncate font-mono text-[12.5px] font-semibold">{submitted.request.id}</span>
                          <CopyButton text={submitted.request.id} label="Copy request ID" size="xs" />
                        </span>
                      </Detail>
                      <Detail label="Status">
                        <span className="flex flex-wrap gap-1.5">
                          <Badge tone="warning" dot>
                            {submitted.request.status === 'pending' ? 'Pending review' : submitted.request.status}
                          </Badge>
                          {submitted.request.verified ? (
                            <Badge tone="success" icon={ShieldCheck}>
                              Verified
                            </Badge>
                          ) : (
                            <Badge tone="warning" icon={TriangleAlert}>
                              Unverified
                            </Badge>
                          )}
                        </span>
                      </Detail>
                      {submitted.request.server_hostname && <Detail label="Server">{submitted.request.server_hostname}</Detail>}
                      {submitted.request.suggested_host_pattern && (
                        <Detail label="Suggested rule">
                          <PatternText host={submitted.request.suggested_host_pattern} path={submitted.request.suggested_path_pattern} wrap />
                        </Detail>
                      )}
                    </dl>
                    <div>
                      <p className="text-[13px] font-semibold text-fg">What happens next</p>
                      <ol className="mt-2 space-y-2 text-[13px] leading-5 text-fg-muted">
                        {[
                          'A reviewer for the server’s group checks the request and may narrow the rule.',
                          'Once approved, the new rule reaches every proxy worker within seconds.',
                          'Run the blocked command again. Quote the request ID if you contact the team.',
                        ].map((t, i) => (
                          <li key={i} className="flex gap-2.5">
                            <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-surface-3 text-[11px] font-semibold text-fg-muted">{i + 1}</span>
                            <span>{t}</span>
                          </li>
                        ))}
                      </ol>
                    </div>
                    <Button icon={RotateCcw} onClick={reset}>
                      Submit another request
                    </Button>
                  </div>
                ) : (
                  <form className="space-y-5" onSubmit={submit} noValidate>
                    {!hasToken && (
                      <div className="grid gap-4 sm:grid-cols-[120px_minmax(0,1fr)]">
                        <Field label="Method">
                          <Select value={method} onChange={(e) => setMethod(e.target.value)} options={METHODS.map((m) => ({ value: m, label: m }))} />
                        </Field>
                        <Field label="Blocked URL" required error={urlError}>
                          <Input mono type="url" inputMode="url" value={blockedURL} onChange={(e) => setBlockedURL(e.target.value)} placeholder="https://example.com/path/to/file" />
                        </Field>
                      </div>
                    )}
                    <Field label="Who needs access?" required error={requesterError} hint="Your name, team e-mail or change ticket. Reviewers use it to reach you.">
                      <Input value={requester} onChange={(e) => setRequester(e.target.value)} placeholder="jane.doe@corp.example" autoComplete="email" maxLength={200} />
                    </Field>

                    <fieldset className="min-w-0">
                      <legend className="label mb-1.5">Scope</legend>
                      {allowedScopes && allowedScopes.length > 0 && (
                        <p className="mb-2 text-[12px] text-fg-subtle">Only the scopes your administrators allow for this server are shown.</p>
                      )}
                      <div role="radiogroup" aria-label="Scope" className="grid gap-2 sm:grid-cols-2">
                        {scopeOptions.map((o) => {
                          const active = scope === o.value;
                          return (
                            <button
                              key={o.value}
                              type="button"
                              role="radio"
                              aria-checked={active}
                              onClick={() => setScope(o.value)}
                              className={cn(
                                'flex min-w-0 items-start gap-2.5 rounded-lg border p-3 text-left transition-colors',
                                active ? 'border-accent bg-accent-soft ring-1 ring-accent' : 'border-border bg-surface hover:border-border-strong hover:bg-surface-2'
                              )}
                            >
                              <span className={cn('mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full border', active ? 'border-primary bg-primary' : 'border-border-strong bg-surface')}>
                                {active && <span className="h-1.5 w-1.5 rounded-full bg-white" />}
                              </span>
                              <span className="min-w-0">
                                <span className="block text-[13px] font-semibold text-fg">{o.title}</span>
                                <span className="mt-0.5 block text-[12px] leading-5 text-fg-muted">{o.description}</span>
                              </span>
                            </button>
                          );
                        })}
                      </div>
                    </fieldset>

                    <fieldset className="min-w-0">
                      <legend className="label mb-1.5">Duration</legend>
                      {allowedDurations && allowedDurations.length > 0 && (
                        <p className="mb-2 text-[12px] text-fg-subtle">Only the durations your administrators allow for this server are shown.</p>
                      )}
                      <div role="radiogroup" aria-label="Duration" className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                        {durationOptions.map((d) => {
                          const active = duration === d.value;
                          return (
                            <button
                              key={d.value}
                              type="button"
                              role="radio"
                              aria-checked={active}
                              onClick={() => setDuration(d.value)}
                              className={cn(
                                'rounded-lg border px-3 py-2 text-left transition-colors',
                                active ? 'border-accent bg-accent-soft ring-1 ring-accent' : 'border-border bg-surface hover:border-border-strong hover:bg-surface-2'
                              )}
                            >
                              <span className="block text-[13px] font-semibold text-fg">{d.label}</span>
                              <span className="block text-[11.5px] text-fg-subtle">{d.hint}</span>
                            </button>
                          );
                        })}
                      </div>
                    </fieldset>

                    <Field label="Justification" required error={reasonError} hint="What breaks without this destination? Add a change or incident ticket if you have one.">
                      <Textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={4} maxLength={2000} placeholder="The nightly build downloads the Terraform release from GitHub (CHG-50812)." />
                    </Field>

                    {error && (
                      <Callout tone={error.narrowed ? 'warning' : 'danger'} title={error.narrowed ? `Choose another ${error.narrowed}` : 'The request was not submitted'}>
                        {error.narrowed && !nothingOffered ? (
                          <>
                            This server only allows{' '}
                            {(error.narrowed === 'scope' ? scopeOptions.map((o) => o.title) : durationOptions.map((o) => o.label)).map((t) => `“${t}”`).join(', ')}. The
                            options above are updated — submit again.
                            <span className="mt-1 block text-[12px] text-fg-subtle">Server message: {error.message}</span>
                          </>
                        ) : (
                          error.message
                        )}
                      </Callout>
                    )}
                    {nothingOffered && (
                      <Callout tone="danger" title="Self-service is not offered for this server">
                        Contact the team that owns the server to request access.
                      </Callout>
                    )}

                    <Button type="submit" variant="primary" size="lg" fullWidth loading={submitting} icon={Send} disabled={(hasToken && tokenExpired) || !!nothingOffered}>
                      {submitting ? 'Submitting…' : 'Submit access request'}
                    </Button>
                  </form>
                )}
              </div>
            </Card>
          </div>

          {/* Root CA */}
          <aside className="min-w-0 space-y-6">
            <Card>
              <div className="p-5">
                <div className="flex items-start gap-3">
                  <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-accent-soft text-accent">
                    <FileKey className="h-[18px] w-[18px]" aria-hidden />
                  </span>
                  <div className="min-w-0">
                    <h2 className="text-[15px] font-semibold text-fg">Trust the root CA</h2>
                    <p className="mt-0.5 text-[12.5px] leading-5 text-fg-muted">Seeing TLS certificate errors? Install the enterprise root CA on this server.</p>
                  </div>
                </div>

                {ca ? (
                  <div className="mt-4 space-y-3">
                    <CaValidityBadge ca={ca} />
                    <div>
                      <div className="flex items-center gap-1.5 text-[12px] font-medium text-fg-subtle">
                        <Fingerprint className="h-3.5 w-3.5" aria-hidden />
                        SHA-256 fingerprint
                      </div>
                      <div className="mt-1 flex items-start gap-1">
                        <code className="min-w-0 flex-1 break-all rounded-md border border-border bg-surface-2 px-2 py-1.5 font-mono text-[11px] leading-[18px] text-fg">{ca.fingerprint}</code>
                        <CopyButton text={ca.fingerprint} label="Copy fingerprint" />
                      </div>
                      <p className="mt-1.5 text-[11.5px] leading-[18px] text-fg-subtle">
                        Compare it with the value in the {product} console, opened over https, before trusting the certificate: a value on this page is only as trustworthy as the
                        connection that delivered it.
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="mt-4 flex items-center gap-2 text-[12.5px] text-fg-subtle">
                    <Spinner className="h-3.5 w-3.5" /> Loading certificate details…
                  </div>
                )}

                <div className="mt-4 grid grid-cols-2 gap-2">
                  <a href={api.public.caDownloadUrl('crt')} download="aegis-enterprise-ca.crt" className={buttonClass('primary', 'sm', 'w-full')}>
                    <Download className="h-4 w-4" aria-hidden />
                    .crt (PEM)
                  </a>
                  <a href={api.public.caDownloadUrl('der')} download="aegis-enterprise-ca.der" className={buttonClass('secondary', 'sm', 'w-full')}>
                    <Download className="h-4 w-4" aria-hidden />
                    .der (Windows)
                  </a>
                  <a href={api.public.linuxInstallerUrl()} target="_blank" rel="noreferrer" className={buttonClass('secondary', 'sm', 'w-full')}>
                    <Terminal className="h-4 w-4" aria-hidden />
                    Linux installer
                  </a>
                  <a href={api.public.windowsInstallerUrl()} target="_blank" rel="noreferrer" className={buttonClass('secondary', 'sm', 'w-full')}>
                    <Terminal className="h-4 w-4" aria-hidden />
                    Windows installer
                  </a>
                </div>
              </div>
              <div className="border-t border-border p-5">
                <p className="text-[13px] font-semibold text-fg">Import guide</p>
                <p className="mt-0.5 text-[11.5px] leading-[18px] text-fg-subtle">Every command trusts the certificate only after its fingerprint matched the value from the console.</p>
                <div className="mt-2 flex flex-wrap gap-1.5" role="tablist" aria-label="Platform">
                  {TRUST_OS.map((t) => (
                    <button
                      key={t.id}
                      type="button"
                      role="tab"
                      aria-selected={os === t.id}
                      onClick={() => setOs(t.id)}
                      className={cn(
                        'rounded-md border px-2 py-1 text-[12px] font-medium transition-colors',
                        os === t.id ? 'border-accent bg-accent-soft text-accent' : 'border-border text-fg-muted hover:border-border-strong hover:text-fg'
                      )}
                    >
                      {t.label}
                    </button>
                  ))}
                </div>
                <CodeBlock className="mt-3" title={TRUST_OS.find((t) => t.id === os)?.label} code={trustSnippet(os, base, ca)} wrap maxHeight={300} />
              </div>
            </Card>

            <div className="flex gap-3 rounded-xl border border-border bg-surface-2 p-4 text-[12.5px] leading-5 text-fg-muted">
              <Terminal className="mt-0.5 h-4 w-4 shrink-0 text-fg-subtle" aria-hidden />
              <span>
                Working in a terminal? When <code className="font-mono text-fg">curl</code>, <code className="font-mono text-fg">git</code> or{' '}
                <code className="font-mono text-fg">apt</code> is blocked, the proxy prints a signed one-line command that files a verified request directly.
              </span>
            </div>
          </aside>
        </div>

        <footer className="mt-10 flex flex-wrap items-center justify-center gap-x-3 gap-y-1 text-center text-[12px] text-fg-subtle">
          <span>
            {product}
            {meta?.version ? ` ${meta.version}` : ''}
          </span>
          {meta?.demo_mode && <Badge tone="warning">Demo mode</Badge>}
          {ca && <span>Root CA valid until {formatDate(ca.not_after)}</span>}
        </footer>
      </main>
    </div>
  );
};
