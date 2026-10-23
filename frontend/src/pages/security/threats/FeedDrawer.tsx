import React, { useEffect, useState } from 'react';
import { ArrowRight, KeyRound, Lock, ShieldHalf } from 'lucide-react';
import { api } from '../../../api';
import { useAction } from '../../../data/AppData';
import type { FeedFormat, ThreatFeed } from '../../../types';
import { Badge, Button, ButtonLink, Callout, DescriptionList, Drawer, Field, Input, RelativeTime, Select, Switch, Textarea } from '../../../ui';
import { formatNumber } from '../../../lib/format';
import { categoryOptions, FEED_FORMATS, isDefenderFeed } from './meta';

interface Draft {
  name: string;
  description: string;
  url: string;
  format: FeedFormat;
  category: string;
  license: string;
  enabled: boolean;
  match_subdomains: boolean;
  refresh_minutes: string;
  auth_header_name: string;
  auth_header_value: string;
  /** 'keep' the stored secret, 'replace' it or 'none' when nothing is stored */
  secret: 'keep' | 'replace' | 'none';
  lookback_days: string;
  ca_cert_pem: string;
}

const toDraft = (f?: ThreatFeed | null): Draft => ({
  name: f?.name ?? '',
  description: f?.description ?? '',
  url: f?.url ?? '',
  format: f?.format ?? 'domains',
  category: f?.category ?? 'malware',
  license: f?.license ?? '',
  enabled: f?.enabled ?? true,
  match_subdomains: f?.match_subdomains ?? true,
  refresh_minutes: String(f?.refresh_minutes ?? 360),
  auth_header_name: f?.auth_header_name ?? '',
  auth_header_value: '',
  secret: f?.has_auth_value ? 'keep' : 'none',
  lookback_days: f?.lookback_days ? String(f.lookback_days) : '',
  ca_cert_pem: f?.ca_cert_pem ?? '',
});

const STRUCTURED_HELP: Record<string, { url: string; placeholder: string; hint: string; header: string; value: string }> = {
  taxii21: {
    url: 'Collection URL',
    placeholder: 'https://taxii.corp.example/api1/collections/9cfa669c-ee94-4ece-afd2-f8edac37d8fd/',
    hint: 'The collection (…/collections/<id>/) or its objects endpoint. Pagination is followed; only indicator objects are read.',
    header: 'Authorization',
    value: 'Basic … or Bearer …',
  },
  misp: {
    url: 'MISP URL',
    placeholder: 'https://misp.corp.example',
    hint: 'Base URL of the instance. Attributes marked for IDS export are read via /attributes/restSearch; MISP warninglists are honoured.',
    header: 'Authorization',
    value: 'MISP automation key',
  },
};

/** Add a custom feed or edit a feed (built-ins: enabled, refresh, subdomain matching and auth only). */
export const FeedDrawer: React.FC<{ open: boolean; feed?: ThreatFeed | null; onClose: () => void; onSaved: () => void }> = ({ open, feed, onClose, onSaved }) => {
  const { run, pending } = useAction();
  const [d, setD] = useState<Draft>(() => toDraft(feed));
  const [touched, setTouched] = useState(false);
  useEffect(() => {
    if (open) {
      setD(toDraft(feed));
      setTouched(false);
    }
  }, [open, feed]);

  const builtin = !!feed?.builtin;
  const structured = d.format === 'taxii21' || d.format === 'misp';
  const help = STRUCTURED_HELP[d.format];
  const lookback = d.lookback_days.trim() === '' ? 0 : Number(d.lookback_days);
  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setD((p) => ({ ...p, [k]: v }));
  const refresh = Number(d.refresh_minutes || 0);
  const errors = {
    name: !builtin && !d.name.trim() ? 'Give the feed a name.' : null,
    url: !builtin && !/^https:\/\/[^\s/]+/i.test(d.url.trim()) ? `The ${structured ? 'source' : 'feed'} URL must start with https://` : null,
    lookback: structured && (!Number.isInteger(lookback) || lookback < 0 || lookback > 3650) ? 'Between 0 (default 90) and 3650 days.' : null,
    ca: structured && d.ca_cert_pem.trim() && !d.ca_cert_pem.includes('BEGIN CERTIFICATE') ? 'Paste a PEM certificate (-----BEGIN CERTIFICATE-----).' : null,
    refresh: !Number.isInteger(refresh) || (refresh !== 0 && (refresh < 15 || refresh > 10080)) ? 'Between 15 and 10080 minutes (0 = default).' : null,
    header: /[\s:]/.test(d.auth_header_name) ? 'Header names cannot contain spaces or colons.' : null,
    secret: d.auth_header_name.trim() && d.secret === 'replace' && !d.auth_header_value ? 'Enter the header value or keep the stored one.' : null,
  };
  const invalid = Object.values(errors).some(Boolean);

  const save = async () => {
    setTouched(true);
    if (invalid) return;
    const payload: Partial<ThreatFeed> = {
      ...(feed ? { id: feed.id } : {}),
      name: d.name.trim(),
      description: d.description.trim(),
      url: d.url.trim(),
      format: d.format,
      category: d.category.trim(),
      license: d.license.trim(),
      enabled: d.enabled,
      match_subdomains: d.match_subdomains,
      refresh_minutes: refresh,
      auth_header_name: d.auth_header_name.trim(),
      lookback_days: structured ? lookback : 0,
      ca_cert_pem: structured ? d.ca_cert_pem.trim() : '',
    };
    // write-only: only sent when a new value was typed (empty keeps the stored value)
    if (d.auth_header_name.trim() && (d.secret === 'replace' || d.secret === 'none') && d.auth_header_value) payload.auth_header_value = d.auth_header_value;
    const r = await run(() => api.security.upsertFeed(payload), {
      key: 'feed-save',
      success: feed ? `Saved feed “${payload.name || feed.name}”` : `Added feed “${payload.name}”${d.enabled ? ' — first download scheduled' : ''}`,
      errorTitle: 'The feed could not be saved',
    });
    if (r) {
      onSaved();
      onClose();
    }
  };

  const err = (k: keyof typeof errors) => (touched ? errors[k] : null);

  if (feed && isDefenderFeed(feed)) {
    return (
      <Drawer
        open={open}
        onClose={onClose}
        width="md"
        title={feed.name}
        titleAside={<Badge tone="info" icon={ShieldHalf}>Microsoft Defender</Badge>}
        footer={
          <>
            <Button onClick={onClose}>Close</Button>
            <ButtonLink to="/settings/defender" variant="primary" iconRight={ArrowRight} onClick={onClose}>
              Defender settings
            </ButtonLink>
          </>
        }
      >
        <div className="space-y-5">
          <Callout tone="info" icon={Lock} title="Managed by the Microsoft Defender integration">
            This feed imports the custom indicators of your Defender tenant. It is enabled, refreshed and authenticated through Settings → Microsoft Defender — edit the
            integration instead of the feed.
          </Callout>
          {feed.description && <p className="text-[13px] leading-6 text-fg-muted">{feed.description}</p>}
          <DescriptionList
            items={[
              { label: 'State', value: feed.enabled ? <Badge tone="success" dot>Importing</Badge> : <Badge tone="neutral">Import off</Badge> },
              { label: 'Indicators', value: <span className="tabular">{formatNumber(feed.entry_count || 0)}</span> },
              { label: 'Last import', value: feed.last_success_at ? <RelativeTime value={feed.last_success_at} /> : <span className="text-fg-subtle">Never</span> },
              { label: 'Refresh', value: feed.refresh_minutes ? `Every ${feed.refresh_minutes} minutes` : '—' },
              { label: 'Source', value: <span className="break-all font-mono text-[12px]">{feed.url || '—'}</span>, full: true },
              { label: 'Last error', value: <span className="font-mono text-[12px] text-danger [overflow-wrap:anywhere]">{feed.last_error}</span>, full: true, hidden: !feed.last_error },
            ]}
          />
        </div>
      </Drawer>
    );
  }

  return (
    <Drawer
      open={open}
      onClose={onClose}
      dismissible={pending !== 'feed-save'}
      width="md"
      title={feed ? `Edit ${feed.name}` : 'Add threat feed'}
      titleAside={builtin ? <Badge tone="neutral">Built-in</Badge> : undefined}
      description={feed ? undefined : 'A blocklist URL, a TAXII 2.1 collection or a MISP instance. The control plane fetches it over HTTPS, compiles it into the threat-intel snapshot and every worker enforces it.'}
      footer={
        <>
          <Button onClick={onClose} disabled={pending === 'feed-save'}>
            Cancel
          </Button>
          <Button variant="primary" loading={pending === 'feed-save'} onClick={save}>
            {feed ? 'Save feed' : 'Add feed'}
          </Button>
        </>
      }
    >
      <form
        className="space-y-5"
        onSubmit={(ev) => {
          ev.preventDefault();
          save();
        }}
      >
        {builtin && (
          <Callout tone="neutral" icon={Lock}>
            Built-in feeds are maintained with the product. You can change whether they are enabled, how often they refresh, subdomain matching and an optional authentication
            header.
          </Callout>
        )}
        <Field label="Name" required={!builtin} error={err('name')}>
          <Input value={d.name} onChange={(e) => set('name', e.target.value)} disabled={builtin} placeholder="Vendor blocklist" data-autofocus />
        </Field>
        <Field label="Type" hint={FEED_FORMATS.find((f) => f.value === d.format)?.hint}>
          <Select
            value={d.format}
            onChange={(e) => {
              const v = e.target.value as FeedFormat;
              setD((p) => ({
                ...p,
                format: v,
                auth_header_name: v === 'misp' && !p.auth_header_name ? 'Authorization' : p.auth_header_name,
                // TAXII / MISP deliver mixed indicator types: default to the generic category
                category: !feed && (v === 'taxii21' || v === 'misp') && p.category === 'malware' ? 'threat_intel' : p.category,
              }));
            }}
            disabled={builtin}
            options={[
              ...FEED_FORMATS.filter((f) => !f.structured).map((f) => ({ value: f.value, label: `List — ${f.label}` })),
              ...FEED_FORMATS.filter((f) => f.structured).map((f) => ({ value: f.value, label: f.label })),
            ]}
          />
        </Field>
        <Field
          label={help ? help.url : 'Feed URL'}
          required={!builtin}
          error={err('url')}
          hint={builtin ? undefined : help ? help.hint : 'HTTPS only. Conditional downloads (ETag / Last-Modified), at most 96 MiB.'}
        >
          <Input value={d.url} onChange={(e) => set('url', e.target.value)} disabled={builtin} mono placeholder={help ? help.placeholder : 'https://feeds.example.org/blocklist.txt'} />
        </Field>
        <Field label="Description" optional>
          <Input value={d.description} onChange={(e) => set('description', e.target.value)} disabled={builtin} />
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Category" hint="Shown on events and lookups; sets the event severity.">
            <Select value={d.category} onChange={(e) => set('category', e.target.value)} disabled={builtin} options={categoryOptions(d.category)} />
          </Field>
          <Field label="License" optional hint="Check the terms before enabling commercial-use-restricted lists.">
            <Input value={d.license} onChange={(e) => set('license', e.target.value)} disabled={builtin} placeholder="CC0, MIT, commercial …" />
          </Field>
          <Field label="Refresh interval" error={err('refresh')} hint={err('refresh') ? undefined : '15 to 10080 minutes; 0 uses the default.'}>
            <Input
              type="number"
              min={0}
              max={10080}
              value={d.refresh_minutes}
              onChange={(e) => set('refresh_minutes', e.target.value)}
              trailing={<span className="text-[12px] text-fg-subtle">minutes</span>}
            />
          </Field>
          {structured && (
            <Field label="Indicator age" error={err('lookback')} hint={err('lookback') ? undefined : 'Only indicators added within this window. Empty or 0 = 90 days.'}>
              <Input
                type="number"
                min={0}
                max={3650}
                value={d.lookback_days}
                onChange={(e) => set('lookback_days', e.target.value)}
                placeholder="90"
                trailing={<span className="text-[12px] text-fg-subtle">days</span>}
              />
            </Field>
          )}
        </div>
        {structured && (
          <Field label="Private CA certificate" optional error={err('ca')} hint={err('ca') ? undefined : 'PEM of the CA that signed the server certificate of an internal threat-intel platform.'}>
            <Textarea mono rows={3} value={d.ca_cert_pem} onChange={(e) => set('ca_cert_pem', e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" spellCheck={false} />
          </Field>
        )}
        <div className="space-y-4 rounded-lg border border-border p-4">
          <Switch checked={d.enabled} onChange={(v) => set('enabled', v)} label="Enabled" description="Disabled feeds are kept but not downloaded or enforced." />
          <Switch
            checked={d.match_subdomains}
            onChange={(v) => set('match_subdomains', v)}
            label="Match subdomains"
            description="A listed domain also matches all of its subdomains (domains and hosts formats)."
          />
        </div>

        <section className="space-y-4" aria-labelledby="feed-auth-title">
          <div>
            <h3 id="feed-auth-title" className="flex items-center gap-2 text-[13px] font-semibold text-fg">
              <KeyRound className="h-4 w-4 text-fg-subtle" aria-hidden />
              Authentication
              <span className="font-normal text-fg-subtle">(optional)</span>
            </h3>
            <p className="mt-1 text-[12.5px] leading-5 text-fg-muted">
              {d.format === 'misp'
                ? 'MISP expects the automation key in the Authorization header. The value is stored write-only.'
                : d.format === 'taxii21'
                  ? 'TAXII servers usually use Authorization with Basic or Bearer credentials. The value is stored write-only.'
                  : 'Some providers require an API key header, e.g. abuse.ch uses Auth-Key. The value is stored write-only.'}
            </p>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Header name" error={err('header')}>
              <Input value={d.auth_header_name} onChange={(e) => set('auth_header_name', e.target.value)} mono placeholder={help ? help.header : 'Auth-Key'} />
            </Field>
            <Field label="Header value" error={err('secret')}>
              {(ids) =>
                d.secret === 'keep' ? (
                  <div className="flex h-[var(--control-h)] items-center justify-between gap-2 rounded-md border border-border bg-surface-2 pl-3 pr-1">
                    <span id={ids.id} className="text-[13px] text-fg-muted">
                      Stored <span className="tracking-widest">••••••</span>
                    </span>
                    <Button size="xs" variant="ghost" onClick={() => set('secret', 'replace')} disabled={!d.auth_header_name.trim()}>
                      Replace
                    </Button>
                  </div>
                ) : (
                  <Input
                    id={ids.id}
                    aria-describedby={ids.describedBy}
                    type="password"
                    autoComplete="new-password"
                    value={d.auth_header_value}
                    onChange={(e) => set('auth_header_value', e.target.value)}
                    disabled={!d.auth_header_name.trim()}
                    mono
                    placeholder={d.auth_header_name.trim() ? (help ? help.value : 'API key or token') : 'Enter a header name first'}
                    trailing={
                      feed?.has_auth_value ? (
                        <button type="button" className="text-[12px] font-medium text-accent hover:underline" onClick={() => setD((p) => ({ ...p, secret: 'keep', auth_header_value: '' }))}>
                          Keep stored
                        </button>
                      ) : null
                    }
                  />
                )
              }
            </Field>
          </div>
          {feed?.has_auth_value && (
            <p className="text-[12px] text-fg-subtle">Clearing the header name removes the stored value when you save.</p>
          )}
        </section>
        <button type="submit" hidden />
      </form>
    </Drawer>
  );
};
