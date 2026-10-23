import React, { useEffect, useState } from 'react';
import { Ban, FileCheck2, History, ScanSearch, ShieldAlert, ShieldCheck } from 'lucide-react';
import { api, errorMessage } from '../../../api';
import { cn } from '../../../lib/cn';
import { pluralize } from '../../../lib/format';
import { Link, useSearchParams } from '../../../lib/router';
import type { ThreatLookupResult } from '../../../types';
import { Badge, Button, ButtonLink, Callout, Card, CardHeader, Input, Spinner } from '../../../ui';
import { MonoValue } from './components';
import { categoryLabel, guessIndicatorType } from './meta';
import { useThreatData } from './useThreatData';

// Recent lookups of this browser session (kept while the console is open).
let recent: string[] = [];

const EXAMPLES = ['https://malware-drop.example/payload/stage2.bin', '203.0.113.66', 'evil.example'];

/** /threats/lookup?value=… — check a URL, domain, IP or SHA-256 against every active source. */
export const LookupTab: React.FC = () => {
  const d = useThreatData();
  const [params, setParams] = useSearchParams();
  const query = (params.get('value') || '').trim();
  const [text, setText] = useState(query);
  const [result, setResult] = useState<ThreatLookupResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => setText(query), [query]);

  useEffect(() => {
    if (!query) {
      setResult(null);
      setError(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    api.security
      .lookup(query)
      .then((r) => {
        if (cancelled) return;
        setResult(r);
        recent = [query, ...recent.filter((x) => x !== query)].slice(0, 8);
      })
      .catch((err) => !cancelled && (setError(errorMessage(err)), setResult(null)))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [query]);

  const submit = (v: string) => {
    const t = v.trim();
    if (!t) return;
    if (t === query && !loading) {
      // re-run the same lookup
      setParams({ value: null });
      window.setTimeout(() => setParams({ value: t }), 0);
    } else setParams({ value: t });
  };

  const matches = result?.matches ?? [];
  const kind = guessIndicatorType(result?.value || query);

  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
      <div className="space-y-5 xl:col-span-2">
        <Card padded>
          <form
            className="flex flex-col gap-2 sm:flex-row"
            onSubmit={(e) => {
              e.preventDefault();
              submit(text);
            }}
          >
            <Input
              icon={ScanSearch}
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="URL, domain, IP address or SHA-256 hash"
              aria-label="Value to look up"
              mono
              className="min-w-0 flex-1"
              autoFocus={!query}
              spellCheck={false}
            />
            <Button type="submit" variant="primary" loading={loading} disabled={!text.trim()}>
              Check
            </Button>
          </form>
          {!query && (
            <div className="mt-3 flex flex-wrap items-center gap-1.5 text-[12px] text-fg-subtle">
              Try
              {EXAMPLES.map((x) => (
                <button key={x} type="button" onClick={() => submit(x)} className="max-w-full truncate rounded border border-dashed border-border-strong px-1.5 py-0.5 font-mono text-fg-muted hover:border-accent hover:text-accent">
                  {x}
                </button>
              ))}
            </div>
          )}
        </Card>

        {error && (
          <Callout tone="danger" title="The lookup failed">
            {error}
          </Callout>
        )}

        {loading && !result && (
          <Card padded className="flex items-center gap-2 text-[13px] text-fg-muted">
            <Spinner /> Checking every source…
          </Card>
        )}

        {result && !error && (
          <Card className={cn('overflow-hidden', loading && 'opacity-60')}>
            <div className={cn('flex flex-col gap-3 p-[var(--card-p)] sm:flex-row sm:items-start', matches.length > 0 && 'border-b', result.malicious ? 'border-danger-border bg-danger-soft' : 'bg-success-soft')}>
              <span className={cn('flex h-10 w-10 shrink-0 items-center justify-center rounded-full', result.malicious ? 'bg-danger-solid text-white' : 'bg-success-solid text-white')}>
                {result.malicious ? <ShieldAlert className="h-5 w-5" aria-hidden /> : <ShieldCheck className="h-5 w-5" aria-hidden />}
              </span>
              <div className="min-w-0 flex-1">
                <p className={cn('text-[15px] font-semibold', result.malicious ? 'text-danger' : 'text-success')}>
                  {result.malicious ? `Malicious — ${pluralize(matches.length, 'match', 'matches')}` : 'No match in any active source'}
                </p>
                <div className="mt-1">
                  <MonoValue value={result.value} />
                </div>
                <p className="mt-1 text-[12px] text-fg-subtle">
                  Snapshot <span className="font-mono">{(result.version || '—').slice(0, 12)}</span>
                  {!result.malicious && d.tiEntries === 0 ? ' · no threat-intel entries are loaded, so only custom indicators were checked' : ''}
                </p>
              </div>
              {d.canManage && (
                <div className="flex shrink-0 flex-wrap gap-2">
                  {result.malicious ? (
                    <ButtonLink
                      size="sm"
                      icon={FileCheck2}
                      to={`/threats/exceptions?new=1&kind=${kind === 'cidr' ? 'ip' : kind}&value=${encodeURIComponent(result.value)}`}
                    >
                      Add exception
                    </ButtonLink>
                  ) : (
                    <ButtonLink size="sm" icon={Ban} to={`/threats/iocs?new=1&kind=${kind}&value=${encodeURIComponent(result.value)}`}>
                      Block as indicator
                    </ButtonLink>
                  )}
                </div>
              )}
            </div>
            {matches.length > 0 && (
              <ul>
                {matches.map((mt, i) => (
                  <li key={`${mt.source_id}-${mt.indicator}-${i}`} className="flex flex-col gap-1 border-t border-border px-[var(--card-p)] py-3 first:border-t-0 sm:flex-row sm:items-center sm:gap-4">
                    <div className="min-w-0 flex-1">
                      <MonoValue value={mt.indicator} tone="danger" />
                      <div className="mt-0.5 text-[12px] text-fg-muted">
                        {mt.source_name || mt.source_id}
                        {mt.source_id && mt.source_name && <span className="font-mono text-fg-subtle"> · {mt.source_id}</span>}
                      </div>
                    </div>
                    <div className="flex shrink-0 flex-wrap gap-1.5">
                      <Badge tone="neutral">{mt.type}</Badge>
                      <Badge tone="danger">{categoryLabel(mt.category)}</Badge>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        )}
      </div>

      <div className="space-y-5">
        <Card>
          <CardHeader title="What is checked" divider />
          <ul className="space-y-2.5 p-[var(--card-p)] text-[12.5px] leading-5 text-fg-muted">
            <li>
              <span className="font-medium text-fg">Domains</span> — exact and parent-domain matches in feeds and custom indicators.
            </li>
            <li>
              <span className="font-medium text-fg">URLs</span> — the canonical URL plus its host.
            </li>
            <li>
              <span className="font-medium text-fg">IP addresses</span> — single IPs and networks (CIDR).
            </li>
            <li>
              <span className="font-medium text-fg">SHA-256</span> — known-malicious file hashes.
            </li>
            <li>Exceptions are applied, so a suppressed value reports no match.</li>
          </ul>
        </Card>
        {recent.length > 0 && (
          <Card>
            <CardHeader title="Recent lookups" icon={History} divider />
            <ul>
              {recent.map((r) => (
                <li key={r} className="border-t border-border first:border-t-0">
                  <Link to={`/threats/lookup?value=${encodeURIComponent(r)}`} replace className={cn('block truncate px-[var(--card-p)] py-2 font-mono text-[12.5px] hover:bg-surface-2', r === query ? 'text-accent' : 'text-fg')}>
                    {r}
                  </Link>
                </li>
              ))}
            </ul>
          </Card>
        )}
      </div>
    </div>
  );
};
