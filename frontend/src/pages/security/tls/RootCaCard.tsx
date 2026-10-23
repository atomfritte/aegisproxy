import React, { useState } from 'react';
import { CalendarClock, ChevronDown, Download, FileKey, Fingerprint } from 'lucide-react';
import { api, publicBaseUrl } from '../../../api';
import { cn } from '../../../lib/cn';
import { formatDate, formatDuration, toTime } from '../../../lib/format';
import { useAsync, useNow } from '../../../lib/hooks';
import type { CAInfo } from '../../../types';
import { Badge, buttonClass, Callout, Card, CardHeader, CodeBlock, CopyButton, Skeleton, Tone, Tooltip } from '../../../ui';
import { commonName, installCommands, parseDN } from './ca';

/** Validity badge: green, amber within 90 days, red when expired. */
export const CaValidityBadge: React.FC<{ ca: Pick<CAInfo, 'not_before' | 'not_after'> }> = ({ ca }) => {
  const now = useNow();
  const end = toTime(ca.not_after);
  if (end === null) return null;
  const left = end - now;
  const tone: Tone = left < 0 ? 'danger' : left < 90 * 86_400_000 ? 'warning' : 'success';
  const label = left < 0 ? `Expired ${formatDuration(left)} ago` : left < 90 * 86_400_000 ? `Expires in ${formatDuration(left)}` : `Valid until ${formatDate(ca.not_after)}`;
  return (
    <Tooltip content={`Valid ${formatDate(ca.not_before)} – ${formatDate(ca.not_after)}`}>
      <Badge tone={tone} icon={CalendarClock}>
        {label}
      </Badge>
    </Tooltip>
  );
};

/** Long hex fingerprint with copy button, broken into readable groups. */
export const FingerprintValue: React.FC<{ value: string; className?: string }> = ({ value, className }) => (
  <div className={cn('flex items-start gap-1.5', className)}>
    <code className="min-w-0 flex-1 break-all rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-[11.5px] leading-5 text-fg">{value}</code>
    <CopyButton text={value} label="Copy fingerprint" />
  </div>
);

const Row: React.FC<{ label: React.ReactNode; children: React.ReactNode }> = ({ label, children }) => (
  <div className="min-w-0">
    <dt className="text-[12px] font-medium text-fg-subtle">{label}</dt>
    <dd className="mt-1 min-w-0 text-[13px] text-fg">{children}</dd>
  </div>
);

/** Enterprise root CA: identity, validity, fingerprint, downloads, installers and PEM. */
export const RootCaCard: React.FC = () => {
  const { data: ca, error, loading } = useAsync(() => api.public.caInfo(), []);
  const [showPem, setShowPem] = useState(false);
  const base = publicBaseUrl(ca?.public_url);
  const cmds = installCommands(base);
  const subject = ca ? parseDN(ca.subject) : {};
  const selfSigned = ca && ca.subject === ca.issuer;

  return (
    <Card>
      <CardHeader
        icon={FileKey}
        title="Enterprise root CA"
        description="Servers must trust this certificate so the proxy can inspect HTTPS. Compare the fingerprint before installing it anywhere."
        actions={ca ? <CaValidityBadge ca={ca} /> : null}
      />
      <div className="p-[var(--card-p)]">
        {loading && !ca ? (
          <div className="grid gap-6 lg:grid-cols-2">
            <div className="space-y-3">
              <Skeleton className="h-5 w-2/3" />
              <Skeleton className="h-4 w-1/2" />
              <Skeleton className="h-10 w-full" />
            </div>
            <Skeleton className="h-32" />
          </div>
        ) : error || !ca ? (
          <Callout tone="danger" title="Could not load the root CA">
            {error || 'The control plane did not return certificate details.'}
          </Callout>
        ) : (
          <div className="grid gap-x-8 gap-y-6 lg:grid-cols-2">
            <div className="min-w-0 space-y-5">
              <dl className="grid gap-4 sm:grid-cols-2">
                <div className="sm:col-span-2">
                  <dt className="text-[12px] font-medium text-fg-subtle">Subject</dt>
                  <dd className="mt-1 min-w-0">
                    <div className="text-[14px] font-semibold text-fg">{commonName(ca.subject)}</div>
                    <div className="mt-0.5 break-words text-[12px] leading-5 text-fg-muted">{[subject.O, subject.OU, subject.C].filter(Boolean).join(' · ')}</div>
                  </dd>
                </div>
                <Row label="Issuer">{selfSigned ? <span className="text-fg-muted">Self-signed</span> : <span className="break-words">{commonName(ca.issuer)}</span>}</Row>
                <Row label="Validity">
                  <span className="tabular">
                    {formatDate(ca.not_before)} – {formatDate(ca.not_after)}
                  </span>
                </Row>
                <Row label="Serial number">
                  <span className="break-all font-mono text-[12px]">{ca.serial}</span>
                </Row>
                <div className="sm:col-span-2">
                  <dt className="flex items-center gap-1.5 text-[12px] font-medium text-fg-subtle">
                    <Fingerprint className="h-3.5 w-3.5" aria-hidden />
                    SHA-256 fingerprint
                  </dt>
                  <dd className="mt-1">
                    <FingerprintValue value={ca.fingerprint} />
                  </dd>
                </div>
              </dl>
              <div>
                <div className="mb-2 text-[12px] font-medium text-fg-subtle">Download</div>
                <div className="flex flex-wrap gap-2">
                  <a href={api.public.caDownloadUrl('crt')} download="aegis-enterprise-ca.crt" className={buttonClass('primary', 'sm')}>
                    <Download className="h-4 w-4" aria-hidden />
                    Certificate (.crt)
                  </a>
                  <a href={api.public.caDownloadUrl('pem')} download="aegis-enterprise-ca.pem" className={buttonClass('secondary', 'sm')}>
                    PEM
                  </a>
                  <a href={api.public.caDownloadUrl('der')} download="aegis-enterprise-ca.der" className={buttonClass('secondary', 'sm')}>
                    DER (Windows)
                  </a>
                </div>
              </div>
            </div>

            <div className="min-w-0 space-y-3">
              <div>
                <div className="text-[13px] font-semibold text-fg">Install on servers</div>
                <p className="mt-0.5 text-[12.5px] leading-5 text-fg-muted">
                  The installers verify the fingerprint above before adding the CA to the system trust store.
                </p>
              </div>
              <CodeBlock title="Linux (run as root)" code={cmds.linux} wrap />
              <CodeBlock title="Windows (Administrator PowerShell)" code={cmds.windows} wrap />
              <button
                type="button"
                aria-expanded={showPem}
                onClick={() => setShowPem((s) => !s)}
                className="inline-flex items-center gap-1.5 text-[12.5px] font-medium text-accent hover:underline"
              >
                <ChevronDown className={cn('h-3.5 w-3.5 transition-transform', showPem && 'rotate-180')} aria-hidden />
                {showPem ? 'Hide certificate (PEM)' : 'Show certificate (PEM)'}
              </button>
              {showPem && <CodeBlock title="aegis-enterprise-ca.pem" code={ca.pem_content} maxHeight={240} />}
            </div>
          </div>
        )}
      </div>
    </Card>
  );
};
