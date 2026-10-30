import React, { useState } from 'react';
import { Bug, ExternalLink, FileText, FlaskConical, ScrollText, ShieldCheck, Waypoints } from 'lucide-react';
import { formatBytes } from '../../lib/format';
import type { PackageAdvisory, PackageNode, PackageVerification } from '../../types';
import { Badge, Button, Callout, DescriptionList, Drawer } from '../../ui';
import { RelativeTime } from '../../ui/Time';
import { EcosystemBadge, KindBadge } from '../../components/packages/EcosystemBadge';
import { NodeStateChip, RiskBadge } from '../../components/packages/RiskBadge';
import { PackageVerificationChip } from '../../components/packages/PackageVerificationChip';
import { SandboxReportView } from '../../components/packages/SandboxReportView';
import { ageHours, hasMalware, humanHours, nameVersion, riskTone } from '../../components/packages/packageUtils';
import { RawReportDrawer } from './RawReportDrawer';

const Section: React.FC<{ title: React.ReactNode; children: React.ReactNode; className?: string }> = ({ title, children, className }) => (
  <section className={className}>
    <h3 className="mb-2 text-[13px] font-semibold text-fg">{title}</h3>
    {children}
  </section>
);

const AdvisoryItem: React.FC<{ advisory: PackageAdvisory }> = ({ advisory: a }) => (
  <li className={`rounded-lg border p-2.5 ${a.withdrawn ? 'border-border bg-surface-2 opacity-70' : 'border-border bg-surface-2'}`}>
    <div className="flex flex-wrap items-center gap-2">
      <Badge tone={riskTone(a.severity)} size="sm">{a.malware ? 'malware' : a.severity}</Badge>
      {a.url ? (
        <a href={a.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 font-mono text-[12.5px] font-medium text-accent hover:underline">
          {a.id} <ExternalLink className="h-3 w-3" aria-hidden />
        </a>
      ) : (
        <span className="font-mono text-[12.5px] font-medium text-fg">{a.id}</span>
      )}
      <Badge tone="neutral" size="sm">{a.source}</Badge>
      {a.cvss ? <span className="text-[12px] text-fg-subtle">CVSS {a.cvss.toFixed(1)}</span> : null}
      {a.withdrawn && <Badge tone="neutral" size="sm">withdrawn</Badge>}
    </div>
    {a.summary && <p className="mt-1 text-[12.5px] leading-5 text-fg-muted [overflow-wrap:anywhere]">{a.summary}</p>}
    {(a.aliases ?? []).length > 0 && <p className="mt-1 font-mono text-[11.5px] text-fg-subtle">{(a.aliases ?? []).join(', ')}</p>}
  </li>
);

const VerificationDetail: React.FC<{ label: string; icon: React.ReactNode; v?: PackageVerification | null }> = ({ label, icon, v }) => (
  <div className="rounded-lg border border-border bg-surface-2 p-2.5">
    <div className="mb-1 flex items-center gap-2">
      {icon}
      <PackageVerificationChip label={label} verification={v} />
    </div>
    {v && (v.identity || v.source_repo || v.commit || v.workflow || v.key_id || v.kind) ? (
      <dl className="space-y-0.5 text-[11.5px]">
        {v.kind && <Detail k="Kind" val={v.kind} />}
        {v.identity && <Detail k="Identity" val={v.identity} mono />}
        {v.source_repo && <Detail k="Source repo" val={v.source_repo} mono />}
        {v.commit && <Detail k="Commit" val={v.commit} mono />}
        {v.workflow && <Detail k="Workflow" val={v.workflow} mono />}
        {v.key_id && <Detail k="Key id" val={v.key_id} mono />}
      </dl>
    ) : (
      <p className="text-[11.5px] text-fg-subtle">Nothing was verified.</p>
    )}
  </div>
);

const Detail: React.FC<{ k: string; val: string; mono?: boolean }> = ({ k, val, mono }) => (
  <div className="flex gap-2">
    <dt className="w-20 shrink-0 text-fg-subtle">{k}</dt>
    <dd className={`min-w-0 break-all text-fg ${mono ? 'font-mono' : ''}`}>{val}</dd>
  </div>
);

/** Full per-node assessment: advisories, signature + provenance, and the sandbox result. */
export const NodeDrawer: React.FC<{ node: PackageNode | null; onClose: () => void; resolveName: (key: string) => string }> = ({ node, onClose, resolveName }) => {
  const [rawJob, setRawJob] = useState<string | null>(null);
  const a = node?.assessment;
  const age = ageHours(node?.published_at);
  const edges = node?.required_by ?? [];
  const sandboxJob = a?.sandbox?.job_id;

  return (
    <>
      <Drawer
        open={!!node}
        onClose={onClose}
        width="lg"
        title={node ? <span className="break-all font-mono text-[15px]">{nameVersion(node.name, node.version, node.display_name)}</span> : ''}
        titleAside={node ? <span className="flex items-center gap-1.5"><RiskBadge risk={a?.risk} malware={hasMalware(a)} /><NodeStateChip state={node.state} /></span> : undefined}
      >
        {node && (
          <div className="space-y-6">
            {a?.summary && <Callout tone={riskTone(a.risk)}>{a.summary}</Callout>}

            <DescriptionList
              columns={2}
              items={[
                { label: 'Ecosystem', value: <EcosystemBadge ecosystem={node.ecosystem} /> },
                { label: 'Version', value: <span className="font-mono text-[12.5px]">{node.version}</span> },
                {
                  label: 'Kinds',
                  value: (node.kinds ?? []).length ? <span className="flex flex-wrap gap-1">{(node.kinds ?? []).map((k) => <KindBadge key={k} kind={k} />)}</span> : '—',
                },
                { label: 'License', value: node.license || 'Unknown' },
                {
                  label: 'Published',
                  value: node.published_at ? <span>{<RelativeTime value={node.published_at} />}{age !== null ? ` · cooldown ${humanHours(age)}` : ''}</span> : '—',
                },
                {
                  label: 'Flags',
                  value: (
                    <span className="flex flex-wrap gap-1">
                      {node.root && <Badge tone="accent" size="sm">root</Badge>}
                      {node.direct && <Badge tone="info" size="sm">direct</Badge>}
                      {node.deprecated && <Badge tone="warning" size="sm">deprecated</Badge>}
                      {node.yanked && <Badge tone="danger" size="sm">yanked</Badge>}
                      {!node.root && !node.direct && !node.deprecated && !node.yanked && <span className="text-fg-subtle">—</span>}
                    </span>
                  ),
                },
              ]}
            />

            <Section title={<span className="flex items-center gap-2"><Waypoints className="h-4 w-4 text-fg-muted" aria-hidden /> Required by</span>}>
              {edges.length === 0 ? (
                <p className="text-[12.5px] text-fg-subtle">Requested directly (root of this request).</p>
              ) : (
                <ul className="space-y-1 text-[12.5px]">
                  {edges.map((e, i) => (
                    <li key={i} className="flex flex-wrap items-center gap-2 rounded border border-border bg-surface-2 px-2 py-1">
                      <span className="font-mono text-fg">{e.parent ? resolveName(e.parent) : 'root request'}</span>
                      {e.range && <Badge tone="neutral" size="sm">wants {e.range}</Badge>}
                      {e.kind && <KindBadge kind={e.kind} />}
                    </li>
                  ))}
                </ul>
              )}
            </Section>

            <Section title={<span className="flex items-center gap-2"><Bug className="h-4 w-4 text-fg-muted" aria-hidden /> Advisories {a?.advisories?.length ? `(${a.advisories.length})` : ''}</span>}>
              {(a?.advisories ?? []).length === 0 ? (
                <p className="text-[12.5px] text-fg-subtle">
                  No advisories{(a?.sources ?? []).length ? ` across ${(a?.sources ?? []).join(', ')}` : ' from the configured sources'}.
                </p>
              ) : (
                <ul className="space-y-2">
                  {(a?.advisories ?? []).map((adv, i) => (
                    <AdvisoryItem key={`${adv.id}-${i}`} advisory={adv} />
                  ))}
                </ul>
              )}
            </Section>

            <Section title={<span className="flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-fg-muted" aria-hidden /> Signature &amp; provenance</span>}>
              <div className="grid gap-3 sm:grid-cols-2">
                <VerificationDetail label="Signature" icon={<ScrollText className="h-4 w-4 text-fg-subtle" aria-hidden />} v={a?.signature} />
                <VerificationDetail label="Provenance" icon={<FileText className="h-4 w-4 text-fg-subtle" aria-hidden />} v={a?.provenance} />
              </div>
            </Section>

            {(node.files ?? []).length > 0 && (
              <Section title="Pinned files">
                <ul className="space-y-1 text-[12px]">
                  {(node.files ?? []).map((fp) => (
                    <li key={fp.filename} className="rounded border border-border bg-surface-2 px-2 py-1">
                      <span className="break-all font-mono text-fg">{fp.filename}</span>
                      {fp.size ? <span className="ml-1 text-fg-subtle">{formatBytes(fp.size)}</span> : null}
                      {(fp.sha256 || fp.sha512) && <div className="break-all font-mono text-[11px] text-fg-subtle">{fp.sha256 ? `sha256:${fp.sha256}` : `sha512:${fp.sha512}`}</div>}
                    </li>
                  ))}
                </ul>
              </Section>
            )}

            <Section
              title={
                <span className="flex items-center justify-between gap-2">
                  <span className="flex items-center gap-2"><FlaskConical className="h-4 w-4 text-fg-muted" aria-hidden /> Sandbox analysis</span>
                  {sandboxJob && (
                    <Button size="xs" variant="secondary" icon={ScrollText} onClick={() => setRawJob(sandboxJob)}>
                      Raw report
                    </Button>
                  )}
                </span>
              }
            >
              <SandboxReportView result={a?.sandbox} findings={a?.findings} />
            </Section>
          </div>
        )}
      </Drawer>
      <RawReportDrawer open={!!rawJob} onClose={() => setRawJob(null)} jobId={rawJob} />
    </>
  );
};
