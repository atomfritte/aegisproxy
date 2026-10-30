import React from 'react';
import { Braces, Globe, Play, ShieldAlert } from 'lucide-react';
import { api } from '../../api';
import { formatBytes, formatNumber } from '../../lib/format';
import { useAsync } from '../../lib/hooks';
import type { SandboxPhase, SandboxReport } from '../../types';
import { Badge, Callout, CodeBlock, Drawer, Skeleton } from '../../ui';
import { RelativeTime } from '../../ui/Time';
import { riskTone } from '../../components/packages/packageUtils';

const Row: React.FC<{ label: string; value: React.ReactNode }> = ({ label, value }) => (
  <div className="flex gap-2">
    <dt className="w-28 shrink-0 text-fg-subtle">{label}</dt>
    <dd className="min-w-0 break-all text-fg">{value}</dd>
  </div>
);

const PhaseView: React.FC<{ phase: SandboxPhase }> = ({ phase }) => {
  const http = phase.network?.http ?? [];
  const conns = phase.network?.connections ?? [];
  const dns = phase.network?.dns ?? [];
  const procs = phase.processes ?? [];
  const written = phase.files?.written ?? [];
  const readSensitive = phase.files?.read_sensitive ?? [];
  const canary = phase.canary_hits ?? [];
  const topSyscalls = Object.entries(phase.syscalls?.counts ?? {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);
  return (
    <div className="rounded-lg border border-border bg-surface-2 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone="neutral" icon={Play}>{phase.name}</Badge>
        {phase.skipped ? (
          <Badge tone="neutral">skipped: {phase.skipped}</Badge>
        ) : (
          <>
            <Badge tone={phase.exit_code === 0 ? 'success' : 'warning'}>exit {phase.exit_code}</Badge>
            {phase.timed_out && <Badge tone="danger">timed out</Badge>}
            <span className="text-[12px] text-fg-subtle">{formatNumber(phase.duration_ms)} ms · {formatNumber(phase.syscalls?.total ?? 0)} syscalls</span>
          </>
        )}
      </div>
      {!phase.skipped && (
        <div className="mt-2 space-y-2 text-[12px]">
          {http.length > 0 && (
            <div>
              <p className="mb-1 flex items-center gap-1.5 font-medium text-fg"><Globe className="h-3.5 w-3.5 text-warning" aria-hidden /> HTTP requests</p>
              <ul className="space-y-1">
                {http.slice(0, 40).map((h, i) => (
                  <li key={i} className="break-all rounded border border-warning-border bg-warning-soft px-2 py-1 font-mono text-fg">
                    <span className="font-semibold">{h.method}</span> {h.url}
                    {h.tls && <span className="ml-1 text-fg-subtle">(TLS)</span>}
                    {h.body_size > 0 && <span className="ml-1 text-fg-subtle">· {formatBytes(h.body_size)} body</span>}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {conns.length > 0 && (
            <div>
              <p className="mb-1 font-medium text-fg">Connections</p>
              <ul className="space-y-1">
                {conns.slice(0, 30).map((c, i) => (
                  <li key={i} className="break-all rounded border border-border bg-surface px-2 py-1 font-mono text-fg">
                    {c.protocol} {c.hostname || c.address}:{c.port ?? '—'} {c.result ? `→ ${c.result}` : ''}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {dns.length > 0 && <p className="text-fg-muted">DNS: {dns.slice(0, 20).map((d) => d.name).join(', ')}</p>}
          {topSyscalls.length > 0 && (
            <p className="text-fg-muted">
              <span className="font-medium text-fg">Top syscalls:</span> {topSyscalls.map(([n, c]) => `${n} ${formatNumber(c)}`).join(', ')}
            </p>
          )}
          {procs.length > 0 && (
            <div>
              <p className="mb-1 font-medium text-fg">Processes</p>
              <ul className="space-y-1">
                {procs.slice(0, 20).map((p, i) => (
                  <li key={i} className="break-all rounded border border-border bg-surface px-2 py-1 font-mono text-fg">{(p.argv ?? [p.exe]).join(' ')}</li>
                ))}
              </ul>
            </div>
          )}
          {written.length > 0 && <p className="text-fg-muted"><span className="font-medium text-fg">Files written:</span> {written.slice(0, 20).map((f) => f.path).join(', ')}</p>}
          {readSensitive.length > 0 && <p className="text-danger"><span className="font-medium">Sensitive reads:</span> {readSensitive.slice(0, 20).map((f) => f.path).join(', ')}</p>}
          {canary.length > 0 && (
            <div className="rounded border border-danger-border bg-danger-soft px-2 py-1 text-fg">
              <span className="font-semibold text-danger">Canary hits:</span> {canary.map((c) => `${c.canary} (${c.where})`).join(', ')}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

/** "Raw report" drawer: the full sandbox.Report for one analysis job (structured + raw JSON). */
export const RawReportDrawer: React.FC<{ open: boolean; onClose: () => void; jobId: string | null }> = ({ open, onClose, jobId }) => {
  const { data, error, loading } = useAsync(() => (jobId ? api.packages.analysis.get(jobId) : Promise.resolve(undefined)), [jobId, open]);
  const report = open ? data : undefined;
  return (
    <Drawer open={open} onClose={onClose} width="xl" title="Sandbox report" description={jobId ? `Analysis job ${jobId}` : undefined}>
      {loading && !report && (
        <div className="space-y-3">
          <Skeleton className="h-24" />
          <Skeleton className="h-48" />
        </div>
      )}
      {error && !report && (
        <Callout tone="danger" title="The report could not be loaded">
          {error}
        </Callout>
      )}
      {report && <ReportBody report={report} />}
    </Drawer>
  );
};

const ReportBody: React.FC<{ report: SandboxReport }> = ({ report }) => {
  const indicators = report.static?.indicators ?? [];
  const hooks = report.static?.install_hooks ?? [];
  const findings = (report.findings ?? []).slice().sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
  return (
    <div className="space-y-5">
      <dl className="space-y-1.5 text-[12.5px]">
        <Row label="Driver" value={<>{report.driver} <span className="text-fg-subtle">{report.isolation}</span></>} />
        <Row label="Image" value={<span className="font-mono text-[12px]">{report.image}</span>} />
        <Row label="Artifact" value={<span className="font-mono text-[12px]">{report.artifact?.filename} · {report.artifact?.format} · {formatBytes(report.artifact?.size)}</span>} />
        <Row label="SHA-256" value={<span className="font-mono text-[11.5px]">{report.artifact?.sha256 || '—'}</span>} />
        <Row label="Finished" value={report.finished_at ? <RelativeTime value={report.finished_at} /> : '—'} />
      </dl>

      {report.truncated && <Callout tone="warning">Some lists were capped — see the Dropped counters in the raw JSON.</Callout>}
      {(report.errors ?? []).length > 0 && (
        <Callout tone="danger" title="Runner errors">
          <ul className="list-disc space-y-0.5 pl-4 font-mono text-[12px]">
            {(report.errors ?? []).map((e, i) => (
              <li key={i} className="[overflow-wrap:anywhere]">{e}</li>
            ))}
          </ul>
        </Callout>
      )}

      {findings.length > 0 && (
        <section>
          <h4 className="mb-1.5 flex items-center gap-2 text-[13px] font-semibold text-fg"><ShieldAlert className="h-4 w-4 text-danger" aria-hidden /> Findings</h4>
          <ul className="space-y-2">
            {findings.map((f) => (
              <li key={f.id} className="rounded-lg border border-border bg-surface-2 p-2.5 text-[12.5px]">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={riskTone(f.severity)} size="sm">{f.severity}</Badge>
                  <span className="font-medium text-fg">{f.title}</span>
                  <Badge tone="neutral" size="sm">{f.category}</Badge>
                  {f.phase && <span className="text-[11.5px] text-fg-subtle">{f.phase}</span>}
                </div>
                {f.detail && <p className="mt-1 text-fg-muted [overflow-wrap:anywhere]">{f.detail}</p>}
                {(f.evidence ?? []).length > 0 && (
                  <ul className="mt-1 space-y-0.5 font-mono text-[11.5px] text-fg-subtle">
                    {(f.evidence ?? []).slice(0, 8).map((ev, i) => (
                      <li key={i} className="[overflow-wrap:anywhere]">{ev}</li>
                    ))}
                  </ul>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}

      {indicators.length > 0 && (
        <section>
          <h4 className="mb-1.5 text-[13px] font-semibold text-fg">Static indicators</h4>
          <ul className="space-y-1 text-[12px]">
            {indicators.slice(0, 30).map((ind, i) => (
              <li key={i} className="rounded border border-border bg-surface-2 px-2 py-1">
                <span className="font-medium text-fg">{ind.rule}</span> <Badge tone={riskTone(ind.severity)} size="sm">{ind.severity}</Badge>
                <span className="ml-1 font-mono text-[11.5px] text-fg-subtle">{ind.file}{ind.line ? `:${ind.line}` : ''}</span>
                {ind.description && <span className="block text-fg-muted">{ind.description}</span>}
              </li>
            ))}
          </ul>
        </section>
      )}

      {hooks.length > 0 && (
        <section>
          <h4 className="mb-1.5 text-[13px] font-semibold text-fg">Install / build hooks</h4>
          <ul className="space-y-1 text-[12px]">
            {hooks.map((h, i) => (
              <li key={i} className="rounded border border-warning-border bg-warning-soft px-2 py-1 font-mono text-fg">
                {h.kind} · {h.name}{h.command ? ` → ${h.command}` : ''}
              </li>
            ))}
          </ul>
        </section>
      )}

      {(report.phases ?? []).length > 0 && (
        <section>
          <h4 className="mb-1.5 text-[13px] font-semibold text-fg">Execution phases</h4>
          <div className="space-y-2">
            {(report.phases ?? []).map((p, i) => (
              <PhaseView key={i} phase={p} />
            ))}
          </div>
        </section>
      )}

      <section>
        <h4 className="mb-1.5 flex items-center gap-2 text-[13px] font-semibold text-fg"><Braces className="h-4 w-4 text-fg-muted" aria-hidden /> Raw JSON</h4>
        <CodeBlock title="sandbox.Report" code={safeJson(report)} wrap maxHeight={420} />
      </section>
    </div>
  );
};

function sevRank(s?: string): number {
  return { critical: 5, high: 4, medium: 3, unknown: 3, low: 2, info: 1, none: 0 }[s ?? ''] ?? 0;
}

function safeJson(v: unknown): string {
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}
