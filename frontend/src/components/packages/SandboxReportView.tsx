import React from 'react';
import type { LucideIcon } from 'lucide-react';
import { Bug, FileWarning, Globe, KeyRound, Network, Play, ShieldAlert, TerminalSquare } from 'lucide-react';
import { cn } from '../../lib/cn';
import { formatNumber } from '../../lib/format';
import { Badge, StatusChip, Tone } from '../../ui';
import { RelativeTime } from '../../ui/Time';
import type { PackageFinding, PackageSandboxResult } from '../../types';
import { riskTone, syscallTotal } from './packageUtils';

const STATUS_TONE: Record<string, Tone> = {
  completed: 'success',
  running: 'info',
  queued: 'neutral',
  skipped: 'neutral',
  failed: 'danger',
};

const Section: React.FC<{ icon: LucideIcon; title: React.ReactNode; count?: number; children: React.ReactNode; tone?: Tone }> = ({ icon: Icon, title, count, children, tone = 'neutral' }) => (
  <section className="min-w-0">
    <h4 className="mb-1.5 flex items-center gap-2 text-[12.5px] font-semibold text-fg">
      <Icon className={cn('h-4 w-4 shrink-0', tone === 'danger' ? 'text-danger' : 'text-fg-muted')} aria-hidden />
      {title}
      {count !== undefined && <Badge tone={count > 0 ? tone : 'neutral'} size="sm">{formatNumber(count)}</Badge>}
    </h4>
    {children}
  </section>
);

const MonoList: React.FC<{ items: string[]; tone?: 'default' | 'danger' | 'warning'; empty: string; max?: number }> = ({ items, tone = 'default', empty, max = 50 }) => {
  if (items.length === 0) return <p className="text-[12.5px] text-fg-subtle">{empty}</p>;
  const shown = items.slice(0, max);
  return (
    <ul className="space-y-1">
      {shown.map((it, i) => (
        <li
          key={`${it}-${i}`}
          className={cn(
            'break-all rounded border px-2 py-1 font-mono text-[12px] leading-5',
            tone === 'danger' ? 'border-danger-border bg-danger-soft text-fg' : tone === 'warning' ? 'border-warning-border bg-warning-soft text-fg' : 'border-border bg-surface-2 text-fg'
          )}
        >
          {it}
        </li>
      ))}
      {items.length > shown.length && <li className="text-[12px] text-fg-subtle">+{items.length - shown.length} more</li>}
    </ul>
  );
};

/** Histogram of the aggregate system-call counts (top calls), token-colored, readable in both themes. */
const SyscallHistogram: React.FC<{ counts: Record<string, number> }> = ({ counts }) => {
  const entries = Object.entries(counts)
    .filter(([, v]) => v > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 16);
  if (entries.length === 0) return <p className="text-[12.5px] text-fg-subtle">No system calls were recorded.</p>;
  const max = entries[0][1] || 1;
  // file / network / process calls read as more sensitive — tint them.
  const tintOf = (name: string): string => {
    if (/^(connect|sendto|sendmsg|recvfrom|socket|getaddrinfo)/.test(name)) return 'bg-info-solid';
    if (/^(execve|fork|clone|vfork|ptrace)/.test(name)) return 'bg-warning-solid';
    if (/^(unlink|chmod|chown|rename|open|openat|write)/.test(name)) return 'bg-violet-solid';
    return 'bg-accent';
  };
  return (
    <ul className="space-y-1">
      {entries.map(([name, count]) => (
        <li key={name} className="flex items-center gap-2 text-[12px]">
          <span className="w-28 shrink-0 truncate font-mono text-fg" title={name}>
            {name}
          </span>
          <span className="relative h-3.5 min-w-0 flex-1 overflow-hidden rounded bg-surface-3">
            <span className={cn('absolute inset-y-0 left-0 rounded', tintOf(name))} style={{ width: `${Math.max(3, (count / max) * 100)}%` }} aria-hidden />
          </span>
          <span className="w-14 shrink-0 text-right tabular text-fg-muted">{formatNumber(count)}</span>
        </li>
      ))}
    </ul>
  );
};

/** Sandbox behaviour summary: web addresses contacted, syscall histogram, processes, files, canaries and findings. */
export const SandboxReportView: React.FC<{ result?: PackageSandboxResult | null; findings?: PackageFinding[] | null }> = ({ result, findings }) => {
  if (!result) {
    return (
      <div className="rounded-lg border border-border bg-surface-2 px-3 py-6 text-center text-[13px] text-fg-muted">
        <ShieldAlert className="mx-auto mb-2 h-5 w-5 text-fg-subtle" aria-hidden />
        No sandbox analysis has run for this version.
      </div>
    );
  }

  const urls = result.urls ?? [];
  const hosts = result.hosts ?? [];
  const dns = result.dns_names ?? [];
  const reach = urls.length > 0 ? urls : hosts.length > 0 ? hosts : dns;
  const procs = result.processes ?? [];
  const files = result.files_written ?? [];
  const secrets = result.secrets_read ?? [];
  const canary = result.canary_hits ?? 0;
  const list = (findings ?? []).slice().sort((a, b) => sevRank(b.severity) - sevRank(a.severity));

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2 text-[12px] text-fg-muted">
        <StatusChip tone={STATUS_TONE[result.status] ?? 'neutral'} label={result.status === 'completed' ? 'Analysis complete' : result.status} />
        {result.driver && <Badge tone="neutral" size="sm">{result.driver}</Badge>}
        {result.finished_at && <RelativeTime value={result.finished_at} prefix="finished" />}
        <span className="inline-flex items-center gap-1">
          <Network className="h-3.5 w-3.5" aria-hidden /> {formatNumber(syscallTotal(result.syscall_counts))} syscalls
        </span>
      </div>

      {result.error && (
        <p className="rounded-md border border-danger-border bg-danger-soft px-3 py-2 font-mono text-[12px] text-fg [overflow-wrap:anywhere]">{result.error}</p>
      )}

      {canary > 0 && (
        <div className="flex items-start gap-2 rounded-lg border border-danger-border bg-danger-soft px-3 py-2.5 text-[13px]">
          <Bug className="mt-0.5 h-4 w-4 shrink-0 text-danger" aria-hidden />
          <span className="text-fg">
            <span className="font-semibold text-danger">{formatNumber(canary)} canary {canary === 1 ? 'credential' : 'credentials'} touched.</span> Bait secrets planted in the sandbox were read or exfiltrated — a strong malware signal.
          </span>
        </div>
      )}

      <Section icon={Globe} title="Web addresses contacted" count={reach.length} tone={reach.length ? 'warning' : 'neutral'}>
        <MonoList items={reach} tone={reach.length ? 'warning' : 'default'} empty="The package made no outbound requests in the sandbox." />
        {urls.length === 0 && hosts.length > 0 && <p className="mt-1 text-[11.5px] text-fg-subtle">Hosts shown (no full URLs captured).</p>}
      </Section>

      <Section icon={Network} title="System calls" tone="info">
        <SyscallHistogram counts={result.syscall_counts ?? {}} />
      </Section>

      <Section icon={Play} title="Spawned processes" count={procs.length} tone="warning">
        <MonoList items={procs} tone={procs.length ? 'warning' : 'default'} empty="No child processes were spawned." />
      </Section>

      <Section icon={FileWarning} title="Files written" count={files.length}>
        <MonoList items={files} empty="No files were written outside the package directory." />
      </Section>

      <Section icon={KeyRound} title="Secrets read" count={secrets.length} tone="danger">
        <MonoList items={secrets} tone="danger" empty="No sensitive files or bait credentials were read." />
      </Section>

      <Section icon={ShieldAlert} title="Findings" count={list.length} tone="danger">
        {list.length === 0 ? (
          <p className="text-[12.5px] text-fg-subtle">No findings were raised.</p>
        ) : (
          <ul className="space-y-2">
            {list.map((f) => (
              <li key={f.id} className="rounded-lg border border-border bg-surface-2 p-2.5">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={riskTone(f.severity)} size="sm">{f.severity}</Badge>
                  <span className="text-[13px] font-medium text-fg">{f.title}</span>
                  <Badge tone="neutral" size="sm">{f.category}</Badge>
                  <Badge tone="neutral" size="sm">{f.source}</Badge>
                </div>
                {f.detail && <p className="mt-1 text-[12.5px] leading-5 text-fg-muted [overflow-wrap:anywhere]">{f.detail}</p>}
              </li>
            ))}
          </ul>
        )}
      </Section>
    </div>
  );
};

function sevRank(s?: string): number {
  return { critical: 5, high: 4, medium: 3, unknown: 3, low: 2, info: 1, none: 0 }[s ?? ''] ?? 0;
}
