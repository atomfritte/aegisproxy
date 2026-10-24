import React from 'react';
import { Minus, Pencil, Plus, Settings2 } from 'lucide-react';
import type { PolicyDiff, PolicyRule, PolicySetSpec } from '../types';
import { cn } from '../lib/cn';
import { formatDateTime } from '../lib/format';
import { Badge } from './Badge';
import { EmptyState } from './EmptyState';
import { MethodList, PatternText } from './Pattern';

export const DIFF_FIELD_LABELS: Record<string, string> = {
  name: 'Name',
  description: 'Description',
  owner_team: 'Owner team',
  tags: 'Tags',
  priority: 'Priority',
  enabled: 'Enabled',
  group_ids: 'Assigned groups',
  server_ids: 'Assigned servers',
  review_interval_days: 'Review interval (days)',
  action: 'Action',
  host_pattern: 'Host pattern',
  path_pattern: 'Path pattern',
  methods: 'Methods',
  follow_redirects: 'Follow redirects',
  redirect_hosts: 'Redirect targets',
  companion_rules: 'Companion rules',
  expires_at: 'Expires',
};

export type DiffValueFormatter = (field: string, value: unknown) => React.ReactNode | undefined;

function defaultFormat(field: string, value: unknown): React.ReactNode {
  if (value === null || value === undefined || value === '') return <span className="text-fg-subtle">—</span>;
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (field === 'expires_at' && typeof value === 'string') return formatDateTime(value);
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="text-fg-subtle">none</span>;
    return (
      <span className="inline-flex flex-wrap gap-1">
        {value.map((v) => (
          <span key={String(v)} className="rounded bg-surface-3 px-1.5 py-0.5 font-mono text-[11.5px]">
            {String(v)}
          </span>
        ))}
      </span>
    );
  }
  return String(value);
}

const ruleField = (r: PolicyRule | undefined, f: string): unknown => (r ? (r as unknown as Record<string, unknown>)[f] : undefined);

export interface DiffViewProps {
  diff: PolicyDiff | null | undefined;
  /** Specs on both sides: enables old → new values for set-level changes. */
  from?: PolicySetSpec | null;
  to?: PolicySetSpec | null;
  /** Custom value rendering (e.g. group ids → names). Return undefined for the default. */
  formatValue?: DiffValueFormatter;
  emptyTitle?: string;
  emptyDescription?: React.ReactNode;
  className?: string;
}

/** Rule-level rendering of a backend PolicyDiff: summary, changed settings, added/removed/modified rules. */
export const DiffView: React.FC<DiffViewProps> = ({ diff, from, to, formatValue, emptyTitle = 'No changes', emptyDescription, className }) => {
  const fmt = (field: string, v: unknown) => formatValue?.(field, v) ?? defaultFormat(field, v);
  const meta = diff?.metadata ?? [];
  const rules = diff?.rules ?? [];
  if (!diff || (meta.length === 0 && rules.length === 0)) {
    return <EmptyState title={emptyTitle} description={emptyDescription} size="sm" className={className} />;
  }
  const order = { added: 0, modified: 1, removed: 2 } as const;
  const sortedRules = [...rules].sort((a, b) => order[a.op] - order[b.op]);

  return (
    <div className={cn('space-y-4', className)}>
      <div className="flex flex-wrap items-center gap-2">
        {diff.added > 0 && (
          <Badge tone="success" icon={Plus}>
            {diff.added} added
          </Badge>
        )}
        {diff.modified > 0 && (
          <Badge tone="warning" icon={Pencil}>
            {diff.modified} modified
          </Badge>
        )}
        {diff.removed > 0 && (
          <Badge tone="danger" icon={Minus}>
            {diff.removed} removed
          </Badge>
        )}
        {meta.length > 0 && (
          <Badge tone="info" icon={Settings2}>
            {meta.length} setting{meta.length === 1 ? '' : 's'} changed
          </Badge>
        )}
      </div>

      {meta.length > 0 && (
        <section className="overflow-hidden rounded-lg border border-border">
          <h3 className="border-b border-border bg-surface-2 px-4 py-2 text-[12.5px] font-semibold text-fg">Set settings</h3>
          <ul className="divide-y divide-border">
            {meta.map((f) => (
              <li key={f} className="grid gap-1 px-4 py-2.5 text-[13px] sm:grid-cols-[180px_1fr]">
                <span className="font-medium text-fg-muted">{DIFF_FIELD_LABELS[f] || f}</span>
                {from || to ? (
                  <span className="flex min-w-0 flex-wrap items-center gap-2">
                    <span className="rounded bg-danger-soft px-1.5 py-0.5 text-danger line-through decoration-danger/50">
                      {fmt(f, (from as unknown as Record<string, unknown> | undefined)?.[f])}
                    </span>
                    <span className="text-fg-subtle" aria-label="changed to">
                      →
                    </span>
                    <span className="rounded bg-success-soft px-1.5 py-0.5 text-success">{fmt(f, (to as unknown as Record<string, unknown> | undefined)?.[f])}</span>
                  </span>
                ) : (
                  <span className="text-fg-subtle">changed</span>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}

      {sortedRules.length > 0 && (
        <section className="space-y-2">
          {sortedRules.map((c) => {
            const r = c.after || c.before;
            const tone = c.op === 'added' ? 'success' : c.op === 'removed' ? 'danger' : 'warning';
            const bar = c.op === 'added' ? 'bg-success-solid' : c.op === 'removed' ? 'bg-danger-solid' : 'bg-warning-solid';
            return (
              <article key={`${c.op}-${c.rule_id}`} className="relative overflow-hidden rounded-lg border border-border bg-surface">
                <span className={cn('absolute inset-y-0 left-0 w-[3px]', bar)} aria-hidden />
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 px-4 py-2.5">
                  <Badge tone={tone} icon={c.op === 'added' ? Plus : c.op === 'removed' ? Minus : Pencil}>
                    {c.op === 'added' ? 'Added' : c.op === 'removed' ? 'Removed' : 'Modified'}
                  </Badge>
                  <Badge tone={r?.action === 'BLOCK' ? 'danger' : 'success'} variant="outline">
                    {r?.action || 'ALLOW'}
                  </Badge>
                  <span className={cn('min-w-0 text-[13px] font-medium text-fg', c.op === 'removed' && 'line-through decoration-fg-subtle')}>{r?.name || c.rule_id}</span>
                  <PatternText host={r?.host_pattern || ''} path={r?.path_pattern} className="min-w-0 max-w-full" />
                  {c.op !== 'modified' && <MethodList methods={r?.methods} />}
                </div>
                {c.op === 'modified' && (c.fields?.length ?? 0) > 0 && (
                  <ul className="divide-y divide-border border-t border-border bg-surface-2/60">
                    {c.fields!.map((f) => (
                      <li key={f} className="grid gap-1 px-4 py-2 text-[12.5px] sm:grid-cols-[160px_1fr]">
                        <span className="font-medium text-fg-muted">{DIFF_FIELD_LABELS[f] || f}</span>
                        <span className="flex min-w-0 flex-wrap items-center gap-2">
                          <span className="min-w-0 break-all rounded bg-danger-soft px-1.5 py-0.5 text-danger line-through decoration-danger/50">
                            {fmt(f, ruleField(c.before, f))}
                          </span>
                          <span className="text-fg-subtle" aria-label="changed to">
                            →
                          </span>
                          <span className="min-w-0 break-all rounded bg-success-soft px-1.5 py-0.5 text-success">{fmt(f, ruleField(c.after, f))}</span>
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </article>
            );
          })}
        </section>
      )}
    </div>
  );
};
