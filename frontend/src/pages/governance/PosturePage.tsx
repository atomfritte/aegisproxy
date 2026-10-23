import React, { useMemo } from 'react';
import { BookOpen, Lock, RefreshCw, ShieldCheck } from 'lucide-react';
import { api } from '../../api';
import { usePermissions } from '../../data/AppData';
import { cn } from '../../lib/cn';
import { useAsync, useDocumentTitle } from '../../lib/hooks';
import { useSearchParams } from '../../lib/router';
import type { PostureCheck, PostureStatus } from '../../types';
import { Badge, Button, Callout, Card, CopyButton, EmptyState, PageHeader, RelativeTime, SegmentedControl, Skeleton, StatusChip } from '../../ui';
import { categoryMeta, CATEGORY_META, ScoreRing, scoreBand, STATUS_META } from './posture/postureMeta';

type Filter = 'all' | 'attention' | PostureStatus;
const FILTERS: Filter[] = ['all', 'attention', 'fail', 'warn', 'pass', 'info'];
const CATEGORY_ORDER = Object.keys(CATEGORY_META);

const CheckRow: React.FC<{ check: PostureCheck }> = ({ check: c }) => {
  const m = STATUS_META[c.status] ?? STATUS_META.info;
  const Icon = m.icon;
  const tone = { danger: 'text-danger', warning: 'text-warning', info: 'text-info', success: 'text-success' }[m.tone as 'danger' | 'warning' | 'info' | 'success'];
  return (
    <li className="flex gap-3 px-[var(--card-p)] py-3.5" data-testid={`posture-check-${c.id}`}>
      <Icon className={cn('mt-0.5 h-[18px] w-[18px] shrink-0', tone)} aria-hidden />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-start justify-between gap-x-3 gap-y-1">
          <h3 className="min-w-0 text-[13.5px] font-medium leading-5 text-fg">{c.title}</h3>
          <StatusChip tone={m.tone} label={m.label} className="shrink-0" />
        </div>
        {c.detail && <p className="mt-0.5 text-[12.5px] leading-5 text-fg-muted [overflow-wrap:anywhere]">{c.detail}</p>}
        {c.remediation && c.status !== 'pass' && (
          <div className="mt-2 rounded-md border border-border bg-surface-2 px-3 py-2 text-[12.5px] leading-5">
            <span className="font-medium text-fg">How to fix: </span>
            <span className="text-fg-muted">{c.remediation}</span>
          </div>
        )}
        {c.doc_link && c.status !== 'pass' && (
          <p className="mt-1.5 flex items-center gap-1.5 text-[12px] text-fg-subtle">
            <BookOpen className="h-3.5 w-3.5 shrink-0" aria-hidden />
            Operator documentation:
            {c.doc_url ? (
              <a href={c.doc_url} target="_blank" rel="noreferrer noopener" className="min-w-0 truncate text-accent underline-offset-2 hover:underline">
                {c.doc_link}
              </a>
            ) : (
              <>
                <code className="min-w-0 truncate font-mono text-fg-muted" title={c.doc_link}>
                  {c.doc_link}
                </code>
                <CopyButton text={c.doc_link} size="xs" label="Copy documentation path" />
              </>
            )}
          </p>
        )}
      </div>
    </li>
  );
};

/** /posture — hardening checks of the deployment (InfoSec / Super Admin). */
export const PosturePage: React.FC = () => {
  useDocumentTitle('Security posture');
  const perms = usePermissions();
  if (!perms.canManageSystem) {
    return (
      <>
        <PageHeader title="Security posture" description="Hardening checks of this AegisProxy deployment." />
        <Card>
          <EmptyState icon={Lock} title="Restricted" description="Only InfoSec Approvers and Super Admins can view the security posture of the deployment." />
        </Card>
      </>
    );
  }
  return <Posture />;
};

const Posture: React.FC = () => {
  const data = useAsync(() => api.system.posture(), []);
  const [params, setParams] = useSearchParams();
  const raw = params.get('status') as Filter | null;
  const filter: Filter = raw && FILTERS.includes(raw) ? raw : 'all';
  const checks = useMemo(() => data.data?.checks ?? [], [data.data]);
  const counts = useMemo(() => {
    const c: Record<PostureStatus, number> = { pass: 0, warn: 0, fail: 0, info: 0 };
    for (const x of checks) c[x.status] = (c[x.status] ?? 0) + 1;
    return c;
  }, [checks]);
  const visible = checks.filter((c) => filter === 'all' || (filter === 'attention' ? c.status === 'fail' || c.status === 'warn' : c.status === filter));
  const groups = useMemo(() => {
    const m = new Map<string, PostureCheck[]>();
    for (const c of visible) m.set(c.category, [...(m.get(c.category) ?? []), c]);
    for (const list of m.values()) list.sort((a, b) => STATUS_META[a.status].order - STATUS_META[b.status].order);
    return [...m.entries()].sort((a, b) => (CATEGORY_ORDER.indexOf(a[0]) + 99) % 99 - (CATEGORY_ORDER.indexOf(b[0]) + 99) % 99);
  }, [visible]);
  const score = data.data?.score ?? 0;
  const band = scoreBand(score);
  const setFilter = (f: Filter) => setParams({ status: f === 'all' ? null : f });

  return (
    <>
      <PageHeader
        title="Security posture"
        description="Hardening checks of this deployment — transport security, identity, secrets, detection coverage and governance — with concrete remediation. Re-run after every change."
        actions={
          <Button icon={RefreshCw} onClick={() => data.reload()} loading={data.loading && !!data.data}>
            Re-run checks
          </Button>
        }
      />
      {data.error && !data.data && (
        <Callout tone="danger" title="The posture report could not be loaded" action={<Button size="sm" onClick={() => data.reload()}>Try again</Button>}>
          {data.error}
        </Callout>
      )}
      {!data.data && !data.error && (
        <div className="space-y-4" role="status" aria-label="Loading">
          <Skeleton className="h-44" />
          <Skeleton className="h-64" />
        </div>
      )}
      {data.data && (
        <div className="space-y-6">
          <Card>
            <div className="flex flex-col gap-6 p-[var(--card-p)] md:flex-row md:items-center">
              <ScoreRing score={score} />
              <div className="min-w-0 flex-1 space-y-3">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="text-[17px] font-semibold text-fg">Posture score</h2>
                    <StatusChip tone={band.tone} label={band.label} />
                  </div>
                  <p className="mt-1 max-w-2xl text-[13px] leading-5 text-fg-muted">
                    Each check counts equally: passed checks score fully, warnings half, failures nothing; informational checks are not scored. Generated{' '}
                    <RelativeTime value={data.data.generated_at} />.
                  </p>
                </div>
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-4" role="group" aria-label="Filter by status">
                  {(['fail', 'warn', 'pass', 'info'] as PostureStatus[]).map((st) => {
                    const m = STATUS_META[st];
                    const Icon = m.icon;
                    const active = filter === st;
                    return (
                      <button
                        key={st}
                        type="button"
                        aria-pressed={active}
                        onClick={() => setFilter(active ? 'all' : st)}
                        className={cn(
                          'flex items-center gap-2.5 rounded-lg border px-3 py-2 text-left transition-colors',
                          active ? 'border-accent bg-accent-soft ring-1 ring-accent' : 'border-border bg-surface hover:border-border-strong hover:bg-surface-2'
                        )}
                      >
                        <Icon
                          className={cn('h-4 w-4 shrink-0', { danger: 'text-danger', warning: 'text-warning', info: 'text-info', success: 'text-success' }[m.tone as string])}
                          aria-hidden
                        />
                        <span className="min-w-0">
                          <span className="block text-[18px] font-semibold leading-6 text-fg">{counts[st]}</span>
                          <span className="block text-[12px] text-fg-muted">{m.plural}</span>
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>
          </Card>

          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <SegmentedControl<Filter>
              aria-label="Show checks"
              value={filter}
              onChange={setFilter}
              className="max-w-full flex-wrap"
              options={[
                { value: 'all', label: `All (${checks.length})` },
                { value: 'attention', label: `Needs attention (${counts.fail + counts.warn})` },
                { value: 'fail', label: 'Failing' },
                { value: 'warn', label: 'Warnings' },
                { value: 'pass', label: 'Passed' },
              ]}
            />
            <span className="text-[12.5px] text-fg-subtle">
              {visible.length} of {checks.length} checks
            </span>
          </div>

          {groups.length === 0 ? (
            <Card>
              <EmptyState
                icon={ShieldCheck}
                title={filter === 'attention' || filter === 'fail' || filter === 'warn' ? 'Nothing needs attention' : 'No checks match'}
                description={filter === 'attention' || filter === 'fail' ? 'Every scored check passes. Re-run the checks after configuration changes.' : 'Choose another filter.'}
                action={
                  filter !== 'all' && (
                    <Button size="sm" onClick={() => setFilter('all')}>
                      Show all checks
                    </Button>
                  )
                }
              />
            </Card>
          ) : (
            <div className="gap-5 xl:columns-2 [&>*]:mb-5 [&>*]:break-inside-avoid">
              {groups.map(([cat, list]) => {
                const meta = categoryMeta(cat);
                const Icon = meta.icon;
                const fails = list.filter((c) => c.status === 'fail').length;
                const warns = list.filter((c) => c.status === 'warn').length;
                return (
                  <Card as="section" key={cat} aria-labelledby={`posture-${cat}`}>
                    <div className="flex items-start justify-between gap-3 border-b border-border px-[var(--card-p)] py-3.5">
                      <div className="flex min-w-0 items-start gap-2.5">
                        <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-surface-3 text-fg-muted">
                          <Icon className="h-4 w-4" aria-hidden />
                        </span>
                        <div className="min-w-0">
                          <h2 id={`posture-${cat}`} className="text-[14px] font-semibold leading-6 text-fg">
                            {meta.label}
                          </h2>
                          {meta.description && <p className="text-[12px] text-fg-subtle">{meta.description}</p>}
                        </div>
                      </div>
                      <div className="flex shrink-0 flex-wrap justify-end gap-1">
                        {fails > 0 && <Badge tone="danger">{fails} failing</Badge>}
                        {warns > 0 && <Badge tone="warning">{warns} {warns === 1 ? 'warning' : 'warnings'}</Badge>}
                        {fails + warns === 0 && <Badge tone="success">OK</Badge>}
                      </div>
                    </div>
                    <ul className="divide-y divide-border">
                      {list.map((c) => (
                        <CheckRow key={c.id} check={c} />
                      ))}
                    </ul>
                  </Card>
                );
              })}
            </div>
          )}
        </div>
      )}
    </>
  );
};
