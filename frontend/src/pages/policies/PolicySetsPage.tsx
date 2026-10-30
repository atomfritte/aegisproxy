import React, { useMemo } from 'react';
import { Download, FileUp, Globe2, Inbox, Layers, Plus } from 'lucide-react';
import { api } from '../../api';
import { useConsoleState, usePermissions } from '../../data/AppData';
import { useLookups } from '../../data/lookups';
import { cn } from '../../lib/cn';
import { formatCompact, formatNumber } from '../../lib/format';
import { useDocumentTitle } from '../../lib/hooks';
import { Link, useSearchParams } from '../../lib/router';
import { useUrlFilters } from '../../lib/useUrlFilters';
import type { PolicySet, PolicySetKind } from '../../types';
import { Badge, Button, ButtonLink, buttonClass, Column, DataTable, EmptyState, PageHeader, RelativeTime, Tooltip } from '../../ui';
import { ImportPolicySetsDrawer } from './ImportPolicySetsDrawer';
import { AssignmentChips, DraftIndicator, KIND_META, PolicyKindBadge, ReviewStateChip } from '../../components/policy/PolicyBadges';
import { totalHits } from '../../components/policy/policyUtils';

const FILTERS = ['kind', 'review', 'state', 'tag', 'owner', 'group', 'enabled'];
const KIND_ICONS = { baseline: Globe2, standard: Layers, approvals: Inbox };

function setState(s: PolicySet): string {
  if (s.draft?.status === 'in_review') return 'in_review';
  if (s.draft) return 'draft';
  return s.version === 0 ? 'never_published' : 'published';
}

/** Policy sets list: kind summary, search and faceted filters (URL-synced), grouped by kind. */
export const PolicySetsPage: React.FC = () => {
  useDocumentTitle('Policy sets');
  const state = useConsoleState();
  const perms = usePermissions();
  const { groupName } = useLookups();
  const f = useUrlFilters(FILTERS);
  const sets = state.policy_sets ?? [];
  const [params, setParams] = useSearchParams();
  const importing = params.get('import') === '1' && !perms.isReadOnly;
  const setImporting = (v: boolean) => setParams({ import: v ? '1' : null });

  const counts = useMemo(() => {
    const c: Record<PolicySetKind, number> = { baseline: 0, standard: 0, approvals: 0 };
    for (const s of sets) c[s.kind]++;
    return c;
  }, [sets]);

  const columns: Column<PolicySet>[] = [
    {
      id: 'name',
      header: 'Policy set',
      width: '30%',
      sortValue: (s) => s.name.toLowerCase(),
      cell: (s) => (
        <div className="min-w-0">
          <Link to={`/policies/${encodeURIComponent(s.id)}`} className="font-medium text-fg hover:text-accent hover:underline">
            {s.name}
          </Link>
          {s.description && <p className="mt-0.5 line-clamp-1 max-w-[520px] text-[12px] text-fg-subtle">{s.description}</p>}
          {((s.tags ?? []).length > 0 || s.owner_team) && (
            <div className="mt-1 flex flex-wrap items-center gap-1">
              {s.owner_team && <span className="mr-1 text-[12px] text-fg-muted">{s.owner_team}</span>}
              {(s.tags ?? []).map((t) => (
                <span key={t} className="rounded bg-surface-3 px-1.5 py-px text-[11px] text-fg-muted">
                  {t}
                </span>
              ))}
            </div>
          )}
        </div>
      ),
    },
    { id: 'kind', header: 'Kind', width: 116, hideBelow: 'xl', sortValue: (s) => s.kind, cell: (s) => <PolicyKindBadge kind={s.kind} /> },
    {
      id: 'version',
      header: 'Version',
      width: 120,
      sortValue: (s) => s.version,
      cell: (s) =>
        s.version === 0 ? (
          <span className="text-[12.5px] text-fg-subtle">Unpublished</span>
        ) : (
          <div className="leading-tight">
            <span className="font-medium tabular text-fg">v{s.version}</span>
            <div className="text-[12px] text-fg-subtle">
              <RelativeTime value={s.published_at} />
            </div>
          </div>
        ),
    },
    {
      id: 'assigned',
      header: 'Assigned to',
      width: '22%',
      cell: (s) => <AssignmentChips kind={s.kind} groupIds={s.group_ids} serverIds={s.server_ids} max={2} />,
    },
    {
      id: 'rules',
      header: 'Rules',
      align: 'right',
      width: 72,
      sortValue: (s) => (s.rules ?? []).length,
      cell: (s) => <span className="tabular text-fg">{formatNumber((s.rules ?? []).length)}</span>,
    },
    {
      id: 'hits',
      header: 'Hits',
      align: 'right',
      width: 80,
      hideBelow: 'xl',
      sortValue: (s) => totalHits(s.rules),
      cell: (s) => (
        <Tooltip content={`${formatNumber(totalHits(s.rules))} matched requests`}>
          <span className="tabular text-fg-muted">{formatCompact(totalHits(s.rules))}</span>
        </Tooltip>
      ),
    },
    {
      id: 'review',
      header: 'Recertification',
      width: 170,
      sortValue: (s) => ({ overdue: 0, due_soon: 1, ok: 2 }[s.review_state || 'ok'] ?? 3),
      cell: (s) => <ReviewStateChip set={s} />,
    },
    {
      id: 'status',
      header: 'Status',
      width: 120,
      cell: (s) => (
        <span className="flex flex-wrap gap-1">
          <DraftIndicator set={s} />
          {s.version > 0 && !s.enabled && <Badge tone="neutral">Disabled</Badge>}
          {!s.draft && s.enabled && s.version > 0 && <span className="text-[12.5px] text-fg-subtle">Live</span>}
        </span>
      ),
    },
  ];

  const allTags = [...new Set(sets.flatMap((s) => s.tags ?? []))].sort((a, b) => String(a).localeCompare(String(b)));
  const allOwners = [...new Set(sets.map((s) => s.owner_team).filter(Boolean))].sort((a, b) => String(a).localeCompare(String(b)));
  const kindFilter = f.values.kind;

  return (
    <>
      <PageHeader
        title="Policy sets"
        description="Versioned collections of ALLOW and BLOCK rules. Edit a draft, review the impact, then publish — every server picks up the new version within seconds."
        actions={
          <>
            <Tooltip content="Download the published content of every set as JSON (policy as code)">
              <a href={api.policySets.exportUrl()} download className={buttonClass('secondary', 'md')} data-testid="export-policy-sets">
                <Download className="h-4 w-4" aria-hidden />
                Export
              </a>
            </Tooltip>
            {!perms.isReadOnly && (
              <Button icon={FileUp} onClick={() => setImporting(true)}>
                Import
              </Button>
            )}
            {!perms.isReadOnly && (
              <ButtonLink to="/policies/new" variant="primary" icon={Plus}>
                New policy set
              </ButtonLink>
            )}
          </>
        }
      />
      <ImportPolicySetsDrawer open={importing} onClose={() => setImporting(false)} />

      <div className="mb-5 grid grid-cols-3 gap-2 md:gap-3" role="group" aria-label="Filter by kind">
        {(['baseline', 'standard', 'approvals'] as PolicySetKind[]).map((k) => {
          const Icon = KIND_ICONS[k];
          const active = kindFilter.includes(k);
          return (
            <button
              key={k}
              type="button"
              aria-pressed={active}
              onClick={() => f.onChange('kind', active ? kindFilter.filter((x) => x !== k) : [...kindFilter, k])}
              className={cn(
                'flex min-w-0 items-start gap-3 rounded-lg border bg-surface p-2.5 text-left shadow-card transition-colors md:p-3.5',
                active ? 'border-accent ring-1 ring-accent' : 'border-border hover:border-border-strong hover:bg-surface-2'
              )}
            >
              <span
                className={cn(
                  'hidden h-8 w-8 shrink-0 items-center justify-center rounded-md md:flex',
                  k === 'baseline' ? 'bg-violet-soft text-violet' : k === 'standard' ? 'bg-accent-soft text-accent' : 'bg-info-soft text-info'
                )}
              >
                <Icon className="h-4 w-4" aria-hidden />
              </span>
              <span className="min-w-0">
                <span className="flex items-baseline gap-2">
                  <span className="text-[13px] font-semibold text-fg">{KIND_META[k].label}</span>
                  <span className="text-[13px] tabular text-fg-muted">{counts[k]}</span>
                </span>
                <span className="mt-0.5 hidden text-[12px] leading-5 text-fg-muted md:block">{KIND_META[k].description}</span>
              </span>
            </button>
          );
        })}
      </div>

      <DataTable
        rows={sets}
        columns={columns}
        getRowId={(s) => s.id}
        rowHref={(s) => `/policies/${encodeURIComponent(s.id)}`}
        mobileCard={(s) => (
          <div className="min-w-0 space-y-2">
            <div className="flex items-start justify-between gap-2">
              <Link to={`/policies/${encodeURIComponent(s.id)}`} className="min-w-0 font-medium text-fg">
                {s.name}
              </Link>
              <span className="shrink-0 text-[12.5px] tabular text-fg-muted">{s.version ? `v${s.version}` : 'Unpublished'}</span>
            </div>
            {s.description && <p className="line-clamp-2 text-[12.5px] text-fg-subtle">{s.description}</p>}
            <div className="flex flex-wrap items-center gap-1.5">
              <ReviewStateChip set={s} />
              <DraftIndicator set={s} />
              <span className="text-[12px] text-fg-muted">
                {formatNumber((s.rules ?? []).length)} rules, {formatCompact(totalHits(s.rules))} hits
              </span>
            </div>
            <AssignmentChips kind={s.kind} groupIds={s.group_ids} serverIds={s.server_ids} max={3} />
          </div>
        )}
        getSearchText={(s) => `${s.name} ${s.description} ${s.owner_team} ${(s.tags ?? []).join(' ')} ${s.id} ${(s.rules ?? []).map((r) => r.host_pattern).join(' ')}`}
        searchPlaceholder="Search sets, tags, hosts…"
        search={f.search}
        onSearchChange={f.setSearch}
        facetValues={f.values}
        onFacetChange={f.onChange}
        facets={[
          { id: 'kind', label: 'Kind', getValue: (s) => s.kind, options: (['baseline', 'standard', 'approvals'] as const).map((k) => ({ value: k, label: KIND_META[k].label })) },
          {
            id: 'review',
            label: 'Recertification',
            getValue: (s) => (s.version === 0 ? 'never' : s.review_state || 'none'),
            options: [
              { value: 'overdue', label: 'Overdue' },
              { value: 'due_soon', label: 'Due soon' },
              { value: 'ok', label: 'Certified' },
              { value: 'never', label: 'Never published' },
            ],
          },
          {
            id: 'state',
            label: 'Status',
            getValue: setState,
            options: [
              { value: 'draft', label: 'Has draft' },
              { value: 'in_review', label: 'In review' },
              { value: 'published', label: 'Published, no draft' },
              { value: 'never_published', label: 'Never published' },
            ],
          },
          { id: 'tag', label: 'Tag', getValue: (s) => s.tags ?? [], options: allTags.map((t) => ({ value: t, label: t })) },
          { id: 'owner', label: 'Owner team', getValue: (s) => s.owner_team || '', options: allOwners.map((o) => ({ value: o, label: o })) },
          {
            id: 'group',
            label: 'Group',
            getValue: (s) => (s.kind === 'baseline' ? state.groups.map((g) => g.id) : s.group_ids ?? []),
            options: state.groups.map((g) => ({ value: g.id, label: g.name })),
          },
          {
            id: 'enabled',
            label: 'Enabled',
            getValue: (s) => (s.enabled ? 'yes' : 'no'),
            options: [
              { value: 'yes', label: 'Enabled' },
              { value: 'no', label: 'Disabled' },
            ],
          },
        ]}
        groupBy={{
          key: (s) => s.kind,
          label: (k, rows) => (
            <span className="flex items-center gap-2">
              {KIND_META[k as PolicySetKind]?.label ?? k}
              <span className="font-normal text-fg-subtle">{rows.length}</span>
            </span>
          ),
        }}
        empty={
          <EmptyState
            icon={Layers}
            title="No policy sets yet"
            description="Policy sets group the rules that open destinations for your servers. Start with a baseline of guardrails or a set for one team."
            action={
              !perms.isReadOnly && (
                <ButtonLink to="/policies/new" variant="primary" icon={Plus}>
                  New policy set
                </ButtonLink>
              )
            }
          />
        }
        aria-label="Policy sets"
      />
      {f.values.group.length > 0 && (
        <p className="mt-2 text-[12px] text-fg-subtle">Baseline sets apply to every group, so they are included in group filters ({f.values.group.map(groupName).join(', ')}).</p>
      )}
    </>
  );
};
