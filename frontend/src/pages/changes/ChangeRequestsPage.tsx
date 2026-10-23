import React, { useMemo } from 'react';
import { GitPullRequestArrow, Inbox, ListTodo, UserRound } from 'lucide-react';
import { useConsole, useConsoleState } from '../../data/AppData';
import { useSession } from '../../data/session';
import { formatNumber } from '../../lib/format';
import { useDocumentTitle } from '../../lib/hooks';
import { Link } from '../../lib/router';
import { useUrlFilters } from '../../lib/useUrlFilters';
import type { ChangeRequest } from '../../types';
import { Badge, ButtonLink, Callout, Column, DataTable, EmptyState, PageHeader, RelativeTime, Tabs, useUrlTab } from '../../ui';
import { UserName } from '../../components/common/EntityChips';
import { ChangeRequestStatusChip, changeRequestStatusLabel } from '../../components/policy/PolicyBadges';

const TABS = ['review', 'mine', 'all'] as const;
type Tab = (typeof TABS)[number];

/** Change request inbox: To review (open, not mine) / Mine / All. */
export const ChangeRequestsPage: React.FC = () => {
  useDocumentTitle('Change requests');
  const state = useConsoleState();
  const { perms } = useConsole();
  const { user } = useSession();
  const [tab, setTab] = useUrlTab<Tab>(TABS, 'review');
  const f = useUrlFilters(['status', 'set']);
  const me = (user?.username || '').toLowerCase();
  const all = state.change_requests ?? [];

  const lists = useMemo(
    () => ({
      review: all.filter((c) => c.status === 'open' && c.submitted_by.toLowerCase() !== me),
      mine: all.filter((c) => c.submitted_by.toLowerCase() === me),
      all,
    }),
    [all, me]
  );
  const rows = lists[tab];

  const columns: Column<ChangeRequest>[] = [
    {
      id: 'title',
      header: 'Change',
      sortValue: (c) => c.title.toLowerCase(),
      cell: (c) => (
        <div className="min-w-0">
          <Link to={`/changes/${encodeURIComponent(c.id)}`} className="font-medium text-fg hover:text-accent hover:underline">
            {c.title}
          </Link>
          <div className="mt-0.5 truncate text-[12px] text-fg-subtle">
            <Link to={`/policies/${encodeURIComponent(c.policy_set_id)}`} className="hover:text-fg hover:underline">
              {c.policy_set_name}
            </Link>
            <span> from v{c.base_version}</span>
          </div>
        </div>
      ),
    },
    { id: 'status', header: 'Status', width: 170, sortValue: (c) => c.status, cell: (c) => <ChangeRequestStatusChip status={c.status} /> },
    {
      id: 'diff',
      header: 'Rules',
      width: 170,
      hideBelow: 'lg',
      cell: (c) =>
        c.diff ? (
          <span className="flex flex-wrap gap-1">
            {c.diff.added > 0 && <Badge tone="success">+{c.diff.added}</Badge>}
            {c.diff.modified > 0 && <Badge tone="warning">~{c.diff.modified}</Badge>}
            {c.diff.removed > 0 && <Badge tone="danger">-{c.diff.removed}</Badge>}
            {(c.diff.metadata ?? []).length > 0 && <Badge tone="info">settings</Badge>}
          </span>
        ) : (
          <span className="text-fg-subtle">—</span>
        ),
    },
    {
      id: 'impact',
      header: 'Impact',
      width: 170,
      hideBelow: 'xl',
      cell: (c) =>
        c.impact ? (
          <span className="text-[12.5px] text-fg-muted">
            {c.impact.newly_blocked > 0 ? <span className="font-medium text-danger">{formatNumber(c.impact.newly_blocked)} newly blocked</span> : `${formatNumber(c.impact.newly_allowed)} newly allowed`}
            <span className="block text-[12px] text-fg-subtle">{formatNumber(c.impact.affected_servers)} servers affected</span>
          </span>
        ) : (
          <span className="text-fg-subtle">—</span>
        ),
    },
    {
      id: 'submitted',
      header: 'Submitted',
      width: 190,
      sortValue: (c) => c.submitted_at,
      cell: (c) => (
        <div className="leading-tight">
          <UserName username={c.submitted_by} />
          <div className="text-[12px] text-fg-subtle">
            <RelativeTime value={c.submitted_at} />
          </div>
        </div>
      ),
    },
    {
      id: 'reviews',
      header: 'Reviews',
      align: 'right',
      width: 80,
      hideBelow: 'lg',
      sortValue: (c) => (c.reviews ?? []).length,
      cell: (c) => <span className="tabular text-fg-muted">{(c.reviews ?? []).length}</span>,
    },
  ];

  const empty = {
    review: (
      <EmptyState
        icon={Inbox}
        title="Nothing to review"
        description={perms.isReadOnly ? 'Open change requests from other people appear here. Auditors can comment on them.' : 'When someone submits a policy change, it waits here for a second approver.'}
      />
    ),
    mine: <EmptyState icon={UserRound} title="You have not submitted any changes" description="Submit a draft for review from its policy set page." action={<ButtonLink to="/policies">Policy sets</ButtonLink>} />,
    all: <EmptyState icon={GitPullRequestArrow} title="No change requests yet" />,
  }[tab];

  return (
    <>
      <PageHeader
        title="Change requests"
        description="Four-eyes review of policy changes. Each request carries a rule-level diff and an impact simulation; approving publishes the change."
      />
      {!state.governance?.require_policy_review && (
        <Callout tone="info" className="mb-5" title="Four-eyes review is currently off">
          Authors publish their drafts directly, so new change requests are rare.{' '}
          {perms.canManageSystem ? (
            <Link to="/settings/governance" className="font-medium text-accent hover:underline">
              Turn on review in Settings
            </Link>
          ) : (
            'InfoSec can turn it on in Settings.'
          )}
        </Callout>
      )}
      <Tabs<Tab>
        className="mb-4"
        value={tab}
        onChange={setTab}
        aria-label="Change request lists"
        tabs={[
          { id: 'review', label: 'To review', icon: ListTodo, count: lists.review.length, countTone: lists.review.length ? 'warning' : 'neutral' },
          { id: 'mine', label: 'Mine', icon: UserRound, count: lists.mine.length },
          { id: 'all', label: 'All', icon: GitPullRequestArrow, count: lists.all.length },
        ]}
      />
      <DataTable
        rows={rows}
        columns={columns}
        getRowId={(c) => c.id}
        rowHref={(c) => `/changes/${encodeURIComponent(c.id)}`}
        getSearchText={(c) => `${c.title} ${c.description} ${c.policy_set_name} ${c.submitted_by} ${c.id}`}
        searchPlaceholder="Search changes…"
        search={f.search}
        onSearchChange={f.setSearch}
        facetValues={f.values}
        onFacetChange={f.onChange}
        facets={[
          {
            id: 'status',
            label: 'Status',
            getValue: (c) => c.status,
            options: (['open', 'approved', 'rejected', 'withdrawn', 'superseded'] as const).map((s) => ({ value: s, label: changeRequestStatusLabel(s) })),
          },
          { id: 'set', label: 'Policy set', getValue: (c) => c.policy_set_id, optionLabel: (v) => all.find((c) => c.policy_set_id === v)?.policy_set_name || v },
        ]}
        empty={empty}
        aria-label="Change requests"
      />
    </>
  );
};
