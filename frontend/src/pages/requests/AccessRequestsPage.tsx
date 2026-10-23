import React, { useMemo, useState } from 'react';
import { AlarmClock, Archive, CheckCheck, Clock, Inbox, Layers, ListFilter, UserCheck, XCircle } from 'lucide-react';
import { useConsoleState, usePermissions } from '../../data/AppData';
import { useSession } from '../../data/session';
import { DURATION_LABELS } from '../../lib/format';
import { useDocumentTitle, useNow } from '../../lib/hooks';
import { useUrlFilters } from '../../lib/useUrlFilters';
import type { AccessRequest } from '../../types';
import { Button, ButtonLink, EmptyState, FacetDef, PageHeader, TabPanel, Tabs, useUrlTab } from '../../ui';
import { BulkReviewDialog } from '../../components/requests/BulkReviewDialog';
import { RequestsTable } from '../../components/requests/RequestsTable';
import { canHandle, isExpired, isOverdue, SCOPE_META } from '../../components/requests/requestUtils';

const TABS = ['pending', 'mine', 'overdue', 'approved', 'closed', 'all'] as const;
type Tab = (typeof TABS)[number];
const FILTERS = ['group', 'verified', 'scope', 'duration', 'state'];

const EMPTY: Record<Tab, { title: string; description: string }> = {
  pending: { title: 'Inbox zero', description: 'No access request is waiting for a decision. New requests from block pages and the CLI appear here.' },
  mine: { title: 'Nothing assigned to you', description: 'Requests that someone assigns to you show up here.' },
  overdue: { title: 'Nothing is overdue', description: 'Every pending request is still within its SLA.' },
  approved: { title: 'No approved requests', description: 'Approved requests stay here with their expiry so you can extend or revoke access.' },
  closed: { title: 'No rejected or revoked requests', description: 'Rejected and revoked requests are kept for the record.' },
  all: { title: 'No access requests yet', description: 'When a server is blocked, users can request access from the block page or the CLI.' },
};

/** /requests — inbox with work queues, faceted filters, SLA chips and bulk review. */
export const AccessRequestsPage: React.FC = () => {
  useDocumentTitle('Access requests');
  const state = useConsoleState();
  const perms = usePermissions();
  const { user } = useSession();
  const now = useNow();
  const f = useUrlFilters(FILTERS);
  const [tab, setTab] = useUrlTab<Tab>(TABS, 'pending', 'status');
  const [bulk, setBulk] = useState<{ approve: boolean; rows: AccessRequest[]; clear: () => void } | null>(null);
  const me = (user?.username || '').toLowerCase();

  const lists = useMemo(() => {
    const all = [...state.requests].sort((a, b) => b.created_at.localeCompare(a.created_at));
    return {
      pending: all.filter((r) => r.status === 'pending'),
      mine: all.filter((r) => r.status === 'pending' && (r.assigned_to || '').toLowerCase() === me),
      overdue: all.filter((r) => isOverdue(r, now)),
      approved: all.filter((r) => r.status === 'approved'),
      closed: all.filter((r) => r.status === 'rejected' || r.status === 'revoked'),
      all,
    } satisfies Record<Tab, AccessRequest[]>;
  }, [state.requests, me, now]);

  const rows = lists[tab];
  const sla = state.governance?.request_sla_hours ?? 0;
  const maxDays = state.governance?.max_temporary_access_days ?? 0;
  const groupOptions = state.groups.map((g) => ({ value: g.id, label: g.name }));

  const facets: FacetDef<AccessRequest>[] = [
    { id: 'group', label: 'Group', getValue: (r: AccessRequest) => r.target_group_ids ?? [], options: groupOptions },
    {
      id: 'verified',
      label: 'Source',
      getValue: (r: AccessRequest) => (r.verified ? 'verified' : 'unverified'),
      options: [
        { value: 'verified', label: 'Verified (block token)' },
        { value: 'unverified', label: 'Unverified' },
      ],
    },
    {
      id: 'scope',
      label: 'Scope',
      getValue: (r: AccessRequest) => r.requested_scope,
      options: Object.entries(SCOPE_META).map(([value, m]) => ({ value, label: m.label })),
    },
    {
      id: 'duration',
      label: 'Duration',
      getValue: (r: AccessRequest) => r.duration,
      options: ['1h', '24h', '7d', 'permanent'].map((d) => ({ value: d, label: DURATION_LABELS[d] })),
    },
  ];
  if (tab === 'approved' || tab === 'closed' || tab === 'all') {
    facets.push({
      id: 'state',
      label: 'Status',
      getValue: (r: AccessRequest) => (r.status === 'approved' ? (isExpired(r, now) ? 'expired' : 'active') : r.status),
      options: [
        { value: 'pending', label: 'Pending' },
        { value: 'active', label: 'Approved, active' },
        { value: 'expired', label: 'Approved, expired' },
        { value: 'rejected', label: 'Rejected' },
        { value: 'revoked', label: 'Revoked' },
      ].filter((o) => tab === 'all' || (tab === 'approved' ? ['active', 'expired'].includes(o.value) : ['rejected', 'revoked'].includes(o.value))),
    });
  }

  const pendingTab = tab === 'pending' || tab === 'mine' || tab === 'overdue';
  const emptyCopy = EMPTY[tab];

  return (
    <>
      <PageHeader
        title="Access requests"
        description={
          <>
            Requests from blocked servers, submitted on the block page or with the CLI. Approving adds a rule to the group's approvals policy set.
            {sla > 0 && ` Decide within ${sla} h (SLA).`}
            {perms.isTeamLead && maxDays > 0 && ` As a Team Lead you can grant up to ${maxDays} days.`}
          </>
        }
        actions={
          <ButtonLink to="/policies?kind=approvals" icon={Layers}>
            Approvals sets
          </ButtonLink>
        }
      />

      <Tabs<Tab>
        idPrefix="rq"
        className="mb-4"
        value={tab}
        onChange={(t) => {
          setTab(t);
          if (f.values.state.length) f.onChange('state', []);
        }}
        aria-label="Request queues"
        tabs={[
          { id: 'pending', label: 'Pending', icon: Clock, count: lists.pending.length, countTone: lists.pending.length ? 'warning' : 'neutral' },
          { id: 'mine', label: 'Assigned to me', icon: UserCheck, count: lists.mine.length || undefined, countTone: 'info', hidden: perms.isReadOnly },
          { id: 'overdue', label: 'Overdue', icon: AlarmClock, count: lists.overdue.length || undefined, countTone: 'danger' },
          { id: 'approved', label: 'Approved', icon: CheckCheck, count: lists.approved.length || undefined },
          { id: 'closed', label: 'Rejected / revoked', icon: XCircle, count: lists.closed.length || undefined },
          { id: 'all', label: 'All', icon: Archive, count: lists.all.length },
        ]}
      />

      <TabPanel id={tab} idPrefix="rq">
        <RequestsTable
          key={tab}
          rows={rows}
          showState={!pendingTab}
          getSearchText={(r) => `${r.requested_url} ${r.requester} ${r.reason} ${r.server_hostname} ${r.server_ip} ${r.id} ${r.suggested_host_pattern}${r.suggested_path_pattern} ${r.assigned_to ?? ''}`}
          searchPlaceholder="Search URL, server, requester…"
          search={f.search}
          onSearchChange={f.setSearch}
          facetValues={f.values}
          onFacetChange={f.onChange}
          facets={facets}
          initialSort={pendingTab ? { id: 'deadline', dir: 'asc' } : undefined}
          selectable={pendingTab && !perms.isReadOnly ? (r) => r.status === 'pending' && canHandle(perms, r) : undefined}
          bulkActions={(sel, clear) => (
            <>
              <Button size="sm" variant="primary" icon={CheckCheck} onClick={() => setBulk({ approve: true, rows: sel, clear })}>
                Approve
              </Button>
              <Button size="sm" variant="danger-ghost" icon={XCircle} onClick={() => setBulk({ approve: false, rows: sel, clear })}>
                Reject
              </Button>
            </>
          )}
          empty={
            <EmptyState
              icon={tab === 'pending' ? Inbox : ListFilter}
              title={emptyCopy.title}
              description={emptyCopy.description}
              action={
                tab !== 'all' && lists.all.length > 0 ? (
                  <Button size="sm" onClick={() => setTab('all')}>
                    Show all requests
                  </Button>
                ) : undefined
              }
            />
          }
        />
      </TabPanel>
      {perms.isReadOnly && <p className="mt-3 text-[12px] text-fg-subtle">You have read-only access: you can follow requests but not review, assign or comment.</p>}

      <BulkReviewDialog
        open={!!bulk}
        onClose={() => setBulk(null)}
        approve={bulk?.approve ?? true}
        requests={bulk?.rows ?? []}
        onDone={() => bulk?.clear()}
      />
    </>
  );
};
