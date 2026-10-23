import React, { useMemo, useState } from 'react';
import { Activity, FileWarning, Inbox, Layers, MoreHorizontal, Pencil, Server as ServerIcon, Tag, Trash2 } from 'lucide-react';
import { useConsoleState, usePermissions } from '../../data/AppData';
import { formatNumber } from '../../lib/format';
import { useDocumentTitle } from '../../lib/hooks';
import { Link, navigate, useParams } from '../../lib/router';
import type { PolicySet, Server, ServerGroup } from '../../types';
import { Badge, Button, Card, Column, DataTable, EmptyState, Menu, PageHeader, TabPanel, Tabs, Tooltip } from '../../ui';
import { LabelChips } from '../../components/common/EntityChips';
import { CidrChips, GroupTile, LastSeen, SelectorChips, ServerHealthChip, StrictBadge } from '../../components/fleet/FleetChips';
import { FlowsTable } from '../../components/fleet/FlowsTable';
import { groupMembers, hasSelector, labelsMatch, staticGroups } from '../../components/fleet/fleetUtils';
import { GroupFormDrawer } from '../../components/fleet/GroupFormDrawer';
import { PolicyKindBadge, ReviewStateChip } from '../../components/policy/PolicyBadges';
import { RequestsTable } from '../../components/requests/RequestsTable';
import { NotFoundPage } from '../system/NotFoundPage';
import { useDeleteGroup } from './useDeleteGroup';

const TABS = ['members', 'policy', 'traffic', 'requests'] as const;
type Tab = (typeof TABS)[number];

/** /groups/:id/:tab? — membership rule, members, assigned policy sets, traffic and requests. */
export const GroupDetailPage: React.FC = () => {
  const { id, tab: rawTab } = useParams<{ id: string; tab?: string }>();
  const state = useConsoleState();
  const g = state.groups.find((x) => x.id === id);
  useDocumentTitle(g?.name ?? 'Group');
  if (!g) return <NotFoundPage title="Group not found" description="It may have been deleted." backTo="/groups" backLabel="All groups" />;
  const tab: Tab = (TABS as readonly string[]).includes(rawTab || '') ? (rawTab as Tab) : 'members';
  return <GroupDetail key={g.id} group={g} tab={tab} />;
};

const GroupDetail: React.FC<{ group: ServerGroup; tab: Tab }> = ({ group: g, tab }) => {
  const state = useConsoleState();
  const perms = usePermissions();
  const remove = useDeleteGroup();
  const [editOpen, setEditOpen] = useState(false);
  const go = (t: Tab) => navigate(`/groups/${encodeURIComponent(g.id)}${t === 'members' ? '' : `/${t}`}`, { preserveScroll: true });

  const members = useMemo(() => groupMembers(g, state.servers), [g, state.servers]);
  const sets = useMemo(() => {
    const own = state.policy_sets.filter((s) => s.kind !== 'baseline' && (s.group_ids ?? []).includes(g.id));
    const baseline = state.policy_sets.filter((s) => s.kind === 'baseline');
    return { own, baseline };
  }, [state.policy_sets, g.id]);
  const requests = useMemo(() => state.requests.filter((r) => (r.target_group_ids ?? []).includes(g.id)), [state.requests, g.id]);
  const pending = requests.filter((r) => r.status === 'pending').length;
  const template = state.block_pages.find((t) => t.id === g.block_page_template_id) ?? state.block_pages.find((t) => t.is_default);

  return (
    <>
      <PageHeader
        breadcrumbs={[{ label: 'Groups', to: '/groups' }, { label: g.name }]}
        leading={<GroupTile group={g} />}
        title={g.name}
        description={g.description || undefined}
        meta={
          <>
            <span className="rounded-md border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[11.5px] text-fg-muted">{g.id}</span>
            {g.environment && <Badge tone={g.environment === 'prod' ? 'accent' : 'neutral'}>{g.environment}</Badge>}
            {g.owner_team && <span className="text-[12.5px] text-fg-muted">{g.owner_team}</span>}
            {g.strict_isolation && <StrictBadge />}
            {hasSelector(g) && (
              <Badge tone="info" icon={Tag}>
                Dynamic
              </Badge>
            )}
          </>
        }
        actions={
          perms.canManageSystem && (
            <>
              <Button icon={Pencil} onClick={() => setEditOpen(true)}>
                Edit
              </Button>
              <Menu
                items={[{ id: 'delete', label: 'Delete group', icon: Trash2, danger: true, onSelect: () => remove(g) }]}
                trigger={(p) => <Button {...p} icon={MoreHorizontal} aria-label="More actions" />}
              />
            </>
          )
        }
      />

      <Card className="mb-6 grid grid-cols-1 divide-y divide-border sm:grid-cols-2 sm:divide-y-0 lg:grid-cols-4 lg:divide-x">
        <Fact label="Registered members">
          <span className="text-[18px] font-semibold tabular leading-6">{formatNumber(members.all.length)}</span>
          <span className="block text-[12px] text-fg-subtle">
            {members.static.length} static · {members.dynamic.length} by labels{g.server_count ? ` · ${formatNumber(g.server_count)} planned` : ''}
          </span>
        </Fact>
        <Fact label="Label selector">
          {hasSelector(g) ? <SelectorChips selector={g.match_labels} max={4} /> : <span className="text-fg-subtle">None (static membership)</span>}
        </Fact>
        <Fact label="CIDR ranges">
          <CidrChips cidrs={g.cidrs} max={4} />
          {(g.cidrs ?? []).length > 0 && <span className="mt-1 block text-[12px] text-fg-subtle">Attributes unregistered sources</span>}
        </Fact>
        <Fact label="Block page">
          {template ? (
            <Link to={`/block-pages/${encodeURIComponent(template.id)}`} className="inline-flex items-center gap-1.5 text-accent hover:underline">
              <FileWarning className="h-3.5 w-3.5" aria-hidden />
              {template.name}
            </Link>
          ) : (
            <span className="text-fg-subtle">Default</span>
          )}
          {!g.block_page_template_id && <span className="mt-0.5 block text-[12px] text-fg-subtle">Default template</span>}
        </Fact>
      </Card>

      <Tabs<Tab>
        idPrefix="gd"
        className="mb-6"
        value={tab}
        onChange={go}
        aria-label="Group sections"
        tabs={[
          { id: 'members', label: 'Members', icon: ServerIcon, count: members.all.length },
          { id: 'policy', label: 'Policy sets', icon: Layers, count: sets.own.length },
          { id: 'traffic', label: 'Traffic', icon: Activity },
          { id: 'requests', label: 'Access requests', icon: Inbox, count: pending || undefined, countTone: 'warning' },
        ]}
      />

      <TabPanel id={tab} idPrefix="gd">
        {tab === 'members' && <MembersTable group={g} servers={members.all} canEdit={perms.canManageSystem} onEdit={() => setEditOpen(true)} />}
        {tab === 'policy' && <PolicyList group={g} own={sets.own} baseline={sets.baseline} />}
        {tab === 'traffic' && <FlowsTable match={(f) => (f.group_ids ?? []).includes(g.id)} showServer emptyTitle="No recent traffic from this group" />}
        {tab === 'requests' && (
          <RequestsTable
            rows={requests}
            showState
            empty={<EmptyState icon={Inbox} size="sm" title="No access requests for this group" description="Requests from member servers that target this group appear here." />}
          />
        )}
      </TabPanel>

      <GroupFormDrawer open={editOpen} onClose={() => setEditOpen(false)} group={g} />
    </>
  );
};

const Fact: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div className="min-w-0 px-[var(--card-p)] py-3.5">
    <div className="mb-1 text-[12px] font-medium text-fg-subtle">{label}</div>
    <div className="min-w-0 text-[13px] text-fg">{children}</div>
  </div>
);

const MembersTable: React.FC<{ group: ServerGroup; servers: Server[]; canEdit: boolean; onEdit: () => void }> = ({ group: g, servers, canEdit, onEdit }) => {
  const kind = (s: Server) => (staticGroups(s).includes(g.id) ? (labelsMatch(s.labels, g.match_labels) ? 'both' : 'static') : 'labels');
  const columns: Column<Server>[] = [
    {
      id: 'host',
      header: 'Server',
      sortValue: (s) => s.hostname.toLowerCase(),
      cell: (s) => (
        <div className="min-w-0">
          <Link to={`/servers/${encodeURIComponent(s.id)}`} className="block truncate font-medium text-fg hover:text-accent hover:underline">
            {s.hostname}
          </Link>
          <div className="truncate font-mono text-[11.5px] text-fg-subtle">
            {s.ip || 'No IP'} · {s.id}
          </div>
        </div>
      ),
    },
    {
      id: 'kind',
      header: 'Membership',
      width: 160,
      sortValue: kind,
      cell: (s) => {
        const k = kind(s);
        return k === 'labels' ? (
          <Tooltip content="Joined automatically because its labels match the selector">
            <Badge tone="info" icon={Tag}>
              Label selector
            </Badge>
          </Tooltip>
        ) : k === 'both' ? (
          <Badge tone="neutral">Static + labels</Badge>
        ) : (
          <Badge tone="neutral">Static</Badge>
        );
      },
    },
    { id: 'labels', header: 'Labels', width: '26%', hideBelow: 'lg', cell: (s) => <LabelChips labels={s.labels} max={3} /> },
    { id: 'seen', header: 'Last seen', width: 104, sortValue: (s) => s.last_seen_at || '', cell: (s) => <LastSeen server={s} /> },
    { id: 'status', header: 'Status', width: 128, cell: (s) => <ServerHealthChip server={s} /> },
  ];
  return (
    <DataTable
      rows={servers}
      columns={columns}
      getRowId={(s) => s.id}
      rowHref={(s) => `/servers/${encodeURIComponent(s.id)}`}
      getSearchText={(s) => `${s.hostname} ${s.id} ${s.ip} ${Object.entries(s.labels ?? {}).map(([k, v]) => `${k}=${v}`).join(' ')}`}
      searchPlaceholder="Search members…"
      facets={[
        {
          id: 'kind',
          label: 'Membership',
          getValue: kind,
          options: [
            { value: 'static', label: 'Static' },
            { value: 'labels', label: 'Label selector' },
            { value: 'both', label: 'Static + labels' },
          ],
        },
      ]}
      empty={
        <EmptyState
          icon={ServerIcon}
          size="sm"
          title="No registered members"
          description={
            hasSelector(g)
              ? 'No registered server has labels that match the selector yet. Add the labels to servers, or add servers statically from the server editor.'
              : 'Add servers to this group in the server editor (static membership), or give the group a label selector.'
          }
          action={
            canEdit ? (
              <Button size="sm" icon={Pencil} onClick={onEdit}>
                Edit membership rule
              </Button>
            ) : undefined
          }
        />
      }
      aria-label="Group members"
    />
  );
};

const PolicyList: React.FC<{ group: ServerGroup; own: PolicySet[]; baseline: PolicySet[] }> = ({ group: g, own, baseline }) => {
  const columns: Column<PolicySet>[] = [
    {
      id: 'name',
      header: 'Policy set',
      sortValue: (s) => s.name.toLowerCase(),
      cell: (s) => (
        <div className="min-w-0">
          <Link to={`/policies/${encodeURIComponent(s.id)}`} className="block truncate font-medium text-fg hover:text-accent hover:underline">
            {s.name}
          </Link>
          {s.description && <div className="truncate text-[12px] text-fg-subtle">{s.description}</div>}
        </div>
      ),
    },
    { id: 'kind', header: 'Kind', width: 120, cell: (s) => <PolicyKindBadge kind={s.kind} /> },
    { id: 'version', header: 'Version', width: 100, hideBelow: 'lg', cell: (s) => (s.version ? <span className="tabular">v{s.version}</span> : <span className="text-fg-subtle">Unpublished</span>) },
    { id: 'rules', header: 'Rules', width: 72, align: 'right', sortValue: (s) => (s.rules ?? []).length, cell: (s) => <span className="tabular">{(s.rules ?? []).length}</span> },
    { id: 'review', header: 'Recertification', width: 170, hideBelow: 'lg', cell: (s) => <ReviewStateChip set={s} /> },
  ];
  return (
    <div className="space-y-6">
      <section className="space-y-2">
        <h2 className="text-[14px] font-semibold text-fg">Assigned to {g.name}</h2>
        <DataTable
          rows={own}
          columns={columns}
          getRowId={(s) => s.id}
          rowHref={(s) => `/policies/${encodeURIComponent(s.id)}`}
          hideToolbar
          empty={
            <EmptyState
              icon={Layers}
              size="sm"
              title="No policy set is assigned to this group"
              description="Assign standard sets to the group on the policy set's draft, or approve access requests to create its approvals set."
              action={<Link to="/policies" className="text-[13px] font-medium text-accent hover:underline">Open policy sets</Link>}
            />
          }
          aria-label="Assigned policy sets"
        />
      </section>
      {baseline.length > 0 && (
        <section className="space-y-2">
          <h2 className="text-[14px] font-semibold text-fg">Baseline (applies to every server)</h2>
          <DataTable rows={baseline} columns={columns} getRowId={(s) => s.id} rowHref={(s) => `/policies/${encodeURIComponent(s.id)}`} hideToolbar aria-label="Baseline policy sets" />
        </section>
      )}
    </div>
  );
};
