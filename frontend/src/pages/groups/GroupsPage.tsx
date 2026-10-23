import React, { useMemo, useState } from 'react';
import { Boxes, Eye, MoreHorizontal, Pencil, Plus, Trash2 } from 'lucide-react';
import { useConsoleState, usePermissions } from '../../data/AppData';
import { formatNumber } from '../../lib/format';
import { useDocumentTitle } from '../../lib/hooks';
import { Link } from '../../lib/router';
import { useUrlFilters } from '../../lib/useUrlFilters';
import type { ServerGroup } from '../../types';
import { Badge, Button, Column, DataTable, EmptyState, Menu, PageHeader, Tooltip } from '../../ui';
import { CidrChips, GroupTile, SelectorChips, StrictBadge } from '../../components/fleet/FleetChips';
import { groupMembers, GroupMembers, hasSelector } from '../../components/fleet/fleetUtils';
import { GroupFormDrawer } from '../../components/fleet/GroupFormDrawer';
import { useDeleteGroup } from './useDeleteGroup';

const FILTERS = ['env', 'owner', 'membership', 'isolation'];

interface Row {
  group: ServerGroup;
  members: GroupMembers;
  sets: number;
  template: string;
}

/** /groups — server groups with membership rules, members and assigned policy. */
export const GroupsPage: React.FC = () => {
  useDocumentTitle('Groups');
  const state = useConsoleState();
  const perms = usePermissions();
  const f = useUrlFilters(FILTERS);
  const [form, setForm] = useState<{ group: ServerGroup | null } | null>(null);
  const remove = useDeleteGroup();

  const rows = useMemo<Row[]>(() => {
    const def = state.block_pages.find((t) => t.is_default);
    return state.groups.map((g) => ({
      group: g,
      members: groupMembers(g, state.servers),
      sets: state.policy_sets.filter((s) => s.kind !== 'baseline' && (s.group_ids ?? []).includes(g.id) && (s.kind !== 'approvals' || (s.rules ?? []).length > 0)).length,
      template: state.block_pages.find((t) => t.id === g.block_page_template_id)?.name ?? (g.block_page_template_id ? g.block_page_template_id : `Default${def ? ` (${def.name})` : ''}`),
    }));
  }, [state.groups, state.servers, state.policy_sets, state.block_pages]);

  const menu = (g: ServerGroup) =>
    perms.canManageSystem ? (
      <Menu
        items={[
          { id: 'open', label: 'Open', icon: Eye, to: `/groups/${encodeURIComponent(g.id)}` },
          { id: 'edit', label: 'Edit', icon: Pencil, onSelect: () => setForm({ group: g }) },
          { id: 'delete', label: 'Delete', icon: Trash2, danger: true, separator: true, onSelect: () => remove(g, () => undefined) },
        ]}
        trigger={(p) => (
          <button {...p} type="button" aria-label={`Actions for ${g.name}`} className="inline-flex h-7 w-7 items-center justify-center rounded-md text-fg-subtle hover:bg-surface-3 hover:text-fg">
            <MoreHorizontal className="h-4 w-4" />
          </button>
        )}
      />
    ) : null;

  const columns: Column<Row>[] = [
    {
      id: 'name',
      header: 'Group',
      width: '28%',
      sortValue: (r) => r.group.name.toLowerCase(),
      cell: ({ group: g }) => (
        <div className="flex min-w-0 items-start gap-2.5">
          <GroupTile group={g} size="sm" />
          <div className="min-w-0">
            <Link to={`/groups/${encodeURIComponent(g.id)}`} className="block truncate font-medium text-fg hover:text-accent hover:underline">
              {g.name}
            </Link>
            <div className="truncate font-mono text-[11.5px] text-fg-subtle">{g.id}</div>
          </div>
        </div>
      ),
    },
    {
      id: 'env',
      header: 'Environment',
      width: 150,
      hideBelow: 'xl',
      sortValue: (r) => r.group.environment,
      cell: ({ group: g }) => (
        <div className="min-w-0 leading-5">
          {g.environment ? <Badge tone={g.environment === 'prod' ? 'accent' : 'neutral'}>{g.environment}</Badge> : <span className="text-fg-subtle">—</span>}
          {g.owner_team && <div className="mt-0.5 truncate text-[12px] text-fg-subtle">{g.owner_team}</div>}
        </div>
      ),
    },
    {
      id: 'membership',
      header: 'Membership rule',
      width: '26%',
      cell: ({ group: g }) => (
        <div className="min-w-0 space-y-1">
          {hasSelector(g) && <SelectorChips selector={g.match_labels} max={2} />}
          {(g.cidrs ?? []).length > 0 && <CidrChips cidrs={g.cidrs} max={2} />}
          {!hasSelector(g) && (g.cidrs ?? []).length === 0 && <span className="text-[12.5px] text-fg-subtle">Static members only</span>}
          {g.strict_isolation && <StrictBadge />}
        </div>
      ),
    },
    {
      id: 'members',
      header: 'Registered members',
      width: 150,
      sortValue: (r) => r.members.all.length,
      cell: ({ members: m, group: g }) => (
        <Tooltip content={g.server_count ? `Planned fleet size: ${formatNumber(g.server_count)} servers` : undefined}>
          <div className="leading-5">
            <span className="tabular font-medium text-fg">{formatNumber(m.all.length)}</span>
            <span className="block text-[12px] text-fg-subtle">
              {m.static.length} static · {m.dynamic.length} by labels
            </span>
          </div>
        </Tooltip>
      ),
    },
    {
      id: 'sets',
      header: 'Policy sets',
      width: 104,
      align: 'right',
      hideBelow: 'lg',
      sortValue: (r) => r.sets,
      cell: (r) => (
        <Link to={`/policies?group=${encodeURIComponent(r.group.id)}`} className="tabular text-fg hover:text-accent hover:underline">
          {r.sets}
        </Link>
      ),
    },
    { id: 'template', header: 'Block page', width: 150, hideBelow: 'xl', sortValue: (r) => r.template, cell: (r) => <span className="block truncate text-[12.5px] text-fg-muted">{r.template}</span> },
    { id: 'menu', header: <span className="sr-only">Actions</span>, width: 48, align: 'right', cell: (r) => menu(r.group) },
  ];

  const envs = [...new Set(state.groups.map((g) => g.environment).filter(Boolean))].sort();
  const owners = [...new Set(state.groups.map((g) => g.owner_team).filter(Boolean))].sort();

  return (
    <>
      <PageHeader
        title="Groups"
        description="Groups scope policy sets, access request approvals, Team Lead permissions and block pages. Servers join statically, by CIDR range or automatically through a label selector."
        actions={
          perms.canManageSystem && (
            <Button variant="primary" icon={Plus} onClick={() => setForm({ group: null })}>
              New group
            </Button>
          )
        }
      />
      <DataTable
        rows={rows}
        columns={columns}
        getRowId={(r) => r.group.id}
        rowHref={(r) => `/groups/${encodeURIComponent(r.group.id)}`}
        getSearchText={(r) =>
          `${r.group.name} ${r.group.id} ${r.group.description} ${r.group.environment} ${r.group.owner_team} ${(r.group.cidrs ?? []).join(' ')} ${Object.entries(r.group.match_labels ?? {})
            .map(([k, v]) => `${k}=${v}`)
            .join(' ')}`
        }
        searchPlaceholder="Search groups, CIDRs, labels…"
        search={f.search}
        onSearchChange={f.setSearch}
        facetValues={f.values}
        onFacetChange={f.onChange}
        facets={[
          { id: 'env', label: 'Environment', getValue: (r) => r.group.environment || '', options: envs.map((e) => ({ value: e, label: e })) },
          { id: 'owner', label: 'Owner', getValue: (r) => r.group.owner_team || '', options: owners.map((o) => ({ value: o, label: o })) },
          {
            id: 'membership',
            label: 'Membership',
            getValue: (r) => [hasSelector(r.group) ? 'labels' : '', (r.group.cidrs ?? []).length ? 'cidr' : '', !hasSelector(r.group) && !(r.group.cidrs ?? []).length ? 'static' : ''].filter(Boolean),
            options: [
              { value: 'labels', label: 'Label selector' },
              { value: 'cidr', label: 'CIDR ranges' },
              { value: 'static', label: 'Static only' },
            ],
          },
          {
            id: 'isolation',
            label: 'Isolation',
            getValue: (r) => (r.group.strict_isolation ? 'strict' : 'standard'),
            options: [
              { value: 'strict', label: 'Strict isolation' },
              { value: 'standard', label: 'Standard' },
            ],
          },
        ]}
        mobileCard={(r) => (
          <div className="min-w-0 space-y-2">
            <div className="flex items-start gap-2.5">
              <GroupTile group={r.group} size="sm" />
              <div className="min-w-0 flex-1">
                <Link to={`/groups/${encodeURIComponent(r.group.id)}`} className="block truncate font-medium text-fg">
                  {r.group.name}
                </Link>
                <div className="truncate text-[12px] text-fg-subtle">
                  {formatNumber(r.members.all.length)} members · {r.sets} policy sets{r.group.environment ? ` · ${r.group.environment}` : ''}
                </div>
              </div>
              {menu(r.group)}
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              {hasSelector(r.group) && <SelectorChips selector={r.group.match_labels} max={2} />}
              {(r.group.cidrs ?? []).length > 0 && <CidrChips cidrs={r.group.cidrs} max={2} />}
              {r.group.strict_isolation && <StrictBadge />}
            </div>
          </div>
        )}
        empty={
          <EmptyState
            icon={Boxes}
            title="No groups yet"
            description="Create groups for teams, environments or compliance scopes, then assign policy sets to them."
            action={
              perms.canManageSystem && (
                <Button variant="primary" icon={Plus} onClick={() => setForm({ group: null })}>
                  New group
                </Button>
              )
            }
          />
        }
        aria-label="Server groups"
      />
      <GroupFormDrawer open={!!form} onClose={() => setForm(null)} group={form?.group ?? null} />
    </>
  );
};
