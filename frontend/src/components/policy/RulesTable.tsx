import React from 'react';
import { Copy, Inbox, MoreHorizontal, Pencil, Power, Radar, Repeat, Trash2 } from 'lucide-react';
import type { PolicyRule, RuleInput } from '../../types';
import { cn } from '../../lib/cn';
import { formatNumber } from '../../lib/format';
import { Link } from '../../lib/router';
import { Badge, Column, CountdownChip, DataTable, Menu, MethodList, PatternText, Tooltip } from '../../ui';
import { RuleActionBadge } from './PolicyBadges';

export interface RuleRow {
  key: string;
  rule: PolicyRule | RuleInput;
  /** Draft marker relative to the published version. */
  mark?: 'added' | 'modified';
}

export interface RulesTableProps {
  rows: RuleRow[];
  /** Row click (read-only details or edit). */
  onOpen?: (row: RuleRow) => void;
  /** Enables the row menu. */
  actions?: {
    canEdit: (row: RuleRow) => boolean;
    onEdit: (row: RuleRow) => void;
    onDuplicate: (row: RuleRow) => void;
    onToggle: (row: RuleRow) => void;
    onDelete: (row: RuleRow) => void;
    lockedReason?: string;
  };
  showHits?: boolean;
  empty?: React.ReactNode;
  toolbar?: React.ReactNode;
}

const hits = (r: PolicyRule | RuleInput) => (r as PolicyRule).hit_count ?? 0;

/** Rules of a policy set (published or draft). */
export const RulesTable: React.FC<RulesTableProps> = ({ rows, onOpen, actions, showHits = true, empty, toolbar }) => {
  const columns: Column<RuleRow>[] = [
    {
      id: 'name',
      header: 'Rule',
      sortValue: (x) => x.rule.name,
      cell: (row) => {
        const { rule: r, mark } = row;
        return (
        <div className={cn('min-w-0', !r.enabled && 'opacity-60')}>
          <div className="flex min-w-0 flex-wrap items-center gap-1.5">
            {onOpen ? (
              <button type="button" onClick={() => onOpen(row)} className="truncate text-left font-medium text-fg hover:text-accent hover:underline">
                {r.name || <span className="italic text-fg-subtle">Unnamed rule</span>}
              </button>
            ) : (
              <span className="truncate font-medium text-fg">{r.name}</span>
            )}
            {mark === 'added' && <Badge tone="success">New</Badge>}
            {mark === 'modified' && <Badge tone="warning">Changed</Badge>}
            {!r.enabled && <Badge tone="neutral" icon={Power}>Disabled</Badge>}
          </div>
          {r.description && <div className="mt-0.5 line-clamp-1 text-[12px] text-fg-subtle">{r.description}</div>}
          <div className="mt-1 flex flex-wrap gap-1.5 empty:hidden">
            {r.follow_redirects && (
              <Tooltip content="Allows the object a matching response redirects to">
                <Badge tone="neutral" icon={Repeat}>
                  Follows redirects
                </Badge>
              </Tooltip>
            )}
            {(r as PolicyRule).access_request_id && (
              <Link to={`/requests/${encodeURIComponent((r as PolicyRule).access_request_id!)}`} className="inline-flex">
                <Badge tone="info" icon={Inbox}>
                  Request {(r as PolicyRule).access_request_id}
                </Badge>
              </Link>
            )}
            {(r as PolicyRule).source_session_id && (
              <Badge tone="violet" icon={Radar}>
                Learning session
              </Badge>
            )}
          </div>
        </div>
        );
      },
    },
    { id: 'action', header: 'Action', width: 96, sortValue: (x) => x.rule.action, cell: ({ rule: r }) => <RuleActionBadge action={r.action} /> },
    {
      id: 'dest',
      header: 'Destination',
      width: '30%',
      sortValue: (x) => `${x.rule.host_pattern}${x.rule.path_pattern}`,
      cell: ({ rule: r }) => {
        const comps = r.companion_rules ?? [];
        return (
          <div className="min-w-0">
            <PatternText host={r.host_pattern} path={r.path_pattern} />
            {comps.length > 0 && (
              <Tooltip content={<span className="font-mono text-[11.5px]">{comps.join('\n')}</span>}>
                <span className="mt-0.5 inline-block text-[12px] text-fg-subtle">
                  +{comps.length} companion{comps.length === 1 ? '' : 's'}
                </span>
              </Tooltip>
            )}
          </div>
        );
      },
    },
    { id: 'methods', header: 'Methods', width: 156, hideBelow: 'lg', cell: ({ rule: r }) => <MethodList methods={r.methods} /> },
    {
      id: 'expires',
      header: 'Expires',
      width: 140,
      hideBelow: 'xl',
      sortValue: (x) => x.rule.expires_at || '9999',
      cell: ({ rule: r }) => (r.expires_at ? <CountdownChip due={r.expires_at} kind="expiry" /> : <span className="text-fg-subtle">Never</span>),
    },
  ];
  if (showHits) {
    columns.push({
      id: 'hits',
      header: 'Hits',
      align: 'right',
      width: 80,
      sortValue: (x) => hits(x.rule),
      cell: ({ rule: r }) => <span className="tabular text-fg-muted">{formatNumber(hits(r))}</span>,
    });
  }
  if (actions) {
    columns.push({
      id: 'menu',
      header: <span className="sr-only">Actions</span>,
      width: 52,
      align: 'right',
      hideOnMobile: false,
      mobileLabel: 'Actions',
      cell: (row) => {
        const can = actions.canEdit(row);
        return (
          <Menu
            items={[
              { id: 'edit', label: can ? 'Edit' : 'View', icon: Pencil, onSelect: () => actions.onEdit(row) },
              { id: 'dup', label: 'Duplicate', icon: Copy, onSelect: () => actions.onDuplicate(row), disabled: !can },
              { id: 'toggle', label: row.rule.enabled ? 'Disable' : 'Enable', icon: Power, onSelect: () => actions.onToggle(row), disabled: !can },
              { id: 'del', label: 'Delete', icon: Trash2, danger: true, separator: true, onSelect: () => actions.onDelete(row), disabled: !can, description: !can ? actions.lockedReason : undefined },
            ]}
            trigger={(p) => (
              <button {...p} type="button" aria-label={`Actions for ${row.rule.name}`} className="inline-flex h-7 w-7 items-center justify-center rounded-md text-fg-subtle hover:bg-surface-3 hover:text-fg">
                <MoreHorizontal className="h-4 w-4" />
              </button>
            )}
          />
        );
      },
    });
  }
  return (
    <DataTable
      rows={rows}
      columns={columns}
      getRowId={(x) => x.key}
      getSearchText={(x) => `${x.rule.name} ${x.rule.description} ${x.rule.host_pattern}${x.rule.path_pattern} ${(x.rule.companion_rules ?? []).join(' ')}`}
      searchPlaceholder="Filter rules…"
      facets={[
        { id: 'action', label: 'Action', getValue: (x) => x.rule.action, options: [{ value: 'ALLOW', label: 'Allow' }, { value: 'BLOCK', label: 'Block' }] },
        { id: 'enabled', label: 'State', getValue: (x) => (x.rule.enabled ? 'enabled' : 'disabled'), options: [{ value: 'enabled', label: 'Enabled' }, { value: 'disabled', label: 'Disabled' }] },
      ]}
      onRowClick={onOpen ? (row) => onOpen(row) : undefined}
      mobileCard={(row) => {
        const r = row.rule;
        const menu = actions ? columns[columns.length - 1].cell(row) : null;
        return (
          <div className={cn('min-w-0 space-y-1.5', !r.enabled && 'opacity-70')}>
            <div className="flex items-start gap-2">
              <span className="min-w-0 flex-1 font-medium text-fg">{r.name || 'Unnamed rule'}</span>
              <RuleActionBadge action={r.action} />
              {menu}
            </div>
            <PatternText host={r.host_pattern} path={r.path_pattern} wrap />
            <div className="flex flex-wrap items-center gap-1.5">
              <MethodList methods={r.methods} />
              {row.mark === 'added' && <Badge tone="success">New</Badge>}
              {row.mark === 'modified' && <Badge tone="warning">Changed</Badge>}
              {!r.enabled && <Badge tone="neutral">Disabled</Badge>}
              {r.follow_redirects && <Badge tone="neutral" icon={Repeat}>Redirects</Badge>}
              {(r.companion_rules ?? []).length > 0 && <span className="text-[12px] text-fg-subtle">+{(r.companion_rules ?? []).length} companions</span>}
              {r.expires_at && <CountdownChip due={r.expires_at} kind="expiry" />}
              {showHits && <span className="text-[12px] text-fg-subtle">{formatNumber(hits(r))} hits</span>}
            </div>
          </div>
        );
      }}
      empty={empty}
      toolbar={toolbar}
      pageSize={100}
      aria-label="Rules"
    />
  );
};
