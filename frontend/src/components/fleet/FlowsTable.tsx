import React from 'react';
import { Activity } from 'lucide-react';
import { useFlows } from '../../data/AppData';
import { Link } from '../../lib/router';
import type { TrafficFlow } from '../../types';
import { Badge, Column, DataTable, EmptyState, RelativeTime, Tooltip } from '../../ui';
import { isAllowedVerdict, VerdictBadge } from '../traffic/VerdictBadge';

/** Recent flows (live stream, newest first) filtered by `match`. */
export const FlowsTable: React.FC<{
  match: (f: TrafficFlow) => boolean;
  showServer?: boolean;
  emptyTitle?: string;
  emptyDescription?: React.ReactNode;
  pageSize?: number;
}> = ({ match, showServer, emptyTitle = 'No recent traffic', emptyDescription, pageSize = 25 }) => {
  const { flows, connected } = useFlows();
  const rows = flows.filter(match);
  const columns: Column<TrafficFlow>[] = [
    { id: 'time', header: 'Time', width: 110, sortValue: (f) => f.timestamp, cell: (f) => <RelativeTime value={f.timestamp} className="text-[12.5px] text-fg-muted" /> },
    { id: 'verdict', header: 'Verdict', width: 150, sortValue: (f) => f.verdict, cell: (f) => <VerdictBadge verdict={f.verdict} /> },
    {
      id: 'dest',
      header: 'Request',
      cell: (f) => (
        <div className="min-w-0">
          <div className="flex min-w-0 items-center gap-1.5">
            <span className="shrink-0 rounded border border-border px-1 font-mono text-[10.5px] font-medium leading-4 text-fg-muted">{f.method}</span>
            <Tooltip content={<span className="break-all font-mono text-[11.5px]">{f.full_url}</span>} className="min-w-0">
              <span className="block min-w-0 truncate font-mono text-[12.5px]">
                <span className="font-semibold text-fg">{f.host}</span>
                <span className="text-fg-muted">{f.path}</span>
              </span>
            </Tooltip>
          </div>
          {(f.matched_rule_name || f.block_reason) && (
            <div className="mt-0.5 truncate text-[12px] text-fg-subtle">{f.matched_rule_name || f.block_reason}</div>
          )}
        </div>
      ),
    },
  ];
  if (showServer) {
    columns.push({
      id: 'server',
      header: 'Server',
      width: '22%',
      hideBelow: 'lg',
      sortValue: (f) => f.server_hostname,
      cell: (f) =>
        f.server_id && !f.server_id.startsWith('srv-unregistered-') && !f.server_id.startsWith('srv-auto-') ? (
          <Link to={`/servers/${encodeURIComponent(f.server_id)}`} className="block truncate text-[12.5px] text-fg hover:text-accent hover:underline">
            {f.server_hostname || f.server_ip}
          </Link>
        ) : (
          <span className="block truncate font-mono text-[12px] text-fg-muted">{f.server_ip}</span>
        ),
    });
  }
  columns.push({
    id: 'status',
    header: 'Status',
    width: 72,
    align: 'right',
    hideBelow: 'lg',
    sortValue: (f) => f.status_code,
    cell: (f) => <span className="tabular text-[12.5px] text-fg-muted">{f.status_code || '—'}</span>,
  });

  return (
    <DataTable
      rows={rows}
      columns={columns}
      getRowId={(f) => f.id}
      getSearchText={(f) => `${f.full_url} ${f.matched_rule_name ?? ''} ${f.verdict} ${f.server_hostname}`}
      searchPlaceholder="Filter requests…"
      facets={[
        {
          id: 'outcome',
          label: 'Outcome',
          getValue: (f) => (isAllowedVerdict(f.verdict) ? 'allowed' : 'blocked'),
          options: [
            { value: 'allowed', label: 'Allowed' },
            { value: 'blocked', label: 'Blocked' },
          ],
        },
      ]}
      toolbar={
        <Badge tone={connected ? 'success' : 'neutral'} dot pulse={connected}>
          {connected ? 'Live' : 'Offline'}
        </Badge>
      }
      mobileCard={(f) => (
        <div className="min-w-0 space-y-1">
          <div className="flex items-center justify-between gap-2">
            <VerdictBadge verdict={f.verdict} />
            <RelativeTime value={f.timestamp} className="text-[12px] text-fg-subtle" />
          </div>
          <div className="break-all font-mono text-[12px]">
            <span className="text-fg-muted">{f.method} </span>
            <span className="font-semibold text-fg">{f.host}</span>
            <span className="text-fg-muted">{f.path.length > 80 ? `${f.path.slice(0, 80)}…` : f.path}</span>
          </div>
          {showServer && <div className="truncate text-[12px] text-fg-subtle">{f.server_hostname || f.server_ip}</div>}
        </div>
      )}
      pageSize={pageSize}
      empty={<EmptyState icon={Activity} size="sm" title={emptyTitle} description={emptyDescription ?? 'Requests appear here live as soon as the proxy records them.'} />}
      aria-label="Recent traffic"
    />
  );
};
