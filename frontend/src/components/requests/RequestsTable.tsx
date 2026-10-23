import React from 'react';
import { Inbox, Lock, ShieldAlert, UserRound } from 'lucide-react';
import { useConsoleState, usePermissions } from '../../data/AppData';
import { useLookups } from '../../data/lookups';
import { DURATION_LABELS } from '../../lib/format';
import { Link } from '../../lib/router';
import type { AccessRequest } from '../../types';
import { Avatar, Column, DataTable, DataTableProps, EmptyState, RelativeTime, Tooltip } from '../../ui';
import { DeadlineChip, RequestStateChip, ScopeBadge, VerifiedBadge } from './RequestBadges';
import { canHandle } from './requestUtils';

const href = (r: AccessRequest) => `/requests/${encodeURIComponent(r.id)}`;

export const RequestDestination: React.FC<{ request: AccessRequest; link?: boolean }> = ({ request: r, link = true }) => {
  const body = (
    <span className="line-clamp-2 min-w-0 font-mono text-[12.5px] leading-5 [overflow-wrap:anywhere]" title={r.requested_url}>
      <span className="font-semibold text-fg">{r.host}</span>
      <span className="text-fg-muted">{r.path !== '/' ? r.path : ''}</span>
    </span>
  );
  return link ? (
    <Link to={href(r)} className="block min-w-0 hover:underline">
      {body}
    </Link>
  ) : (
    body
  );
};

export const Assignee: React.FC<{ username?: string }> = ({ username }) => {
  const { userName } = useLookups();
  if (!username) return <span className="text-[12px] text-fg-subtle">Unassigned</span>;
  return (
    <Tooltip content={`Assigned to ${userName(username)}`}>
      <span className="inline-flex min-w-0 items-center gap-1.5 text-[12.5px]">
        <Avatar name={userName(username)} size="xs" />
        <span className="max-w-[120px] truncate text-fg">{username}</span>
      </span>
    </Tooltip>
  );
};

const AssigneeAvatar: React.FC<{ username?: string }> = ({ username }) => {
  const { userName } = useLookups();
  if (!username)
    return (
      <Tooltip content="Unassigned">
        <span className="inline-flex h-6 w-6 items-center justify-center rounded-full border border-dashed border-border-strong text-fg-subtle">
          <UserRound className="h-3.5 w-3.5" aria-label="Unassigned" />
        </span>
      </Tooltip>
    );
  return (
    <Tooltip content={`Assigned to ${userName(username)} (@${username})`}>
      <Avatar name={userName(username)} size="sm" title={username} />
    </Tooltip>
  );
};

type Props = Omit<DataTableProps<AccessRequest>, 'columns' | 'getRowId'> & {
  /** Hide the server column (server detail page). */
  hideServer?: boolean;
  /** Show the state chip column (non-pending lists). */
  showState?: boolean;
};

/** Access requests list: destination, server, requester, verification, scope, SLA, assignee, age. */
export const RequestsTable: React.FC<Props> = ({ hideServer, showState, ...rest }) => {
  const perms = usePermissions();
  const state = useConsoleState();
  const { groupName } = useLookups();
  const columns: Column<AccessRequest>[] = [
    {
      id: 'dest',
      header: 'Requested destination',
      sortValue: (r) => `${r.host}${r.path}`,
      cell: (r) => (
        <div className="min-w-[190px] xl:min-w-[240px]">
          <div className="flex items-start gap-1.5">
            <span className="mt-0.5 shrink-0 rounded border border-border px-1 font-mono text-[10.5px] font-medium leading-4 text-fg-muted">{r.method || 'GET'}</span>
            <RequestDestination request={r} />
          </div>
          <div className="mt-0.5 line-clamp-1 text-[12px] text-fg-subtle" title={r.reason}>
            {r.reason}
          </div>
        </div>
      ),
    },
  ];
  if (!hideServer) {
    columns.push({
      id: 'server',
      header: 'Server and requester',
      sortValue: (r) => r.server_hostname || r.server_ip,
      cell: (r) => {
        const registered = state.servers.some((s) => s.id === r.server_id);
        const name = r.server_hostname || r.server_ip;
        return (
          <div className="min-w-[140px] max-w-[230px] leading-5">
            <span className="flex items-start gap-1">
              {registered ? (
                <Link to={`/servers/${encodeURIComponent(r.server_id)}`} className="text-[12.5px] text-fg [overflow-wrap:anywhere] hover:text-accent hover:underline">
                  {name}
                </Link>
              ) : (
                <span className="text-[12.5px] text-fg [overflow-wrap:anywhere]">{name}</span>
              )}
              {!r.verified && (
                <Tooltip content="Unverified source: no signed block token">
                  <ShieldAlert className="mt-1 h-3.5 w-3.5 shrink-0 text-warning xl:hidden" aria-label="unverified" />
                </Tooltip>
              )}
            </span>
            <span className="block truncate text-[11.5px] text-fg-subtle" title={r.requester}>
              {r.requester}
            </span>
            <span className="block truncate text-[11.5px] text-fg-subtle">{(r.target_group_ids ?? []).map(groupName).join(', ')}</span>
          </div>
        );
      },
    });
  }
  columns.push(
    {
      id: 'verified',
      header: 'Source',
      hideBelow: 'xl',
      sortValue: (r) => (r.verified ? 1 : 0),
      cell: (r) => <VerifiedBadge verified={r.verified} compact />,
    },
    {
      id: 'scope',
      header: 'Scope',
      hideBelow: 'xl',
      sortValue: (r) => r.requested_scope,
      cell: (r) => (
        <div className="flex min-w-0 flex-col items-start gap-0.5">
          <ScopeBadge scope={r.requested_scope} />
          {r.requested_scope !== 'learning_session_15m' && <span className="whitespace-nowrap text-[11.5px] text-fg-subtle">{DURATION_LABELS[r.duration] ?? r.duration}</span>}
        </div>
      ),
    },
    {
      id: 'deadline',
      header: showState ? 'Status' : 'SLA',
      sortValue: (r) => (showState ? r.created_at : r.due_at || '9999'),
      cell: (r) => (
        <div className="flex flex-col items-start gap-0.5">
          <span className="inline-flex items-center gap-1">
            {showState ? <RequestStateChip request={r} /> : <DeadlineChip request={r} />}
            {r.status === 'pending' && !canHandle(perms, r) && (
              <Tooltip content="Outside your groups: you can view but not review this request.">
                <Lock className="h-3.5 w-3.5 text-fg-subtle" aria-label="outside your groups" />
              </Tooltip>
            )}
          </span>
          <span className="whitespace-nowrap text-[11.5px] text-fg-subtle">
            {showState && r.status === 'pending' && r.due_at ? (
              <>
                due <RelativeTime value={r.due_at} />
              </>
            ) : showState && r.status === 'approved' ? (
              r.expires_at ? (
                <>
                  {new Date(r.expires_at).getTime() < Date.now() ? 'ended' : 'ends'} <RelativeTime value={r.expires_at} />
                </>
              ) : (
                'permanent'
              )
            ) : showState && (r.revoked_at || r.reviewed_at) ? (
              <>
                decided <RelativeTime value={r.revoked_at || r.reviewed_at} />
              </>
            ) : (
              <>
                opened <RelativeTime value={r.created_at} />
              </>
            )}
          </span>
        </div>
      ),
    },
    {
      id: 'assignee',
      header: <span className="sr-only">Assignee</span>,
      mobileLabel: 'Assignee',
      width: 48,
      align: 'center',
      hideBelow: 'lg',
      cell: (r) => <AssigneeAvatar username={r.assigned_to} />,
    }
  );

  return (
    <DataTable<AccessRequest>
      columns={columns}
      getRowId={(r) => r.id}
      rowHref={href}
      rowClassName={(r) => (r.status === 'pending' && r.due_at && new Date(r.due_at).getTime() < Date.now() ? 'bg-danger-soft/30' : undefined)}
      mobileCard={(r) => (
        <div className="min-w-0 space-y-1.5">
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0 flex-1">
              <RequestDestination request={r} />
              <div className="truncate text-[12px] text-fg-subtle">
                {r.server_hostname || r.server_ip} · <RelativeTime value={r.created_at} />
              </div>
            </div>
            {showState ? <RequestStateChip request={r} /> : <DeadlineChip request={r} />}
          </div>
          <p className="line-clamp-2 text-[12.5px] text-fg-muted">{r.reason}</p>
          <div className="flex flex-wrap items-center gap-1.5">
            <VerifiedBadge verified={r.verified} compact />
            <ScopeBadge scope={r.requested_scope} />
            {showState && r.status !== 'pending' && <DeadlineChip request={r} />}
            {r.assigned_to && <Assignee username={r.assigned_to} />}
          </div>
        </div>
      )}
      empty={<EmptyState icon={Inbox} size="sm" title="No access requests" description="Requests submitted from block pages and the CLI appear here." />}
      aria-label="Access requests"
      {...rest}
    />
  );
};
