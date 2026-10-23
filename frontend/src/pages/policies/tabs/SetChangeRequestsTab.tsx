import React from 'react';
import { GitPullRequestArrow } from 'lucide-react';
import type { ChangeRequest } from '../../../types';
import { Link } from '../../../lib/router';
import { Column, DataTable, EmptyState, RelativeTime } from '../../../ui';
import { UserName } from '../../../components/common/EntityChips';
import { ChangeRequestStatusChip } from '../../../components/policy/PolicyBadges';

/** Change requests of one policy set (newest first). */
export const SetChangeRequestsTab: React.FC<{ requests: ChangeRequest[] }> = ({ requests }) => {
  const columns: Column<ChangeRequest>[] = [
    {
      id: 'title',
      header: 'Change request',
      cell: (c) => (
        <div className="min-w-0">
          <Link to={`/changes/${encodeURIComponent(c.id)}`} className="font-medium text-fg hover:text-accent hover:underline">
            {c.title}
          </Link>
          <div className="text-[12px] text-fg-subtle">
            {c.id}, based on v{c.base_version}
            {c.published_version ? `, published as v${c.published_version}` : ''}
          </div>
        </div>
      ),
    },
    { id: 'status', header: 'Status', width: 170, sortValue: (c) => c.status, cell: (c) => <ChangeRequestStatusChip status={c.status} /> },
    {
      id: 'by',
      header: 'Submitted',
      width: 200,
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
      id: 'decided',
      header: 'Decided',
      width: 200,
      hideBelow: 'lg',
      cell: (c) =>
        c.decided_by ? (
          <div className="leading-tight">
            <UserName username={c.decided_by} />
            <div className="text-[12px] text-fg-subtle">
              <RelativeTime value={c.decided_at} />
            </div>
          </div>
        ) : (
          <span className="text-fg-subtle">—</span>
        ),
    },
  ];
  return (
    <DataTable
      rows={requests}
      columns={columns}
      getRowId={(c) => c.id}
      rowHref={(c) => `/changes/${encodeURIComponent(c.id)}`}
      hideToolbar
      empty={<EmptyState icon={GitPullRequestArrow} title="No change requests yet" description="With four-eyes review enabled, submitting a draft creates a change request." size="sm" />}
    />
  );
};
