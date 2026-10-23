import React from 'react';
import type { PolicyDiff, PolicySetSpec } from '../../types';
import { DiffView } from '../../ui';
import { useLookups } from '../../data/lookups';

/** DiffView with group / server ids rendered as names. */
export const PolicyDiffView: React.FC<{
  diff: PolicyDiff | null | undefined;
  from?: PolicySetSpec | null;
  to?: PolicySetSpec | null;
  emptyTitle?: string;
  emptyDescription?: React.ReactNode;
}> = (props) => {
  const { groupName, serverName } = useLookups();
  return (
    <DiffView
      {...props}
      formatValue={(field, value) => {
        if ((field === 'group_ids' || field === 'server_ids') && Array.isArray(value)) {
          if (value.length === 0) return <span className="text-fg-subtle">none</span>;
          const name = field === 'group_ids' ? groupName : serverName;
          return value.map((v) => name(String(v))).join(', ');
        }
        if (field === 'review_interval_days' && typeof value === 'number') return value === 0 ? 'No recertification' : `${value} days`;
        return undefined;
      }}
    />
  );
};
