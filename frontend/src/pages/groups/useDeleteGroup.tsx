import React from 'react';
import { api } from '../../api';
import { useConsole } from '../../data/AppData';
import { navigate } from '../../lib/router';
import type { ServerGroup } from '../../types';
import { Callout, useConfirm, useToast } from '../../ui';
import { groupMembers } from '../../components/fleet/fleetUtils';

/** Delete a group with typed confirmation; the server explains remaining references. */
export function useDeleteGroup() {
  const confirm = useConfirm();
  const toast = useToast();
  const { state, refresh } = useConsole();
  return (g: ServerGroup, after?: () => void) => {
    const m = state ? groupMembers(g, state.servers) : null;
    const sets = (state?.policy_sets ?? []).filter((s) => s.kind === 'standard' && (s.group_ids ?? []).includes(g.id));
    return confirm({
      title: `Delete ${g.name}?`,
      description: 'Its empty approvals set is removed as well. Servers that only matched its label selector simply lose the membership.',
      tone: 'danger',
      confirmLabel: 'Delete group',
      typeToConfirm: g.id,
      body:
        (m && m.static.length > 0) || sets.length > 0 ? (
          <Callout tone="warning" title="Still referenced">
            {m && m.static.length > 0 && <span className="block">{m.static.length} servers are static members — remove them from the group first.</span>}
            {sets.length > 0 && <span className="block">Assigned to {sets.map((s) => s.name).join(', ')}.</span>}
            <span className="block">The server refuses the deletion while references remain.</span>
          </Callout>
        ) : undefined,
      onConfirm: async () => {
        await api.groups.remove(g.id);
        await refresh();
        toast.success(`Deleted ${g.name}`);
        if (after) after();
        else navigate('/groups', { replace: true });
      },
    });
  };
}
