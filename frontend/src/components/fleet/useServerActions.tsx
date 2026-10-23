import React from 'react';
import { api } from '../../api';
import { useConsole } from '../../data/AppData';
import { navigate } from '../../lib/router';
import type { Server } from '../../types';
import { Callout, useConfirm, useToast } from '../../ui';
import { effectiveGroups } from './fleetUtils';
import { forEachServer } from './BulkServerDialogs';
import { quarantinedByLabel } from './DefenderDevice';

/** Permission hints for one server (the server re-checks every action). */
export function useServerPerms() {
  const { perms } = useConsole();
  return {
    canManage: perms.canManageSystem,
    canQuarantine: (s: Server) => !perms.isReadOnly && (perms.canManageSystem || (perms.isTeamLead && perms.canApproveFor(effectiveGroups(s)))),
    canRelease: perms.canManageSystem,
  };
}

/** Quarantine / release / decommission with confirmation dialogs. */
export function useServerActions() {
  const confirm = useConfirm();
  const toast = useToast();
  const { refresh } = useConsole();

  const quarantine = (servers: Server[]) =>
    confirm({
      title: servers.length === 1 ? `Quarantine ${servers[0].hostname}?` : `Quarantine ${servers.length} servers?`,
      description: 'Every request from the server is denied (verdict QUARANTINED) within seconds, until InfoSec releases it. A security event is raised.',
      tone: 'danger',
      confirmLabel: 'Quarantine',
      reason: { label: 'Reason', required: true, placeholder: 'Incident number and what was observed', hint: 'Recorded in the audit trail and shown on the server.' },
      onConfirm: async (reason) => {
        const failures = await forEachServer(servers, (s) => api.servers.quarantine(s.id, true, reason));
        await refresh();
        if (failures.length === servers.length) throw new Error(failures.join('; '));
        if (failures.length) toast.warning(`Quarantined ${servers.length - failures.length} of ${servers.length} servers`, { description: failures.join('; ') });
        else toast.success(servers.length === 1 ? `Quarantined ${servers[0].hostname}` : `Quarantined ${servers.length} servers`, { description: 'All egress is blocked.' });
      },
    });

  const release = (s: Server) =>
    confirm({
      title: `Release ${s.hostname} from quarantine?`,
      description: 'Its group policy applies again immediately.',
      body: s.quarantine_reason ? (
        <Callout tone="neutral" title="Quarantined because">
          {s.quarantine_reason}
          {s.quarantined_by ? ` — ${quarantinedByLabel(s.quarantined_by)}` : ''}
        </Callout>
      ) : undefined,
      confirmLabel: 'Release',
      reason: { label: 'Comment', placeholder: 'Why is the server clean again?', multiline: false },
      onConfirm: async (reason) => {
        await api.servers.quarantine(s.id, false, reason);
        await refresh();
        toast.success(`Released ${s.hostname}`);
      },
    });

  const decommission = (s: Server, after?: () => void) =>
    confirm({
      title: `Decommission ${s.hostname}?`,
      description: 'The server is removed from the inventory and from every policy set and TLS exception that names it. Its proxy token stops working immediately.',
      tone: 'danger',
      confirmLabel: 'Decommission',
      typeToConfirm: s.id,
      onConfirm: async () => {
        await api.servers.remove(s.id);
        await refresh();
        toast.success(`Decommissioned ${s.hostname}`);
        if (after) after();
        else navigate('/servers', { replace: true });
      },
    });

  return { quarantine, release, decommission };
}
