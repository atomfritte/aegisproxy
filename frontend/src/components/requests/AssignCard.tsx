import React from 'react';
import { UserCheck, UserMinus } from 'lucide-react';
import { api } from '../../api';
import { useAction, useConsoleState, usePermissions } from '../../data/AppData';
import { ROLE_LABELS } from '../../data/permissions';
import { useSession } from '../../data/session';
import type { AccessRequest } from '../../types';
import { Button, Card, CardHeader, Combobox } from '../../ui';
import { Assignee } from './RequestsTable';
import { canHandle, eligibleAssignees } from './requestUtils';

/** Responsible reviewer: assign to me / someone who can approve for the request's groups / nobody. */
export const AssignCard: React.FC<{ request: AccessRequest }> = ({ request: r }) => {
  const state = useConsoleState();
  const perms = usePermissions();
  const { user } = useSession();
  const { run, pending } = useAction();
  const can = canHandle(perms, r) && r.status === 'pending';
  const eligible = eligibleAssignees(state.users, r.target_group_ids ?? []);
  const me = user?.username.toLowerCase() ?? '';
  const meEligible = eligible.some((u) => u.username.toLowerCase() === me);
  const assigned = (r.assigned_to || '').toLowerCase();

  const assign = (username: string) =>
    run(() => api.requests.assign(r.id, username), {
      key: 'assign',
      success: username ? (username === me ? 'Assigned to you' : `Assigned to ${username}`) : 'Assignee removed',
      errorTitle: 'The request was not assigned',
    });

  return (
    <Card>
      <CardHeader title="Assignee" icon={UserCheck} />
      <div className="space-y-3 px-[var(--card-p)] pb-[var(--card-p)] pt-2">
        <Assignee username={r.assigned_to} />
        {can ? (
          <>
            <Combobox
              value={assigned}
              onChange={(v) => v !== assigned && assign(v)}
              options={eligible.map((u) => ({
                value: u.username.toLowerCase(),
                label: u.display_name || u.username,
                description: `@${u.username} · ${ROLE_LABELS[u.role]}`,
              }))}
              placeholder="Choose a reviewer"
              searchPlaceholder="Search reviewers…"
              emptyText="Nobody else can approve for these groups"
              disabled={pending === 'assign'}
              aria-label="Assignee"
              clearable
            />
            <div className="flex flex-wrap gap-2">
              {meEligible && assigned !== me && (
                <Button size="sm" icon={UserCheck} onClick={() => assign(me)} loading={pending === 'assign'}>
                  Assign to me
                </Button>
              )}
              {assigned && (
                <Button size="sm" variant="ghost" icon={UserMinus} onClick={() => assign('')} disabled={pending === 'assign'}>
                  Unassign
                </Button>
              )}
            </div>
            <p className="text-[12px] leading-5 text-fg-subtle">Only users who can approve for all target groups are listed.</p>
          </>
        ) : (
          <p className="text-[12px] text-fg-subtle">
            {r.status !== 'pending' ? 'Assignment ends with the decision.' : perms.isReadOnly ? 'Read-only access.' : 'You cannot handle requests of these groups.'}
          </p>
        )}
      </div>
    </Card>
  );
};
