// Client-side mirror of the control-plane RBAC rules (auth.CanApproveForGroups, canManageSetLocked,
// CanModifyRule). Used only to hide/disable actions — the server is authoritative, so always
// surface its error messages (toast.error(err)).

import type { PolicySet, PolicySetKind, Role, Server, User } from '../types';

export const ROLE_LABELS: Record<Role, string> = {
  SUPER_ADMIN: 'Super Admin',
  INFOSEC_APPROVER: 'InfoSec Approver',
  TEAM_LEAD_APPROVER: 'Team Lead',
  OPERATOR_AUDITOR: 'Auditor (read-only)',
};

export interface Permissions {
  user: User | null;
  role: Role | null;
  isSuperAdmin: boolean;
  /** Super Admin or InfoSec: fleet, TLS, threat protection, governance, baseline sets, deletes. */
  canManageSystem: boolean;
  /** Super Admin only. */
  canManageUsers: boolean;
  isTeamLead: boolean;
  /** Auditor / operator: read-only (may comment on change requests). */
  isReadOnly: boolean;
  /** Mirrors auth.CanApproveForGroups (Team Leads: every group must be in allowed_groups). */
  canApproveFor: (groupIds: string[] | null | undefined) => boolean;
  /** May create/edit/publish a policy set of this kind and scope. */
  canManageSetScope: (kind: PolicySetKind, groupIds: string[], serverIds: string[], servers?: Server[]) => boolean;
  canManageSet: (set: PolicySet, servers?: Server[]) => boolean;
  /** Team Leads cannot create or change BLOCK rules. */
  canEditBlockRules: boolean;
}

export function permissionsFor(user: User | null | undefined): Permissions {
  const role = user?.role ?? null;
  const isSuperAdmin = role === 'SUPER_ADMIN';
  const canManageSystem = role === 'SUPER_ADMIN' || role === 'INFOSEC_APPROVER';
  const isTeamLead = role === 'TEAM_LEAD_APPROVER';
  const allowed = new Set(user?.allowed_groups ?? []);

  const canApproveFor = (groupIds: string[] | null | undefined): boolean => {
    if (!role) return false;
    if (canManageSystem) return true;
    if (!isTeamLead) return false;
    const g = groupIds ?? [];
    if (g.length === 0) return false;
    if (allowed.has('*')) return true;
    return g.every((id) => id !== '*' && allowed.has(id));
  };

  const canManageSetScope = (kind: PolicySetKind, groupIds: string[], serverIds: string[], servers: Server[] = []): boolean => {
    if (!role || role === 'OPERATOR_AUDITOR') return false;
    if (kind === 'baseline') return canManageSystem;
    if (canManageSystem) return true;
    if (groupIds.length === 0 && serverIds.length === 0) return true; // empty draft; server checks once rules exist
    if (groupIds.length > 0 && !canApproveFor(groupIds)) return false;
    for (const sid of serverIds) {
      const srv = servers.find((s) => s.id === sid);
      if (!srv || !canApproveFor(srv.effective_group_ids ?? srv.group_ids ?? [])) return false;
    }
    return true;
  };

  return {
    user: user ?? null,
    role,
    isSuperAdmin,
    canManageSystem,
    canManageUsers: isSuperAdmin,
    isTeamLead,
    isReadOnly: role === 'OPERATOR_AUDITOR' || role === null,
    canApproveFor,
    canManageSetScope,
    canManageSet: (set, servers) => canManageSetScope(set.kind, set.group_ids ?? [], set.server_ids ?? [], servers),
    canEditBlockRules: canManageSystem,
  };
}
