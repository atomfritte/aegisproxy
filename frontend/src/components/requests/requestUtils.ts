// Access request helpers: derived states (overdue, expired), scopes, grant durations with the
// Team Lead cap, eligible assignees and the rules an approval created.

import type { Permissions } from '../../data/permissions';
import { toTime } from '../../lib/format';
import type { AccessDuration, AccessRequest, AccessScope, DashboardState, PolicyRule, PolicySet, User } from '../../types';

export type RequestState = 'pending' | 'overdue' | 'approved' | 'expired' | 'rejected' | 'revoked';

export function isOverdue(r: AccessRequest, now = Date.now()): boolean {
  const t = toTime(r.due_at);
  return r.status === 'pending' && t !== null && t < now;
}

export function isExpired(r: AccessRequest, now = Date.now()): boolean {
  const t = toTime(r.expires_at);
  return r.status === 'approved' && t !== null && t < now;
}

export function requestState(r: AccessRequest, now = Date.now()): RequestState {
  if (r.status === 'pending') return isOverdue(r, now) ? 'overdue' : 'pending';
  if (r.status === 'approved') return isExpired(r, now) ? 'expired' : 'approved';
  return r.status;
}

export const SCOPE_META: Record<AccessScope, { label: string; short: string; description: string }> = {
  exact_path: { label: 'Exact path', short: 'Exact path', description: 'Only the requested URL path.' },
  prefix_with_objects: {
    label: 'Path prefix with redirect objects',
    short: 'Prefix + objects',
    description: 'The path prefix (e.g. one GitHub organisation) and the objects it redirects to.',
  },
  domain: { label: 'Whole domain', short: 'Domain', description: 'Every path on the host.' },
  learning_session_15m: {
    label: '15-minute learning session',
    short: 'Learning session',
    description: 'Approval starts a 15-minute record & allow learning session on the server instead of creating a rule.',
  },
};

export function scopeLabel(s: string, short = false): string {
  const m = SCOPE_META[s as AccessScope];
  return m ? (short ? m.short : m.label) : s;
}

export const GRANT_DURATIONS: AccessDuration[] = ['1h', '8h', '24h', '7d', '30d', '90d', 'permanent'];

const HOUR = 3600_000;
export const DURATION_MS: Record<string, number> = { '1h': HOUR, '8h': 8 * HOUR, '24h': 24 * HOUR, '7d': 7 * 24 * HOUR, '30d': 30 * 24 * HOUR, '90d': 90 * 24 * HOUR };

export const DURATION_SHORT: Record<string, string> = { '1h': '1 h', '8h': '8 h', '24h': '24 h', '7d': '7 d', '30d': '30 d', '90d': '90 d', permanent: 'Permanent' };

/**
 * Why a grant duration is not available to this reviewer (mirrors store.expiryForLocked), or null.
 * Team Leads: temporary only, at most `max_temporary_access_days` (0 = no cap).
 */
export function durationBlockedReason(d: string, perms: Permissions, maxDays: number): string | null {
  if (perms.canManageSystem) return null;
  if (d === 'permanent') return `Team Leads can grant temporary access only${maxDays > 0 ? ` (at most ${maxDays} days)` : ''}; permanent access needs InfoSec.`;
  if (maxDays > 0 && (DURATION_MS[d] ?? 0) > maxDays * 24 * HOUR) return `Team Leads can grant at most ${maxDays} days (governance setting).`;
  return null;
}

/** Default methods of an approval: read-only plus the requested method (server default). */
export function defaultMethods(r: AccessRequest): string[] {
  const m = ['GET', 'HEAD'];
  if (r.method && !m.includes(r.method) && r.method !== 'CONNECT') m.push(r.method);
  return m;
}

/** Users who may be assigned (mirrors store.AssignRequest: not disabled, not read-only, can approve for the groups). */
export function eligibleAssignees(users: User[], groups: string[]): User[] {
  return users.filter((u) => {
    if (u.disabled || u.role === 'OPERATOR_AUDITOR') return false;
    if (u.role === 'SUPER_ADMIN' || u.role === 'INFOSEC_APPROVER') return true;
    const allowed = new Set(u.allowed_groups ?? []);
    if (groups.length === 0) return false;
    return allowed.has('*') || groups.every((g) => g !== '*' && allowed.has(g));
  });
}

/** May the signed-in user comment / assign / review / extend / revoke this request? */
export function canHandle(perms: Permissions, r: Pick<AccessRequest, 'target_group_ids'>): boolean {
  return !perms.isReadOnly && perms.canApproveFor(r.target_group_ids ?? []);
}

export function approvalsSetId(groupId: string): string {
  return `approvals-${groupId}`;
}

/** Rules created by an approved request, located in the approvals policy sets. */
export function createdRules(state: DashboardState, r: AccessRequest): Array<{ set: PolicySet; rule: PolicyRule }> {
  const ids = new Set([...(r.created_rule_ids ?? []), ...(r.created_rule_id ? [r.created_rule_id] : [])]);
  const out: Array<{ set: PolicySet; rule: PolicyRule }> = [];
  for (const set of state.policy_sets ?? []) {
    for (const rule of set.rules ?? []) {
      if (ids.has(rule.id) || rule.access_request_id === r.id) out.push({ set, rule });
    }
  }
  return out;
}

export function requestTitle(r: Pick<AccessRequest, 'host' | 'path'>, max = 64): string {
  const p = r.path && r.path !== '/' ? r.path : '';
  const full = `${r.host}${p}`;
  return full.length > max ? `${full.slice(0, max - 1)}…` : full;
}
