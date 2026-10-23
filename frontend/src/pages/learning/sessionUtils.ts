import type { Permissions } from '../../data/permissions';
import { toTime } from '../../lib/format';
import type { DashboardState, LearningSession, PolicySet, Server } from '../../types';

export type SessionPhase = 'recording' | 'ended' | 'published' | 'stopped';

/** "active" sessions whose expiry passed are shown as ended (the server never flips them). */
export function sessionPhase(s: LearningSession, now = Date.now()): SessionPhase {
  if (s.status === 'published') return 'published';
  if (s.status === 'stopped') return 'stopped';
  if (s.status === 'active' && (toTime(s.expires_at) ?? 0) > now) return 'recording';
  return 'ended';
}

export const PHASE_META: Record<SessionPhase, { label: string; tone: 'info' | 'neutral' | 'success' | 'warning' }> = {
  recording: { label: 'Recording', tone: 'info' },
  ended: { label: 'Ready for review', tone: 'warning' },
  published: { label: 'Published', tone: 'success' },
  stopped: { label: 'Stopped', tone: 'neutral' },
};

export const MODE_META: Record<LearningSession['mode'], { label: string; description: string }> = {
  record_and_allow: {
    label: 'Record & allow',
    description: 'Every request of the server is allowed and recorded (BLOCK guardrails, threat protection and internal destinations still apply).',
  },
  record_only: { label: 'Record only', description: 'Normal policy applies; blocked and allowed requests are recorded as candidates.' },
};

/** Mirrors StartLearningSession: the reviewer must be able to approve for the server's effective groups (static + label-selected). */
export function canStartOn(perms: Permissions, s: Server): boolean {
  return !perms.isReadOnly && perms.canApproveFor(s.effective_group_ids ?? s.group_ids ?? []);
}

export function canManageSession(perms: Permissions, s: LearningSession): boolean {
  return !perms.isReadOnly && perms.canApproveFor(s.group_ids ?? []);
}

/** Policy sets that contain rules (published or in the draft) compiled from this session. */
export function setsFromSession(state: DashboardState, sessionId: string): PolicySet[] {
  return (state.policy_sets ?? []).filter(
    (p) => (p.rules ?? []).some((r) => r.source_session_id === sessionId) || (p.draft?.spec.rules ?? []).some((r) => r.source_session_id === sessionId)
  );
}

export const DURATIONS = [15, 30, 60, 120, 240];

export const SCENARIOS = [
  { id: 'github_microsoft_release', label: 'GitHub release download', description: 'github.com release asset with a redirect to objects.githubusercontent.com' },
  { id: 'docker_k8s_pull', label: 'Container image pull', description: 'nvcr.io manifest, CDN layer redirect and a Helm index' },
];
