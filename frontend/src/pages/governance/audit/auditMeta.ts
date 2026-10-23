// Presentation helpers for audit events: category labels/icons, action tones, entity links.
import type { LucideIcon } from 'lucide-react';
import {
  Boxes,
  FileWarning,
  Gavel,
  Inbox,
  KeyRound,
  Layers,
  Lock,
  Radar,
  ScrollText,
  Server,
  Settings,
  ShieldAlert,
  Sliders,
  Users,
} from 'lucide-react';
import { ROLE_LABELS } from '../../../data/permissions';
import { humanize } from '../../../lib/format';
import type { AuditCategory, AuditEvent, PolicyRule, Role } from '../../../types';
import type { Tone } from '../../../ui';

export const CATEGORY_META: Record<AuditCategory, { label: string; icon: LucideIcon; tone: Tone; description: string }> = {
  POLICY: { label: 'Policy', icon: Layers, tone: 'accent', description: 'Policy sets, drafts, publications, change requests' },
  APPROVAL: { label: 'Approvals', icon: Inbox, tone: 'warning', description: 'Access requests and their reviews' },
  FLEET: { label: 'Fleet', icon: Server, tone: 'info', description: 'Servers, groups, quarantine, tokens' },
  SECURITY: { label: 'Security', icon: ShieldAlert, tone: 'danger', description: 'Threat protection, feeds, indicators, events' },
  SYSTEM: { label: 'System', icon: Settings, tone: 'neutral', description: 'Settings, block pages, log export, governance' },
  IDENTITY: { label: 'Identity', icon: Users, tone: 'violet', description: 'Users, roles, passwords, sign-ins' },
  TLS_BYPASS: { label: 'TLS exceptions', icon: Lock, tone: 'violet', description: 'TLS no-break exceptions' },
  SESSION: { label: 'Learning', icon: Radar, tone: 'info', description: 'Learning sessions' },
  RULE: { label: 'Rules (legacy)', icon: Sliders, tone: 'neutral', description: 'Rule changes recorded before 2.1' },
};

export const CATEGORY_ORDER: AuditCategory[] = ['POLICY', 'APPROVAL', 'FLEET', 'SECURITY', 'SYSTEM', 'IDENTITY', 'TLS_BYPASS', 'SESSION', 'RULE'];

export function categoryMeta(c: string) {
  return CATEGORY_META[c as AuditCategory] ?? { label: humanize(c || 'other'), icon: ScrollText, tone: 'neutral' as Tone, description: '' };
}

const ENTITY_LABELS: Record<string, string> = {
  policy_set: 'Policy set',
  policy_rule: 'Rule',
  change_request: 'Change request',
  access_request: 'Access request',
  server: 'Server',
  server_group: 'Group',
  block_page: 'Block page',
  export_sink: 'Log export destination',
  security_event: 'Security event',
  security_policy: 'Threat protection policy',
  threat_feed: 'Threat feed',
  indicator: 'Indicator',
  threat_exception: 'Threat exception',
  tls_bypass: 'TLS exception',
  user: 'User',
  entra_config: 'Entra ID settings',
  notify_config: 'Notification settings',
  governance: 'Governance settings',
  learning_session: 'Learning session',
  control_plane: 'Control plane',
};

export function entityLabel(type: string): string {
  return ENTITY_LABELS[type] ?? humanize(type || 'entity');
}

export const ENTITY_ICONS: Record<string, LucideIcon> = {
  policy_set: Layers,
  server_group: Boxes,
  block_page: FileWarning,
  governance: Gavel,
  user: Users,
  entra_config: KeyRound,
};

/**
 * Console page for an audited entity (or null). `rules` resolves legacy rule ids to their policy set.
 */
export function entityHref(ev: Pick<AuditEvent, 'entity_type' | 'entity_id'>, rules: PolicyRule[] = []): { to: string; label: string } | null {
  const id = encodeURIComponent(ev.entity_id || '');
  switch (ev.entity_type) {
    case 'policy_set':
      return ev.entity_id ? { to: `/policies/${id}/history`, label: 'Open version history' } : null;
    case 'policy_rule': {
      const r = rules.find((x) => x.id === ev.entity_id);
      return r?.policy_set_id ? { to: `/policies/${encodeURIComponent(r.policy_set_id)}`, label: `Open ${r.policy_set_name || 'policy set'}` } : null;
    }
    case 'server':
      return ev.entity_id ? { to: `/servers/${id}`, label: 'Open server' } : null;
    case 'server_group':
      return ev.entity_id ? { to: `/groups/${id}`, label: 'Open group' } : null;
    case 'access_request':
      return ev.entity_id ? { to: `/requests/${id}`, label: 'Open access request' } : null;
    case 'change_request':
      return ev.entity_id ? { to: `/changes/${id}`, label: 'Open change request' } : null;
    case 'block_page':
      return ev.entity_id ? { to: `/block-pages/${id}`, label: 'Open block page' } : null;
    case 'export_sink':
      // ?edit= opens the destination drawer (ignored when it was deleted meanwhile)
      return { to: ev.entity_id ? `/settings/log-export?edit=${id}` : '/settings/log-export', label: 'Open log export destination' };
    case 'security_event':
      return ev.entity_id ? { to: `/threats/events/${id}`, label: 'Open security event' } : null;
    case 'user':
    case 'entra_config':
      return { to: '/settings/identity', label: 'Open identity settings' };
    case 'notify_config':
      return { to: '/settings/notifications', label: 'Open notification settings' };
    case 'governance':
      return { to: '/settings/governance', label: 'Open governance settings' };
    case 'tls_bypass':
      return { to: '/tls', label: 'Open TLS exceptions' };
    case 'threat_feed':
      return { to: '/threats/feeds', label: 'Open threat feeds' };
    case 'indicator':
      return { to: '/threats/iocs', label: 'Open indicators' };
    case 'threat_exception':
      return { to: '/threats/exceptions', label: 'Open threat exceptions' };
    case 'security_policy':
      return { to: '/threats/policy', label: 'Open threat protection policy' };
    case 'learning_session':
      return { to: '/learning', label: 'Open learning sessions' };
    default:
      return null;
  }
}

const SUCCESS_VERBS = ['CREATED', 'APPROVED', 'PUBLISHED', 'ADDED', 'ENABLED', 'RECERTIFIED', 'ACKNOWLEDGED', 'RESTORED', 'RELEASED', 'IMPORTED'];
const DANGER_VERBS = ['DELETED', 'REJECTED', 'REVOKED', 'REMOVED', 'QUARANTINED', 'FAILED', 'DENIED', 'DISCARDED', 'LOCKED', 'DECOMMISSIONED'];
const WARNING_VERBS = ['SUBMITTED', 'EMERGENCY', 'ROLLED_BACK', 'ROLLBACK', 'RESET', 'EXPIRED', 'WITHDRAWN', 'SUPERSEDED'];
const INFO_VERBS = ['UPDATED', 'TOGGLED', 'CHANGED', 'EXTENDED', 'ASSIGNED', 'COMMENTED', 'ROTATED', 'STARTED', 'STOPPED', 'SAVED', 'PRUNED', 'MIGRATED'];

/** Tone for an action like RULE_UPDATED / POLICY_SET_PUBLISHED. */
export function actionTone(action: string): Tone {
  const a = (action || '').toUpperCase();
  if (DANGER_VERBS.some((v) => a.includes(v))) return 'danger';
  if (a.includes('EMERGENCY')) return 'warning';
  if (SUCCESS_VERBS.some((v) => a.includes(v))) return 'success';
  if (WARNING_VERBS.some((v) => a.includes(v))) return 'warning';
  if (INFO_VERBS.some((v) => a.includes(v))) return 'info';
  return 'neutral';
}

const ACRONYMS: Record<string, string> = { tls: 'TLS', ioc: 'IOC', ca: 'CA', dlp: 'DLP', id: 'ID', av: 'AV' };

/** RULE_UPDATED → "Rule updated", TLS_BYPASS_ADDED → "TLS bypass added". */
export function actionLabel(action: string): string {
  return humanize(action || 'event')
    .split(' ')
    .map((w) => ACRONYMS[w.toLowerCase()] ?? w)
    .join(' ');
}

/** "Super Admin", "Server portal", "System" … */
export function roleLabel(role: string): string {
  if (!role) return '';
  return ROLE_LABELS[role as Role] ?? humanize(role);
}

export type TimeRange = '24h' | '7d' | '30d' | 'all';
export const RANGE_MS: Record<Exclude<TimeRange, 'all'>, number> = { '24h': 86_400_000, '7d': 7 * 86_400_000, '30d': 30 * 86_400_000 };
