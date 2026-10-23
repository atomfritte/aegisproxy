import React from 'react';
import { Lock, ShieldOff, Tag, WifiOff } from 'lucide-react';
import { useLookups } from '../../data/lookups';
import { cn } from '../../lib/cn';
import { formatDateTime } from '../../lib/format';
import { useNow } from '../../lib/hooks';
import { Link } from '../../lib/router';
import type { Server, ServerGroup } from '../../types';
import { Badge, RelativeTime, StatusChip, Tooltip } from '../../ui';
import { ChipList } from '../common/EntityChips';
import { dynamicGroups, formatLabel, HEALTH_META, serverHealth, staticGroups } from './fleetUtils';
import { quarantinedByLabel } from './DefenderDevice';

const chipBase =
  'inline-flex max-w-[190px] items-center gap-1.5 rounded-md border px-1.5 py-0.5 text-[12px] leading-4 text-fg transition-colors';

/**
 * One group membership. Static memberships use a solid chip; label-selected (dynamic) memberships
 * a dashed outline with a tag icon, so both kinds are distinguishable without color.
 */
export const MembershipChip: React.FC<{ id: string; dynamic?: boolean; link?: boolean; className?: string }> = ({ id, dynamic, link = true, className }) => {
  const { groupById } = useLookups();
  const g = groupById.get(id);
  const cls = cn(
    chipBase,
    dynamic ? 'border-dashed border-border-strong bg-transparent' : 'border-border bg-surface-2',
    link && g && 'hover:border-fg-subtle hover:bg-surface-3',
    className
  );
  const body = (
    <>
      <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: g?.color || 'rgb(var(--c-fg-subtle))' }} aria-hidden />
      <span className="truncate">{g?.name || id}</span>
      {dynamic && <Tag className="h-3 w-3 shrink-0 text-fg-subtle" aria-hidden />}
      {dynamic && <span className="sr-only">(matched by labels)</span>}
    </>
  );
  const tip = dynamic
    ? `Member through the label selector ${Object.entries(g?.match_labels ?? {})
        .map(([k, v]) => formatLabel(k, v))
        .join(', ')}`
    : 'Static member';
  const el =
    link && g ? (
      <Link to={`/groups/${encodeURIComponent(id)}`} className={cls}>
        {body}
      </Link>
    ) : (
      <span className={cls}>{body}</span>
    );
  return <Tooltip content={tip}>{el}</Tooltip>;
};

/** Static chips first, then dynamic (label-selected) chips. */
export const MembershipChips: React.FC<{ server: Server; max?: number; className?: string }> = ({ server, max = 3, className }) => {
  const st = staticGroups(server);
  const dyn = dynamicGroups(server);
  if (st.length + dyn.length === 0) return <span className="text-[12.5px] text-fg-subtle">No group</span>;
  return (
    <ChipList max={max} className={className}>
      {[...st.map((id) => <MembershipChip key={`s-${id}`} id={id} />), ...dyn.map((id) => <MembershipChip key={`d-${id}`} id={id} dynamic />)]}
    </ChipList>
  );
};

/** Server health: quarantined / stale / never seen / healthy. */
export const ServerHealthChip: React.FC<{ server: Server; showHealthy?: boolean }> = ({ server, showHealthy = true }) => {
  const now = useNow();
  const h = serverHealth(server, now);
  if (h === 'healthy' && !showHealthy) return null;
  const m = HEALTH_META[h];
  const tip =
    h === 'quarantined'
      ? `${server.quarantine_reason || 'No reason recorded'}${server.quarantined_by ? ` — by ${quarantinedByLabel(server.quarantined_by)}` : ''}${server.quarantined_at ? `, ${formatDateTime(server.quarantined_at)}` : ''}`
      : m.description;
  return (
    <Tooltip content={tip}>
      {h === 'quarantined' ? (
        <Badge tone="danger" icon={ShieldOff}>
          {m.label}
        </Badge>
      ) : h === 'stale' ? (
        <Badge tone="warning" icon={WifiOff}>
          {m.label}
        </Badge>
      ) : (
        <StatusChip tone={m.tone} label={m.label} />
      )}
    </Tooltip>
  );
};

/** Last seen with stale highlighting. */
export const LastSeen: React.FC<{ server: Server }> = ({ server }) => {
  const now = useNow();
  const h = serverHealth(server, now);
  if (h === 'never') return <span className="text-[12.5px] text-fg-subtle">Never</span>;
  return <RelativeTime value={server.last_seen_at} className={cn('text-[12.5px]', h === 'stale' ? 'font-medium text-warning' : 'text-fg-muted')} />;
};

/** Label selector of a dynamic group (`*` shown as "any"). */
export const SelectorChips: React.FC<{ selector?: Record<string, string> | null; max?: number; className?: string }> = ({ selector, max = 4, className }) => {
  const entries = Object.entries(selector ?? {}).sort(([a], [b]) => a.localeCompare(b));
  if (entries.length === 0) return <span className="text-[12.5px] text-fg-subtle">—</span>;
  return (
    <ChipList max={max} className={className}>
      {entries.map(([k, v]) => (
        <span key={k} className="inline-flex items-center gap-1 rounded border border-dashed border-border-strong px-1.5 py-0.5 font-mono text-[11px] leading-4">
          <Tag className="h-3 w-3 shrink-0 text-fg-subtle" aria-hidden />
          <span className="text-fg-muted">{k}</span>
          <span className="text-fg-subtle">=</span>
          {v === '*' ? <span className="font-sans italic text-fg-subtle">any</span> : <span className="text-fg">{v}</span>}
        </span>
      ))}
    </ChipList>
  );
};

export const CidrChips: React.FC<{ cidrs?: string[] | null; max?: number }> = ({ cidrs, max = 3 }) => {
  const list = cidrs ?? [];
  if (list.length === 0) return <span className="text-[12.5px] text-fg-subtle">—</span>;
  return (
    <ChipList max={max}>
      {list.map((c) => (
        <span key={c} className="rounded border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[11px] leading-4 text-fg">
          {c}
        </span>
      ))}
    </ChipList>
  );
};

export const StrictBadge: React.FC = () => (
  <Tooltip content="Zero-internet tier: global TLS exceptions do not apply and record & allow learning sessions are refused.">
    <Badge tone="danger" icon={Lock}>
      Strict isolation
    </Badge>
  </Tooltip>
);

/** Square color tile with the group's initials (page headers, lists). */
export const GroupTile: React.FC<{ group: Pick<ServerGroup, 'color' | 'name'>; size?: 'sm' | 'md' }> = ({ group, size = 'md' }) => (
  <span
    aria-hidden
    className={cn('flex shrink-0 items-center justify-center rounded-lg font-semibold text-white shadow-xs', size === 'md' ? 'h-10 w-10 text-[13px]' : 'h-7 w-7 text-[10.5px]')}
    style={{ background: group.color || '#64748B' }}
  >
    {(group.name || '?')
      .split(/[\s/&·-]+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((w) => w[0]?.toUpperCase())
      .join('')}
  </span>
);
