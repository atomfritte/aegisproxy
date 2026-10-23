import React from 'react';
import { Globe2, Server as ServerIcon, Tag } from 'lucide-react';
import { cn } from '../../lib/cn';
import { Link } from '../../lib/router';
import { useLookups } from '../../data/lookups';
import { Avatar, Tooltip } from '../../ui';

const chip =
  'inline-flex max-w-[min(220px,100%)] items-center gap-1.5 rounded-md border border-border bg-surface-2 px-1.5 py-0.5 text-[12px] leading-4 text-fg';

/** Server group chip with the group's color; links to the group page. */
export const GroupChip: React.FC<{ id: string; link?: boolean; className?: string }> = ({ id, link = true, className }) => {
  const { groupById } = useLookups();
  const g = groupById.get(id);
  const body = (
    <>
      <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: g?.color || 'rgb(var(--c-fg-subtle))' }} aria-hidden />
      <span className="truncate">{g?.name || id}</span>
      {g?.match_labels && Object.keys(g.match_labels).length > 0 && <Tag className="h-3 w-3 shrink-0 text-fg-subtle" aria-label="dynamic group" />}
    </>
  );
  if (link && g) {
    return (
      <Tooltip content={g.description || g.name}>
        <Link to={`/groups/${encodeURIComponent(id)}`} className={cn(chip, 'hover:border-border-strong hover:bg-surface-3', className)}>
          {body}
        </Link>
      </Tooltip>
    );
  }
  return <span className={cn(chip, className)}>{body}</span>;
};

/** Registered server chip (hostname); links to the server page. */
export const ServerChip: React.FC<{ id: string; link?: boolean; className?: string }> = ({ id, link = true, className }) => {
  const { serverById } = useLookups();
  const s = serverById.get(id);
  const body = (
    <>
      <ServerIcon className="h-3 w-3 shrink-0 text-fg-subtle" aria-hidden />
      <span className="truncate">{s?.hostname || id}</span>
    </>
  );
  if (link && s) {
    return (
      <Link to={`/servers/${encodeURIComponent(id)}`} className={cn(chip, 'hover:border-border-strong hover:bg-surface-3', className)} title={`${s.hostname} (${s.ip})`}>
        {body}
      </Link>
    );
  }
  return <span className={cn(chip, className)}>{body}</span>;
};

/** "All servers" chip for baseline sets. */
export const AllServersChip: React.FC<{ className?: string }> = ({ className }) => (
  <span className={cn(chip, 'border-violet-border bg-violet-soft text-violet', className)}>
    <Globe2 className="h-3 w-3 shrink-0" aria-hidden />
    All servers
  </span>
);

/** Chips with an overflow counter. */
export const ChipList: React.FC<{ children: React.ReactNode[]; max?: number; className?: string }> = ({ children, max = 3, className }) => {
  const items = React.Children.toArray(children);
  const shown = items.slice(0, max);
  const rest = items.length - shown.length;
  return (
    <span className={cn('flex min-w-0 flex-wrap items-center gap-1', className)}>
      {shown}
      {rest > 0 && <span className="text-[12px] text-fg-subtle">+{rest}</span>}
    </span>
  );
};

/** Username with avatar and display name tooltip. */
export const UserName: React.FC<{ username?: string | null; className?: string; avatar?: boolean }> = ({ username, className, avatar = true }) => {
  const { userName } = useLookups();
  if (!username) return <span className="text-fg-subtle">—</span>;
  const display = userName(username);
  return (
    <Tooltip content={display !== username ? `${display} (@${username})` : `@${username}`}>
      <span className={cn('inline-flex min-w-0 items-center gap-1.5', className)}>
        {avatar && <Avatar name={display} size="xs" />}
        <span className="truncate">{username}</span>
      </span>
    </Tooltip>
  );
};

/** Label pairs (key=value) as compact mono chips. */
export const LabelChips: React.FC<{ labels?: Record<string, string> | null; max?: number }> = ({ labels, max = 4 }) => {
  const entries = Object.entries(labels || {}).sort(([a], [b]) => a.localeCompare(b));
  if (entries.length === 0) return <span className="text-fg-subtle">—</span>;
  return (
    <ChipList max={max}>
      {entries.map(([k, v]) => (
        <span key={k} className="inline-flex items-center rounded border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[11px] leading-4">
          <span className="text-fg-muted">{k}</span>
          <span className="text-fg-subtle">=</span>
          <span className="text-fg">{v}</span>
        </span>
      ))}
    </ChipList>
  );
};
