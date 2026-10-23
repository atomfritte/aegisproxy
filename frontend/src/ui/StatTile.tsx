import React from 'react';
import type { LucideIcon } from 'lucide-react';
import { ChevronRight } from 'lucide-react';
import { cn } from '../lib/cn';
import { Link } from '../lib/router';
import { Skeleton } from './Skeleton';
import type { Tone } from './Badge';

const iconTone: Record<Tone, string> = {
  neutral: 'bg-surface-3 text-fg-muted',
  accent: 'bg-accent-soft text-accent',
  success: 'bg-success-soft text-success',
  warning: 'bg-warning-soft text-warning',
  danger: 'bg-danger-soft text-danger',
  info: 'bg-info-soft text-info',
  violet: 'bg-violet-soft text-violet',
};

export interface StatTileProps {
  label: React.ReactNode;
  value: React.ReactNode;
  icon?: LucideIcon;
  /** Colors the icon chip; use a status tone only when the value represents that state. */
  tone?: Tone;
  /** Secondary line under the value. */
  hint?: React.ReactNode;
  /** Small visual (e.g. Sparkline) at the bottom. */
  trend?: React.ReactNode;
  /** Makes the whole tile a link (work queues). */
  to?: string;
  onClick?: () => void;
  loading?: boolean;
  className?: string;
  /** Emphasize the tile (attention needed): tinted left edge. */
  attention?: boolean;
}

/** KPI / work-queue tile: label, value, optional hint and trend; clickable when `to` is set. */
export const StatTile: React.FC<StatTileProps> = ({ label, value, icon: Icon, tone = 'neutral', hint, trend, to, onClick, loading, className, attention }) => {
  const body = (
    <>
      <div className="flex items-start justify-between gap-3">
        <span className="text-[12.5px] font-medium leading-5 text-fg-muted">{label}</span>
        {Icon && (
          <span className={cn('flex h-7 w-7 shrink-0 items-center justify-center rounded-md', iconTone[tone])}>
            <Icon className="h-4 w-4" aria-hidden />
          </span>
        )}
      </div>
      {loading ? (
        <Skeleton className="mt-2 h-7 w-20" />
      ) : (
        <div className="mt-1 text-[26px] font-semibold leading-8 tracking-[-0.02em] text-fg">{value}</div>
      )}
      {hint && <div className="mt-1 text-[12px] leading-5 text-fg-subtle">{hint}</div>}
      {trend && <div className="mt-3">{trend}</div>}
      {(to || onClick) && (
        <ChevronRight
          className="absolute bottom-3 right-3 h-4 w-4 text-fg-subtle opacity-0 transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100"
          aria-hidden
        />
      )}
    </>
  );
  const cls = cn(
    'group relative block min-w-0 rounded-lg border border-border bg-surface p-4 shadow-card',
    (to || onClick) && 'transition-colors hover:border-border-strong hover:bg-surface-2 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring/60',
    attention && 'border-l-[3px] border-l-warning-solid',
    className
  );
  if (to) {
    return (
      <Link to={to} className={cls}>
        {body}
      </Link>
    );
  }
  if (onClick) {
    return (
      <button type="button" onClick={onClick} className={cn(cls, 'w-full text-left')}>
        {body}
      </button>
    );
  }
  return <div className={cls}>{body}</div>;
};
