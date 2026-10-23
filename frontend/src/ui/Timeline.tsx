import React from 'react';
import type { LucideIcon } from 'lucide-react';
import { cn } from '../lib/cn';
import type { Tone } from './Badge';

export interface TimelineItem {
  id: string;
  icon?: LucideIcon;
  tone?: Tone;
  title: React.ReactNode;
  /** Right-aligned / secondary info (time, author). */
  meta?: React.ReactNode;
  body?: React.ReactNode;
  /** Highlight this entry (e.g. current version). */
  current?: boolean;
}

const dotTone: Record<Tone, string> = {
  neutral: 'bg-surface text-fg-muted border-border-strong',
  accent: 'bg-accent-soft text-accent border-accent-border',
  success: 'bg-success-soft text-success border-success-border',
  warning: 'bg-warning-soft text-warning border-warning-border',
  danger: 'bg-danger-soft text-danger border-danger-border',
  info: 'bg-info-soft text-info border-info-border',
  violet: 'bg-violet-soft text-violet border-violet-border',
};

/** Vertical event list with connecting rail (versions, reviews, comments). */
export const Timeline: React.FC<{ items: TimelineItem[]; className?: string }> = ({ items, className }) => (
  <ol className={cn('relative', className)}>
    {items.map((it, i) => {
      const Icon = it.icon;
      const last = i === items.length - 1;
      return (
        <li key={it.id} className="relative flex gap-3 pb-5 last:pb-0">
          {!last && <span aria-hidden className="absolute left-[13px] top-7 h-[calc(100%-20px)] w-px bg-border" />}
          <span
            className={cn(
              'relative z-[1] flex h-7 w-7 shrink-0 items-center justify-center rounded-full border',
              dotTone[it.tone || 'neutral'],
              it.current && 'ring-2 ring-accent/40'
            )}
          >
            {Icon ? <Icon className="h-3.5 w-3.5" aria-hidden /> : <span className="h-1.5 w-1.5 rounded-full bg-current" />}
          </span>
          <div className="min-w-0 flex-1 pt-0.5">
            <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5">
              <div className="min-w-0 text-[13px] font-medium text-fg">{it.title}</div>
              {it.meta && <div className="shrink-0 text-[12px] text-fg-subtle">{it.meta}</div>}
            </div>
            {it.body && <div className="mt-1 text-[13px] leading-5 text-fg-muted">{it.body}</div>}
          </div>
        </li>
      );
    })}
  </ol>
);
