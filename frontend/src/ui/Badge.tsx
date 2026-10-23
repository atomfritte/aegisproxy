import React from 'react';
import type { LucideIcon } from 'lucide-react';
import { cn } from '../lib/cn';

export type Tone = 'neutral' | 'accent' | 'success' | 'warning' | 'danger' | 'info' | 'violet';

const soft: Record<Tone, string> = {
  neutral: 'bg-neutral-soft text-neutral border-neutral-border',
  accent: 'bg-accent-soft text-accent border-accent-border',
  success: 'bg-success-soft text-success border-success-border',
  warning: 'bg-warning-soft text-warning border-warning-border',
  danger: 'bg-danger-soft text-danger border-danger-border',
  info: 'bg-info-soft text-info border-info-border',
  violet: 'bg-violet-soft text-violet border-violet-border',
};

const solid: Record<Tone, string> = {
  neutral: 'bg-neutral-solid text-white border-transparent',
  accent: 'bg-primary text-primary-fg border-transparent',
  success: 'bg-success-solid text-white border-transparent',
  warning: 'bg-warning-solid text-white border-transparent',
  danger: 'bg-danger-solid text-white border-transparent',
  info: 'bg-info-solid text-white border-transparent',
  violet: 'bg-violet-solid text-white border-transparent',
};

const dotColor: Record<Tone, string> = {
  neutral: 'bg-neutral-solid',
  accent: 'bg-accent',
  success: 'bg-success-solid',
  warning: 'bg-warning-solid',
  danger: 'bg-danger-solid',
  info: 'bg-info-solid',
  violet: 'bg-violet-solid',
};

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  tone?: Tone;
  variant?: 'soft' | 'solid' | 'outline';
  size?: 'sm' | 'md';
  icon?: LucideIcon;
  /** Leading status dot (pulses when `pulse`). */
  dot?: boolean;
  pulse?: boolean;
}

/** Small label: kinds, states, counts. Use StatusChip for workflow states. */
export const Badge: React.FC<BadgeProps> = ({ tone = 'neutral', variant = 'soft', size = 'sm', icon: Icon, dot, pulse, className, children, ...rest }) => (
  <span
    className={cn(
      'inline-flex max-w-full shrink-0 items-center gap-1 whitespace-nowrap rounded-md border font-medium leading-none',
      size === 'sm' ? 'h-[22px] px-1.5 text-[11.5px]' : 'h-6 px-2 text-[12.5px]',
      variant === 'solid' ? solid[tone] : variant === 'outline' ? cn('bg-transparent border-border-strong', soft[tone].split(' ')[1]) : soft[tone],
      className
    )}
    {...rest}
  >
    {dot && (
      <span className="relative flex h-1.5 w-1.5 shrink-0">
        {pulse && <span className={cn('absolute inline-flex h-full w-full animate-ping rounded-full opacity-60', dotColor[tone])} />}
        <span className={cn('relative inline-flex h-1.5 w-1.5 rounded-full', dotColor[tone])} />
      </span>
    )}
    {Icon && <Icon className="h-3 w-3 shrink-0" aria-hidden />}
    <span className="truncate leading-4">{children}</span>
  </span>
);

/** Workflow / health state with a colored dot (never color alone: always a label). */
export const StatusChip: React.FC<{ tone: Tone; label: React.ReactNode; icon?: LucideIcon; pulse?: boolean; className?: string; title?: string }> = ({
  tone,
  label,
  icon,
  pulse,
  className,
  title,
}) => (
  <Badge tone={tone} dot={!icon} icon={icon} pulse={pulse} className={className} title={title}>
    {label}
  </Badge>
);

/** Numeric pill for navigation and tabs. */
export const CountBadge: React.FC<{ count?: number | null; tone?: Tone; className?: string; max?: number }> = ({ count, tone = 'neutral', className, max = 99 }) => {
  if (count === undefined || count === null) return null;
  return (
    <span
      className={cn(
        'inline-flex h-[18px] min-w-[18px] items-center justify-center rounded-full px-1.5 text-[11px] font-semibold tabular leading-none',
        tone === 'neutral' ? 'bg-surface-3 text-fg-muted' : soft[tone],
        className
      )}
    >
      {count > max ? `${max}+` : count}
    </span>
  );
};

export function toneDot(tone: Tone): string {
  return dotColor[tone];
}
