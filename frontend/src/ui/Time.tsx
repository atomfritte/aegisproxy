import React from 'react';
import { Clock, Hourglass } from 'lucide-react';
import { cn } from '../lib/cn';
import { formatDateTime, formatDuration, formatRelative, toTime } from '../lib/format';
import { useNow } from '../lib/hooks';
import { Badge, Tone } from './Badge';
import { Tooltip } from './Tooltip';

/** "3m ago" with the absolute timestamp as tooltip; re-renders every 15 s. */
export const RelativeTime: React.FC<{ value?: string | null; className?: string; prefix?: string }> = ({ value, className, prefix }) => {
  const now = useNow();
  if (!toTime(value)) return <span className={cn('text-fg-subtle', className)}>—</span>;
  return (
    <Tooltip content={formatDateTime(value)}>
      <time dateTime={value!} className={cn('whitespace-nowrap', className)}>
        {prefix ? `${prefix} ` : ''}
        {formatRelative(value, now)}
      </time>
    </Tooltip>
  );
};

export interface CountdownChipProps {
  /** Deadline (SLA due date, expiry, review due date). */
  due?: string | null;
  /** 'due': "Due in 3h" / "Overdue by 2h"; 'expiry': "Expires in 5d" / "Expired". */
  kind?: 'due' | 'expiry' | 'review';
  /** Remaining time below which the chip turns warning (default 4h for due, 3d for expiry, 14d for review). */
  warnWithinMs?: number;
  className?: string;
}

/** Deadline chip: neutral → warning (close) → danger (passed). */
export const CountdownChip: React.FC<CountdownChipProps> = ({ due, kind = 'due', warnWithinMs, className }) => {
  const now = useNow();
  const t = toTime(due);
  if (t === null) return null;
  const left = t - now;
  const warn = warnWithinMs ?? (kind === 'due' ? 4 * 3600_000 : kind === 'expiry' ? 3 * 86400_000 : 14 * 86400_000);
  let tone: Tone = 'neutral';
  let label: string;
  if (left < 0) {
    tone = 'danger';
    label = kind === 'expiry' ? `Expired ${formatDuration(left)} ago` : `Overdue by ${formatDuration(left)}`;
  } else {
    if (left < warn) tone = 'warning';
    label = kind === 'expiry' ? `Expires in ${formatDuration(left)}` : kind === 'review' ? `Review in ${formatDuration(left)}` : `Due in ${formatDuration(left)}`;
  }
  return (
    <Tooltip content={`${kind === 'expiry' ? 'Expires' : 'Due'} ${formatDateTime(due)}`}>
      <Badge tone={tone} icon={kind === 'expiry' ? Hourglass : Clock} className={className}>
        {label}
      </Badge>
    </Tooltip>
  );
};
