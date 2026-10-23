// Small presentational pieces shared by the threat protection tabs.
import React from 'react';
import { Ban, CheckCircle2, Radar } from 'lucide-react';
import { cn } from '../../../lib/cn';
import { formatDateTime } from '../../../lib/format';
import type { SecurityEvent, SecuritySeverity } from '../../../types';
import { Badge, CopyButton, RelativeTime, Tooltip } from '../../../ui';
import { UserName } from '../../../components/common/EntityChips';
import { eventTypeMeta, MODE_META, SEVERITY_META } from './meta';

export const SeverityBadge: React.FC<{ severity: SecuritySeverity | string; className?: string }> = ({ severity, className }) => {
  const m = SEVERITY_META[severity as SecuritySeverity] ?? { label: severity || 'Unknown', tone: 'neutral' as const };
  return (
    <Badge tone={m.tone} variant={m.solid ? 'solid' : 'soft'} dot={!m.solid} className={className}>
      {m.label}
    </Badge>
  );
};

export const ActionBadge: React.FC<{ action: string }> = ({ action }) =>
  action === 'blocked' ? (
    <Badge tone="danger" variant="outline" icon={Ban}>
      Blocked
    </Badge>
  ) : (
    <Badge tone="warning" variant="outline" icon={Radar}>
      Detected
    </Badge>
  );

export const ModeBadge: React.FC<{ mode: string; prefix?: string; className?: string }> = ({ mode, prefix, className }) => {
  const m = MODE_META[mode] ?? { label: mode || 'n/a', tone: 'neutral' as const, description: '' };
  return (
    <Tooltip content={m.description}>
      <Badge tone={m.tone} dot className={className}>
        {prefix ? `${prefix}: ${m.label.toLowerCase()}` : m.label}
      </Badge>
    </Tooltip>
  );
};

/** Compact "Blocked" / "Detected" text with icon (tables). */
export const ActionLabel: React.FC<{ action: string }> = ({ action }) =>
  action === 'blocked' ? (
    <span className="inline-flex items-center gap-1 text-[12px] text-fg-muted">
      <Ban className="h-3 w-3 text-danger" aria-hidden />
      Blocked
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 text-[12px] text-fg-muted">
      <Radar className="h-3 w-3 text-warning" aria-hidden />
      Detected
    </span>
  );

/** Event type with icon and the detail line. */
export const EventTypeCell: React.FC<{ event: SecurityEvent; clamp?: boolean }> = ({ event, clamp = true }) => {
  const m = eventTypeMeta(event.type);
  const Icon = m.icon;
  return (
    <div className="flex min-w-0 items-start gap-2.5">
      <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-surface-3 text-fg-muted">
        <Icon className="h-4 w-4" aria-hidden />
      </span>
      <div className="min-w-0">
        <div className="flex flex-wrap items-baseline gap-x-1.5">
          <span className="text-[13px] font-medium text-fg group-hover/ev:text-accent group-hover/ev:underline">{m.label}</span>
          {event.count > 1 && <span className="text-[12px] tabular text-fg-subtle">×{event.count}</span>}
        </div>
        {event.detail && <p className={cn('text-[12px] leading-5 text-fg-muted', clamp && 'line-clamp-2')}>{event.detail}</p>}
      </div>
    </div>
  );
};

/** Acknowledged-by line or "Open". */
export const AckState: React.FC<{ event: SecurityEvent }> = ({ event }) =>
  event.acknowledged ? (
    <Tooltip content={event.acknowledged_at ? `Acknowledged ${formatDateTime(event.acknowledged_at)}` : 'Acknowledged'}>
      <span className="inline-flex min-w-0 items-center gap-1.5 text-[12.5px] text-fg-muted">
        <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-success" aria-hidden />
        <UserName username={event.acknowledged_by} avatar={false} />
      </span>
    </Tooltip>
  ) : (
    <Badge tone="warning" dot>
      Open
    </Badge>
  );

/** Monospace value with copy button (indicators, hashes, URLs). */
export const MonoValue: React.FC<{ value: string; className?: string; copy?: boolean; tone?: 'danger' | 'default' }> = ({ value, className, copy = true, tone = 'default' }) => (
  <span className={cn('inline-flex min-w-0 max-w-full items-start gap-1', className)}>
    <span className={cn('min-w-0 break-all font-mono text-[12.5px] leading-5', tone === 'danger' ? 'text-danger' : 'text-fg')}>{value}</span>
    {copy && value && <CopyButton text={value} size="xs" label="Copy value" className="-my-0.5 shrink-0" />}
  </span>
);

/** "3m ago" over an absolute date (table time cells). */
export const TimeCell: React.FC<{ value?: string | null }> = ({ value }) => (
  <div className="leading-tight">
    <RelativeTime value={value} className="text-[13px] text-fg" />
    <div className="mt-0.5 whitespace-nowrap text-[11.5px] text-fg-subtle">{formatDateTime(value)}</div>
  </div>
);

/** Section heading inside cards / drawers. */
export const SectionTitle: React.FC<{ children: React.ReactNode; aside?: React.ReactNode; className?: string }> = ({ children, aside, className }) => (
  <div className={cn('mb-2 flex items-center justify-between gap-3', className)}>
    <h3 className="text-[12.5px] font-semibold text-fg">{children}</h3>
    {aside}
  </div>
);
