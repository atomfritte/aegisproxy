import React from 'react';
import { cn } from '../../lib/cn';
import { Badge, StatusChip } from '../../ui';
import { ECOSYSTEM_META, ecosystemLabel, modeMeta } from './packageUtils';

/** Ecosystem mark: icon + label (npm / PyPI / NuGet / PowerShell Gallery). */
export const EcosystemBadge: React.FC<{ ecosystem: string; short?: boolean; className?: string }> = ({ ecosystem, short, className }) => {
  const meta = ECOSYSTEM_META[ecosystem];
  const Icon = meta?.icon;
  return (
    <span
      className={cn(
        'inline-flex max-w-full shrink-0 items-center gap-1.5 whitespace-nowrap rounded-md border border-border bg-surface-2 px-1.5 py-0.5 text-[12px] font-medium leading-4 text-fg',
        className
      )}
      title={meta ? `${meta.label} — ${meta.clients}` : ecosystem}
    >
      {Icon && <Icon className="h-3.5 w-3.5 shrink-0 text-fg-muted" aria-hidden />}
      <span className="truncate">{short ? meta?.short ?? ecosystemLabel(ecosystem) : ecosystemLabel(ecosystem)}</span>
    </span>
  );
};

/** Enforcement mode of an ecosystem as a status chip (off / monitor / enforce). */
export const ModeChip: React.FC<{ mode: string; className?: string }> = ({ mode, className }) => {
  const m = modeMeta(mode);
  return <StatusChip tone={m.tone} label={m.label} className={className} title={m.hint} />;
};

/** Small kind chip (runtime / dev / optional / peer / build / framework). */
export const KindBadge: React.FC<{ kind: string }> = ({ kind }) => (
  <Badge tone={kind === 'runtime' ? 'neutral' : kind === 'dev' ? 'info' : kind === 'build' ? 'violet' : kind === 'peer' ? 'warning' : 'neutral'} size="sm">
    {kind}
  </Badge>
);
