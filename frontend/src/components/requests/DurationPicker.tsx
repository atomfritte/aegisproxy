import React from 'react';
import { usePermissions } from '../../data/AppData';
import { cn } from '../../lib/cn';
import { formatDateTime } from '../../lib/format';
import type { AccessDuration } from '../../types';
import { Tooltip } from '../../ui';
import { DURATION_MS, DURATION_SHORT, durationBlockedReason, GRANT_DURATIONS } from './requestUtils';

/** Grant duration radio pills (1h … permanent) with the Team Lead cap applied. */
export const DurationPicker: React.FC<{
  value: AccessDuration;
  onChange: (d: AccessDuration) => void;
  maxDays: number;
  /** Highlight the requested duration. */
  requested?: string;
  disabled?: boolean;
  id?: string;
}> = ({ value, onChange, maxDays, requested, disabled, id }) => {
  const perms = usePermissions();
  return (
    <div id={id} role="radiogroup" aria-label="Access duration" className="flex flex-wrap gap-1.5">
      {GRANT_DURATIONS.map((d) => {
        const blocked = durationBlockedReason(d, perms, maxDays);
        const active = d === value;
        const btn = (
          <button
            type="button"
            role="radio"
            aria-checked={active}
            disabled={disabled || !!blocked}
            onClick={() => onChange(d)}
            className={cn(
              'relative inline-flex h-8 items-center rounded-md border px-3 text-[12.5px] font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-45',
              active ? 'border-accent bg-accent-soft text-accent ring-1 ring-accent' : 'border-border-strong bg-surface text-fg hover:bg-surface-3'
            )}
          >
            {DURATION_SHORT[d]}
            {requested === d && <span className="ml-1.5 h-1.5 w-1.5 rounded-full bg-accent" aria-label="(requested)" />}
          </button>
        );
        return blocked ? (
          <Tooltip key={d} content={blocked}>
            {btn}
          </Tooltip>
        ) : (
          <React.Fragment key={d}>{btn}</React.Fragment>
        );
      })}
    </div>
  );
};

/** Expiry for a duration starting now, or null for permanent. */
export function expiryFor(d: string, now = Date.now()): number | null {
  const ms = DURATION_MS[d];
  return ms ? now + ms : null;
}

export function expiryText(d: string, now = Date.now()): string {
  const t = expiryFor(d, now);
  return t === null ? 'no expiry' : `until ${formatDateTime(new Date(t).toISOString())}`;
}

/** Largest allowed duration not longer than `wanted` (for Team Leads whose cap is below the request). */
export function clampDuration(wanted: string, blocked: (d: string) => string | null): AccessDuration {
  if (!blocked(wanted) && (GRANT_DURATIONS as string[]).includes(wanted)) return wanted as AccessDuration;
  const allowed = GRANT_DURATIONS.filter((d) => !blocked(d) && d !== 'permanent');
  return allowed[allowed.length - 1] ?? '24h';
}
