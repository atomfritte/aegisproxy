// Security posture: status/category metadata and the score meter (page + overview card).
import React from 'react';
import type { LucideIcon } from 'lucide-react';
import { CheckCircle2, CircleAlert, Database, Fingerprint, Gavel, Info, Radar, Server, XCircle } from 'lucide-react';
import { cn } from '../../../lib/cn';
import type { PostureStatus } from '../../../types';
import type { Tone } from '../../../ui';

export const STATUS_META: Record<PostureStatus, { label: string; plural: string; tone: Tone; icon: LucideIcon; order: number }> = {
  fail: { label: 'Failing', plural: 'failing', tone: 'danger', icon: XCircle, order: 0 },
  warn: { label: 'Warning', plural: 'warnings', tone: 'warning', icon: CircleAlert, order: 1 },
  info: { label: 'Info', plural: 'informational', tone: 'info', icon: Info, order: 2 },
  pass: { label: 'Passed', plural: 'passed', tone: 'success', icon: CheckCircle2, order: 3 },
};

export const CATEGORY_META: Record<string, { label: string; icon: LucideIcon; description: string }> = {
  identity: { label: 'Identity and access', icon: Fingerprint, description: 'Sign-in, accounts and keys' },
  data: { label: 'Data protection', icon: Database, description: 'Secrets, encryption and retention' },
  detection: { label: 'Detection', icon: Radar, description: 'Threat intelligence, malware scanning, DLP' },
  governance: { label: 'Governance', icon: Gavel, description: 'Review, recertification and audit' },
  platform: { label: 'Platform', icon: Server, description: 'Transport security, deployment and workers' },
};

export const categoryMeta = (c: string) =>
  CATEGORY_META[c] ?? { label: c ? c.charAt(0).toUpperCase() + c.slice(1) : 'Other', icon: Info, description: '' };

/** Score band: ≥ 80 good, ≥ 50 needs attention, below at risk. */
export function scoreBand(score: number): { label: string; tone: Tone } {
  if (score >= 80) return { label: 'Good', tone: 'success' };
  if (score >= 50) return { label: 'Needs attention', tone: 'warning' };
  return { label: 'At risk', tone: 'danger' };
}

const STROKE: Record<string, string> = { success: 'stroke-success-solid', warning: 'stroke-warning-solid', danger: 'stroke-danger-solid' };
const TRACK: Record<string, string> = { success: 'stroke-success-soft', warning: 'stroke-warning-soft', danger: 'stroke-danger-soft' };

/**
 * Circular meter for the posture score (0–100): the fill carries the band color, the track is a
 * lighter step of the same tone. The number is the headline; the band label never relies on color.
 */
export const ScoreRing: React.FC<{ score: number; size?: number; className?: string; label?: boolean }> = ({ score, size = 144, className, label = true }) => {
  const s = Math.max(0, Math.min(100, Math.round(score)));
  const band = scoreBand(s);
  const stroke = size >= 100 ? 10 : 7;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  return (
    <div className={cn('relative inline-flex shrink-0 items-center justify-center', className)} style={{ width: size, height: size }} role="img" aria-label={`Security posture score ${s} of 100: ${band.label}`}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90" aria-hidden>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={stroke} className={TRACK[band.tone]} />
        {s > 0 && (
          <circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={`${(c * s) / 100} ${c}`}
            className={cn(STROKE[band.tone], 'transition-[stroke-dasharray] duration-500')}
          />
        )}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center leading-none">
        <span className={cn('font-semibold tracking-[-0.03em] text-fg', size >= 100 ? 'text-[48px]' : 'text-[24px]')}>{s}</span>
        {label && size >= 100 && <span className="mt-1 text-[11.5px] font-medium text-fg-subtle">of 100</span>}
      </div>
    </div>
  );
};
