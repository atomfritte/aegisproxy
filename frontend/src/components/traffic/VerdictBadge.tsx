import React from 'react';
import { Badge, Tone } from '../../ui';
import { humanize } from '../../lib/format';

const VERDICTS: Record<string, { label: string; tone: Tone }> = {
  ALLOWED: { label: 'Allowed', tone: 'success' },
  REDIRECT_OBJECT_ALLOWED: { label: 'Redirect allowed', tone: 'success' },
  LEARNING_ALLOWED: { label: 'Learning', tone: 'info' },
  TLS_BYPASS: { label: 'TLS bypass', tone: 'violet' },
  BLOCKED: { label: 'Blocked', tone: 'danger' },
  POLICY_BLOCKED: { label: 'Policy blocked', tone: 'danger' },
  THREAT_BLOCKED: { label: 'Threat blocked', tone: 'danger' },
  MALWARE_BLOCKED: { label: 'Malware blocked', tone: 'danger' },
  DLP_BLOCKED: { label: 'DLP blocked', tone: 'danger' },
  FILETYPE_BLOCKED: { label: 'File type blocked', tone: 'danger' },
  QUARANTINED: { label: 'Quarantined', tone: 'danger' },
  SIMULATED: { label: 'Simulated', tone: 'neutral' },
};

/** Flow verdict (ALLOWED, BLOCKED, THREAT_BLOCKED ...) as a colored badge. */
export const VerdictBadge: React.FC<{ verdict: string }> = ({ verdict }) => {
  const m = VERDICTS[verdict] ?? { label: humanize(verdict || 'unknown'), tone: 'neutral' as Tone };
  return (
    <Badge tone={m.tone} dot>
      {m.label}
    </Badge>
  );
};

export function isAllowedVerdict(v: string): boolean {
  return v === 'ALLOWED' || v === 'REDIRECT_OBJECT_ALLOWED' || v === 'LEARNING_ALLOWED' || v === 'TLS_BYPASS';
}
