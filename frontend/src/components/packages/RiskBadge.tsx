import React from 'react';
import { AlertOctagon, Bug } from 'lucide-react';
import { Badge, StatusChip, Tone } from '../../ui';
import { advisoryCounts, nodeStateMeta, riskMeta } from './packageUtils';
import type { PackageAssessment, PackageRisk } from '../../types';

/** Overall risk level → tone that reads in light and dark. Critical is solid so it jumps out. */
export const RiskBadge: React.FC<{ risk?: string | null; size?: 'sm' | 'md'; malware?: boolean; className?: string }> = ({ risk, size = 'sm', malware, className }) => {
  const m = riskMeta(risk);
  if (malware) {
    return (
      <Badge tone="danger" variant="solid" size={size} icon={Bug} className={className}>
        Malware
      </Badge>
    );
  }
  return (
    <Badge tone={m.tone} variant={m.solid ? 'solid' : 'soft'} size={size} icon={m.solid ? AlertOctagon : undefined} className={className}>
      {m.label}
    </Badge>
  );
};

/** State of a node relative to the current approvals (new / update / approved / blocked). */
export const NodeStateChip: React.FC<{ state: string; className?: string }> = ({ state, className }) => {
  const m = nodeStateMeta(state);
  return <StatusChip tone={m.tone} label={m.label} className={className} />;
};

const SEV_TONE: Record<string, Tone> = { critical: 'danger', high: 'danger', medium: 'warning', low: 'success', info: 'info', unknown: 'neutral', none: 'neutral' };

/** Compact advisory tally by severity, e.g. "1 critical · 2 high". */
export const AdvisorySummary: React.FC<{ assessment?: PackageAssessment | null; className?: string }> = ({ assessment, className }) => {
  const counts = advisoryCounts(assessment);
  if (counts.length === 0) return null;
  return (
    <span className={className}>
      {counts.map(({ severity, count }) => (
        <Badge key={severity} tone={SEV_TONE[severity] ?? 'neutral'} size="sm" className="mr-1">
          {count} {severityLabel(severity)}
        </Badge>
      ))}
    </span>
  );
};

function severityLabel(s: PackageRisk): string {
  return s === 'none' ? 'clean' : s;
}
