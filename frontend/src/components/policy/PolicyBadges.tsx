import React from 'react';
import { Ban, CheckCheck, Clock, FileEdit, Globe2, Inbox, Layers, Lock, ShieldCheck, ShieldX, Undo2, XCircle } from 'lucide-react';
import type { ChangeRequestStatus, PolicySet, PolicySetKind, ReviewState, RuleAction } from '../../types';
import { Badge, StatusChip, Tone, Tooltip } from '../../ui';
import { formatDate } from '../../lib/format';
import { AllServersChip, ChipList, GroupChip, ServerChip } from '../common/EntityChips';

export const KIND_META: Record<PolicySetKind, { label: string; tone: Tone; description: string }> = {
  baseline: {
    label: 'Baseline',
    tone: 'violet',
    description: 'Applies to every registered server. Typically BLOCK guardrails managed by InfoSec.',
  },
  standard: {
    label: 'Standard',
    tone: 'accent',
    description: 'Applies to the server groups and servers it is assigned to.',
  },
  approvals: {
    label: 'Approvals',
    tone: 'info',
    description: 'System-managed: rules created by approved access requests for one group.',
  },
};

export const PolicyKindBadge: React.FC<{ kind: PolicySetKind }> = ({ kind }) => {
  const m = KIND_META[kind] ?? KIND_META.standard;
  return (
    <Tooltip content={m.description}>
      <Badge tone={m.tone} icon={kind === 'baseline' ? Globe2 : kind === 'approvals' ? Inbox : Layers}>
        {m.label}
      </Badge>
    </Tooltip>
  );
};

const REVIEW_META: Record<ReviewState, { label: string; tone: Tone }> = {
  ok: { label: 'Certified', tone: 'success' },
  due_soon: { label: 'Review due soon', tone: 'warning' },
  overdue: { label: 'Review overdue', tone: 'danger' },
};

/** Recertification state (computed by the server from last review + interval). */
export const ReviewStateChip: React.FC<{ set: Pick<PolicySet, 'review_state' | 'review_due_at' | 'version'> }> = ({ set }) => {
  if (set.version === 0) return <StatusChip tone="neutral" label="Never published" />;
  if (!set.review_state) return <StatusChip tone="neutral" label="No recertification" />;
  const m = REVIEW_META[set.review_state];
  return (
    <Tooltip content={set.review_due_at ? `Recertification due ${formatDate(set.review_due_at)}` : undefined}>
      <StatusChip tone={m.tone} label={m.label} />
    </Tooltip>
  );
};

/** Draft / in-review indicator. */
export const DraftIndicator: React.FC<{ set: Pick<PolicySet, 'draft'> }> = ({ set }) => {
  if (!set.draft) return null;
  return set.draft.status === 'in_review' ? (
    <Badge tone="warning" icon={Lock}>
      In review
    </Badge>
  ) : (
    <Badge tone="info" icon={FileEdit}>
      Draft
    </Badge>
  );
};

/** Where a set applies: All servers (baseline) or group / server chips. */
export const AssignmentChips: React.FC<{ kind: PolicySetKind; groupIds?: string[] | null; serverIds?: string[] | null; max?: number }> = ({ kind, groupIds, serverIds, max = 3 }) => {
  if (kind === 'baseline') return <AllServersChip />;
  const g = groupIds ?? [];
  const s = serverIds ?? [];
  if (g.length === 0 && s.length === 0) return <span className="text-[12.5px] text-fg-subtle">Not assigned</span>;
  return (
    <ChipList max={max}>
      {[...g.map((id) => <GroupChip key={`g-${id}`} id={id} />), ...s.map((id) => <ServerChip key={`s-${id}`} id={id} />)]}
    </ChipList>
  );
};

export const RuleActionBadge: React.FC<{ action: RuleAction | string }> = ({ action }) =>
  action === 'BLOCK' ? (
    <Badge tone="danger" icon={ShieldX}>
      Block
    </Badge>
  ) : (
    <Badge tone="success" icon={ShieldCheck}>
      Allow
    </Badge>
  );

const CR_META: Record<ChangeRequestStatus, { label: string; tone: Tone; icon: typeof Clock }> = {
  open: { label: 'Awaiting review', tone: 'warning', icon: Clock },
  approved: { label: 'Approved', tone: 'success', icon: CheckCheck },
  rejected: { label: 'Rejected', tone: 'danger', icon: XCircle },
  withdrawn: { label: 'Withdrawn', tone: 'neutral', icon: Undo2 },
  superseded: { label: 'Superseded', tone: 'neutral', icon: Ban },
};

export const ChangeRequestStatusChip: React.FC<{ status: ChangeRequestStatus }> = ({ status }) => {
  const m = CR_META[status] ?? CR_META.open;
  return (
    <Badge tone={m.tone} icon={m.icon}>
      {m.label}
    </Badge>
  );
};

export function changeRequestStatusLabel(s: ChangeRequestStatus): string {
  return (CR_META[s] ?? CR_META.open).label;
}
