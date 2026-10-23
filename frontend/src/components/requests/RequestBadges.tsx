import React from 'react';
import type { LucideIcon } from 'lucide-react';
import { AlarmClock, Ban, CheckCheck, Clock, Hourglass, ShieldAlert, ShieldCheck, XCircle } from 'lucide-react';
import { useNow } from '../../lib/hooks';
import { formatDateTime } from '../../lib/format';
import type { AccessRequest } from '../../types';
import { Badge, CountdownChip, Tone, Tooltip } from '../../ui';
import { requestState, RequestState, SCOPE_META, scopeLabel } from './requestUtils';

export const STATE_META: Record<RequestState, { label: string; tone: Tone; icon: LucideIcon }> = {
  pending: { label: 'Pending', tone: 'warning', icon: Clock },
  overdue: { label: 'Overdue', tone: 'danger', icon: AlarmClock },
  approved: { label: 'Approved', tone: 'success', icon: CheckCheck },
  expired: { label: 'Expired', tone: 'neutral', icon: Hourglass },
  rejected: { label: 'Rejected', tone: 'danger', icon: XCircle },
  revoked: { label: 'Revoked', tone: 'neutral', icon: Ban },
};

export const RequestStateChip: React.FC<{ request: AccessRequest }> = ({ request }) => {
  const now = useNow();
  const m = STATE_META[requestState(request, now)];
  return (
    <Badge tone={m.tone} icon={m.icon}>
      {m.label}
    </Badge>
  );
};

/** Server identity attested by a data-plane-signed block token, or self-reported. */
export const VerifiedBadge: React.FC<{ verified: boolean; compact?: boolean }> = ({ verified, compact }) => (
  <Tooltip
    content={
      verified
        ? 'The request carried a block token signed by the data plane: server identity and URL are attested.'
        : 'Submitted without a valid block token: server identity and URL are self-reported. Check the source IP.'
    }
  >
    {verified ? (
      <Badge tone="success" icon={ShieldCheck}>
        {compact ? 'Verified' : 'Verified source'}
      </Badge>
    ) : (
      <Badge tone="warning" icon={ShieldAlert}>
        {compact ? 'Unverified' : 'Unverified source'}
      </Badge>
    )}
  </Tooltip>
);

export const ScopeBadge: React.FC<{ scope: string }> = ({ scope }) => (
  <Tooltip content={SCOPE_META[scope as keyof typeof SCOPE_META]?.description}>
    <Badge tone={scope === 'learning_session_15m' ? 'violet' : scope === 'domain' ? 'info' : 'neutral'}>{scopeLabel(scope, true)}</Badge>
  </Tooltip>
);

/** SLA (pending) or access expiry (approved) or the decision time. */
export const DeadlineChip: React.FC<{ request: AccessRequest }> = ({ request: r }) => {
  if (r.status === 'pending') {
    return r.due_at ? <CountdownChip due={r.due_at} kind="due" /> : <span className="text-[12px] text-fg-subtle">No SLA</span>;
  }
  if (r.status === 'approved') {
    return r.expires_at ? (
      <CountdownChip due={r.expires_at} kind="expiry" warnWithinMs={24 * 3600_000} />
    ) : (
      <Badge tone="violet" icon={CheckCheck}>
        Permanent
      </Badge>
    );
  }
  const at = r.revoked_at || r.reviewed_at;
  return <span className="text-[12px] text-fg-subtle">{at ? formatDateTime(at) : '—'}</span>;
};
