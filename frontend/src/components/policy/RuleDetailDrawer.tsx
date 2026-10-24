import React from 'react';
import type { PolicyRule, RuleInput } from '../../types';
import { formatBytes, formatDateTime, formatNumber } from '../../lib/format';
import { Link } from '../../lib/router';
import { Badge, CompanionText, CountdownChip, DescriptionList, Drawer, MethodList, PatternText } from '../../ui';
import { UserName } from '../common/EntityChips';
import { RuleActionBadge } from './PolicyBadges';
import { describeRule } from './policyUtils';

/** Read-only details of one rule. */
export const RuleDetailDrawer: React.FC<{ rule: PolicyRule | RuleInput | null; onClose: () => void; footer?: React.ReactNode }> = ({ rule, onClose, footer }) => {
  const r = rule as PolicyRule | null;
  return (
    <Drawer
      open={!!rule}
      onClose={onClose}
      width="md"
      title={r?.name || 'Rule'}
      titleAside={r && <RuleActionBadge action={r.action} />}
      description={r?.description}
      footer={footer}
    >
      {r && (
        <div className="space-y-6">
          <div className="rounded-lg border border-border bg-surface-2 p-4">
            <PatternText host={r.host_pattern} path={r.path_pattern} wrap className="text-[13.5px]" />
            <p className="mt-1.5 text-[13px] text-fg-muted">{describeRule({ ...r, methods: r.methods ?? [] })}</p>
          </div>
          <DescriptionList
            items={[
              { label: 'Methods', value: <MethodList methods={r.methods} /> },
              { label: 'State', value: r.enabled ? <Badge tone="success">Enabled</Badge> : <Badge tone="neutral">Disabled</Badge> },
              {
                label: 'Follows redirects',
                value: !r.follow_redirects
                  ? 'No'
                  : r.redirect_hosts?.length
                    ? `Yes, to ${r.redirect_hosts.join(', ')} (two minutes per redirect)`
                    : 'Yes, to any public host (two minutes per redirect)',
              },
              { label: 'Expires', value: r.expires_at ? <CountdownChip due={r.expires_at} kind="expiry" /> : 'Never' },
              {
                label: 'Companion rules',
                full: true,
                value:
                  (r.companion_rules ?? []).length === 0 ? (
                    <span className="text-fg-subtle">None</span>
                  ) : (
                    <ul className="space-y-1">
                      {(r.companion_rules ?? []).map((c) => (
                        <li key={c}>
                          <CompanionText value={c} />
                        </li>
                      ))}
                    </ul>
                  ),
              },
              { label: 'Hits', value: formatNumber(r.hit_count ?? 0), hidden: r.hit_count === undefined },
              { label: 'Traffic', value: formatBytes(r.total_bytes ?? 0), hidden: !r.total_bytes },
              { label: 'Created', value: r.created_at ? <span>{formatDateTime(r.created_at)}</span> : '—', hidden: !r.created_at },
              { label: 'Created by', value: <UserName username={r.created_by} />, hidden: !r.created_by },
              { label: 'Approved by', value: <UserName username={r.approved_by} />, hidden: !r.approved_by },
              { label: 'Rule version', value: r.version ? `v${r.version}${r.updated_at ? `, changed ${formatDateTime(r.updated_at)}` : ''}` : '—', hidden: !r.version },
              {
                label: 'Access request',
                value: <Link to={`/requests/${encodeURIComponent(r.access_request_id || '')}`} className="text-accent hover:underline">{r.access_request_id}</Link>,
                hidden: !r.access_request_id,
              },
              { label: 'Learning session', value: <span className="font-mono text-[12px]">{r.source_session_id}</span>, hidden: !r.source_session_id },
              { label: 'Rule id', value: <span className="font-mono text-[12px]">{r.id || 'assigned on save'}</span> },
            ]}
          />
        </div>
      )}
    </Drawer>
  );
};
