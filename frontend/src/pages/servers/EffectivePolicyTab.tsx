import React, { useState } from 'react';
import { FileWarning, Globe2, Layers, Lock, ShieldCheck, ShieldOff, ShieldX, Unlock } from 'lucide-react';
import { api } from '../../api';
import { useConsoleState } from '../../data/AppData';
import { formatNumber } from '../../lib/format';
import { useAsync } from '../../lib/hooks';
import { Link } from '../../lib/router';
import type { EffectivePolicy, EffectivePolicySet, PolicyRule, Server } from '../../types';
import {
  Badge,
  Button,
  Callout,
  Card,
  CardHeader,
  Column,
  CountdownChip,
  DataTable,
  EmptyState,
  MethodList,
  PatternText,
  Skeleton,
  StatTile,
  Tooltip,
} from '../../ui';
import { MembershipChip } from '../../components/fleet/FleetChips';
import { PolicyKindBadge, RuleActionBadge } from '../../components/policy/PolicyBadges';
import { RuleDetailDrawer } from '../../components/policy/RuleDetailDrawer';

/** Which policy sets, rules and exceptions apply to one server, and why ("via"). */
export const EffectivePolicyTab: React.FC<{ server: Server }> = ({ server }) => {
  const state = useConsoleState();
  const ep = useAsync<EffectivePolicy>(() => api.servers.effectivePolicy(server.id), [server.id, state.revision]);
  const [rule, setRule] = useState<PolicyRule | null>(null);

  if (ep.loading && !ep.data) {
    return (
      <div className="space-y-4" role="status" aria-label="Loading effective policy">
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
        <Skeleton className="h-64" />
      </div>
    );
  }
  if (!ep.data) {
    return (
      <Callout tone="danger" title="The effective policy could not be loaded" action={<Button size="sm" onClick={() => ep.reload()}>Retry</Button>}>
        {ep.error}
      </Callout>
    );
  }
  const d = ep.data;
  const sets = d.policy_sets ?? [];
  const tls = d.tls_bypass ?? [];
  const template = state.block_pages.find((t) => t.id === d.block_page_template_id);
  const dynamic = new Set(d.dynamic_group_ids ?? []);

  return (
    <div className="space-y-6">
      {d.quarantined && (
        <Callout tone="danger" icon={ShieldOff} title="Quarantine overrides everything below">
          While the server is quarantined every request is denied. The rules take effect again after the release.
        </Callout>
      )}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile label="Policy sets" value={formatNumber(sets.length)} icon={Layers} tone="accent" hint="Enabled, published, in scope" />
        <StatTile label="Allow rules" value={formatNumber(d.allow_rules)} icon={ShieldCheck} tone="success" hint="Active, not expired" />
        <StatTile label="Block rules" value={formatNumber(d.block_rules)} icon={ShieldX} tone="danger" hint="Checked before allow rules" />
        <StatTile label="TLS exceptions" value={formatNumber(tls.length)} icon={Unlock} tone="violet" hint="Not inspected" />
      </div>

      <Card>
        <CardHeader title="Context" description="Everything besides rules that shapes what this server may reach." divider />
        <dl className="grid gap-x-6 gap-y-4 p-[var(--card-p)] sm:grid-cols-2 lg:grid-cols-3">
          <div className="min-w-0">
            <dt className="text-[12px] font-medium text-fg-subtle">Effective groups</dt>
            <dd className="mt-1 flex flex-wrap gap-1">
              {d.effective_group_ids.length ? d.effective_group_ids.map((g) => <MembershipChip key={g} id={g} dynamic={dynamic.has(g)} />) : <span className="text-[13px] text-fg-subtle">None — only baseline sets apply</span>}
            </dd>
          </div>
          <div className="min-w-0">
            <dt className="text-[12px] font-medium text-fg-subtle">Block page</dt>
            <dd className="mt-1 text-[13px]">
              {template ? (
                <Link to={`/block-pages/${encodeURIComponent(template.id)}`} className="inline-flex items-center gap-1.5 text-accent hover:underline">
                  <FileWarning className="h-3.5 w-3.5" aria-hidden />
                  {template.name}
                </Link>
              ) : (
                <span className="text-fg-muted">{d.block_page_template_id || 'Default template'}</span>
              )}
              {template?.is_default && <span className="ml-1.5 text-[12px] text-fg-subtle">(default)</span>}
            </dd>
          </div>
          <div className="min-w-0">
            <dt className="text-[12px] font-medium text-fg-subtle">Isolation</dt>
            <dd className="mt-1 text-[13px]">
              {d.strict_isolation ? (
                <span className="inline-flex flex-wrap items-center gap-1.5">
                  <Badge tone="danger" icon={Lock}>
                    Strict isolation
                  </Badge>
                  <span className="text-[12px] text-fg-muted">Global TLS exceptions and learning sessions do not apply.</span>
                </span>
              ) : (
                <span className="text-fg-muted">Standard</span>
              )}
            </dd>
          </div>
          <div className="min-w-0 sm:col-span-2 lg:col-span-3">
            <dt className="text-[12px] font-medium text-fg-subtle">Blocked file types</dt>
            <dd className="mt-1 flex flex-wrap gap-1">
              {(d.blocked_file_types ?? []).length ? (
                (d.blocked_file_types ?? []).map((t) => (
                  <span key={t} className="rounded border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[11px] text-fg">
                    {t}
                  </span>
                ))
              ) : (
                <span className="text-[13px] text-fg-subtle">None</span>
              )}
            </dd>
          </div>
        </dl>
      </Card>

      <section aria-labelledby="ep-sets" className="space-y-4">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h2 id="ep-sets" className="text-[15px] font-semibold text-fg">
            Applied policy sets
          </h2>
          <span className="text-[12px] text-fg-subtle">Highest priority first. BLOCK rules win over ALLOW rules.</span>
        </div>
        {sets.length === 0 ? (
          <Card>
            <EmptyState
              icon={Layers}
              title="No policy set applies"
              description="Only the default deny applies: every request is blocked. Add the server to a group that has policy sets, or assign a set to the server."
              action={<Link to="/policies" className="text-[13px] font-medium text-accent hover:underline">Open policy sets</Link>}
            />
          </Card>
        ) : (
          sets.map((s) => <SetCard key={s.id} set={s} dynamic={dynamic} onOpen={setRule} />)
        )}
      </section>

      {tls.length > 0 && (
        <Card>
          <CardHeader title="TLS inspection exceptions" description="Traffic to these hosts is passed through without inspection." icon={Unlock} divider />
          <ul className="divide-y divide-border">
            {tls.map((b) => (
              <li key={b.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-[var(--card-p)] py-2.5 text-[13px]">
                <span className="font-mono text-[12.5px] font-medium text-fg">{b.pattern}</span>
                <Badge tone="violet">{b.category || b.match_type}</Badge>
                <span className="min-w-0 flex-1 truncate text-fg-muted">{b.reason}</span>
                {b.expires_at && <CountdownChip due={b.expires_at} kind="expiry" />}
              </li>
            ))}
          </ul>
        </Card>
      )}

      <RuleDetailDrawer rule={rule} onClose={() => setRule(null)} />
    </div>
  );
};

const SetCard: React.FC<{ set: EffectivePolicySet; dynamic: Set<string>; onOpen: (r: PolicyRule) => void }> = ({ set, dynamic, onOpen }) => {
  const columns: Column<PolicyRule>[] = [
    { id: 'action', header: 'Action', width: 96, cell: (r) => <RuleActionBadge action={r.action} /> },
    {
      id: 'dest',
      header: 'Destination',
      cell: (r) => (
        <div className="min-w-0">
          <button type="button" onClick={() => onOpen(r)} className="block max-w-full text-left hover:underline">
            <PatternText host={r.host_pattern} path={r.path_pattern} />
          </button>
          <div className="truncate text-[12px] text-fg-subtle">{r.name}</div>
        </div>
      ),
    },
    { id: 'methods', header: 'Methods', width: 150, hideBelow: 'lg', cell: (r) => <MethodList methods={r.methods} /> },
    {
      id: 'expires',
      header: 'Expires',
      width: 140,
      hideBelow: 'xl',
      cell: (r) => (r.expires_at ? <CountdownChip due={r.expires_at} kind="expiry" /> : <span className="text-[12.5px] text-fg-subtle">Never</span>),
    },
    { id: 'hits', header: 'Hits', width: 72, align: 'right', sortValue: (r) => r.hit_count, cell: (r) => <span className="tabular text-fg-muted">{formatNumber(r.hit_count)}</span> },
  ];
  return (
    <Card>
      <div className="flex flex-wrap items-start justify-between gap-3 px-[var(--card-p)] pb-3 pt-[calc(var(--card-p)-4px)]">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Link to={`/policies/${encodeURIComponent(set.id)}`} className="text-[14px] font-semibold text-fg hover:text-accent hover:underline">
              {set.name}
            </Link>
            <PolicyKindBadge kind={set.kind} />
            <Badge tone="neutral">v{set.version}</Badge>
            <Tooltip content="Higher priority sets are evaluated first">
              <span className="text-[12px] text-fg-subtle">Priority {set.priority}</span>
            </Tooltip>
          </div>
          <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-[12px] text-fg-subtle">
            <span>Applies via</span>
            {set.via.map((v) =>
              v === 'baseline' ? (
                <Badge key={v} tone="violet" icon={Globe2}>
                  Baseline · all servers
                </Badge>
              ) : v === 'server' ? (
                <Badge key={v} tone="accent">
                  Assigned to this server
                </Badge>
              ) : v.startsWith('group:') ? (
                <MembershipChip key={v} id={v.slice(6)} dynamic={dynamic.has(v.slice(6))} />
              ) : (
                <Badge key={v}>{v}</Badge>
              )
            )}
          </div>
        </div>
        <span className="text-[12px] tabular text-fg-subtle">{set.rules.length} active rules</span>
      </div>
      <div className="border-t border-border">
        {set.rules.length === 0 ? (
          <p className="px-[var(--card-p)] py-4 text-[13px] text-fg-subtle">No active rules (all disabled or expired).</p>
        ) : (
          <DataTable
            rows={set.rules}
            columns={columns}
            getRowId={(r) => r.id}
            hideToolbar
            pageSize={10}
            mobileCard={(r) => (
              <button type="button" onClick={() => onOpen(r)} className="block w-full min-w-0 space-y-1 text-left">
                <span className="flex items-start gap-2">
                  <RuleActionBadge action={r.action} />
                  <PatternText host={r.host_pattern} path={r.path_pattern} wrap className="min-w-0 flex-1" />
                </span>
                <span className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px] text-fg-subtle">
                  <MethodList methods={r.methods} />
                  <span className="tabular">{formatNumber(r.hit_count)} hits</span>
                  {r.expires_at && <CountdownChip due={r.expires_at} kind="expiry" />}
                </span>
              </button>
            )} className="[&>div]:rounded-none [&>div]:border-0 [&>div]:shadow-none" aria-label={`Rules of ${set.name}`} />
        )}
      </div>
    </Card>
  );
};
