import React from 'react';
import { Activity, ShieldCheck, ShieldX, Server as ServerIcon, Equal } from 'lucide-react';
import type { ImpactSample, ImpactSummary } from '../../types';
import { formatNumber } from '../../lib/format';
import { Callout, Column, DataTable, EmptyState, RelativeTime, StatTile } from '../../ui';
import { VerdictBadge } from '../traffic/VerdictBadge';

/** Impact simulation result: tiles + table of sample requests whose verdict flips. */
export const ImpactSummaryView: React.FC<{ impact: ImpactSummary; compact?: boolean }> = ({ impact, compact }) => {
  const samples = impact.samples ?? [];
  const columns: Column<ImpactSample>[] = [
    {
      id: 'request',
      header: 'Request',
      cell: (s) => (
        <div className="min-w-0">
          <div className="truncate font-mono text-[12.5px] text-fg" title={s.url}>
            <span className="mr-1.5 text-fg-subtle">{s.method}</span>
            {s.url}
          </div>
          {s.rule_name && <div className="truncate text-[12px] text-fg-subtle">Rule: {s.rule_name}</div>}
        </div>
      ),
      sortValue: (s) => s.url,
    },
    {
      id: 'server',
      header: 'Server',
      cell: (s) => (
        <div className="min-w-0">
          <div className="truncate">{s.server_hostname || s.server_ip}</div>
          {s.server_hostname && <div className="font-mono text-[11.5px] text-fg-subtle">{s.server_ip}</div>}
        </div>
      ),
      sortValue: (s) => s.server_hostname || s.server_ip,
      width: '22%',
    },
    {
      id: 'change',
      header: 'Verdict change',
      cell: (s) => (
        <span className="inline-flex flex-wrap items-center gap-1.5">
          <VerdictBadge verdict={s.before} />
          <span className="text-fg-subtle" aria-label="becomes">
            →
          </span>
          <VerdictBadge verdict={s.after} />
        </span>
      ),
      width: 260,
    },
  ];
  return (
    <div className="space-y-4">
      <div className={compact ? 'grid grid-cols-2 gap-3 lg:grid-cols-4' : 'grid grid-cols-2 gap-3 xl:grid-cols-5'}>
        <StatTile label="Requests evaluated" value={formatNumber(impact.flows_evaluated)} icon={Activity} hint="Recorded traffic window" />
        <StatTile
          label="Newly allowed"
          value={formatNumber(impact.newly_allowed)}
          icon={ShieldCheck}
          tone={impact.newly_allowed > 0 ? 'success' : 'neutral'}
        />
        <StatTile label="Newly blocked" value={formatNumber(impact.newly_blocked)} icon={ShieldX} tone={impact.newly_blocked > 0 ? 'danger' : 'neutral'} attention={impact.newly_blocked > 0} />
        {!compact && <StatTile label="Unchanged" value={formatNumber(impact.unchanged)} icon={Equal} />}
        <StatTile
          label="Servers affected"
          value={formatNumber(impact.affected_servers)}
          icon={ServerIcon}
          hint={`of ${formatNumber(impact.target_servers)} in scope`}
        />
      </div>
      {impact.newly_blocked > 0 && (
        <Callout tone="warning" title="This change blocks traffic that is currently allowed">
          Check the samples below with the server owners before publishing.
        </Callout>
      )}
      <div>
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-[13px] font-semibold text-fg">Sample requests that change verdict</h3>
          <span className="text-[12px] text-fg-subtle">
            Computed <RelativeTime value={impact.computed_at} />
          </span>
        </div>
        <DataTable
          rows={samples}
          columns={columns}
          getRowId={(s) => `${s.server_ip}-${s.method}-${s.url}-${s.before}`}
          hideToolbar
          pageSize={10}
          empty={
            <EmptyState
              size="sm"
              icon={Equal}
              title="No recorded request changes its verdict"
              description={
                impact.flows_evaluated === 0
                  ? 'There is no recorded traffic for the servers in scope yet, so the impact cannot be estimated.'
                  : 'Every recorded request in scope keeps its current verdict.'
              }
            />
          }
        />
        {samples.length > 0 && (
          <p className="mt-2 text-[12px] text-fg-subtle">
            {samples.length} sample{samples.length === 1 ? '' : 's'} shown. This is a simulation; nothing was changed.
          </p>
        )}
      </div>
    </div>
  );
};
