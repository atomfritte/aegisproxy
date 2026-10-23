import React, { useMemo, useState } from 'react';
import { Activity, BarChart3, GitMerge, Globe2, HardDrive, Lock, LockOpen, Server as ServerIcon, Table2, Zap } from 'lucide-react';
import { api } from '../../api';
import { useAction, useConsole, useConsoleState } from '../../data/AppData';
import { useLookups } from '../../data/lookups';
import { formatBytes, formatCompact, formatNumber } from '../../lib/format';
import { useDocumentTitle } from '../../lib/hooks';
import { Link } from '../../lib/router';
import { useUrlFilters } from '../../lib/useUrlFilters';
import type { DestinationVolumeEntry, ServerVolumeEntry } from '../../types';
import {
  Badge,
  Button,
  ButtonLink,
  Card,
  CardHeader,
  Column,
  DataTable,
  EmptyState,
  PageHeader,
  PatternText,
  SegmentedControl,
  Sparkline,
  StatTile,
  Tooltip,
} from '../../ui';
import { formatMbps, percent } from './bandwidth/bandwidthFormat';
import { SERIES, ThroughputChart, ThroughputLegend, VIZ_VARS } from './bandwidth/ThroughputChart';

/** Horizontal meter: value relative to the largest row (single accent hue on a same-hue track). */
const Meter: React.FC<{ value: number; max: number; label: string }> = ({ value, max, label }) => (
  <span className="flex items-center justify-end gap-2.5">
    <span className="hidden h-1.5 w-24 overflow-hidden rounded-full bg-accent-soft sm:block" aria-hidden>
      <span className="block h-full rounded-full bg-accent" style={{ width: `${Math.max(3, Math.round((value / Math.max(1, max)) * 100))}%` }} />
    </span>
    <span className="min-w-[64px] text-right font-medium tabular text-fg">{label}</span>
  </span>
);

const Rank: React.FC<{ n: number }> = ({ n }) => <span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-surface-3 text-[11.5px] font-semibold tabular text-fg-muted">{n}</span>;

/** Throughput over time, traffic classes, top talkers and destinations (24 h window). */
export const BandwidthPage: React.FC = () => {
  useDocumentTitle('Bandwidth');
  const state = useConsoleState();
  const { demoMode } = useConsole();
  const { run, pending } = useAction();
  const { groupById, groupName, serverById } = useLookups();
  const f = useUrlFilters(['group']);
  const [view, setView] = useState<'chart' | 'table'>('chart');
  const bw = state.bandwidth;
  const series = bw?.time_series ?? [];
  const topServers = bw?.top_servers ?? [];
  const topDest = bw?.top_destinations ?? [];
  const groups = useMemo(() => [...(bw?.group_breakdown ?? [])].sort((a, b) => b.total_bytes - a.total_bytes), [bw]);
  const total = bw?.total_bytes_24h ?? 0;
  const peakRps = Math.max(0, ...series.map((s) => s.requests_per_sec));
  const maxServer = Math.max(1, ...topServers.map((s) => s.total_bytes));
  const maxDest = Math.max(1, ...topDest.map((s) => s.total_bytes));
  const maxGroup = Math.max(1, ...groups.map((g) => g.total_bytes));
  const rank = useMemo(() => new Map([...topServers].sort((a, b) => b.total_bytes - a.total_bytes).map((s, i) => [s.server_id, i + 1])), [topServers]);
  const destRank = useMemo(() => new Map([...topDest].sort((a, b) => b.total_bytes - a.total_bytes).map((d, i) => [d.host + d.path_pattern, i + 1])), [topDest]);

  const simulate = () =>
    run(
      () =>
        api.simulate.request({
          server_ip: '10.20.1.15',
          method: 'GET',
          full_url: 'https://github.com/microsoft/onnxruntime/releases/download/v1.19.2/onnxruntime-linux-x64-gpu-1.19.2.whl',
          user_agent: 'curl/8.5.0',
          simulate_redirect: true,
        }),
      {
        key: 'burst',
        success: (r) => (r.dry_run ? 'Evaluated as a dry run — nothing was recorded' : 'Release download simulated — see the request and its redirect object in Live traffic'),
        errorTitle: 'Simulation failed',
      }
    );

  const serverColumns: Column<ServerVolumeEntry>[] = [
    { id: 'rank', header: '#', width: 48, sortValue: (s) => rank.get(s.server_id) ?? 0, cell: (s) => <Rank n={rank.get(s.server_id) ?? 0} /> },
    {
      id: 'server',
      header: 'Server',
      sortValue: (s) => s.hostname,
      cell: (s) => (
        <div className="min-w-0">
          {serverById.has(s.server_id) ? (
            <Link to={`/servers/${encodeURIComponent(s.server_id)}`} className="whitespace-nowrap font-medium text-fg hover:text-accent hover:underline">
              {s.hostname}
            </Link>
          ) : (
            <span className="whitespace-nowrap font-medium text-fg">{s.hostname}</span>
          )}
          <div className="flex items-center gap-2 font-mono text-[11.5px] text-fg-subtle">
            {s.ip}
            {(s.group_ids ?? []).slice(0, 1).map((g) => (
              <span key={g} className="inline-flex min-w-0 items-center gap-1 font-sans">
                <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: groupById.get(g)?.color || 'rgb(var(--c-fg-subtle))' }} aria-hidden />
                <span className="truncate">{groupName(g)}</span>
              </span>
            ))}
          </div>
        </div>
      ),
    },
    {
      id: 'dest',
      header: 'Top destination',
      hideBelow: 'xl',
      cell: (s) => (
        <span className="block w-0 min-w-full truncate font-mono text-[12px] text-fg-muted" title={s.top_destination}>
          {s.top_destination || '—'}
        </span>
      ),
    },
    { id: 'peak', header: 'Peak', align: 'right', width: 96, sortValue: (s) => s.peak_mbps, cell: (s) => <span className="tabular text-fg-muted">{formatMbps(s.peak_mbps)}</span> },
    { id: 'requests', header: 'Requests', align: 'right', width: 92, hideBelow: 'xl', sortValue: (s) => s.request_count, cell: (s) => <span className="tabular text-fg-muted">{formatCompact(s.request_count)}</span> },
    {
      id: 'volume',
      header: 'Volume, 24 h',
      align: 'right',
      width: 180,
      sortValue: (s) => s.total_bytes,
      cell: (s) => (
        <Tooltip content={`Downloaded ${formatBytes(s.bytes_received)}, uploaded ${formatBytes(s.bytes_sent)}`}>
          <span className="block">
            <Meter value={s.total_bytes} max={maxServer} label={formatBytes(s.total_bytes)} />
          </span>
        </Tooltip>
      ),
    },
  ];

  const destColumns: Column<DestinationVolumeEntry>[] = [
    { id: 'rank', header: '#', width: 48, sortValue: (d) => destRank.get(d.host + d.path_pattern) ?? 0, cell: (d) => <Rank n={destRank.get(d.host + d.path_pattern) ?? 0} /> },
    {
      id: 'dest',
      header: 'Destination',
      sortValue: (d) => d.host,
      cell: (d) => (
        <div className="w-0 min-w-full">
          <PatternText host={d.host} path={d.path_pattern} />
          <p className="mt-0.5 truncate text-[12px] text-fg-subtle">
            {d.category}
            {d.parent_rule_name && <span className="hidden xl:inline"> · allowed by {d.parent_rule_name}</span>}
          </p>
        </div>
      ),
    },
    {
      id: 'kind',
      header: 'Traffic',
      width: 156,
      hideBelow: 'lg',
      cell: (d) => (
        <span className="flex flex-wrap gap-1">
          {d.is_redirect_asset && (
            <Tooltip content="Reached through follow-redirect lineage of an allow rule">
              <Badge tone="info" icon={GitMerge}>
                Redirect objects
              </Badge>
            </Tooltip>
          )}
          {d.tls_intercepted ? (
            <Badge tone="neutral" icon={LockOpen}>
              Inspected
            </Badge>
          ) : (
            <Badge tone="violet" icon={Lock}>
              TLS passthrough
            </Badge>
          )}
        </span>
      ),
    },
    { id: 'requests', header: 'Requests', align: 'right', width: 92, sortValue: (d) => d.request_count, cell: (d) => <span className="tabular text-fg-muted">{formatCompact(d.request_count)}</span> },
    {
      id: 'volume',
      header: 'Volume, 24 h',
      align: 'right',
      width: 180,
      sortValue: (d) => d.total_bytes,
      cell: (d) => <Meter value={d.total_bytes} max={maxDest} label={formatBytes(d.total_bytes)} />,
    },
  ];

  const throughputTrend = series.map((s) => ({ label: s.time_label, value: Math.round(s.mbps_total) }));

  return (
    <>
      <PageHeader
        title="Bandwidth"
        description="Outbound throughput by traffic class, the servers that move the most data and the destinations they reach."
        actions={
          <>
            <ButtonLink to="/traffic" icon={Activity}>
              Live traffic
            </ButtonLink>
            {demoMode && (
              <Tooltip content="Demo mode: evaluates a large GitHub release download (and its redirect object) and records it in the live stream.">
                <Button icon={Zap} loading={pending === 'burst'} onClick={simulate}>
                  Simulate a release download
                </Button>
              </Tooltip>
            )}
          </>
        }
      />

      <section aria-label="Key figures" className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile
          label="Throughput now"
          value={formatMbps(bw?.current_mbps)}
          icon={Activity}
          tone="accent"
          hint={`24 h peak ${formatMbps(bw?.peak_mbps_24h)} · ${formatNumber(series[series.length - 1]?.requests_per_sec ?? 0)} requests/s`}
          trend={throughputTrend.length > 1 ? <Sparkline data={throughputTrend} height={36} ariaLabel="Throughput trend" format={(v) => formatMbps(v)} /> : undefined}
        />
        <StatTile label="Volume, 24 h" value={formatBytes(total)} icon={HardDrive} hint={`${formatNumber(groups.length)} server groups, ${formatNumber(peakRps)} requests/s at peak`} />
        <StatTile
          label="Redirect objects, 24 h"
          value={formatBytes(bw?.cdn_redirect_bytes_24h)}
          icon={GitMerge}
          hint={`${percent(bw?.cdn_redirect_bytes_24h ?? 0, total)}% of volume — release assets and CDN blobs reached through follow-redirect rules`}
        />
        <StatTile
          label="TLS passthrough, 24 h"
          value={formatBytes(bw?.tls_bypass_bytes_24h)}
          icon={Lock}
          hint={
            <>
              {percent(bw?.tls_bypass_bytes_24h ?? 0, total)}% not decrypted by{' '}
              <Link to="/tls" className="text-accent hover:underline">
                TLS exceptions
              </Link>
            </>
          }
        />
      </section>

      <div className="mb-6 grid grid-cols-1 items-start gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader
            title="Throughput by traffic class"
            description={series.length ? `Mbps per 15-minute sample, ${series[0].time_label} to ${series[series.length - 1].time_label}` : 'Mbps per sample'}
            actions={
              <SegmentedControl
                size="sm"
                aria-label="Display"
                value={view}
                onChange={setView}
                options={[
                  { value: 'chart', label: 'Chart', icon: BarChart3 },
                  { value: 'table', label: 'Table', icon: Table2 },
                ]}
              />
            }
          />
          <div className="px-[var(--card-p)] pb-[var(--card-p)] pt-2">
            <ThroughputLegend className="mb-3" />
            {view === 'chart' ? (
              <ThroughputChart data={series} />
            ) : (
              <div className={`scroll-thin max-h-[300px] overflow-auto rounded-md border border-border ${VIZ_VARS}`}>
                <table className="w-full text-[12.5px]">
                  <thead className="sticky top-0 bg-surface-2 text-fg-muted">
                    <tr>
                      <th className="px-3 py-2 text-left font-medium">Time</th>
                      {SERIES.map((s) => (
                        <th key={s.key} className="px-3 py-2 text-right font-medium">
                          <span className="inline-flex items-center gap-1.5">
                            <span className="h-2 w-2 rounded-[2px]" style={{ background: s.color }} aria-hidden />
                            {s.label}
                          </span>
                        </th>
                      ))}
                      <th className="px-3 py-2 text-right font-medium">Total</th>
                      <th className="hidden px-3 py-2 text-right font-medium sm:table-cell">Requests/s</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[...series].reverse().map((s) => (
                      <tr key={s.time_label} className="border-t border-border">
                        <td className="px-3 py-1.5 tabular text-fg-muted">{s.time_label}</td>
                        <td className="px-3 py-1.5 text-right tabular">{formatMbps(s.mbps_direct_allow)}</td>
                        <td className="px-3 py-1.5 text-right tabular">{formatMbps(s.mbps_cdn_objects)}</td>
                        <td className="px-3 py-1.5 text-right tabular">{formatMbps(s.mbps_tls_bypass)}</td>
                        <td className="px-3 py-1.5 text-right font-medium tabular">{formatMbps(s.mbps_total)}</td>
                        <td className="hidden px-3 py-1.5 text-right tabular text-fg-muted sm:table-cell">{formatNumber(s.requests_per_sec)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </Card>

        <Card>
          <CardHeader title="By server group" description="Share of the 24 h volume" />
          {groups.length === 0 ? (
            <EmptyState size="sm" icon={ServerIcon} title="No group volume yet" description="Volume appears once servers in a group send traffic through the proxy." />
          ) : (
            <ul className="mt-2">
              {groups.map((g) => {
                const known = groupById.has(g.group_id);
                const name = known ? groupName(g.group_id) : g.group_name;
                return (
                  <li key={g.group_id} className="border-t border-border px-[var(--card-p)] py-2.5 first:border-t-0">
                    <div className="flex items-center gap-2.5">
                      <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: g.color || 'rgb(var(--c-fg-subtle))' }} aria-hidden />
                      <span className="min-w-0 flex-1 truncate text-[13px]">
                        {known ? (
                          <Link to={`/groups/${encodeURIComponent(g.group_id)}`} className="text-fg hover:text-accent hover:underline">
                            {name}
                          </Link>
                        ) : (
                          <span className="text-fg">{name}</span>
                        )}
                      </span>
                      <span className="text-[13px] font-medium tabular text-fg">{formatBytes(g.total_bytes)}</span>
                      <span className="w-9 text-right text-[12px] tabular text-fg-subtle">{percent(g.total_bytes, total)}%</span>
                    </div>
                    <Tooltip content={`${formatNumber(g.server_count)} servers · ${formatMbps(g.current_mbps)} now · ${formatNumber(g.request_count)} requests`} className="mt-1.5 w-full pl-5">
                      <span className="block h-1.5 w-full overflow-hidden rounded-full bg-accent-soft" aria-label={`${percent(g.total_bytes, total)}% of the volume`}>
                        <span className="block h-full rounded-full bg-accent" style={{ width: `${Math.max(2, Math.round((g.total_bytes / maxGroup) * 100))}%` }} />
                      </span>
                    </Tooltip>
                    <p className="mt-1 pl-5 text-[12px] text-fg-subtle">
                      {formatNumber(g.server_count)} servers · {formatMbps(g.current_mbps)} now
                    </p>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>
      </div>

      <section aria-labelledby="top-servers-h" className="mb-6">
        <div className="mb-3 flex items-baseline justify-between gap-3">
          <h2 id="top-servers-h" className="text-[15px] font-semibold text-fg">
            Top servers
          </h2>
          <span className="hidden text-[12.5px] text-fg-subtle sm:inline">By downloaded and uploaded volume, 24 h</span>
        </div>
        <DataTable
          rows={topServers}
          columns={serverColumns}
          getRowId={(s) => s.server_id}
          initialSort={{ id: 'volume', dir: 'desc' }}
          rowHref={(s) => (serverById.has(s.server_id) ? `/servers/${encodeURIComponent(s.server_id)}` : `/traffic?server=${encodeURIComponent(s.server_id)}`)}
          getSearchText={(s) => `${s.hostname} ${s.ip} ${s.top_destination} ${(s.group_ids ?? []).map(groupName).join(' ')}`}
          searchPlaceholder="Search servers…"
          facetValues={f.values}
          onFacetChange={f.onChange}
          facets={[{ id: 'group', label: 'Group', getValue: (s) => s.group_ids ?? [], optionLabel: groupName }]}
          mobileCard={(s) => (
            <div className="min-w-0 space-y-1.5">
              <div className="flex items-start justify-between gap-2">
                <span className="flex min-w-0 items-center gap-2">
                  <Rank n={rank.get(s.server_id) ?? 0} />
                  <span className="min-w-0">
                    <span className="block truncate font-medium text-fg">{s.hostname}</span>
                    <span className="font-mono text-[11.5px] text-fg-subtle">{s.ip}</span>
                  </span>
                </span>
                <span className="shrink-0 font-medium tabular text-fg">{formatBytes(s.total_bytes)}</span>
              </div>
              <p className="truncate font-mono text-[12px] text-fg-muted">{s.top_destination}</p>
              <p className="text-[12px] text-fg-subtle">
                Peak {formatMbps(s.peak_mbps)} · {formatCompact(s.request_count)} requests
              </p>
            </div>
          )}
          empty={<EmptyState size="sm" icon={ServerIcon} title="No server volume yet" description="Servers appear here once they send traffic through the proxy." />}
          aria-label="Top servers by volume"
        />
      </section>

      <section aria-labelledby="top-dest-h">
        <div className="mb-3 flex items-baseline justify-between gap-3">
          <h2 id="top-dest-h" className="text-[15px] font-semibold text-fg">
            Top destinations
          </h2>
          <span className="hidden text-[12.5px] text-fg-subtle sm:inline">Repositories, CDN buckets and update mirrors</span>
        </div>
        <DataTable
          rows={topDest}
          columns={destColumns}
          getRowId={(d) => d.host + d.path_pattern}
          initialSort={{ id: 'volume', dir: 'desc' }}
          getSearchText={(d) => `${d.host} ${d.path_pattern} ${d.category} ${d.parent_rule_name}`}
          searchPlaceholder="Search destinations…"
          mobileCard={(d) => (
            <div className="min-w-0 space-y-1.5">
              <div className="flex items-start justify-between gap-2">
                <PatternText host={d.host} path={d.path_pattern} className="min-w-0" />
                <span className="shrink-0 font-medium tabular text-fg">{formatBytes(d.total_bytes)}</span>
              </div>
              <p className="truncate text-[12px] text-fg-subtle">{d.category}</p>
              <span className="flex flex-wrap gap-1">
                {d.is_redirect_asset && (
                  <Badge tone="info" icon={GitMerge}>
                    Redirect objects
                  </Badge>
                )}
                {d.tls_intercepted ? (
                  <Badge tone="neutral" icon={LockOpen}>
                    Inspected
                  </Badge>
                ) : (
                  <Badge tone="violet" icon={Lock}>
                    TLS passthrough
                  </Badge>
                )}
              </span>
            </div>
          )}
          empty={<EmptyState size="sm" icon={Globe2} title="No destination volume yet" />}
          aria-label="Top destinations by volume"
        />
      </section>
    </>
  );
};
