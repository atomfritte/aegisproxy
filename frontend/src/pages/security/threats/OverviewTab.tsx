import React from 'react';
import { ArrowRight, Ban, Bug, Cpu, Database, RefreshCw, ShieldAlert, ShieldCheck } from 'lucide-react';
import { api } from '../../../api';
import { useAction } from '../../../data/AppData';
import { cn } from '../../../lib/cn';
import { formatNumber, pluralize } from '../../../lib/format';
import { Link } from '../../../lib/router';
import type { SecurityPolicy } from '../../../types';
import { Badge, Button, Callout, Card, CardHeader, EmptyState, RelativeTime, StatTile, Tone, Tooltip } from '../../../ui';
import { ModeBadge, SeverityBadge } from './components';
import { eventPath, eventTypeMeta, MODE_META, SEVERITY_RANK } from './meta';
import { useDelayedRefresh, useThreatData } from './useThreatData';

/** One protection layer row (mode + summary), linking to the policy tab. */
const LayerRow: React.FC<{ title: string; summary: React.ReactNode; status: React.ReactNode; to?: string }> = ({ title, summary, status, to = '/threats/policy' }) => (
  <li className="border-t border-border first:border-t-0">
    <Link to={to} className="group flex items-center gap-3 px-[var(--card-p)] py-2.5 hover:bg-surface-2">
      <span className="min-w-0 flex-1">
        <span className="block text-[13px] font-medium text-fg">{title}</span>
        <span className="block truncate text-[12px] text-fg-subtle">{summary}</span>
      </span>
      <span className="shrink-0">{status}</span>
      <ArrowRight className="h-3.5 w-3.5 shrink-0 text-fg-subtle opacity-0 transition-opacity group-hover:opacity-100" aria-hidden />
    </Link>
  </li>
);

function layers(p: SecurityPolicy) {
  const groupOverrides = Object.keys(p.group_blocked_file_types ?? {}).length;
  const types = (p.blocked_file_types ?? []).length;
  const hygiene = [p.block_ip_literals && 'IP literals', p.block_private_destinations && 'private destinations', p.block_raw_tcp && 'raw TCP'].filter(Boolean);
  return [
    { title: 'Threat intelligence', summary: 'Feeds and custom indicators for domains, URLs, IPs and file hashes', status: <ModeBadge mode={p.threat_intel_mode} /> },
    {
      title: 'Antivirus (ClamAV)',
      summary: p.av_enabled ? `Fail ${p.av_fail_mode} · scans up to ${Math.round(p.av_max_scan_bytes / 1048576)} MiB` : 'Downloads are not scanned',
      status: <ModeBadge mode={p.av_enabled ? p.av_mode : 'off'} />,
    },
    { title: 'Data loss prevention', summary: `${pluralize((p.dlp_detectors ?? []).length, 'detector')} active`, status: <ModeBadge mode={p.dlp_mode} /> },
    {
      title: 'Download control',
      summary: types || groupOverrides ? `${pluralize(types, 'file type')} blocked everywhere${groupOverrides ? ` · ${pluralize(groupOverrides, 'group override')}` : ''}` : 'No file types blocked',
      status: <Badge tone={types || groupOverrides ? 'success' : 'neutral'} dot>{types || groupOverrides ? 'Active' : 'Off'}</Badge>,
    },
    {
      title: 'Destination hygiene',
      summary: hygiene.length ? `Blocks ${hygiene.join(', ')} · ports ${(p.allowed_ports ?? []).join(', ')}` : `Ports ${(p.allowed_ports ?? []).join(', ')}`,
      status: <Badge tone={hygiene.length === 3 ? 'success' : 'warning'} dot>{hygiene.length === 3 ? 'Hardened' : `${hygiene.length} of 3`}</Badge>,
    },
    { title: 'Punycode domains', summary: 'Internationalized (xn--) host names, homograph spoofing', status: <ModeBadge mode={p.punycode_mode} /> },
    {
      title: 'Burst detection',
      summary: p.blocked_burst_threshold > 0 ? `Event after ${p.blocked_burst_threshold} blocked requests per server and minute` : 'Disabled',
      status: <Badge tone={p.blocked_burst_threshold > 0 ? 'success' : 'neutral'} dot>{p.blocked_burst_threshold > 0 ? 'On' : 'Off'}</Badge>,
    },
  ];
}

/** /threats — KPIs, urgent events, protection layers, feeds and worker health. */
export const OverviewTab: React.FC = () => {
  const d = useThreatData();
  const { run, pending } = useAction();
  const later = useDelayedRefresh();
  const urgent = d.openEvents
    .filter((e) => e.severity === 'critical' || e.severity === 'high')
    .sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || b.timestamp.localeCompare(a.timestamp))
    .slice(0, 6);
  const urgentCount = d.openEvents.filter((e) => e.severity === 'critical' || e.severity === 'high').length;
  const enabledFeeds = d.feeds.filter((f) => f.enabled);
  const failingFeeds = enabledFeeds.filter((f) => !!f.last_error);
  const healthy = d.planes.filter((p) => p.healthy).length;
  const clam = d.planes.filter((p) => p.clamav_available === 'yes').length;
  const ti = d.ti;
  const p = d.policy;

  const avTone: Tone = !p?.av_enabled ? 'neutral' : d.planes.length > 0 && clam < d.planes.length ? 'warning' : 'success';
  const breakdown = ti
    ? [
        { label: 'Domains', value: ti.domains },
        { label: 'URLs', value: ti.urls },
        { label: 'IPs', value: ti.ips },
        { label: 'Networks', value: ti.cidrs },
        { label: 'Hashes', value: ti.hashes },
      ]
    : [];
  const maxBreak = Math.max(1, ...breakdown.map((b) => b.value));

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
        <StatTile
          label="Open security events"
          value={formatNumber(d.openEvents.length)}
          icon={ShieldAlert}
          tone={urgentCount > 0 ? 'danger' : d.openEvents.length > 0 ? 'warning' : 'success'}
          attention={urgentCount > 0}
          hint={urgentCount > 0 ? `${urgentCount} critical or high need attention` : d.openEvents.length > 0 ? 'Awaiting acknowledgement' : 'Nothing to acknowledge'}
          to="/threats/events?status=open"
        />
        <StatTile
          label="Blocked threats"
          value={formatNumber(d.stats?.threats ?? 0)}
          icon={Ban}
          tone="danger"
          hint="In the recent flow window"
          to="/traffic"
        />
        <StatTile
          label="Threat-intel entries"
          value={formatNumber(d.tiEntries)}
          icon={Database}
          tone={d.tiEntries > 0 ? 'accent' : 'warning'}
          hint={ti ? `${pluralize(ti.active_feeds, 'active feed')} · ${pluralize(ti.exceptions, 'exception')}` : 'Not initialized'}
          to="/threats/feeds"
        />
        <StatTile
          label="Antivirus"
          value={p?.av_enabled ? (p.av_mode === 'block' ? 'Blocking' : 'Monitoring') : 'Off'}
          icon={Bug}
          tone={avTone}
          hint={d.planes.length === 0 ? 'No data-plane worker has reported yet' : `ClamAV on ${clam} of ${pluralize(d.planes.length, 'worker')}`}
          to="/threats/policy"
        />
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-5">
        <Card className="xl:col-span-3">
          <CardHeader
            title="High and critical events"
            description="Unacknowledged detections that need a look first."
            divider
            actions={
              <Link to="/threats/events" className="text-[12.5px] font-medium text-accent hover:underline">
                All events
              </Link>
            }
          />
          {urgent.length === 0 ? (
            <EmptyState
              size="sm"
              icon={ShieldCheck}
              title="No high or critical events open"
              description={d.openEvents.length > 0 ? `${pluralize(d.openEvents.length, 'lower-severity event')} still open.` : 'Threat intel, antivirus and DLP detections that need acknowledgement show up here.'}
            />
          ) : (
            <ul>
              {urgent.map((e) => {
                const m = eventTypeMeta(e.type);
                const Icon = m.icon;
                return (
                  <li key={e.id} className="border-t border-border first:border-t-0">
                    <Link to={eventPath(e.id)} className="group flex items-start gap-3 px-[var(--card-p)] py-3 hover:bg-surface-2">
                      <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-danger-soft text-danger">
                        <Icon className="h-4 w-4" aria-hidden />
                      </span>
                      <span className="min-w-0 flex-1">
                        <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
                          <span className="text-[13px] font-medium text-fg">{m.label}</span>
                          <SeverityBadge severity={e.severity} />
                          {e.count > 1 && <span className="text-[12px] tabular text-fg-subtle">×{e.count}</span>}
                        </span>
                        <span className="mt-0.5 block truncate text-[12.5px] text-fg-muted">{e.detail}</span>
                        <span className="mt-0.5 block truncate text-[12px] text-fg-subtle">
                          {e.server_hostname || e.server_ip}
                          {e.host ? ` → ${e.host}` : ''}
                        </span>
                      </span>
                      <RelativeTime value={e.timestamp} className="shrink-0 text-[12px] text-fg-subtle" />
                    </Link>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>

        <Card className="xl:col-span-2">
          <CardHeader title="Protection layers" description="Current policy; select a layer to change it." divider />
          {p ? (
            <ul>
              {layers(p).map((l) => (
                <LayerRow key={l.title} {...l} />
              ))}
            </ul>
          ) : (
            <EmptyState size="sm" title="No protection policy" description="The control plane did not return a threat protection policy." />
          )}
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <Card>
          <CardHeader
            title="Threat intelligence"
            description={
              ti?.compiled_at ? (
                <>
                  Snapshot <span className="font-mono">{(ti.version || '').slice(0, 12) || '—'}</span> compiled <RelativeTime value={ti.compiled_at} />
                </>
              ) : (
                'Compiled from enabled feeds, custom indicators and exceptions.'
              )
            }
            divider
            actions={
              d.canManage && (
                <Button
                  size="sm"
                  icon={RefreshCw}
                  loading={pending === 'refresh-all'}
                  onClick={async () => {
                    const r = await run(() => api.security.refreshFeeds(), { key: 'refresh-all', success: 'Refresh scheduled for all enabled feeds' });
                    if (r) later();
                  }}
                >
                  Refresh feeds
                </Button>
              )
            }
          />
          <div className="space-y-4 p-[var(--card-p)]">
            {d.tiEntries === 0 && (
              <Callout tone="warning" title="No threat-intel entries loaded">
                {enabledFeeds.length > 0
                  ? `${pluralize(enabledFeeds.length, 'feed')} enabled, but no download has succeeded yet. Check the feed status or refresh the feeds.`
                  : 'Enable at least one feed or add custom indicators.'}
              </Callout>
            )}
            {failingFeeds.length > 0 && (
              <Callout tone="danger" title={`${pluralize(failingFeeds.length, 'feed')} failed to download`} action={<Link to="/threats/feeds" className="text-[12.5px] font-medium text-accent hover:underline">Review</Link>}>
                {failingFeeds.map((f) => f.name).join(', ')}
              </Callout>
            )}
            <dl className="space-y-2.5">
              {breakdown.map((b) => (
                <div key={b.label} className="grid grid-cols-[88px_1fr_auto] items-center gap-3">
                  <dt className="text-[12.5px] text-fg-muted">{b.label}</dt>
                  <div className="h-2 overflow-hidden rounded-full bg-surface-3" aria-hidden>
                    <div className="h-full rounded-full bg-accent" style={{ width: `${b.value > 0 ? Math.max(2, (b.value / maxBreak) * 100) : 0}%` }} />
                  </div>
                  <dd className="text-right text-[12.5px] font-medium tabular text-fg">{formatNumber(b.value)}</dd>
                </div>
              ))}
            </dl>
            <div className="flex flex-wrap gap-x-5 gap-y-1 border-t border-border pt-3 text-[12.5px] text-fg-muted">
              <Link to="/threats/feeds" className="hover:text-fg hover:underline">
                {enabledFeeds.length} of {pluralize(d.feeds.length, 'feed')} enabled
              </Link>
              <Link to="/threats/iocs" className="hover:text-fg hover:underline">
                {pluralize(d.indicators.length, 'custom indicator')}
              </Link>
              <Link to="/threats/exceptions" className="hover:text-fg hover:underline">
                {pluralize(d.exceptions.length, 'exception')}
              </Link>
            </div>
          </div>
        </Card>

        <Card>
          <CardHeader
            title="Data-plane workers"
            description="Health, ClamAV and threat-intel snapshot per worker."
            divider
            actions={
              <Link to="/settings/data-planes" className="text-[12.5px] font-medium text-accent hover:underline">
                Details
              </Link>
            }
          />
          {d.planes.length === 0 ? (
            <EmptyState size="sm" icon={Cpu} title="No worker has synced yet" description="Workers appear after their first policy bundle download with the data-plane key." />
          ) : (
            <ul>
              {d.planes.map((w) => {
                const behind = !!ti?.version && !!w.threat_intel_version && w.threat_intel_version !== ti.version;
                return (
                  <li key={w.id} className="flex items-center gap-3 border-t border-border px-[var(--card-p)] py-2.5 first:border-t-0">
                    <span className={cn('h-2 w-2 shrink-0 rounded-full', w.healthy ? 'bg-success-solid' : 'bg-danger-solid')} aria-hidden />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-mono text-[12.5px] text-fg">{w.id}</span>
                      <span className="block truncate text-[12px] text-fg-subtle">
                        {w.version || 'unknown version'} · {w.remote_ip} · seen <RelativeTime value={w.last_seen_at} />
                      </span>
                    </span>
                    <span className="flex shrink-0 flex-wrap justify-end gap-1">
                      <Badge tone={w.healthy ? 'success' : 'danger'}>{w.healthy ? 'Healthy' : 'Stale'}</Badge>
                      <Tooltip content={w.clamav_available === 'yes' ? 'clamd reachable' : w.clamav_available === 'no' ? 'clamd not reachable' : 'Not reported'}>
                        <Badge tone={w.clamav_available === 'yes' ? 'success' : w.clamav_available === 'no' ? 'danger' : 'neutral'}>
                          ClamAV {w.clamav_available === 'yes' ? 'ok' : w.clamav_available === 'no' ? 'down' : '?'}
                        </Badge>
                      </Tooltip>
                      {behind && <Badge tone="warning">Intel behind</Badge>}
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
          {d.planes.length > 0 && (
            <div className="border-t border-border px-[var(--card-p)] py-2.5 text-[12.5px] text-fg-muted">
              {healthy} of {pluralize(d.planes.length, 'worker')} healthy · {MODE_META[p?.threat_intel_mode || 'off']?.label ?? '—'} mode for threat intel
            </div>
          )}
        </Card>
      </div>
    </div>
  );
};
