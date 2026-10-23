import React from 'react';
import { Activity, Bug, FileCode2, GitCommitHorizontal, Network, ServerCog, ShieldCheck } from 'lucide-react';
import { useConsoleState } from '../../../data/AppData';
import { useSession } from '../../../data/session';
import { toTime } from '../../../lib/format';
import { useNow } from '../../../lib/hooks';
import type { DataPlaneStatus } from '../../../types';
import { Badge, Card, CodeBlock, Column, DataTable, EmptyState, RelativeTime, StatTile, StatusChip, Tooltip } from '../../../ui';
import { MonoValue, SectionTitle } from './shared';
import { icapState, yaraState } from '../../security/threats/yara';

/** Bundle revision reported by the worker ("42" or an ETag like "rev-42-…") → 42. */
function bundleRevision(b: string): number | null {
  const m = /^"?(?:rev-)?(\d+)/.exec(b || '');
  return m ? Number(m[1]) : null;
}

/** YARA engine state from the heartbeat (ok | idle | unavailable | error:<msg>). */
export const YaraStatus: React.FC<{ v?: string }> = ({ v }) => {
  const st = yaraState(v);
  return (
    <Tooltip content={st.error ? `${st.description} ${st.error}` : st.description}>
      <StatusChip tone={st.tone} label={st.label} />
    </Tooltip>
  );
};

/** ICAP connectivity from the heartbeat ("disabled" | "respmod=ok,reqmod=down"). */
export const IcapStatus: React.FC<{ v?: string }> = ({ v }) => {
  const st = icapState(v);
  return (
    <Tooltip content={st.parts.length ? st.parts.map((p) => `${p.kind.toUpperCase()}: ${p.state}`).join(' · ') : v === 'disabled' ? 'No ICAP service configured' : 'Not reported by this worker'}>
      <StatusChip tone={st.tone} label={st.label} />
    </Tooltip>
  );
};

const ClamAV: React.FC<{ v: string }> = ({ v }) =>
  v === 'yes' ? <StatusChip tone="success" label="Available" /> : v === 'no' ? <StatusChip tone="warning" label="Not available" /> : <StatusChip tone="neutral" label="Unknown" />;

/** Data-plane workers (mitmproxy): heartbeat, versions, policy and threat-intel freshness. */
export const DataPlanesSection: React.FC = () => {
  const state = useConsoleState();
  const { meta } = useSession();
  const now = useNow();
  const workers = state.data_planes ?? [];
  const rev = state.revision ?? 0;
  const tiVersion = state.security?.threat_intel?.version || '';
  const healthy = workers.filter((w) => w.healthy).length;
  const current = workers.filter((w) => bundleRevision(w.bundle_revision) === rev).length;
  const av = workers.filter((w) => w.clamav_available === 'yes').length;
  const avNeeded = !!state.security?.policy?.av_enabled;
  const yaraOk = workers.filter((w) => yaraState(w.yara_status).key === 'ok').length;
  const yaraErr = workers.filter((w) => ['error', 'partial'].includes(yaraState(w.yara_status).key)).length;
  const yaraMode = state.security?.policy?.yara_mode || 'off';
  const icapConfigured = !!(state.security?.policy?.icap_respmod_url || state.security?.policy?.icap_reqmod_url);
  const icapOk = workers.filter((w) => icapState(w.icap_status).tone === 'success').length;
  const icapDown = workers.filter((w) => icapState(w.icap_status).tone === 'danger').length;

  const policyState = (w: DataPlaneStatus) => {
    const r = bundleRevision(w.bundle_revision);
    if (r === null) return <span className="text-fg-subtle">—</span>;
    const behind = rev - r;
    return (
      <span className="inline-flex items-center gap-1.5">
        <MonoValue>r{r}</MonoValue>
        {behind <= 0 ? <Badge tone="success">Current</Badge> : <Badge tone="warning">{behind} behind</Badge>}
      </span>
    );
  };

  const columns: Column<DataPlaneStatus>[] = [
    {
      id: 'id',
      header: 'Worker',
      width: '24%',
      sortValue: (w) => w.id,
      cell: (w) => (
        <div className="min-w-0">
          <div className="truncate font-mono text-[12.5px] font-medium text-fg" title={w.id}>
            {w.id}
          </div>
          <div className="truncate text-[12px] text-fg-subtle">
            {w.remote_ip || '—'}
            {w.version ? ` · v${w.version}` : ''}
          </div>
        </div>
      ),
    },
    {
      id: 'health',
      header: 'Health',
      width: 110,
      sortValue: (w) => (w.healthy ? 1 : 0),
      cell: (w) => (w.healthy ? <StatusChip tone="success" label="Healthy" pulse /> : <StatusChip tone="danger" label="No heartbeat" />),
    },
    {
      id: 'seen',
      header: 'Last seen',
      width: 100,
      sortValue: (w) => w.last_seen_at,
      cell: (w) => <RelativeTime value={w.last_seen_at} className={(now - (toTime(w.last_seen_at) ?? 0)) > 60_000 ? 'text-danger' : 'text-fg-muted'} />,
    },
    {
      id: 'policy',
      header: 'Policy · threat intel',
      width: 170,
      sortValue: (w) => bundleRevision(w.bundle_revision) ?? -1,
      cell: (w) => (
        <div className="space-y-1">
          {policyState(w)}
          <div className="flex items-center gap-1.5 text-[12px] text-fg-subtle">
            {w.threat_intel_version ? (
              <>
                <Tooltip content={`Threat intel ${w.threat_intel_version}`}>
                  <MonoValue className="max-w-[80px] truncate text-[11.5px]">{w.threat_intel_version}</MonoValue>
                </Tooltip>
                {tiVersion && (w.threat_intel_version === tiVersion ? <Badge tone="success">Current</Badge> : <Badge tone="warning">Outdated</Badge>)}
              </>
            ) : (
              'Threat intel —'
            )}
          </div>
        </div>
      ),
    },
    { id: 'clamav', header: 'ClamAV', width: 120, sortValue: (w) => w.clamav_available, cell: (w) => <ClamAV v={w.clamav_available} /> },
    { id: 'yara', header: 'YARA', width: 130, sortValue: (w) => yaraState(w.yara_status).key, cell: (w) => <YaraStatus v={w.yara_status} /> },
    { id: 'icap', header: 'ICAP', width: 120, sortValue: (w) => icapState(w.icap_status).label, cell: (w) => <IcapStatus v={w.icap_status} /> },
  ];

  const base = (meta?.public_url || window.location.origin).replace(/\/+$/, '');

  return (
    <>
      <SectionTitle
        title="Data-plane workers"
        description="mitmproxy workers that enforce the policy. Each worker reports a heartbeat — versions, ClamAV, YARA compile state and ICAP connectivity — when it fetches the policy bundle; workers without a heartbeat for 60 seconds are shown as unhealthy. Status is that of the control-plane replica answering this request."
      />
      {workers.length > 0 && (
        <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-3">
          <StatTile label="Healthy workers" value={`${healthy} / ${workers.length}`} icon={Activity} tone={healthy === workers.length ? 'success' : 'danger'} attention={healthy < workers.length} />
          <StatTile label="On the current policy" value={`${current} / ${workers.length}`} icon={GitCommitHorizontal} tone={current === workers.length ? 'success' : 'warning'} hint={`Revision ${rev}`} />
          <StatTile label="Threat intel" value={tiVersion ? tiVersion.slice(0, 10) : '—'} icon={ShieldCheck} hint="Version compiled by the control plane" />
          <StatTile
            label="ClamAV available"
            value={`${av} / ${workers.length}`}
            icon={Bug}
            tone={avNeeded && av < workers.length ? 'warning' : 'neutral'}
            hint={avNeeded ? 'Antivirus scanning is enabled' : 'Antivirus scanning is off'}
          />
          <StatTile
            label="YARA compiled"
            value={`${yaraOk} / ${workers.length}`}
            icon={FileCode2}
            tone={yaraErr ? 'warning' : yaraMode !== 'off' && yaraOk < workers.length ? 'warning' : 'neutral'}
            attention={yaraErr > 0}
            hint={yaraErr ? `${yaraErr} with compile errors` : `YARA mode: ${yaraMode}`}
            to="/threats/yara"
          />
          <StatTile
            label="ICAP engines reachable"
            value={icapConfigured ? `${icapOk} / ${workers.length}` : 'Off'}
            icon={Network}
            tone={icapDown ? 'danger' : 'neutral'}
            attention={icapDown > 0}
            hint={icapConfigured ? (icapDown ? `Unreachable from ${icapDown}` : 'RESPMOD / REQMOD services') : 'No ICAP service configured'}
            to="/threats/policy#icap"
          />
        </div>
      )}
      <DataTable
        rows={workers}
        columns={columns}
        getRowId={(w) => w.id}
        initialSort={{ id: 'health', dir: 'asc' }}
        mobileCard={(w) => (
          <div className="min-w-0 space-y-2">
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <div className="truncate font-mono text-[12.5px] font-medium text-fg">{w.id}</div>
                <div className="text-[12px] text-fg-subtle">
                  {w.remote_ip} · v{w.version || '?'} · <RelativeTime value={w.last_seen_at} />
                </div>
              </div>
              {w.healthy ? <StatusChip tone="success" label="Healthy" /> : <StatusChip tone="danger" label="No heartbeat" />}
            </div>
            <div className="flex flex-wrap items-center gap-2 text-[12px]">
              {policyState(w)}
              <ClamAV v={w.clamav_available} />
              <span className="inline-flex items-center gap-1 text-fg-subtle">
                YARA <YaraStatus v={w.yara_status} />
              </span>
              <span className="inline-flex items-center gap-1 text-fg-subtle">
                ICAP <IcapStatus v={w.icap_status} />
              </span>
            </div>
          </div>
        )}
        empty={
          <EmptyState
            icon={ServerCog}
            title="No data-plane worker has connected yet"
            description="Workers appear here after their first policy bundle download. Start a worker with the control-plane URL and the shared data-plane key:"
            action={
              <CodeBlock
                className="w-full max-w-xl text-left"
                title="Worker environment"
                wrap
                code={`CONTROL_PLANE_URL=${base}\nAEGIS_DATAPLANE_KEY=<same value as on the control plane>\nAEGIS_WORKER_ID=$(hostname)   # optional, defaults to the hostname`}
              />
            }
          />
        }
      />
    </>
  );
};
