import React, { useCallback, useMemo, useRef, useState } from 'react';
import { Activity, FlaskConical, Lock, Pause, Play } from 'lucide-react';
import { useConsoleState, useFlows } from '../../data/AppData';
import { useLookups } from '../../data/lookups';
import { cn } from '../../lib/cn';
import { formatBytes, formatDateTime, formatNumber } from '../../lib/format';
import { useDocumentTitle, useHotkey } from '../../lib/hooks';
import { Link, useQueryParam } from '../../lib/router';
import { useUrlFilters } from '../../lib/useUrlFilters';
import type { TrafficFlow } from '../../types';
import { Button, Callout, Column, DataTable, EmptyState, Kbd, MethodList, PageHeader, PatternText, StatusChip, Tooltip } from '../../ui';
import { VerdictBadge } from '../../components/traffic/VerdictBadge';
import { FlowDetailDrawer } from './live/FlowDetailDrawer';
import { SimulatorDrawer, SimulatorInput } from './live/SimulatorDrawer';
import {
  ALL_VERDICTS,
  clockTime,
  flowBytes,
  flowSignals,
  reasonLabel,
  SIGNAL_OPTIONS,
  STATUS_OPTIONS,
  statusClass,
  VERDICT_CLASSES,
  verdictClass,
  VerdictClass,
} from './live/flowUtils';
import { TeamLeadScopeNotice } from '../../components/common/ScopeNotice';

export { newSetFromFlowUrl } from './flowLinks';

const FILTERS = ['verdict', 'server', 'group', 'method', 'status', 'tls', 'signal'];
const MAX_FLOWS = 300;

const dotCls: Record<string, string> = {
  success: 'bg-success-solid',
  danger: 'bg-danger-solid',
  violet: 'bg-violet-solid',
  info: 'bg-info-solid',
  neutral: 'bg-neutral-solid',
};

/** Live flows (SSE) with URL-synced filters, pause/resume, flow details and a policy simulator. */
export const LiveTrafficPage: React.FC = () => {
  useDocumentTitle('Live traffic');
  const state = useConsoleState();
  const { flows, connected } = useFlows();
  const { groupName, serverById } = useLookups();
  const f = useUrlFilters(FILTERS);
  const [classParam, setClassParam] = useQueryParam('class');
  const [flowParam, setFlowParam] = useQueryParam('flow');

  const [paused, setPaused] = useState(false);
  const [frozen, setFrozen] = useState<TrafficFlow[]>([]);
  const [simOpen, setSimOpen] = useState(false);
  const [simInitial, setSimInitial] = useState<SimulatorInput | null>(null);
  // Flows that are not in the live buffer (dry-run simulations) are shown from here.
  const [detached, setDetached] = useState<{ flow: TrafficFlow; token?: string } | null>(null);
  const lastSelected = useRef<TrafficFlow | null>(null);
  const initialIds = useRef<Set<string> | null>(null);
  if (initialIds.current === null) initialIds.current = new Set(flows.map((x) => x.id));

  const rows = paused ? frozen : flows;
  const frozenIds = useMemo(() => new Set(frozen.map((x) => x.id)), [frozen]);
  const newWhilePaused = paused ? flows.filter((x) => !frozenIds.has(x.id)).length : 0;

  const togglePause = useCallback(() => {
    if (!paused) setFrozen(flows);
    setPaused(!paused);
  }, [paused, flows]);

  const classes = (classParam ? classParam.split(',') : []) as VerdictClass[];
  const setClasses = (next: VerdictClass[]) => setClassParam(next.length ? next.join(',') : null);
  const classCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const x of rows) {
      const k = verdictClass(x.verdict);
      c[k] = (c[k] || 0) + 1;
    }
    return c;
  }, [rows]);
  const tableRows = useMemo(() => (classes.length ? rows.filter((x) => classes.includes(verdictClass(x.verdict))) : rows), [rows, classes]);

  // selected flow: URL (?flow=id) for buffered flows, `detached` for simulations
  let selected: TrafficFlow | null = detached?.flow ?? null;
  if (!selected && flowParam) {
    selected = rows.find((x) => x.id === flowParam) ?? flows.find((x) => x.id === flowParam) ?? (lastSelected.current?.id === flowParam ? lastSelected.current : null);
  }
  if (selected) lastSelected.current = selected;
  useHotkey('p', togglePause, { enabled: !simOpen && !selected });

  const openFlow = (x: TrafficFlow) => {
    setDetached(null);
    setFlowParam(x.id);
  };
  const closeFlow = () => {
    setDetached(null);
    if (flowParam) setFlowParam(null);
  };
  const openSimulator = (input: SimulatorInput | null) => {
    setSimInitial(input);
    closeFlow();
    setSimOpen(true);
  };

  const verdictLabel = (v: string) => ALL_VERDICTS.find((x) => x.value === v)?.label ?? v;

  const serverLabel = (x: TrafficFlow) =>
    x.server_id && serverById.has(x.server_id) ? (
      <Link to={`/servers/${encodeURIComponent(x.server_id)}`} className="truncate text-fg hover:text-accent hover:underline">
        {x.server_hostname || x.server_id}
      </Link>
    ) : (
      <span className="truncate text-fg">{x.server_hostname || 'Unregistered'}</span>
    );

  const columns: Column<TrafficFlow>[] = [
    {
      id: 'time',
      header: 'Time',
      width: 84,
      sortValue: (x) => x.timestamp,
      cell: (x) => (
        <Tooltip content={formatDateTime(x.timestamp)}>
          <span className="font-mono text-[12px] tabular text-fg-muted">{clockTime(x.timestamp)}</span>
        </Tooltip>
      ),
    },
    {
      id: 'request',
      header: 'Request',
      sortValue: (x) => x.host,
      cell: (x) => {
        const why = x.matched_rule_name || reasonLabel(x);
        return (
          <div className="w-0 min-w-full">
            <div className="flex min-w-0 items-center gap-2">
              <MethodList methods={[x.method]} className="shrink-0" />
              <PatternText host={x.host} path={x.path} className="min-w-0" />
              {!x.tls_intercepted && (
                <Tooltip content="Passed through without TLS decryption">
                  <Lock className="h-3.5 w-3.5 shrink-0 text-violet" aria-label="TLS passthrough" />
                </Tooltip>
              )}
            </div>
            <p className="mt-0.5 flex min-w-0 gap-1 text-[12px] text-fg-subtle">
              <span className="shrink-0 xl:hidden">{x.server_hostname || x.server_ip}</span>
              {why && <span className="shrink-0 xl:hidden" aria-hidden>·</span>}
              {why && <span className="truncate">{why}</span>}
            </p>
          </div>
        );
      },
    },
    {
      id: 'server',
      header: 'Server',
      width: 210,
      hideBelow: 'xl',
      sortValue: (x) => x.server_hostname || x.server_ip,
      cell: (x) => (
        <div className="flex min-w-0 max-w-[190px] flex-col leading-tight">
          {serverLabel(x)}
          <span className="font-mono text-[11.5px] text-fg-subtle">{x.server_ip}</span>
        </div>
      ),
    },
    { id: 'verdict', header: 'Verdict', width: 150, sortValue: (x) => x.verdict, cell: (x) => <VerdictBadge verdict={x.verdict} /> },
    {
      id: 'response',
      header: 'Response',
      width: 108,
      align: 'right',
      sortValue: (x) => x.latency_ms,
      cell: (x) => (
        <div className="leading-tight">
          <span className={cn('tabular', x.status_code >= 400 ? 'text-danger' : 'text-fg')}>{x.status_code || '—'}</span>
          <span className="tabular text-fg-subtle"> · {formatNumber(x.latency_ms)} ms</span>
          <div className="text-[11.5px] tabular text-fg-subtle">{formatBytes(flowBytes(x))}</div>
        </div>
      ),
    },
  ];

  const visibleClasses = VERDICT_CLASSES.filter((c) => c.id !== 'simulated' || (classCounts.simulated ?? 0) > 0);

  return (
    <>
      <PageHeader
        title="Live traffic"
        description="Requests from your servers as data-plane workers report them. Filter, pause the stream, inspect a flow and turn it into a rule."
        meta={
          <>
            {paused ? (
              <StatusChip tone="warning" icon={Pause} label="Paused" />
            ) : connected ? (
              <StatusChip tone="success" label="Live" pulse />
            ) : (
              <StatusChip tone="neutral" label="Reconnecting…" pulse />
            )}
            <span className="text-[12.5px] text-fg-subtle">
              Latest {formatNumber(rows.length)} of up to {MAX_FLOWS} flows kept in this browser
            </span>
          </>
        }
        actions={
          <>
            <Tooltip
              content={
                <span className="inline-flex items-center gap-1.5">
                  {paused ? 'Resume' : 'Pause'} the stream <Kbd>P</Kbd>
                </span>
              }
            >
              <Button icon={paused ? Play : Pause} onClick={togglePause} aria-pressed={paused}>
                {paused ? 'Resume' : 'Pause'}
              </Button>
            </Tooltip>
            <Button variant="primary" icon={FlaskConical} onClick={() => openSimulator(null)}>
              Test a URL
            </Button>
          </>
        }
      />
      <TeamLeadScopeNotice what="the traffic" className="mb-4" />

      {paused && (
        <Callout
          tone="info"
          icon={Pause}
          className="mb-4"
          title={newWhilePaused > 0 ? `${formatNumber(newWhilePaused)} new ${newWhilePaused === 1 ? 'flow' : 'flows'} since you paused` : 'The list is frozen'}
          action={
            <Button size="sm" variant="primary" icon={Play} onClick={togglePause}>
              Resume
            </Button>
          }
        >
          New flows keep arriving in the background and appear when you resume.
        </Callout>
      )}

      <div className="scroll-thin -mx-1 mb-4 overflow-x-auto px-1 pb-1">
        <div className="flex min-w-max gap-2 md:grid md:min-w-0 md:grid-cols-5" role="group" aria-label="Filter by verdict">
          {visibleClasses.map((c) => {
            const count = classCounts[c.id] ?? 0;
            const active = classes.includes(c.id);
            const share = rows.length ? Math.round((count / rows.length) * 100) : 0;
            return (
              <Tooltip key={c.id} content={c.description} className="w-full">
                <button
                  type="button"
                  aria-pressed={active}
                  onClick={() => setClasses(active ? classes.filter((x) => x !== c.id) : [...classes, c.id])}
                  className={cn(
                    'flex w-[150px] min-w-0 flex-col items-start rounded-lg border bg-surface px-3 py-2.5 text-left shadow-card transition-colors md:w-full',
                    active ? 'border-accent ring-1 ring-accent' : 'border-border hover:border-border-strong hover:bg-surface-2'
                  )}
                >
                  <span className="flex w-full items-center gap-2 text-[12.5px] font-medium text-fg-muted">
                    <span className={cn('h-2 w-2 shrink-0 rounded-full', dotCls[c.tone])} aria-hidden />
                    <span className="truncate">{c.label}</span>
                  </span>
                  <span className="mt-1 flex items-baseline gap-1.5">
                    <span className="text-[20px] font-semibold leading-7 text-fg">{formatNumber(count)}</span>
                    <span className="text-[12px] text-fg-subtle">{share}%</span>
                  </span>
                </button>
              </Tooltip>
            );
          })}
        </div>
      </div>

      <DataTable
        rows={tableRows}
        columns={columns}
        getRowId={(x) => x.id}
        onRowClick={openFlow}
        rowClassName={(x) => (x.id === selected?.id ? '!bg-accent-soft/60' : initialIds.current && !initialIds.current.has(x.id) ? 'animate-fade-in' : undefined)}
        getSearchText={(x) =>
          `${x.full_url} ${x.server_hostname} ${x.server_ip} ${x.matched_rule_name || ''} ${x.block_reason || ''} ${x.threat_indicator || ''} ${x.threat_category || ''} ${x.content_sha256 || ''} ${x.proxy_auth_user || ''} ${x.id}`
        }
        searchPlaceholder="Search URL, server, rule, indicator…"
        search={f.search}
        onSearchChange={f.setSearch}
        facetValues={f.values}
        onFacetChange={f.onChange}
        facets={[
          { id: 'verdict', label: 'Verdict', getValue: (x) => x.verdict, optionLabel: verdictLabel },
          { id: 'server', label: 'Server', getValue: (x) => x.server_id || x.server_ip, optionLabel: (v) => serverById.get(v)?.hostname ?? v },
          { id: 'group', label: 'Group', getValue: (x) => x.group_ids ?? [], optionLabel: groupName },
          { id: 'method', label: 'Method', getValue: (x) => x.method },
          { id: 'status', label: 'Status', getValue: (x) => statusClass(x.status_code), options: STATUS_OPTIONS },
          {
            id: 'tls',
            label: 'TLS',
            getValue: (x) => (x.tls_intercepted ? 'inspected' : 'passthrough'),
            options: [
              { value: 'inspected', label: 'Decrypted and inspected' },
              { value: 'passthrough', label: 'Passed through' },
            ],
          },
          { id: 'signal', label: 'Signals', getValue: flowSignals, options: SIGNAL_OPTIONS },
        ]}
        pageSize={50}
        mobileCard={(x) => (
          <div className="min-w-0 space-y-1.5">
            <div className="flex items-start justify-between gap-2">
              <div className="flex min-w-0 items-center gap-1.5">
                <MethodList methods={[x.method]} className="shrink-0" />
                <PatternText host={x.host} path={x.path} className="min-w-0" />
              </div>
              <VerdictBadge verdict={x.verdict} />
            </div>
            {(x.matched_rule_name || reasonLabel(x)) && <p className="truncate text-[12px] text-fg-subtle">{x.matched_rule_name || reasonLabel(x)}</p>}
            <p className="flex flex-wrap items-center gap-x-2 text-[12px] text-fg-muted">
              <span className="truncate">{x.server_hostname || x.server_ip}</span>
              <span className="font-mono tabular text-fg-subtle">{clockTime(x.timestamp)}</span>
              <span className="tabular text-fg-subtle">
                {x.status_code || '—'} · {formatNumber(x.latency_ms)} ms
              </span>
            </p>
          </div>
        )}
        empty={
          <EmptyState
            icon={Activity}
            title={paused ? 'Nothing was captured before you paused' : 'No traffic yet'}
            description={
              paused
                ? 'Resume the stream to see new flows.'
                : 'Flows appear here within seconds of a data-plane worker reporting them. Check that your servers use the proxy, or evaluate a URL with the simulator.'
            }
            action={
              paused ? (
                <Button variant="primary" icon={Play} onClick={togglePause}>
                  Resume
                </Button>
              ) : (
                <Button variant="primary" icon={FlaskConical} onClick={() => openSimulator(null)}>
                  Test a URL
                </Button>
              )
            }
          />
        }
        aria-label="Live flows"
      />
      {classes.length > 0 && (
        <p className="mt-2 text-[12px] text-fg-subtle">
          Showing {classes.map((c) => VERDICT_CLASSES.find((x) => x.id === c)?.label.toLowerCase()).join(', ')} flows.{' '}
          <button type="button" className="font-medium text-accent hover:underline" onClick={() => setClasses([])}>
            Show all verdicts
          </button>
        </p>
      )}

      <FlowDetailDrawer
        flow={selected}
        blockToken={detached?.token}
        onClose={closeFlow}
        onSimulate={(x) => openSimulator({ serverIp: x.server_ip, method: x.method, url: x.full_url })}
      />
      <SimulatorDrawer
        open={simOpen}
        onClose={() => setSimOpen(false)}
        initial={simInitial}
        onInspect={(flow, token) => {
          setSimOpen(false);
          if (flows.some((x) => x.id === flow.id)) {
            setDetached(null);
            setFlowParam(flow.id);
          } else setDetached({ flow, token });
        }}
      />
      {state.demo_mode && rows.length > 0 && (
        <p className="mt-3 text-[12px] text-fg-subtle">Demo mode: the simulator records its evaluations in this stream, so you can follow redirect lineage end to end.</p>
      )}
    </>
  );
};
