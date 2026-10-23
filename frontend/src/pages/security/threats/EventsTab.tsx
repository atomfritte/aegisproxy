import React, { useMemo, useState } from 'react';
import { CheckCheck, ShieldCheck } from 'lucide-react';
import { api } from '../../../api';
import { useConsole } from '../../../data/AppData';
import { useLookups } from '../../../data/lookups';
import { Link, navigate, useLocation } from '../../../lib/router';
import { useUrlFilters } from '../../../lib/useUrlFilters';
import type { SecurityEvent } from '../../../types';
import { Button, Column, DataTable, EmptyState, FacetDef, useToast } from '../../../ui';
import { ActionBadge, ActionLabel, AckState, EventTypeCell, SeverityBadge, TimeCell } from './components';
import { EventDetailDrawer } from './EventDetailDrawer';
import { eventPath, eventSearchText, eventTypeMeta, SEVERITIES, SEVERITY_META, SEVERITY_RANK } from './meta';
import { useThreatData } from './useThreatData';
import { TeamLeadScopeNotice } from '../../../components/common/ScopeNotice';

const FILTERS = ['severity', 'type', 'action', 'status', 'group'];

/** /threats/events and /threats/events/:id (detail drawer, deep link from notifications). */
export const EventsTab: React.FC<{ eventId?: string }> = ({ eventId }) => {
  const d = useThreatData();
  const { refresh } = useConsole();
  const { groupName } = useLookups();
  const toast = useToast();
  const { search } = useLocation();
  const f = useUrlFilters(FILTERS);
  const [acking, setAcking] = useState<string | null>(null);

  const ack = async (e: SecurityEvent) => {
    setAcking(e.id);
    try {
      await api.security.ackEvent(e.id);
      toast.success('Event acknowledged', { description: `${eventTypeMeta(e.type).label} on ${e.server_hostname || e.server_ip}` });
      await refresh();
    } catch (err) {
      toast.error(err, { title: 'Could not acknowledge the event' });
    } finally {
      setAcking(null);
    }
  };

  const ackMany = async (rows: SecurityEvent[], clear: () => void) => {
    setAcking('bulk');
    const results = await Promise.allSettled(rows.map((r) => api.security.ackEvent(r.id)));
    const failed = results.filter((r) => r.status === 'rejected') as PromiseRejectedResult[];
    const ok = results.length - failed.length;
    if (ok > 0) toast.success(`Acknowledged ${ok} ${ok === 1 ? 'event' : 'events'}`);
    if (failed.length > 0) toast.error(failed[0].reason, { title: `${failed.length} could not be acknowledged` });
    clear();
    await refresh();
    setAcking(null);
  };

  const facets: FacetDef<SecurityEvent>[] = useMemo(
    () => [
      { id: 'severity', label: 'Severity', getValue: (e) => e.severity, options: SEVERITIES.map((s) => ({ value: s, label: SEVERITY_META[s].label })) },
      { id: 'type', label: 'Type', getValue: (e) => e.type, optionLabel: (v) => eventTypeMeta(v).label },
      {
        id: 'action',
        label: 'Action',
        getValue: (e) => e.action,
        options: [
          { value: 'blocked', label: 'Blocked' },
          { value: 'detected', label: 'Detected only' },
        ],
      },
      {
        id: 'status',
        label: 'Status',
        getValue: (e) => (e.acknowledged ? 'acknowledged' : 'open'),
        options: [
          { value: 'open', label: 'Open' },
          { value: 'acknowledged', label: 'Acknowledged' },
        ],
      },
      { id: 'group', label: 'Server group', getValue: (e) => e.group_ids ?? [], optionLabel: groupName },
    ],
    [groupName]
  );

  const open = (e: SecurityEvent) => navigate(eventPath(e.id) + search, { preserveScroll: true });

  const columns: Column<SecurityEvent>[] = [
    { id: 'time', header: 'Time', width: 120, sortValue: (e) => e.timestamp, cell: (e) => <TimeCell value={e.timestamp} /> },
    {
      id: 'severity',
      header: 'Severity',
      width: 112,
      sortValue: (e) => SEVERITY_RANK[e.severity] ?? 9,
      cell: (e) => (
        <div className="flex flex-col items-start gap-1">
          <SeverityBadge severity={e.severity} />
          <ActionLabel action={e.action} />
        </div>
      ),
    },
    {
      id: 'event',
      header: 'Event',
      width: '34%',
      sortValue: (e) => eventTypeMeta(e.type).label,
      cell: (e) => (
        <Link to={eventPath(e.id) + search} preserveScroll className="group/ev block min-w-0 rounded">
          <EventTypeCell event={e} />
        </Link>
      ),
    },
    {
      id: 'server',
      header: 'Server',
      sortValue: (e) => e.server_hostname || e.server_ip,
      cell: (e) => (
        <div className="min-w-0 leading-tight">
          <div className="max-w-[190px] truncate text-[13px] text-fg" title={e.server_hostname}>
            {e.server_hostname || '—'}
          </div>
          <div className="font-mono text-[11.5px] text-fg-subtle">{e.server_ip}</div>
        </div>
      ),
    },
    {
      id: 'destination',
      header: 'Destination',
      hideBelow: 'xl',
      sortValue: (e) => e.host,
      cell: (e) => (
        <div className="min-w-0 max-w-[220px] leading-tight">
          <div className="truncate font-mono text-[12.5px] text-fg" title={e.url || e.host}>
            {e.method && <span className="mr-1 text-[11px] font-semibold text-fg-subtle">{e.method}</span>}
            {e.host || '—'}
          </div>
          {e.source && (
            <div className="truncate text-[11.5px] text-fg-subtle" title={[e.source, e.indicator].filter(Boolean).join(' · ')}>
              {e.source}
            </div>
          )}
        </div>
      ),
    },
    {
      id: 'status',
      header: 'Status',
      width: 148,
      align: 'right',
      sortValue: (e) => (e.acknowledged ? 1 : 0),
      cell: (e) =>
        d.canAck(e) ? (
          <Button size="sm" icon={CheckCheck} loading={acking === e.id} disabled={!!acking && acking !== e.id} onClick={() => ack(e)}>
            Acknowledge
          </Button>
        ) : (
          <AckState event={e} />
        ),
    },
  ];

  const selected = eventId ? d.events.find((e) => e.id === eventId) : undefined;

  return (
    <>
      <TeamLeadScopeNotice what="the security events" className="mb-4" />
      <DataTable
        aria-label="Security events"
        rows={d.events}
        columns={columns}
        getRowId={(e) => e.id}
        getSearchText={eventSearchText}
        searchPlaceholder="Search server, host, indicator…"
        search={f.search}
        onSearchChange={f.setSearch}
        facets={facets}
        facetValues={f.values}
        onFacetChange={f.onChange}
        onRowClick={open}
        rowClassName={(e) => (e.acknowledged ? 'opacity-75' : undefined)}
        selectable={(e) => d.canAck(e)}
        bulkActions={(rows, clear) => (
          <Button size="sm" variant="primary" icon={CheckCheck} loading={acking === 'bulk'} onClick={() => ackMany(rows, clear)}>
            Acknowledge {rows.length}
          </Button>
        )}
        pageSize={50}
        mobileCard={(e) => (
          <div className="min-w-0 space-y-2">
            <div className="flex items-start justify-between gap-2">
              <EventTypeCell event={e} />
              <SeverityBadge severity={e.severity} className="shrink-0" />
            </div>
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[12px] text-fg-muted">
              <span className="truncate">{e.server_hostname || e.server_ip}</span>
              {e.host && <span className="truncate font-mono text-fg-subtle">→ {e.host}</span>}
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <ActionBadge action={e.action} />
              {d.canAck(e) ? (
                <Button size="sm" icon={CheckCheck} loading={acking === e.id} onClick={() => ack(e)}>
                  Acknowledge
                </Button>
              ) : (
                <AckState event={e} />
              )}
            </div>
          </div>
        )}
        empty={
          <EmptyState
            icon={ShieldCheck}
            title="No security events yet"
            description="Threat-intel hits, malware, DLP findings, blocked file types and protocol violations reported by the data plane appear here."
          />
        }
      />
      <EventDetailDrawer
        open={!!eventId}
        eventId={eventId}
        event={selected}
        acking={acking === selected?.id}
        onAck={ack}
        onClose={() => navigate('/threats/events' + search, { preserveScroll: true })}
      />
    </>
  );
};
