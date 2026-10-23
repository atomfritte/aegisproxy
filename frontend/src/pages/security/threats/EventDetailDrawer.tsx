import React from 'react';
import type { LucideIcon } from 'lucide-react';
import { Activity, ArrowRight, Ban, CheckCheck, FileCheck2, Lock, RefreshCw, ScanSearch, SearchX } from 'lucide-react';
import { useConsole, useFlows, usePermissions } from '../../../data/AppData';
import { useLookups } from '../../../data/lookups';
import { formatBytes, formatDateTime } from '../../../lib/format';
import { Link } from '../../../lib/router';
import type { SecurityEvent } from '../../../types';
import { Badge, Button, Callout, DescriptionList, Drawer, EmptyState, RelativeTime } from '../../../ui';
import { GroupChip, ServerChip, UserName } from '../../../components/common/EntityChips';
import { VerdictBadge } from '../../../components/traffic/VerdictBadge';
import { ActionBadge, AckState, MonoValue, SectionTitle, SeverityBadge } from './components';
import { eventTypeMeta, guessIndicatorType } from './meta';
import { useThreatData } from './useThreatData';

const NextStep: React.FC<{ icon: LucideIcon; title: React.ReactNode; description: React.ReactNode; to: string }> = ({ icon: Icon, title, description, to }) => (
  <li className="border-t border-border first:border-t-0">
    <Link to={to} className="group flex items-start gap-3 px-3.5 py-2.5 hover:bg-surface-2">
      <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-surface-3 text-fg-muted group-hover:text-accent">
        <Icon className="h-4 w-4" aria-hidden />
      </span>
      <span className="min-w-0 flex-1">
        <span className="block text-[13px] font-medium text-fg">{title}</span>
        <span className="block text-[12px] leading-5 text-fg-muted">{description}</span>
      </span>
      <ArrowRight className="mt-1.5 h-3.5 w-3.5 shrink-0 text-fg-subtle opacity-0 transition-opacity group-hover:opacity-100" aria-hidden />
    </Link>
  </li>
);

function qs(params: Record<string, string | undefined>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v) p.set(k, v);
  return p.toString();
}

/** Detail drawer for /threats/events/:id (also opened from the events table). */
export const EventDetailDrawer: React.FC<{
  open: boolean;
  eventId?: string;
  event?: SecurityEvent;
  acking: boolean;
  onAck: (e: SecurityEvent) => void;
  onClose: () => void;
}> = ({ open, eventId, event: e, acking, onAck, onClose }) => {
  const d = useThreatData();
  const perms = usePermissions();
  const { refresh } = useConsole();
  const { flows } = useFlows();
  const { serverById } = useLookups();

  if (!open) return null;

  if (!e) {
    return (
      <Drawer open onClose={onClose} title="Security event" width="md">
        <EmptyState
          icon={SearchX}
          title="Event not found"
          description={
            <>
              No security event with the ID <span className="font-mono text-[12.5px]">{eventId}</span> exists. It may be older than the retained event history, or it has not reached
              this console yet.
            </>
          }
          action={
            <Button icon={RefreshCw} onClick={() => refresh()}>
              Reload events
            </Button>
          }
        />
      </Drawer>
    );
  }

  const m = eventTypeMeta(e.type);
  const Icon = m.icon;
  const flow = e.flow_id ? flows.find((f) => f.id === e.flow_id) : undefined;
  const registered = e.server_id && serverById.has(e.server_id);
  const indicator = e.indicator || '';
  const lookupValue = indicator || e.url || e.host || '';
  const canException = perms.canManageSystem && (e.type === 'THREAT_INTEL' || e.type === 'MALWARE' || e.type === 'AV_SUPPRESSED') && !!indicator;
  const exType = indicator ? guessIndicatorType(indicator) : 'domain';
  const blockTarget = e.host && !(e.type === 'THREAT_INTEL' && e.action === 'blocked') ? e.host : '';
  const reason = `Security event ${e.id}: ${m.label.toLowerCase()} on ${e.server_hostname || e.server_ip}`;

  return (
    <Drawer
      open
      onClose={onClose}
      width="lg"
      title={m.label}
      titleAside={
        <span className="flex flex-wrap items-center gap-1.5">
          <SeverityBadge severity={e.severity} />
          <ActionBadge action={e.action} />
        </span>
      }
      description={
        <>
          <RelativeTime value={e.timestamp} /> · {formatDateTime(e.timestamp)}
          {e.count > 1 ? ` · seen ${e.count} times` : ''}
        </>
      }
      footer={
        <>
          <Button onClick={onClose}>Close</Button>
          {d.canAck(e) && (
            <Button variant="primary" icon={CheckCheck} loading={acking} onClick={() => onAck(e)}>
              Acknowledge
            </Button>
          )}
        </>
      }
    >
      <div className="space-y-6">
        <div className="flex items-start gap-3 rounded-lg border border-border bg-surface-2 p-3.5">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-danger-soft text-danger">
            <Icon className="h-[18px] w-[18px]" aria-hidden />
          </span>
          <div className="min-w-0">
            <p className="break-words text-[13.5px] font-medium leading-6 text-fg">{e.detail || m.label}</p>
            {m.description && <p className="mt-0.5 text-[12.5px] leading-5 text-fg-muted">{m.description}</p>}
          </div>
        </div>

        {e.acknowledged ? (
          <Callout tone="success" title="Acknowledged">
            By <UserName username={e.acknowledged_by} avatar={false} /> <RelativeTime value={e.acknowledged_at} />.
          </Callout>
        ) : !d.canAck(e) && !perms.isReadOnly && perms.isTeamLead ? (
          <Callout tone="neutral">This event belongs to server groups outside your approval scope. InfoSec can acknowledge it.</Callout>
        ) : null}

        <section>
          <SectionTitle>Details</SectionTitle>
          <DescriptionList
            items={[
              {
                label: 'Server',
                value: (
                  <span className="flex flex-wrap items-center gap-1.5">
                    {registered ? <ServerChip id={e.server_id} /> : <span>{e.server_hostname || 'Unregistered source'}</span>}
                    <span className="font-mono text-[12px] text-fg-subtle">{e.server_ip}</span>
                  </span>
                ),
              },
              {
                label: 'Server groups',
                value:
                  (e.group_ids ?? []).length > 0 ? (
                    <span className="flex flex-wrap gap-1">
                      {(e.group_ids ?? []).map((g) => (
                        <GroupChip key={g} id={g} />
                      ))}
                    </span>
                  ) : (
                    <span className="text-fg-subtle">None</span>
                  ),
              },
              {
                label: 'Destination',
                full: true,
                hidden: !e.url && !e.host,
                value: (
                  <span className="flex min-w-0 items-start gap-2">
                    {e.method && <Badge tone="neutral" className="mt-px font-mono">{e.method}</Badge>}
                    <MonoValue value={e.url || e.host || ''} />
                  </span>
                ),
              },
              { label: 'Verdict', hidden: !e.verdict, value: e.verdict ? <VerdictBadge verdict={e.verdict} /> : null },
              { label: 'Status', value: <AckState event={e} /> },
              { label: 'Source', hidden: !e.source, value: e.source },
              { label: 'Indicator', hidden: !indicator, full: true, value: <MonoValue value={indicator} tone="danger" /> },
              { label: 'Event ID', value: <MonoValue value={e.id} /> },
              { label: 'Occurrences', value: <span className="tabular">{e.count || 1} <span className="text-fg-subtle">(identical events within 15 minutes are counted)</span></span> },
            ]}
          />
        </section>

        {e.flow_id && (
          <section>
            <SectionTitle
              aside={
                <Link to={`/traffic?flow=${encodeURIComponent(e.flow_id)}`} className="text-[12.5px] font-medium text-accent hover:underline">
                  Open in live traffic
                </Link>
              }
            >
              Recorded flow
            </SectionTitle>
            {flow ? (
              <div className="rounded-lg border border-border p-3.5">
                <DescriptionList
                  columns={3}
                  items={[
                    { label: 'Response', value: <span className="tabular">{flow.status_code || '—'}</span> },
                    { label: 'Latency', value: <span className="tabular">{flow.latency_ms ?? 0} ms</span> },
                    { label: 'TLS', value: flow.tls_intercepted ? 'Inspected' : 'Not inspected' },
                    { label: 'Sent', value: formatBytes(flow.bytes_sent) },
                    { label: 'Received', value: formatBytes(flow.bytes_received) },
                    { label: 'Matched rule', value: flow.matched_rule_name || <span className="text-fg-subtle">None</span> },
                    { label: 'User agent', full: true, hidden: !flow.user_agent, value: <span className="break-all font-mono text-[12px]">{flow.user_agent}</span> },
                    { label: 'File', hidden: !flow.file_type && !flow.content_sha256, full: true, value: <MonoValue value={[flow.file_type, flow.content_sha256].filter(Boolean).join(' · ')} /> },
                  ]}
                />
              </div>
            ) : (
              <p className="text-[12.5px] text-fg-muted">
                Flow <span className="font-mono">{e.flow_id}</span> is no longer in the live window of this console.
              </p>
            )}
          </section>
        )}

        <section>
          <SectionTitle>Next steps</SectionTitle>
          <ul className="overflow-hidden rounded-lg border border-border">
            {lookupValue && (
              <NextStep
                icon={ScanSearch}
                title="Look up in all threat sources"
                description={<span className="break-all">Check {lookupValue} against every feed, indicator and exception.</span>}
                to={`/threats/lookup?${qs({ value: lookupValue })}`}
              />
            )}
            {canException && (
              <NextStep
                icon={FileCheck2}
                title="Report a false positive"
                description="Add an exception so this indicator no longer matches. The event history is kept."
                to={`/threats/exceptions?${qs({ new: '1', kind: exType === 'cidr' ? 'ip' : exType, value: indicator, reason: `False positive (${reason})` })}`}
              />
            )}
            {perms.canManageSystem && blockTarget && (
              <NextStep
                icon={Ban}
                title={`Block ${blockTarget} everywhere`}
                description="Add a custom indicator so every server is denied this destination."
                to={`/threats/iocs?${qs({ new: '1', kind: guessIndicatorType(blockTarget) === 'ip' ? 'ip' : 'domain', value: blockTarget, reason })}`}
              />
            )}
            {registered && (
              <NextStep
                icon={Lock}
                title="Investigate or quarantine the server"
                description="Open the server to review its policy, traffic and quarantine it if it is compromised."
                to={`/servers/${encodeURIComponent(e.server_id)}`}
              />
            )}
            <NextStep icon={Activity} title="See all events of this server" description="Filter the event list by this server." to={`/threats/events?q=${encodeURIComponent(e.server_hostname || e.server_ip)}`} />
          </ul>
        </section>
      </div>
    </Drawer>
  );
};
