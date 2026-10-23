import React, { useMemo, useState } from 'react';
import {
  Activity,
  Copy,
  History,
  Inbox,
  KeyRound,
  LayoutList,
  MoreHorizontal,
  Pencil,
  Server as ServerIcon,
  ShieldCheck,
  ShieldOff,
  Tag,
  Trash2,
  Waypoints,
} from 'lucide-react';
import { useConsoleState } from '../../data/AppData';
import { useLookups } from '../../data/lookups';
import { cn } from '../../lib/cn';
import { formatDateTime, humanize } from '../../lib/format';
import { useDocumentTitle } from '../../lib/hooks';
import { Link, navigate, useParams } from '../../lib/router';
import { copyText } from '../../utils';
import type { AuditEvent, Server } from '../../types';
import {
  Badge,
  Button,
  ButtonLink,
  Callout,
  Card,
  CardHeader,
  DescriptionList,
  EmptyState,
  Menu,
  PageHeader,
  RelativeTime,
  TabPanel,
  Tabs,
  Timeline,
  Tooltip,
  useToast,
} from '../../ui';
import { LabelChips, UserName } from '../../components/common/EntityChips';
import { FlowsTable } from '../../components/fleet/FlowsTable';
import { LastSeen, MembershipChip, ServerHealthChip } from '../../components/fleet/FleetChips';
import { formatLabel, labelsMatch, staticGroups, dynamicGroups } from '../../components/fleet/fleetUtils';
import { OnboardingDrawer } from '../../components/fleet/OnboardingDrawer';
import { ServerFormDrawer } from '../../components/fleet/ServerFormDrawer';
import { useServerActions, useServerPerms } from '../../components/fleet/useServerActions';
import { RequestsTable } from '../../components/requests/RequestsTable';
import { NotFoundPage } from '../system/NotFoundPage';
import { EffectivePolicyTab } from './EffectivePolicyTab';
import { DefenderDeviceCard, DefenderRiskBadge, DEFENDER_ACTOR } from '../../components/fleet/DefenderDevice';

const TABS = ['overview', 'policy', 'traffic', 'requests', 'audit'] as const;
type Tab = (typeof TABS)[number];

/** /servers/:id/:tab? — identity, memberships, effective policy, traffic, requests and audit. */
export const ServerDetailPage: React.FC = () => {
  const { id, tab: rawTab } = useParams<{ id: string; tab?: string }>();
  const state = useConsoleState();
  const server = state.servers.find((s) => s.id === id);
  useDocumentTitle(server?.hostname ?? 'Server');
  if (!server) return <NotFoundPage title="Server not found" description="It may have been decommissioned. Its history remains in the audit trail." backTo="/servers" backLabel="All servers" />;
  const tab: Tab = (TABS as readonly string[]).includes(rawTab || '') ? (rawTab as Tab) : 'overview';
  return <ServerDetail key={server.id} server={server} tab={tab} />;
};

const ServerDetail: React.FC<{ server: Server; tab: Tab }> = ({ server: s, tab }) => {
  const state = useConsoleState();
  const sp = useServerPerms();
  const actions = useServerActions();
  const toast = useToast();
  const [editOpen, setEditOpen] = useState(false);
  const [onboardOpen, setOnboardOpen] = useState(false);
  const go = (t: Tab) => navigate(`/servers/${encodeURIComponent(s.id)}${t === 'overview' ? '' : `/${t}`}`, { preserveScroll: true });

  const requests = useMemo(() => state.requests.filter((r) => r.server_id === s.id || (!!s.ip && r.server_ip === s.ip)), [state.requests, s.id, s.ip]);
  const audit = useMemo(() => state.audit_events.filter((e) => e.entity_id === s.id).sort((a, b) => b.timestamp.localeCompare(a.timestamp)), [state.audit_events, s.id]);
  const pendingReq = requests.filter((r) => r.status === 'pending').length;

  const more = [
    { id: 'copy', label: 'Copy server id', icon: Copy, onSelect: () => copyText(s.id).then((ok) => ok && toast.success('Copied server id')) },
    { id: 'traffic', label: 'View live traffic', icon: Activity, onSelect: () => go('traffic') },
    { id: 'delete', label: 'Decommission', icon: Trash2, danger: true, separator: true, onSelect: () => actions.decommission(s), hidden: !sp.canManage },
  ];

  return (
    <>
      <PageHeader
        breadcrumbs={[{ label: 'Servers', to: '/servers' }, { label: s.hostname }]}
        leading={
          <span className={cn('mt-0.5 hidden h-10 w-10 shrink-0 items-center justify-center rounded-lg sm:flex', s.quarantined ? 'bg-danger-soft text-danger' : 'bg-accent-soft text-accent')}>
            {s.quarantined ? <ShieldOff className="h-5 w-5" aria-hidden /> : <ServerIcon className="h-5 w-5" aria-hidden />}
          </span>
        }
        title={<span className="break-all">{s.hostname}</span>}
        description={s.description || undefined}
        meta={
          <>
            <span className="rounded-md border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[11.5px] text-fg-muted">{s.id}</span>
            <ServerHealthChip server={s} />
            {s.ip && <span className="font-mono text-[12px] text-fg-muted">{s.ip}</span>}
            {s.os && <span className="text-[12.5px] text-fg-muted">{s.os}</span>}
            {s.has_proxy_token ? (
              <Tooltip content={s.token_rotated_at ? `Token issued ${formatDateTime(s.token_rotated_at)}` : 'A proxy token is configured'}>
                <Badge tone="success" icon={KeyRound}>
                  Token set
                </Badge>
              </Tooltip>
            ) : (
              <Badge tone="neutral" icon={KeyRound}>
                No token
              </Badge>
            )}
            {s.defender && <DefenderRiskBadge device={s.defender} />}
          </>
        }
        actions={
          <>
            {sp.canManage && (
              <Button icon={Pencil} onClick={() => setEditOpen(true)}>
                Edit
              </Button>
            )}
            {sp.canManage && (
              <Button icon={KeyRound} onClick={() => setOnboardOpen(true)}>
                {s.has_proxy_token ? 'Rotate token' : 'Onboard'}
              </Button>
            )}
            {s.quarantined
              ? sp.canRelease && (
                  <Button variant="primary" icon={ShieldCheck} onClick={() => actions.release(s)}>
                    Release
                  </Button>
                )
              : sp.canQuarantine(s) && (
                  <Button variant="danger" icon={ShieldOff} onClick={() => actions.quarantine([s])}>
                    Quarantine
                  </Button>
                )}
            <Menu
              items={more}
              trigger={(p) => (
                <Button {...p} icon={MoreHorizontal} aria-label="More actions">
                  <span className="sr-only sm:not-sr-only">More</span>
                </Button>
              )}
            />
          </>
        }
      />

      {s.quarantined && (
        <Callout
          tone="danger"
          icon={ShieldOff}
          className="mb-6"
          title="Quarantined — all egress is blocked"
          action={
            sp.canRelease ? (
              <Button size="sm" onClick={() => actions.release(s)}>
                Release
              </Button>
            ) : undefined
          }
        >
          <span className="text-fg">{s.quarantine_reason || 'No reason recorded.'}</span>
          <span className="mt-0.5 block text-[12.5px]">
            {s.quarantined_by === DEFENDER_ACTOR ? (
              <>
                <Badge tone="info" icon={ShieldCheck} className="mr-1 align-middle">
                  Microsoft Defender
                </Badge>
                automatically{' '}
              </>
            ) : (
              s.quarantined_by && (
                <>
                  By <UserName username={s.quarantined_by} avatar={false} />{' '}
                </>
              )
            )}
            {s.quarantined_at && <RelativeTime value={s.quarantined_at} />}
            {!sp.canRelease && ' · Only InfoSec can release a quarantine.'}
          </span>
        </Callout>
      )}

      <Card className="mb-6 grid grid-cols-1 divide-y divide-border sm:grid-cols-2 sm:divide-y-0 lg:grid-cols-4 lg:divide-x">
        <Fact label="Groups">
          <span>
            {staticGroups(s).length} static, {dynamicGroups(s).length} by labels
          </span>
        </Fact>
        <Fact label="Last seen">
          <LastSeen server={s} />
        </Fact>
        <Fact label="Proxy identity">
          <span className="block truncate font-mono text-[12.5px]">{s.proxy_auth_user || <span className="font-sans text-fg-subtle">Not set</span>}</span>
          <span className="mt-0.5 block text-[12px] text-fg-subtle">
            {s.token_rotated_at ? (
              <>
                Token issued <RelativeTime value={s.token_rotated_at} />
              </>
            ) : s.has_proxy_token ? (
              'Token configured'
            ) : (
              'No token issued'
            )}
          </span>
        </Fact>
        <Fact label="Owner">
          <span className="block truncate">{s.owner_team || <span className="text-fg-subtle">No owner team</span>}</span>
          {s.department && s.department !== s.owner_team && <span className="mt-0.5 block truncate text-[12px] text-fg-subtle">{s.department}</span>}
        </Fact>
      </Card>

      <Tabs<Tab>
        idPrefix="sd"
        className="mb-6"
        value={tab}
        onChange={go}
        aria-label="Server sections"
        tabs={[
          { id: 'overview', label: 'Overview', icon: LayoutList },
          { id: 'policy', label: 'Effective policy', icon: Waypoints },
          { id: 'traffic', label: 'Traffic', icon: Activity },
          { id: 'requests', label: 'Requests', icon: Inbox, count: requests.length || undefined, countTone: pendingReq ? 'warning' : 'neutral' },
          { id: 'audit', label: 'Audit', icon: History, count: audit.length || undefined },
        ]}
      />

      <TabPanel id={tab} idPrefix="sd">
        {tab === 'overview' && <OverviewTab server={s} onEdit={sp.canManage ? () => setEditOpen(true) : undefined} />}
        {tab === 'policy' && <EffectivePolicyTab server={s} />}
        {tab === 'traffic' && (
          <FlowsTable
            match={(f) => f.server_id === s.id}
            emptyTitle="No recent traffic from this server"
            emptyDescription={s.has_proxy_token || s.ip ? 'The live view shows the latest requests the proxy recorded. Requests appear here within seconds.' : 'Issue a proxy token or set the IP address so the proxy can identify this server.'}
          />
        )}
        {tab === 'requests' && (
          <RequestsTable
            rows={requests}
            hideServer
            showState
            empty={<EmptyState icon={Inbox} size="sm" title="No access requests from this server" description="When a request from this server is blocked, users can ask for access on the block page." />}
          />
        )}
        {tab === 'audit' && <AuditList events={audit} />}
      </TabPanel>

      <ServerFormDrawer open={editOpen} onClose={() => setEditOpen(false)} server={s} />
      <OnboardingDrawer open={onboardOpen} onClose={() => setOnboardOpen(false)} server={s} />
    </>
  );
};

const Fact: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div className="min-w-0 px-[var(--card-p)] py-3.5">
    <div className="mb-1 text-[12px] font-medium text-fg-subtle">{label}</div>
    <div className="min-w-0 text-[13px] text-fg">{children}</div>
  </div>
);

const OverviewTab: React.FC<{ server: Server; onEdit?: () => void }> = ({ server: s, onEdit }) => {
  const { groupById } = useLookups();
  const st = staticGroups(s);
  const dyn = dynamicGroups(s);
  return (
    <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      <Card>
        <CardHeader title="Identity" icon={ServerIcon} divider />
        <div className="p-[var(--card-p)]">
          <DescriptionList
            items={[
              { label: 'Host name', value: <span className="break-all">{s.hostname}</span> },
              { label: 'Server id', value: <span className="font-mono text-[12.5px]">{s.id}</span> },
              { label: 'IP address', value: s.ip ? <span className="font-mono text-[12.5px]">{s.ip}</span> : <span className="text-fg-subtle">Not set</span> },
              { label: 'Subnet', value: s.subnet_cidr ? <span className="font-mono text-[12.5px]">{s.subnet_cidr}</span> : <span className="text-fg-subtle">Not set</span> },
              { label: 'Proxy user', value: s.proxy_auth_user ? <span className="font-mono text-[12.5px]">{s.proxy_auth_user}</span> : <span className="text-fg-subtle">Not set</span> },
              {
                label: 'Proxy token',
                value: s.has_proxy_token ? (
                  s.token_rotated_at ? (
                    <span>
                      Issued <RelativeTime value={s.token_rotated_at} />
                    </span>
                  ) : (
                    'Configured (issue date unknown)'
                  )
                ) : (
                  <span className="text-fg-subtle">Never issued</span>
                ),
              },
              { label: 'Operating system', value: s.os || <span className="text-fg-subtle">—</span> },
              { label: 'Department', value: s.department || <span className="text-fg-subtle">—</span> },
              { label: 'Owner team', value: s.owner_team || <span className="text-fg-subtle">—</span> },
              { label: 'Registered', value: s.created_at ? <RelativeTime value={s.created_at} /> : <span className="text-fg-subtle">—</span> },
              { label: 'Last seen', value: <LastSeen server={s} /> },
              { label: 'Description', value: s.description || <span className="text-fg-subtle">—</span>, full: true },
            ]}
          />
        </div>
      </Card>

      <div className="min-w-0 space-y-6">
      {s.defender && <DefenderDeviceCard device={s.defender} />}
      <Card>
        <CardHeader
          title="Group membership"
          description="Policy sets, approvals and Team Lead permissions follow the effective groups."
          icon={Waypoints}
          divider
        />
        {st.length + dyn.length === 0 ? (
          <p className="p-[var(--card-p)] text-[13px] text-fg-subtle">Not a member of any group. Only baseline policy sets apply.</p>
        ) : (
          <ul className="divide-y divide-border">
            {st.map((g) => {
              const grp = groupById.get(g);
              const alsoSelector = grp && labelsMatch(s.labels, grp.match_labels);
              return (
                <li key={g} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-[var(--card-p)] py-2.5">
                  <MembershipChip id={g} />
                  <Badge tone="neutral">Static</Badge>
                  {alsoSelector && <span className="text-[12px] text-fg-subtle">also matches its label selector</span>}
                </li>
              );
            })}
            {dyn.map((g) => {
              const sel = groupById.get(g)?.match_labels ?? {};
              return (
                <li key={g} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-[var(--card-p)] py-2.5">
                  <MembershipChip id={g} dynamic />
                  <Badge tone="info" icon={Tag}>
                    Label selector
                  </Badge>
                  <span className="text-[12px] text-fg-muted">
                    matched{' '}
                    {Object.entries(sel).map(([k, v], i) => (
                      <React.Fragment key={k}>
                        {i > 0 && ' and '}
                        <span className="font-mono text-[11.5px] text-fg">{v === '*' ? `${k} (any value: ${s.labels?.[k]})` : formatLabel(k, v)}</span>
                      </React.Fragment>
                    ))}
                  </span>
                </li>
              );
            })}
          </ul>
        )}
      </Card>

      <Card>
        <CardHeader title="Labels" description="Used by dynamic groups and inventory filters." icon={Tag} divider />
        <div className="p-[var(--card-p)]">
          {Object.keys(s.labels ?? {}).length ? <LabelChips labels={s.labels} max={32} /> : <p className="text-[13px] text-fg-subtle">No labels. Add labels such as env=prod or compliance=pci to use dynamic groups.</p>}
        </div>
      </Card>
      </div>
    </div>
  );
};

const AuditList: React.FC<{ events: AuditEvent[] }> = ({ events }) => {
  if (events.length === 0) {
    return (
      <Card>
        <EmptyState icon={History} size="sm" title="No audit events for this server" description="Registration, edits, token rotations and quarantines are recorded in the audit trail." />
      </Card>
    );
  }
  const tone = (a: string) => (/QUARANTINED|DECOMMISSION/.test(a) ? 'danger' : /RELEASED|REGISTERED/.test(a) ? 'success' : /TOKEN/.test(a) ? 'warning' : 'neutral');
  return (
    <Card>
      <CardHeader
        title="Audit events"
        description="Recorded in the hash-chained audit trail."
        divider
        actions={
          <ButtonLink size="sm" variant="ghost" to="/audit">
            Open audit trail
          </ButtonLink>
        }
      />
      <div className="p-[var(--card-p)]">
        <Timeline
          items={events.slice(0, 50).map((e) => ({
            id: e.id,
            tone: tone(e.action),
            title: humanize(e.action),
            meta: (
              <span className="inline-flex items-center gap-1.5">
                <UserName username={e.actor} avatar={false} />
                <RelativeTime value={e.timestamp} />
              </span>
            ),
            body: e.summary,
          }))}
        />
        {events.length > 50 && (
          <p className="mt-4 text-[12px] text-fg-subtle">
            Showing the latest 50 of {events.length} events. <Link to="/audit" className="text-accent hover:underline">See all in the audit trail</Link>.
          </p>
        )}
      </div>
    </Card>
  );
};
