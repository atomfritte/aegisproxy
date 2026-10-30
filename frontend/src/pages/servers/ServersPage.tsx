import React, { useEffect, useMemo, useState } from 'react';
import {
  Boxes,
  Download,
  Eye,
  FileJson,
  FileSpreadsheet,
  KeyRound,
  MoreHorizontal,
  Pencil,
  Plus,
  Radar,
  RefreshCw,
  Server as ServerIcon,
  ShieldCheck,
  ShieldOff,
  Tag,
  Trash2,
  Upload,
  WifiOff,
} from 'lucide-react';
import { api } from '../../api';
import { useConsoleState, usePermissions } from '../../data/AppData';
import { cn } from '../../lib/cn';
import { formatCompact, formatNumber, pluralize } from '../../lib/format';
import { useAsync, useDocumentTitle, useNow } from '../../lib/hooks';
import { Link, useSearchParams } from '../../lib/router';
import { useUrlFilters } from '../../lib/useUrlFilters';
import type { DiscoveredSource, Server } from '../../types';
import {
  Button,
  Callout,
  Column,
  DataTable,
  EmptyState,
  Menu,
  PageHeader,
  RelativeTime,
  TabPanel,
  Tabs,
  Tooltip,
  useToast,
  useUrlTab,
} from '../../ui';
import { ChipList, GroupChip, LabelChips } from '../../components/common/EntityChips';
import { BulkGroupDialog, BulkLabelDialog } from '../../components/fleet/BulkServerDialogs';
import { LastSeen, MembershipChips, ServerHealthChip } from '../../components/fleet/FleetChips';
import { downloadApiFile, effectiveGroups, isStale, saveBlob, serverHealth, serversToCsv, timestamp } from '../../components/fleet/fleetUtils';
import { ImportServersDrawer } from '../../components/fleet/ImportServersDrawer';
import { OnboardingDrawer } from '../../components/fleet/OnboardingDrawer';
import { ServerFormDrawer } from '../../components/fleet/ServerFormDrawer';
import { useServerActions, useServerPerms } from '../../components/fleet/useServerActions';

const FILTERS = ['group', 'label', 'os', 'status', 'owner'];
const VIEWS = ['inventory', 'discovered'] as const;
type View = (typeof VIEWS)[number];

type FormState = { mode: 'create'; initial?: Partial<Server> } | { mode: 'edit'; server: Server } | null;

/** /servers — inventory with URL-synced filters and the discovered (unregistered) sources. */
export const ServersPage: React.FC = () => {
  useDocumentTitle('Servers');
  const state = useConsoleState();
  const perms = usePermissions();
  const sp = useServerPerms();
  const actions = useServerActions();
  const toast = useToast();
  const now = useNow();
  const f = useUrlFilters(FILTERS);
  const [params, setParams] = useSearchParams();
  const [view, setView] = useUrlTab<View>(VIEWS, 'inventory', 'view');
  const [form, setForm] = useState<FormState>(null);
  const [onboard, setOnboard] = useState<Server | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [bulk, setBulk] = useState<{ kind: 'label' | 'group'; servers: Server[]; clear: () => void } | null>(null);
  const servers = state.servers;

  // Overview deep links (/servers?quarantined=1, ?stale=1) → status facet
  useEffect(() => {
    const q = params.get('quarantined') === '1';
    const s = params.get('stale') === '1';
    if (q || s) setParams({ quarantined: null, stale: null, status: [q && 'quarantined', s && 'stale'].filter(Boolean).join(',') });
  }, [params, setParams]);

  const discovered = useAsync<DiscoveredSource[]>(() => api.servers.discovered(), [state.revision]);
  const discoveredCount = discovered.data?.length ?? 0;

  const counts = useMemo(() => {
    const c = { total: servers.length, quarantined: 0, stale: 0, healthy: 0 };
    for (const s of servers) {
      if (s.quarantined) c.quarantined++;
      if (isStale(s, now)) c.stale++;
      else if (!s.quarantined) c.healthy++;
    }
    return c;
  }, [servers, now]);

  const statusOf = (s: Server): string[] => {
    const h = serverHealth(s, now);
    const out: string[] = [];
    if (s.quarantined) out.push('quarantined');
    if (h === 'never') out.push('never', 'stale');
    else if (isStale(s, now)) out.push('stale');
    else if (!s.quarantined) out.push('healthy');
    return out;
  };

  const exportAll = async (format: 'csv' | 'json') => {
    try {
      const name = await downloadApiFile(`/api/servers/export?format=${format}`, `aegis-servers-${timestamp()}.${format}`);
      toast.success(`Exported ${pluralize(servers.length, 'server')}`, { description: name });
    } catch (err) {
      toast.error(err, { title: 'The export failed' });
    }
  };

  const rowMenu = (s: Server) => (
    <Menu
      items={[
        { id: 'open', label: 'Open', icon: Eye, to: `/servers/${encodeURIComponent(s.id)}` },
        { id: 'edit', label: 'Edit', icon: Pencil, onSelect: () => setForm({ mode: 'edit', server: s }), hidden: !sp.canManage },
        { id: 'token', label: s.has_proxy_token ? 'Rotate token' : 'Onboard', icon: KeyRound, onSelect: () => setOnboard(s), hidden: !sp.canManage },
        { id: 'quarantine', label: 'Quarantine', icon: ShieldOff, danger: true, separator: true, onSelect: () => actions.quarantine([s]), hidden: s.quarantined || !sp.canQuarantine(s) },
        { id: 'release', label: 'Release quarantine', icon: ShieldCheck, separator: true, onSelect: () => actions.release(s), hidden: !s.quarantined || !sp.canRelease },
        { id: 'delete', label: 'Decommission', icon: Trash2, danger: true, onSelect: () => actions.decommission(s, () => undefined), hidden: !sp.canManage },
      ]}
      trigger={(p) => (
        <button {...p} type="button" aria-label={`Actions for ${s.hostname}`} className="inline-flex h-7 w-7 items-center justify-center rounded-md text-fg-subtle hover:bg-surface-3 hover:text-fg">
          <MoreHorizontal className="h-4 w-4" />
        </button>
      )}
    />
  );

  const columns: Column<Server>[] = [
    {
      id: 'host',
      header: 'Server',
      sortValue: (s) => s.hostname.toLowerCase(),
      cell: (s) => (
        <div className="min-w-[140px] max-w-[260px]">
          <Link to={`/servers/${encodeURIComponent(s.id)}`} className="block font-medium text-fg [overflow-wrap:anywhere] hover:text-accent hover:underline">
            {s.hostname}
          </Link>
          <div className="font-mono text-[11.5px] text-fg-subtle [overflow-wrap:anywhere]">{s.id}</div>
        </div>
      ),
    },
    {
      id: 'address',
      header: 'Address',
      hideBelow: 'xl',
      sortValue: (s) => s.ip,
      cell: (s) => (
        <div className="font-mono text-[12px] leading-5">
          <div className="whitespace-nowrap text-fg">{s.ip || <span className="font-sans text-fg-subtle">No IP</span>}</div>
          {s.subnet_cidr && <div className="whitespace-nowrap text-fg-subtle">{s.subnet_cidr}</div>}
        </div>
      ),
    },
    { id: 'groups', header: 'Groups', cell: (s) => <MembershipChips server={s} max={2} /> },
    { id: 'labels', header: 'Labels', hideBelow: 'xl', cell: (s) => <LabelChips labels={s.labels} max={2} /> },
    {
      id: 'os',
      header: 'OS / owner',
      hideBelow: 'xl',
      sortValue: (s) => s.os,
      cell: (s) => (
        <div className="max-w-[200px] text-[12.5px] leading-5">
          <div className="text-fg">{s.os || <span className="text-fg-subtle">—</span>}</div>
          {s.owner_team && <div className="text-fg-subtle">{s.owner_team}</div>}
        </div>
      ),
    },
    {
      id: 'status',
      header: 'Status',
      sortValue: (s) => ({ quarantined: 0, stale: 1, never: 2, healthy: 3 })[serverHealth(s, now)],
      cell: (s) => (
        <div className="flex flex-col items-start gap-0.5">
          <ServerHealthChip server={s} />
          <span className="whitespace-nowrap text-[12px] text-fg-subtle">
            {serverHealth(s, now) === 'never' ? 'No traffic yet' : <LastSeen server={s} />}
          </span>
        </div>
      ),
    },
    { id: 'menu', header: <span className="sr-only">Actions</span>, width: 44, align: 'right', cell: rowMenu },
  ];

  const groupOptions = state.groups.map((g) => ({ value: g.id, label: g.name }));
  const labelOptions = useMemo(
    () => [...new Set(servers.flatMap((s) => Object.entries(s.labels ?? {}).map(([k, v]) => `${k}=${v}`)))].sort((a, b) => String(a).localeCompare(String(b))).map((v) => ({ value: v, label: v })),
    [servers]
  );

  const statusCards: Array<{ id: string; label: string; value: number; icon: typeof ServerIcon; tone: string; hint: string }> = [
    { id: '', label: 'Registered', value: counts.total, icon: ServerIcon, tone: 'bg-accent-soft text-accent', hint: `${state.groups.length} groups` },
    { id: 'healthy', label: 'Healthy', value: counts.healthy, icon: ShieldCheck, tone: 'bg-success-soft text-success', hint: 'Seen within 24 h' },
    { id: 'stale', label: 'Stale', value: counts.stale, icon: WifiOff, tone: 'bg-warning-soft text-warning', hint: 'No traffic for 24 h' },
    { id: 'quarantined', label: 'Quarantined', value: counts.quarantined, icon: ShieldOff, tone: 'bg-danger-soft text-danger', hint: 'All egress blocked' },
  ];
  const statusFilter = f.values.status;

  return (
    <>
      <PageHeader
        title="Servers"
        description="Registered servers, their identities, group memberships and labels. Policy applies by group; labels add servers to dynamic groups automatically."
        actions={
          <>
            <Menu
              items={[
                { id: 'csv', label: 'Export CSV', icon: FileSpreadsheet, description: 'Re-importable inventory', onSelect: () => exportAll('csv') },
                { id: 'json', label: 'Export JSON', icon: FileJson, description: 'Full records incl. quarantine state', onSelect: () => exportAll('json') },
              ]}
              trigger={(p) => (
                <Button {...p} icon={Download}>
                  Export
                </Button>
              )}
            />
            {sp.canManage && (
              <Button icon={Upload} onClick={() => setImportOpen(true)}>
                Import
              </Button>
            )}
            {sp.canManage && (
              <Button variant="primary" icon={Plus} onClick={() => setForm({ mode: 'create' })}>
                Register server
              </Button>
            )}
          </>
        }
      />

      <div className="mb-5 grid grid-cols-2 gap-2 md:gap-3 lg:grid-cols-4" role="group" aria-label="Filter by status">
        {statusCards.map((c) => {
          const active = c.id ? statusFilter.includes(c.id) : statusFilter.length === 0;
          const Icon = c.icon;
          return (
            <button
              key={c.id || 'all'}
              type="button"
              aria-pressed={active}
              onClick={() => {
                setView('inventory');
                f.onChange('status', !c.id || active ? [] : [c.id]);
              }}
              className={cn(
                'flex min-w-0 items-center gap-3 rounded-lg border bg-surface p-3 text-left shadow-card transition-colors',
                active ? 'border-accent ring-1 ring-accent' : 'border-border hover:border-border-strong hover:bg-surface-2'
              )}
            >
              <span className={cn('hidden h-8 w-8 shrink-0 items-center justify-center rounded-md sm:flex', c.tone)}>
                <Icon className="h-4 w-4" aria-hidden />
              </span>
              <span className="min-w-0">
                <span className="flex items-baseline gap-2">
                  <span className="text-[20px] font-semibold leading-7 tabular text-fg">{formatNumber(c.value)}</span>
                  <span className="truncate text-[12.5px] font-medium text-fg-muted">{c.label}</span>
                </span>
                <span className="block truncate text-[12px] text-fg-subtle">{c.hint}</span>
              </span>
            </button>
          );
        })}
      </div>

      <Tabs<View>
        idPrefix="srv"
        className="mb-4"
        value={view}
        onChange={setView}
        aria-label="Server lists"
        tabs={[
          { id: 'inventory', label: 'Inventory', icon: ServerIcon, count: servers.length },
          { id: 'discovered', label: 'Discovered', icon: Radar, count: discovered.data ? discoveredCount : undefined, countTone: discoveredCount ? 'warning' : 'neutral' },
        ]}
      />

      <TabPanel id={view} idPrefix="srv">
        {view === 'inventory' ? (
          <DataTable
            rows={servers}
            columns={columns}
            getRowId={(s) => s.id}
            rowHref={(s) => `/servers/${encodeURIComponent(s.id)}`}
            rowClassName={(s) => (s.quarantined ? 'bg-danger-soft/40' : undefined)}
            getSearchText={(s) =>
              `${s.hostname} ${s.id} ${s.ip} ${s.subnet_cidr} ${s.proxy_auth_user} ${s.os} ${s.owner_team ?? ''} ${s.department} ${s.description ?? ''} ${Object.entries(s.labels ?? {})
                .map(([k, v]) => `${k}=${v}`)
                .join(' ')}`
            }
            searchPlaceholder="Search host, IP, id, label…"
            search={f.search}
            onSearchChange={f.setSearch}
            facetValues={f.values}
            onFacetChange={f.onChange}
            facets={[
              { id: 'group', label: 'Group', getValue: effectiveGroups, options: groupOptions },
              { id: 'label', label: 'Label', getValue: (s) => Object.entries(s.labels ?? {}).map(([k, v]) => `${k}=${v}`), options: labelOptions },
              { id: 'os', label: 'OS', getValue: (s) => s.os || '' },
              {
                id: 'status',
                label: 'Status',
                getValue: statusOf,
                options: [
                  { value: 'healthy', label: 'Healthy' },
                  { value: 'stale', label: 'Stale (24 h)' },
                  { value: 'never', label: 'Never seen' },
                  { value: 'quarantined', label: 'Quarantined' },
                ],
              },
              { id: 'owner', label: 'Owner', getValue: (s) => s.owner_team || '' },
            ]}
            selectable
            bulkActions={(rows, clear) => (
              <>
                <Button size="sm" icon={FileSpreadsheet} onClick={() => saveBlob(new Blob([serversToCsv(rows)], { type: 'text/csv' }), `aegis-servers-selection-${timestamp()}.csv`)}>
                  Export CSV
                </Button>
                {sp.canManage && (
                  <>
                    <Button size="sm" icon={Tag} onClick={() => setBulk({ kind: 'label', servers: rows, clear })}>
                      Set label
                    </Button>
                    <Button size="sm" icon={Boxes} onClick={() => setBulk({ kind: 'group', servers: rows, clear })}>
                      Add to group
                    </Button>
                  </>
                )}
                {rows.some((s) => !s.quarantined && sp.canQuarantine(s)) && (
                  <Button size="sm" variant="danger-ghost" icon={ShieldOff} onClick={() => actions.quarantine(rows.filter((s) => !s.quarantined && sp.canQuarantine(s)))}>
                    Quarantine
                  </Button>
                )}
              </>
            )}
            mobileCard={(s) => (
              <div className="min-w-0 space-y-1.5">
                <div className="flex items-start gap-2">
                  <div className="min-w-0 flex-1">
                    <Link to={`/servers/${encodeURIComponent(s.id)}`} className="block truncate font-medium text-fg">
                      {s.hostname}
                    </Link>
                    <div className="truncate font-mono text-[11.5px] text-fg-subtle">
                      {s.ip || 'No IP'} · {s.id}
                    </div>
                  </div>
                  <ServerHealthChip server={s} />
                  {rowMenu(s)}
                </div>
                <MembershipChips server={s} max={3} />
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px] text-fg-subtle">
                  <span className="inline-flex items-center gap-1">
                    Seen <LastSeen server={s} />
                  </span>
                  {s.os && <span className="truncate">{s.os}</span>}
                </div>
                {Object.keys(s.labels ?? {}).length > 0 && <LabelChips labels={s.labels} max={3} />}
              </div>
            )}
            empty={
              <EmptyState
                icon={ServerIcon}
                title="No servers registered yet"
                description="Register servers one by one, import them from a CMDB export, or register sources the proxy has already seen (Discovered)."
                action={
                  sp.canManage && (
                    <>
                      <Button variant="primary" icon={Plus} onClick={() => setForm({ mode: 'create' })}>
                        Register server
                      </Button>
                      <Button icon={Upload} onClick={() => setImportOpen(true)}>
                        Import CSV
                      </Button>
                    </>
                  )
                }
              />
            }
            aria-label="Server inventory"
          />
        ) : (
          <DiscoveredTable
            data={discovered.data}
            loading={discovered.loading}
            error={discovered.error}
            onReload={discovered.reload}
            canRegister={sp.canManage}
            onRegister={(d) =>
              setForm({
                mode: 'create',
                initial: { id: d.suggested_id, ip: d.ip, proxy_auth_user: d.proxy_auth_user ?? '', group_ids: d.matched_groups ?? [] },
              })
            }
          />
        )}
      </TabPanel>

      {perms.isReadOnly && (
        <p className="mt-3 text-[12px] text-fg-subtle">You have read-only access. Registering, importing and quarantining servers needs the InfoSec role.</p>
      )}

      <ServerFormDrawer
        open={!!form}
        onClose={() => setForm(null)}
        server={form?.mode === 'edit' ? form.server : null}
        initial={form?.mode === 'create' ? form.initial : null}
        onOnboard={(s) => {
          setForm(null);
          setOnboard(s);
        }}
      />
      <OnboardingDrawer open={!!onboard} onClose={() => setOnboard(null)} server={onboard ? state.servers.find((s) => s.id === onboard.id) ?? onboard : null} />
      <ImportServersDrawer open={importOpen} onClose={() => setImportOpen(false)} />
      <BulkLabelDialog open={bulk?.kind === 'label'} onClose={() => setBulk(null)} servers={bulk?.servers ?? []} onDone={() => bulk?.clear()} />
      <BulkGroupDialog open={bulk?.kind === 'group'} onClose={() => setBulk(null)} servers={bulk?.servers ?? []} onDone={() => bulk?.clear()} />
    </>
  );
};

const DiscoveredTable: React.FC<{
  data?: DiscoveredSource[];
  loading: boolean;
  error: string | null;
  onReload: () => void;
  canRegister: boolean;
  onRegister: (d: DiscoveredSource) => void;
}> = ({ data, loading, error, onReload, canRegister, onRegister }) => {
  const columns: Column<DiscoveredSource>[] = [
    {
      id: 'ip',
      header: 'Source',
      width: 170,
      sortValue: (d) => d.ip,
      cell: (d) => (
        <div className="min-w-0">
          <div className="truncate font-mono text-[12.5px] font-medium text-fg">{d.ip}</div>
          {d.proxy_auth_user ? (
            <div className="truncate text-[12px] text-fg-subtle">user {d.proxy_auth_user}</div>
          ) : (
            <div className="text-[12px] text-fg-subtle">no proxy user</div>
          )}
        </div>
      ),
    },
    {
      id: 'suggested',
      header: 'Suggested id',
      width: 170,
      hideBelow: 'xl',
      cell: (d) => <span className="block truncate font-mono text-[12px] text-fg-muted">{d.suggested_id}</span>,
    },
    {
      id: 'groups',
      header: 'Matched CIDR groups',
      cell: (d) =>
        (d.matched_groups ?? []).length ? (
          <ChipList max={2}>
            {(d.matched_groups ?? []).map((g) => (
              <GroupChip key={g} id={g} />
            ))}
          </ChipList>
        ) : (
          <span className="text-[12.5px] text-fg-subtle">None</span>
        ),
    },
    {
      id: 'hosts',
      header: 'Top destinations',
      hideBelow: 'lg',
      cell: (d) => (
        <div className="min-w-0 space-y-0.5">
          {(d.top_hosts ?? []).slice(0, 3).map((h) => (
            <div key={h} className="truncate font-mono text-[11.5px] text-fg-muted">
              {h}
            </div>
          ))}
          {(d.user_agent_hints ?? []).length > 0 && (
            <Tooltip content={(d.user_agent_hints ?? []).join('\n')}>
              <span className="block truncate text-[11.5px] text-fg-subtle">{(d.user_agent_hints ?? [])[0]}</span>
            </Tooltip>
          )}
        </div>
      ),
    },
    {
      id: 'requests',
      header: 'Requests',
      align: 'right',
      width: 104,
      sortValue: (d) => d.requests,
      cell: (d) => (
        <div className="text-right leading-5">
          <div className="tabular text-fg">{formatCompact(d.requests)}</div>
          {d.blocked > 0 && <div className="text-[12px] tabular text-danger">{formatCompact(d.blocked)} blocked</div>}
        </div>
      ),
    },
    {
      id: 'seen',
      header: 'Seen',
      width: 120,
      sortValue: (d) => d.last_seen,
      cell: (d) => (
        <div className="text-[12px] leading-5">
          <RelativeTime value={d.last_seen} className="text-fg" />
          <div className="text-fg-subtle">
            first <RelativeTime value={d.first_seen} />
          </div>
        </div>
      ),
    },
    {
      id: 'register',
      header: <span className="sr-only">Register</span>,
      width: 104,
      align: 'right',
      cell: (d) =>
        canRegister ? (
          <Button size="sm" icon={Plus} onClick={() => onRegister(d)}>
            Register
          </Button>
        ) : null,
    },
  ];

  if (error && !data)
    return (
      <Callout tone="danger" title="Discovered sources could not be loaded" action={<Button size="sm" onClick={onReload}>Retry</Button>}>
        {error}
      </Callout>
    );

  return (
    <>
      <Callout tone="info" className="mb-4" icon={Radar}>
        Clients that sent traffic through the proxy but are not registered. They get no group policy except CIDR matches; register them to apply policy, quarantine and onboarding.
      </Callout>
      <DataTable
        rows={data ?? []}
        loading={loading && !data}
        columns={columns}
        getRowId={(d) => d.ip}
        getSearchText={(d) => `${d.ip} ${d.suggested_id} ${d.proxy_auth_user ?? ''} ${(d.top_hosts ?? []).join(' ')} ${(d.user_agent_hints ?? []).join(' ')}`}
        searchPlaceholder="Search IP, destination, user agent…"
        toolbar={
          <Button size="sm" variant="ghost" icon={RefreshCw} onClick={onReload} loading={loading && !!data}>
            Refresh
          </Button>
        }
        initialSort={{ id: 'requests', dir: 'desc' }}
        mobileCard={(d) => (
          <div className="min-w-0 space-y-1.5">
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <div className="font-mono text-[13px] font-medium text-fg">{d.ip}</div>
                <div className="text-[12px] text-fg-subtle">
                  {formatCompact(d.requests)} requests{d.blocked ? `, ${formatCompact(d.blocked)} blocked` : ''} · <RelativeTime value={d.last_seen} />
                </div>
              </div>
              {canRegister && (
                <Button size="sm" icon={Plus} onClick={() => onRegister(d)}>
                  Register
                </Button>
              )}
            </div>
            {(d.top_hosts ?? []).length > 0 && <div className="truncate font-mono text-[11.5px] text-fg-muted">{(d.top_hosts ?? []).join(', ')}</div>}
            {(d.matched_groups ?? []).length > 0 && (
              <div className="flex flex-wrap gap-1">
                {(d.matched_groups ?? []).map((g) => (
                  <GroupChip key={g} id={g} />
                ))}
              </div>
            )}
          </div>
        )}
        empty={
          <EmptyState
            icon={Radar}
            title="No unregistered sources"
            description="Every client the proxy has seen recently is registered. Sources that are not in the inventory show up here with a suggested id and the CIDR groups they match."
          />
        }
        aria-label="Discovered sources"
      />
    </>
  );
};
