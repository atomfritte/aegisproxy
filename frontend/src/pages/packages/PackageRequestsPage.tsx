import React, { useMemo } from 'react';
import { PackageSearch, Plus, UserCheck } from 'lucide-react';
import { api } from '../../api';
import { useConsoleState, usePermissions } from '../../data/AppData';
import { useSession } from '../../data/session';
import { useAsync, useDocumentTitle } from '../../lib/hooks';
import { useQueryParam } from '../../lib/router';
import { useUrlFilters } from '../../lib/useUrlFilters';
import type { PackageRequest } from '../../types';
import { Badge, Button, Callout, Column, DataTable, EmptyState, FacetDef, PageHeader } from '../../ui';
import { RelativeTime } from '../../ui/Time';
import { GroupChip, ChipList, UserName } from '../../components/common/EntityChips';
import { EcosystemBadge, RiskBadge } from '../../components/packages';
import { ecosystemLabel, ECOSYSTEMS, REQUEST_STATUS_META, requestStatusMeta } from '../../components/packages/packageUtils';
import { RequestWizardDrawer } from './RequestWizardDrawer';

const STATUS_OPTIONS = Object.entries(REQUEST_STATUS_META).map(([value, m]) => ({ value, label: m.label }));

function graphSummary(r: PackageRequest): string {
  const c = r.counts ?? {};
  const total = (r.graph ?? []).length || Object.values(c).reduce((a, b) => a + (b || 0), 0);
  const bits: string[] = [];
  if (c.new) bits.push(`${c.new} new`);
  if (c.update) bits.push(`${c.update} update`);
  if (c.blocked) bits.push(`${c.blocked} blocked`);
  return total ? `${total} pkg${total === 1 ? '' : 's'}${bits.length ? ` · ${bits.join(' · ')}` : ''}` : '—';
}

/** /packages/requests — the request inbox with URL filters and a request wizard. */
export const PackageRequestsPage: React.FC = () => {
  useDocumentTitle('Package requests');
  const state = useConsoleState();
  const perms = usePermissions();
  const { user } = useSession();
  const me = (user?.username || '').toLowerCase();
  const f = useUrlFilters(['status', 'ecosystem']);
  const [mine, setMine] = useQueryParam('mine');
  const [wizardNew, setWizardNew] = useQueryParam('new');
  const { data, error, loading, reload } = useAsync(() => api.packages.requests.list({}), [state.revision]);

  const wizardOpen = wizardNew === '1';
  const openWizard = () => setWizardNew('1');
  const closeWizard = () => setWizardNew(null);

  const rows = useMemo(() => {
    let list = (data ?? []).slice().sort((a, b) => (b.updated_at || b.created_at).localeCompare(a.updated_at || a.created_at));
    if (mine === '1') list = list.filter((r) => (r.requested_by || '').toLowerCase() === me);
    return list;
  }, [data, mine, me]);

  const facets: FacetDef<PackageRequest>[] = [
    { id: 'status', label: 'Status', getValue: (r) => r.status, options: STATUS_OPTIONS },
    { id: 'ecosystem', label: 'Ecosystem', getValue: (r) => r.ecosystem, options: ECOSYSTEMS.map((e) => ({ value: e, label: ecosystemLabel(e) })) },
  ];

  const columns: Column<PackageRequest>[] = [
    {
      id: 'package',
      header: 'Package',
      cell: (r) => (
        <div className="flex items-start gap-2">
          <EcosystemBadge ecosystem={r.ecosystem} short className="mt-0.5" />
          <div className="min-w-0">
            <div className="break-all font-mono text-[12.5px] font-medium text-fg">
              {r.display_name || r.name}
              {r.version ? <span className="text-fg-muted">@{r.version}</span> : null}
            </div>
            {r.requested && r.requested !== r.version && <div className="text-[11.5px] text-fg-subtle">requested {r.requested}</div>}
          </div>
        </div>
      ),
      sortValue: (r) => r.name,
      mobileLabel: 'Package',
    },
    {
      id: 'status',
      header: 'Status',
      cell: (r) => {
        const m = requestStatusMeta(r.status);
        return (
          <span className="flex flex-wrap items-center gap-1.5">
            <Badge tone={m.tone} dot>{m.label}</Badge>
            {r.auto_rule_id && <Badge tone="neutral" size="sm" title={r.auto_rule_name}>auto</Badge>}
          </span>
        );
      },
      sortValue: (r) => r.status,
    },
    { id: 'risk', header: 'Risk', cell: (r) => <RiskBadge risk={r.risk} />, sortValue: (r) => r.risk ?? '', width: 110 },
    { id: 'graph', header: 'Graph', cell: (r) => <span className="text-[12px] text-fg-muted">{graphSummary(r)}</span>, hideBelow: 'lg' },
    {
      id: 'groups',
      header: 'Groups',
      cell: (r) => (
        <ChipList max={2}>{(r.group_ids ?? []).map((g) => (g === '*' ? <Badge key="*" tone="violet" size="sm">All groups</Badge> : <GroupChip key={g} id={g} />))}</ChipList>
      ),
      hideBelow: 'xl',
    },
    { id: 'requester', header: 'Requested by', cell: (r) => <UserName username={r.requested_by} avatar={false} />, hideBelow: 'xl' },
    { id: 'updated', header: 'Updated', cell: (r) => <RelativeTime value={r.updated_at || r.created_at} />, sortValue: (r) => r.updated_at || r.created_at, align: 'right' },
  ];

  return (
    <>
      <PageHeader
        title="Package requests"
        description="Each request resolves a package to its full dependency graph, analyzes every version in the sandbox, and — on approval — creates the approvals for the whole graph."
        actions={
          <Button variant="primary" icon={Plus} onClick={openWizard}>
            Request a package
          </Button>
        }
      />

      {error && !data && (
        <Callout tone="danger" title="Requests could not be loaded" action={<Button size="sm" onClick={() => reload()}>Try again</Button>}>
          {error}
        </Callout>
      )}

      <DataTable<PackageRequest>
        rows={rows}
        columns={columns}
        getRowId={(r) => r.id}
        getSearchText={(r) => `${r.name} ${r.display_name} ${r.requested} ${r.version} ${r.requested_by} ${r.id} ${r.ecosystem}`}
        searchPlaceholder="Search package, requester…"
        search={f.search}
        onSearchChange={f.setSearch}
        facetValues={f.values}
        onFacetChange={f.onChange}
        facets={facets}
        loading={loading}
        initialSort={{ id: 'updated', dir: 'desc' }}
        rowHref={(r) => `/packages/requests/${encodeURIComponent(r.id)}`}
        toolbar={
          !perms.isReadOnly ? (
            <Button size="sm" variant={mine === '1' ? 'primary' : 'secondary'} icon={UserCheck} onClick={() => setMine(mine === '1' ? null : '1')}>
              My requests
            </Button>
          ) : undefined
        }
        empty={
          <EmptyState
            icon={PackageSearch}
            title={mine === '1' ? 'You have not requested any packages' : 'No package requests yet'}
            description="Open a request to resolve a package's dependency graph and analyze it before approving."
            action={
              <Button size="sm" variant="primary" icon={Plus} onClick={openWizard}>
                Request a package
              </Button>
            }
          />
        }
      />

      <RequestWizardDrawer open={wizardOpen} onClose={closeWizard} onCreated={() => reload()} />
    </>
  );
};
