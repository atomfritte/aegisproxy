import React, { useEffect, useMemo, useState } from 'react';
import { CheckCircle2 } from 'lucide-react';
import { api } from '../../api';
import { useConsoleState, usePermissions } from '../../data/AppData';
import { useAsync, useDocumentTitle } from '../../lib/hooks';
import { useUrlFilters } from '../../lib/useUrlFilters';
import type { PackageApproval } from '../../types';
import { Badge, Button, Callout, Column, CountdownChip, DataTable, EmptyState, FacetDef, PageHeader } from '../../ui';
import { RelativeTime } from '../../ui/Time';
import { GroupChip, ChipList } from '../../components/common/EntityChips';
import { EcosystemBadge, RiskBadge } from '../../components/packages';
import { ecosystemLabel, ECOSYSTEMS, nameVersion } from '../../components/packages/packageUtils';
import { ApprovalDrawer } from './ApprovalDrawer';

const VIA_TONE = { manual: 'neutral', rule: 'info', dependency: 'violet' } as const;

/** /packages/approvals — approved versions with pinned files, origin and lifecycle actions. */
export const PackageApprovalsPage: React.FC = () => {
  useDocumentTitle('Package approvals');
  const state = useConsoleState();
  const perms = usePermissions();
  const f = useUrlFilters(['ecosystem', 'status', 'via']);
  const first = useAsync(() => api.packages.approvals.list({}), [state.revision]);

  // Cursor paging: accumulate pages beyond the first (graceful when the backend returns all at once).
  const [extra, setExtra] = useState<PackageApproval[]>([]);
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [loadingMore, setLoadingMore] = useState(false);
  useEffect(() => {
    setExtra([]);
    setCursor(first.data?.cursor);
  }, [first.data]);

  const all = useMemo(() => [...(first.data?.approvals ?? []), ...extra], [first.data, extra]);
  const [selected, setSelected] = useState<PackageApproval | null>(null);
  // keep the open drawer in sync after a reload
  const selectedId = selected?.id;
  useEffect(() => {
    if (selectedId) setSelected(all.find((a) => a.id === selectedId) ?? null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [all]);

  const loadMore = async () => {
    if (!cursor) return;
    setLoadingMore(true);
    try {
      const page = await api.packages.approvals.list({ cursor });
      setExtra((prev) => [...prev, ...(page.approvals ?? [])]);
      setCursor(page.cursor);
    } finally {
      setLoadingMore(false);
    }
  };

  const facets: FacetDef<PackageApproval>[] = [
    { id: 'ecosystem', label: 'Ecosystem', getValue: (a) => a.ecosystem, options: ECOSYSTEMS.map((e) => ({ value: e, label: ecosystemLabel(e) })) },
    { id: 'status', label: 'Status', getValue: (a) => a.status, options: [{ value: 'approved', label: 'Active' }, { value: 'revoked', label: 'Revoked' }] },
    { id: 'via', label: 'Via', getValue: (a) => a.via || 'manual', options: [{ value: 'manual', label: 'Manual' }, { value: 'rule', label: 'Rule' }, { value: 'dependency', label: 'Dependency' }] },
  ];

  const columns: Column<PackageApproval>[] = [
    {
      id: 'package',
      header: 'Package',
      cell: (a) => (
        <div className="flex items-start gap-2">
          <EcosystemBadge ecosystem={a.ecosystem} short className="mt-0.5" />
          <span className="min-w-0 break-all font-mono text-[12.5px] font-medium text-fg">{nameVersion(a.name, a.version, a.display_name)}</span>
        </div>
      ),
      sortValue: (a) => a.name,
    },
    {
      id: 'groups',
      header: 'Groups',
      cell: (a) => <ChipList max={2}>{(a.group_ids ?? []).map((g) => (g === '*' ? <Badge key="*" tone="violet" size="sm">All</Badge> : <GroupChip key={g} id={g} />))}</ChipList>,
      hideBelow: 'lg',
    },
    { id: 'risk', header: 'Risk', cell: (a) => <RiskBadge risk={a.risk} />, sortValue: (a) => a.risk ?? '', width: 100 },
    { id: 'via', header: 'Via', cell: (a) => <Badge tone={VIA_TONE[(a.via as keyof typeof VIA_TONE)] ?? 'neutral'} size="sm">{a.via || 'manual'}</Badge>, hideBelow: 'xl' },
    {
      id: 'status',
      header: 'Status',
      cell: (a) => (a.status === 'revoked' ? <Badge tone="danger">Revoked</Badge> : <Badge tone="success">Active</Badge>),
      sortValue: (a) => a.status,
    },
    { id: 'approved', header: 'Approved', cell: (a) => <RelativeTime value={a.approved_at} />, sortValue: (a) => a.approved_at, hideBelow: 'lg' },
    {
      id: 'expiry',
      header: 'Expiry',
      cell: (a) =>
        a.status !== 'approved' ? <span className="text-fg-subtle">—</span> : a.expires_at ? <CountdownChip due={a.expires_at} kind="expiry" /> : <Badge tone="violet">Permanent</Badge>,
      sortValue: (a) => a.expires_at ?? '9999',
      align: 'right',
    },
  ];

  return (
    <>
      <PageHeader
        title="Approvals"
        description="Approved package versions. Each pins the delivered artifact hashes; the data-plane verifies every download against them."
      />

      {first.error && !first.data && (
        <Callout tone="danger" title="Approvals could not be loaded" action={<Button size="sm" onClick={() => first.reload()}>Try again</Button>}>
          {first.error}
        </Callout>
      )}

      <DataTable<PackageApproval>
        rows={all}
        columns={columns}
        getRowId={(a) => a.id}
        getSearchText={(a) => `${a.name} ${a.display_name ?? ''} ${a.version} ${a.ecosystem} ${a.approved_by} ${a.id}`}
        searchPlaceholder="Search package, version…"
        search={f.search}
        onSearchChange={f.setSearch}
        facetValues={f.values}
        onFacetChange={f.onChange}
        facets={facets}
        loading={first.loading}
        initialSort={{ id: 'approved', dir: 'desc' }}
        onRowClick={(a) => setSelected(a)}
        empty={
          <EmptyState
            icon={CheckCircle2}
            title="No approvals yet"
            description="Approve a package request to create approvals, or let a rule auto-approve versions that clear their cooldown and checks."
          />
        }
      />

      {cursor && (
        <div className="mt-3 flex justify-center">
          <Button variant="secondary" onClick={loadMore} loading={loadingMore}>
            Load more approvals
          </Button>
        </div>
      )}

      <ApprovalDrawer approval={selected} canManage={perms.canManageSystem} onClose={() => setSelected(null)} onChanged={() => first.reload()} />
    </>
  );
};
