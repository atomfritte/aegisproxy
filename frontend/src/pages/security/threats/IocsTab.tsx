import React from 'react';
import { Ban, Plus, ScanSearch, Trash2 } from 'lucide-react';
import { api } from '../../../api';
import { useConsole } from '../../../data/AppData';
import { Link, useSearchParams } from '../../../lib/router';
import { useUrlFilters } from '../../../lib/useUrlFilters';
import type { Indicator } from '../../../types';
import { Badge, Button, Callout, Column, CountdownChip, DataTable, EmptyState, IconButton, RelativeTime, useConfirm, useToast } from '../../../ui';
import { UserName } from '../../../components/common/EntityChips';
import { MonoValue } from './components';
import { IndicatorDrawer } from './IndicatorDrawer';
import { categoryLabel, IOC_TYPES } from './meta';
import { useThreatData } from './useThreatData';

const typeLabel = (t: string) => IOC_TYPES.find((x) => x.value === t)?.label ?? t;

/** /threats/iocs — custom indicators of compromise. `?new=1&kind=&value=&reason=&cat=` opens the add drawer prefilled. */
export const IocsTab: React.FC = () => {
  const d = useThreatData();
  const { refresh } = useConsole();
  const toast = useToast();
  const confirm = useConfirm();
  const f = useUrlFilters(['type', 'category']);
  const [params, setParams] = useSearchParams();
  const adding = params.get('new') === '1' && d.canManage;
  const closeDrawer = () => setParams({ new: null, kind: null, value: null, reason: null, cat: null });

  const remove = (i: Indicator) =>
    confirm({
      title: `Remove indicator ${i.value}?`,
      description: 'Workers stop blocking it after their next threat-intel sync.',
      tone: 'danger',
      confirmLabel: 'Remove indicator',
      onConfirm: async () => {
        await api.security.deleteIndicator(i.id);
        toast.success(`Removed indicator ${i.value}`);
        await refresh();
      },
    });

  const columns: Column<Indicator>[] = [
    { id: 'type', header: 'Type', width: 120, sortValue: (i) => i.type, cell: (i) => <Badge tone="neutral">{typeLabel(i.type)}</Badge> },
    { id: 'value', header: 'Value', width: '32%', sortValue: (i) => i.value, cell: (i) => <MonoValue value={i.value} tone="danger" /> },
    {
      id: 'reason',
      header: 'Category and reason',
      sortValue: (i) => i.category,
      cell: (i) => (
        <div className="min-w-0">
          <div className="text-[13px] text-fg">{categoryLabel(i.category)}</div>
          <p className="line-clamp-2 text-[12px] leading-5 text-fg-muted">{i.reason}</p>
        </div>
      ),
    },
    {
      id: 'added',
      header: 'Added',
      width: 150,
      hideBelow: 'lg',
      sortValue: (i) => i.created_at,
      cell: (i) => (
        <div className="leading-tight">
          <UserName username={i.added_by} />
          <div className="mt-0.5 text-[12px] text-fg-subtle">
            <RelativeTime value={i.created_at} />
          </div>
        </div>
      ),
    },
    {
      id: 'expires',
      header: 'Expires',
      width: 150,
      sortValue: (i) => i.expires_at || '9999',
      cell: (i) => (i.expires_at ? <CountdownChip due={i.expires_at} kind="expiry" /> : <span className="text-[12.5px] text-fg-subtle">Never</span>),
    },
    {
      id: 'actions',
      header: <span className="sr-only">Actions</span>,
      width: 84,
      align: 'right',
      hideOnMobile: true,
      cell: (i) => (
        <span className="inline-flex gap-1">
          <Link to={`/threats/lookup?value=${encodeURIComponent(i.value)}`} aria-label={`Look up ${i.value}`} className="inline-flex h-[var(--control-h-sm)] w-[var(--control-h-sm)] items-center justify-center rounded-md text-fg-muted hover:bg-surface-3 hover:text-fg">
            <ScanSearch className="h-4 w-4" aria-hidden />
          </Link>
          {d.canManage && <IconButton icon={Trash2} label={`Remove ${i.value}`} size="sm" variant="danger-ghost" onClick={() => remove(i)} />}
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-5">
      <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <p className="max-w-3xl text-[13px] leading-6 text-fg-muted">
          Hand-curated domains, URLs, IPs, networks and file hashes that are always treated as malicious — for example from an incident or a vendor advisory. Use an expiry for
          temporary blocks; bulk lists belong in a feed.
        </p>
        {d.canManage && (
          <Button variant="primary" icon={Plus} className="shrink-0" onClick={() => setParams({ new: '1' })}>
            Add indicator
          </Button>
        )}
      </div>
      {!d.canManage && <Callout tone="neutral">Only InfoSec Approvers and Super Admins can add or remove indicators.</Callout>}
      <DataTable
        aria-label="Custom indicators"
        rows={d.indicators}
        columns={columns}
        getRowId={(i) => i.id}
        getSearchText={(i) => `${i.value} ${i.category} ${i.reason} ${i.added_by}`}
        searchPlaceholder="Search value, category or reason…"
        search={f.search}
        onSearchChange={f.setSearch}
        facets={[
          { id: 'type', label: 'Type', getValue: (i) => i.type, options: IOC_TYPES.map((t) => ({ value: t.value, label: t.label })) },
          { id: 'category', label: 'Category', getValue: (i) => i.category, optionLabel: categoryLabel },
        ]}
        facetValues={f.values}
        onFacetChange={f.onChange}
        initialSort={{ id: 'added', dir: 'desc' }}
        mobileCard={(i) => (
          <div className="min-w-0 space-y-1.5">
            <div className="flex items-start justify-between gap-2">
              <MonoValue value={i.value} tone="danger" />
              {d.canManage && <IconButton icon={Trash2} label={`Remove ${i.value}`} size="sm" variant="danger-ghost" onClick={() => remove(i)} className="-mr-1 -mt-1 shrink-0" />}
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              <Badge tone="neutral">{typeLabel(i.type)}</Badge>
              <span className="text-[12px] text-fg-muted">{categoryLabel(i.category)}</span>
              {i.expires_at && <CountdownChip due={i.expires_at} kind="expiry" />}
            </div>
            <p className="text-[12px] leading-5 text-fg-muted">{i.reason}</p>
          </div>
        )}
        empty={
          <EmptyState
            icon={Ban}
            title="No custom indicators"
            description="Add a domain, URL, IP, network or file hash to block it on every server — for example while you handle an incident."
            action={
              d.canManage && (
                <Button variant="primary" icon={Plus} onClick={() => setParams({ new: '1' })}>
                  Add indicator
                </Button>
              )
            }
          />
        }
      />
      <IndicatorDrawer
        open={adding}
        prefill={{ type: params.get('kind') || undefined, value: params.get('value') || undefined, category: params.get('cat') || undefined, reason: params.get('reason') || undefined }}
        onClose={closeDrawer}
      />
    </div>
  );
};
