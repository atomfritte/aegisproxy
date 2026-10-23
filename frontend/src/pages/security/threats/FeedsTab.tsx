import React, { useMemo, useState } from 'react';
import { AlertTriangle, Database, Eye, KeyRound, MoreHorizontal, Pencil, Plus, RefreshCw, ShieldHalf, Trash2 } from 'lucide-react';
import { api } from '../../../api';
import { useAction, useConsole } from '../../../data/AppData';
import { formatNumber } from '../../../lib/format';
import type { ThreatFeed } from '../../../types';
import { Badge, Button, Callout, Column, DataTable, EmptyState, IconButton, Menu, RelativeTime, Switch, Tooltip, useConfirm, useToast } from '../../../ui';
import { categoryLabel, feedFormatLabel, isDefenderFeed, RESTRICTIVE_LICENSE } from './meta';
import { FeedDrawer } from './FeedDrawer';
import { ModeBadge } from './components';
import { useDelayedRefresh, useThreatData } from './useThreatData';

const feedPayload = (f: ThreatFeed, patch: Partial<ThreatFeed>): Partial<ThreatFeed> => ({
  id: f.id,
  name: f.name,
  description: f.description,
  url: f.url,
  format: f.format,
  category: f.category,
  license: f.license,
  enabled: f.enabled,
  match_subdomains: f.match_subdomains,
  refresh_minutes: f.refresh_minutes,
  auth_header_name: f.auth_header_name || '',
  lookback_days: f.lookback_days ?? 0,
  ca_cert_pem: f.ca_cert_pem ?? '',
  ...patch,
});

const SourceBadge: React.FC<{ feed: ThreatFeed }> = ({ feed: f }) =>
  isDefenderFeed(f) ? (
    <Tooltip content="Managed by the Microsoft Defender integration (Settings → Microsoft Defender)">
      <Badge tone="info" icon={ShieldHalf}>
        Defender
      </Badge>
    </Tooltip>
  ) : f.builtin ? (
    <Badge tone="neutral">Built-in</Badge>
  ) : f.format === 'taxii21' || f.format === 'misp' ? (
    <Badge tone="violet">{f.format === 'misp' ? 'MISP' : 'TAXII'}</Badge>
  ) : (
    <Badge tone="accent">Custom</Badge>
  );

/** /threats/feeds — built-in and custom threat-intelligence feeds. */
export const FeedsTab: React.FC = () => {
  const d = useThreatData();
  const { run, pending } = useAction();
  const confirm = useConfirm();
  const toast = useToast();
  const { refresh } = useConsole();
  const later = useDelayedRefresh();
  const [editing, setEditing] = useState<ThreatFeed | null | undefined>(undefined);

  const feeds = useMemo(() => [...d.feeds].sort((a, b) => Number(b.enabled) - Number(a.enabled) || Number(b.builtin) - Number(a.builtin) || a.name.localeCompare(b.name)), [d.feeds]);

  const toggle = async (f: ThreatFeed) => {
    const r = await run(() => api.security.upsertFeed(feedPayload(f, { enabled: !f.enabled })), {
      key: `toggle:${f.id}`,
      success: f.enabled ? `Disabled “${f.name}”` : `Enabled “${f.name}” — first download scheduled`,
      errorTitle: 'The feed could not be changed',
    });
    if (r && !f.enabled) later();
  };

  const refreshFeed = async (f?: ThreatFeed) => {
    const r = await run(() => api.security.refreshFeeds(f?.id), {
      key: f ? `refresh:${f.id}` : 'refresh-all',
      success: f ? `Refresh scheduled for “${f.name}”` : 'Refresh scheduled for all enabled feeds',
      errorTitle: 'The refresh could not be scheduled',
    });
    if (r) later();
  };

  const remove = (f: ThreatFeed) =>
    confirm({
      title: `Delete feed “${f.name}”?`,
      description: 'Its entries are removed from the threat-intel snapshot on the next compile.',
      tone: 'danger',
      confirmLabel: 'Delete feed',
      onConfirm: async () => {
        await api.security.deleteFeed(f.id);
        toast.success(`Deleted feed “${f.name}”`);
        await refresh();
      },
    });

  const statusCell = (f: ThreatFeed) => {
    if (!f.enabled) return <span className="text-[12.5px] text-fg-subtle">Not downloaded</span>;
    if (f.last_error)
      return (
        <Tooltip content={<span className="break-words">{f.last_error}</span>}>
          <Badge tone="danger" icon={AlertTriangle}>
            Failed
          </Badge>
        </Tooltip>
      );
    if (!f.last_success_at) return <Badge tone="warning">Pending</Badge>;
    return <Badge tone="success" dot>Current</Badge>;
  };

  const columns: Column<ThreatFeed>[] = [
    {
      id: 'name',
      header: 'Feed',
      sortValue: (f) => f.name.toLowerCase(),
      cell: (f) => (
        <div className="min-w-0 max-w-[420px]">
          <div className="flex flex-wrap items-center gap-1.5">
            <button
              type="button"
              className="text-left font-medium text-fg hover:text-accent hover:underline disabled:no-underline disabled:hover:text-fg"
              disabled={!d.canManage && !isDefenderFeed(f)}
              onClick={() => setEditing(f)}
            >
              {f.name}
            </button>
            <SourceBadge feed={f} />
            {f.has_auth_value && (
              <Tooltip content={`Authenticated with the ${f.auth_header_name || 'auth'} header`}>
                <Badge tone="success" icon={KeyRound}>
                  Key
                </Badge>
              </Tooltip>
            )}
          </div>
          {f.description && <p className="mt-0.5 line-clamp-1 text-[12px] leading-5 text-fg-muted" title={f.description}>{f.description}</p>}
          <p className="mt-0.5 truncate font-mono text-[11.5px] text-fg-subtle" title={f.url}>
            {f.url}
          </p>
        </div>
      ),
    },
    {
      id: 'kind',
      header: 'Category',
      hideBelow: 'xl',
      sortValue: (f) => f.category,
      cell: (f) => (
        <div className="max-w-[200px] leading-tight">
          <div className="text-[13px] text-fg">{categoryLabel(f.category)}</div>
          <div className="mt-0.5 text-[12px] text-fg-subtle">
            {feedFormatLabel(f.format)}
            {f.lookback_days ? ` · ${f.lookback_days} days` : ''}
            {f.license && !RESTRICTIVE_LICENSE.test(f.license) ? ` · ${f.license}` : ''}
          </div>
          {RESTRICTIVE_LICENSE.test(f.license || '') && (
            <Tooltip content="Restricts commercial use — check the terms before enabling.">
              <Badge tone="warning" icon={AlertTriangle} className="mt-1">
                {f.license}
              </Badge>
            </Tooltip>
          )}
        </div>
      ),
    },
    {
      id: 'entries',
      header: 'Entries',
      align: 'right',
      width: 80,
      sortValue: (f) => f.entry_count || 0,
      cell: (f) => <span className="tabular text-fg">{formatNumber(f.entry_count || 0)}</span>,
    },
    {
      id: 'updated',
      header: 'Last download',
      width: 140,
      sortValue: (f) => f.last_success_at || '',
      cell: (f) => (
        <div className="space-y-1 leading-tight">
          {statusCell(f)}
          {f.last_success_at && (
            <div className="text-[12px] text-fg-subtle">
              <RelativeTime value={f.last_success_at} />
              {f.refresh_minutes ? ` · every ${f.refresh_minutes >= 60 && f.refresh_minutes % 60 === 0 ? `${f.refresh_minutes / 60}h` : `${f.refresh_minutes}m`}` : ''}
            </div>
          )}
        </div>
      ),
    },
    {
      id: 'enabled',
      header: 'Enabled',
      width: 76,
      sortValue: (f) => (f.enabled ? 0 : 1),
      cell: (f) => (
        <Tooltip content={isDefenderFeed(f) ? 'Turned on and off with the Defender integration' : d.canManage ? (f.enabled ? 'Disable feed' : 'Enable feed') : 'Only InfoSec can change feeds'}>
          <span className="inline-flex">
            <Switch checked={f.enabled} onChange={() => toggle(f)} disabled={!d.canManage || isDefenderFeed(f) || pending === `toggle:${f.id}`} />
          </span>
        </Tooltip>
      ),
    },
    {
      id: 'actions',
      header: <span className="sr-only">Actions</span>,
      width: 52,
      align: 'right',
      hideOnMobile: true,
      cell: (f) =>
        d.canManage ? (
          <Menu
            items={[
              { id: 'refresh', label: 'Refresh now', icon: RefreshCw, disabled: !f.enabled, description: f.enabled ? undefined : 'Enable the feed first', onSelect: () => refreshFeed(f) },
              { id: 'edit', label: isDefenderFeed(f) ? 'Details' : 'Edit', icon: isDefenderFeed(f) ? Eye : Pencil, onSelect: () => setEditing(f) },
              { id: 'delete', label: 'Delete', icon: Trash2, danger: true, hidden: f.builtin, separator: true, onSelect: () => remove(f) },
            ]}
            trigger={(p) => <IconButton {...p} icon={MoreHorizontal} label={`Actions for ${f.name}`} size="sm" noTooltip loading={pending === `refresh:${f.id}`} />}
          />
        ) : null,
    },
  ];

  return (
    <div className="space-y-5">
      <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <p className="max-w-3xl text-[13px] leading-6 text-fg-muted">
          The control plane downloads enabled feeds, compiles them with your custom indicators and exceptions into a versioned snapshot, and every worker enforces it
          {d.policy ? (
            <>
              {' '}in <ModeBadge mode={d.policy.threat_intel_mode} className="align-middle" /> mode
            </>
          ) : null}
          .
        </p>
        {d.canManage && (
          <div className="flex shrink-0 flex-wrap gap-2">
            <Button icon={RefreshCw} loading={pending === 'refresh-all'} onClick={() => refreshFeed()}>
              Refresh all
            </Button>
            <Button variant="primary" icon={Plus} onClick={() => setEditing(null)}>
              Add feed
            </Button>
          </div>
        )}
      </div>
      {!d.canManage && <Callout tone="neutral">Only InfoSec Approvers and Super Admins can change feeds.</Callout>}
      <Callout tone="warning" title="Check licenses before enabling feeds">
        Some built-in feeds ship disabled because their license restricts commercial use or because they are very large. abuse.ch exports need an account key — add them as
        custom feeds with the Auth-Key header. Internal threat-intel platforms connect as TAXII 2.1 collections or MISP instances.
      </Callout>
      <DataTable
        aria-label="Threat feeds"
        rows={feeds}
        columns={columns}
        getRowId={(f) => f.id}
        getSearchText={(f) => `${f.name} ${f.description} ${f.url} ${f.category} ${f.license}`}
        searchPlaceholder="Search feeds…"
        facets={[
          {
            id: 'source',
            label: 'Source',
            getValue: (f) => (isDefenderFeed(f) ? 'defender' : f.builtin ? 'builtin' : f.format === 'taxii21' || f.format === 'misp' ? 'structured' : 'custom'),
            options: [
              { value: 'builtin', label: 'Built-in' },
              { value: 'custom', label: 'Custom list' },
              { value: 'structured', label: 'TAXII / MISP' },
              { value: 'defender', label: 'Microsoft Defender' },
            ],
          },
          { id: 'state', label: 'State', getValue: (f) => (f.enabled ? 'enabled' : 'disabled'), options: [{ value: 'enabled', label: 'Enabled' }, { value: 'disabled', label: 'Disabled' }] },
        ]}
        rowClassName={(f) => (f.enabled ? undefined : 'opacity-75')}
        mobileCard={(f) => (
          <div className="min-w-0 space-y-2">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <button type="button" className="text-left font-medium text-fg" disabled={!d.canManage && !isDefenderFeed(f)} onClick={() => setEditing(f)}>
                  {f.name}
                </button>
                <div className="mt-0.5 flex flex-wrap gap-1">
                  <SourceBadge feed={f} />
                  {RESTRICTIVE_LICENSE.test(f.license || '') && <Badge tone="warning">Restricted license</Badge>}
                </div>
              </div>
              <Switch checked={f.enabled} onChange={() => toggle(f)} disabled={!d.canManage || isDefenderFeed(f) || pending === `toggle:${f.id}`} />
            </div>
            <p className="truncate font-mono text-[11.5px] text-fg-subtle">{f.url}</p>
            <div className="flex flex-wrap items-center gap-2 text-[12px] text-fg-muted">
              {statusCell(f)}
              <span className="tabular">{formatNumber(f.entry_count || 0)} entries</span>
              {d.canManage && f.enabled && (
                <Button size="xs" variant="ghost" icon={RefreshCw} loading={pending === `refresh:${f.id}`} onClick={() => refreshFeed(f)}>
                  Refresh
                </Button>
              )}
            </div>
          </div>
        )}
        empty={<EmptyState icon={Database} title="No feeds configured" description="Add a blocklist URL, a TAXII 2.1 collection or a MISP instance." />}
      />
      <FeedDrawer open={editing !== undefined} feed={editing} onClose={() => setEditing(undefined)} onSaved={later} />
    </div>
  );
};
