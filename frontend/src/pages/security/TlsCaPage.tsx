import React, { useState } from 'react';
import { Download, Lock, LockOpen, Plus, Trash2 } from 'lucide-react';
import { api } from '../../api';
import { useAction, useConsole, useConsoleState, usePermissions } from '../../data/AppData';
import { formatDateTime, toTime } from '../../lib/format';
import { useDocumentTitle, useNow } from '../../lib/hooks';
import { useUrlFilters } from '../../lib/useUrlFilters';
import type { TLSBypassRule } from '../../types';
import {
  Badge,
  Button,
  Callout,
  Column,
  CountdownChip,
  DataTable,
  EmptyState,
  IconButton,
  PageHeader,
  PatternText,
  RelativeTime,
  Switch,
  Tooltip,
  useConfirm,
  useToast,
  buttonClass,
} from '../../ui';
import { AllServersChip, ChipList, GroupChip, ServerChip, UserName } from '../../components/common/EntityChips';
import { RootCaCard } from './tls/RootCaCard';
import { TlsExceptionDrawer } from './tls/TlsExceptionDrawer';

const FILTERS = ['status', 'category', 'scope'];

function isExpired(t: TLSBypassRule, now: number): boolean {
  const e = toTime(t.expires_at);
  return e !== null && e < now;
}

function statusOf(t: TLSBypassRule, now: number): 'active' | 'disabled' | 'expired' {
  if (isExpired(t, now)) return 'expired';
  return t.enabled ? 'active' : 'disabled';
}

const ScopeChips: React.FC<{ t: TLSBypassRule; max?: number }> = ({ t, max = 3 }) => {
  const g = t.group_ids ?? [];
  const s = t.server_ids ?? [];
  if (g.length === 0 && s.length === 0) return <AllServersChip />;
  return <ChipList max={max}>{[...g.map((id) => <GroupChip key={`g-${id}`} id={id} />), ...s.map((id) => <ServerChip key={`s-${id}`} id={id} />)]}</ChipList>;
};

/** TLS no-break exceptions and the enterprise root CA. */
export const TlsCaPage: React.FC = () => {
  useDocumentTitle('TLS & CA');
  const state = useConsoleState();
  const perms = usePermissions();
  const confirm = useConfirm();
  const toast = useToast();
  const { refresh } = useConsole();
  const { run, pending } = useAction();
  const now = useNow();
  const f = useUrlFilters(FILTERS);
  const [adding, setAdding] = useState(false);
  const rows = state.tls_bypass ?? [];
  const canEdit = perms.canManageSystem;

  const toggle = (t: TLSBypassRule, enabled: boolean) =>
    run(() => api.tlsBypass.toggle(t.id, enabled), {
      key: `toggle:${t.id}`,
      success: enabled ? `${t.pattern} now passes through without decryption` : `${t.pattern} is inspected again`,
      errorTitle: 'Could not change the exception',
    });

  const remove = (t: TLSBypassRule) =>
    confirm({
      title: 'Delete TLS exception?',
      description: (
        <>
          Traffic to <span className="font-mono text-fg">{t.pattern}</span> will be decrypted and inspected again. Clients that pin certificates may fail.
        </>
      ),
      tone: 'danger',
      confirmLabel: 'Delete exception',
      onConfirm: () => api.tlsBypass.remove(t.id),
    }).then((ok) => {
      if (!ok) return;
      toast.success(`TLS exception for ${t.pattern} deleted`);
      refresh();
    });

  const columns: Column<TLSBypassRule>[] = [
    {
      id: 'pattern',
      header: 'Destination',
      width: '34%',
      sortValue: (t) => t.pattern.replace(/^\*\./, ''),
      cell: (t) => (
        <div className="min-w-0">
          <div className="flex min-w-0 items-center gap-2">
            <PatternText host={t.pattern} className="min-w-0" />
            {t.match_type === 'wildcard' && (
              <Tooltip content={`Every subdomain of ${t.pattern.replace(/^\*\./, '')}`}>
                <Badge tone="neutral" className="h-[18px]! text-[10.5px]">
                  Wildcard
                </Badge>
              </Tooltip>
            )}
          </div>
          {t.reason && <p className="mt-0.5 line-clamp-2 max-w-[520px] text-[12px] leading-5 text-fg-subtle">{t.reason}</p>}
        </div>
      ),
    },
    {
      id: 'category',
      header: 'Category',
      width: 170,
      hideBelow: 'xl',
      sortValue: (t) => t.category.toLowerCase(),
      cell: (t) => (t.category ? <span className="text-[12.5px] text-fg-muted">{t.category}</span> : <span className="text-fg-subtle">—</span>),
    },
    { id: 'scope', header: 'Applies to', width: '18%', cell: (t) => <ScopeChips t={t} max={2} /> },
    {
      id: 'expires',
      header: 'Expiry',
      width: 150,
      sortValue: (t) => toTime(t.expires_at) ?? Number.MAX_SAFE_INTEGER,
      cell: (t) => (t.expires_at ? <CountdownChip due={t.expires_at} kind="expiry" /> : <span className="text-[12.5px] text-fg-subtle">No expiry</span>),
    },
    {
      id: 'added',
      header: 'Added',
      width: 150,
      hideBelow: 'lg',
      sortValue: (t) => toTime(t.created_at) ?? 0,
      cell: (t) => (
        <div className="leading-tight">
          <UserName username={t.added_by} />
          <div className="mt-0.5 pl-6 text-[12px] text-fg-subtle">
            <RelativeTime value={t.created_at} />
          </div>
        </div>
      ),
    },
    {
      id: 'enabled',
      header: 'Pass through',
      width: 128,
      sortValue: (t) => statusOf(t, now),
      cell: (t) => {
        const expired = isExpired(t, now);
        return (
          <div className="flex items-center gap-2">
            <Tooltip content={!canEdit ? 'Only InfoSec Approvers and Super Admins can change exceptions' : expired ? 'Expired exceptions no longer apply' : undefined}>
              <Switch
                checked={t.enabled && !expired}
                disabled={!canEdit || expired || pending === `toggle:${t.id}`}
                onChange={(v) => toggle(t, v)}
              />
            </Tooltip>
            <span className="text-[12.5px] text-fg-muted">{expired ? 'Expired' : t.enabled ? 'On' : 'Off'}</span>
          </div>
        );
      },
    },
  ];
  if (canEdit) {
    columns.push({
      id: 'actions',
      header: <span className="sr-only">Actions</span>,
      width: 52,
      align: 'right',
      hideOnMobile: true,
      cell: (t) => <IconButton icon={Trash2} label={`Delete exception ${t.pattern}`} variant="danger-ghost" size="sm" onClick={() => remove(t)} />,
    });
  }

  const categories = [...new Set(rows.map((t) => t.category).filter(Boolean))].sort();
  const active = rows.filter((t) => statusOf(t, now) === 'active').length;

  return (
    <>
      <PageHeader
        title="TLS & CA"
        description="The proxy decrypts HTTPS with the enterprise root CA so rules can match paths and content can be scanned. Destinations that pin certificates or require mutual TLS pass through untouched."
        meta={
          <>
            <Badge tone="violet" icon={LockOpen}>
              {active} active {active === 1 ? 'exception' : 'exceptions'}
            </Badge>
            {rows.length > active && <span className="text-[12.5px] text-fg-subtle">{rows.length - active} disabled or expired</span>}
          </>
        }
        actions={
          <>
            <a href={api.public.caDownloadUrl('crt')} download="aegis-enterprise-ca.crt" className={buttonClass('secondary', 'md')}>
              <Download className="h-4 w-4 shrink-0" aria-hidden />
              Download root CA
            </a>
            {canEdit && (
              <Button variant="primary" icon={Plus} onClick={() => setAdding(true)}>
                Add exception
              </Button>
            )}
          </>
        }
      />

      <section aria-labelledby="tls-exceptions" className="mb-8">
        <div className="mb-3">
          <h2 id="tls-exceptions" className="text-[15px] font-semibold text-fg">
            TLS exceptions
          </h2>
          <p className="mt-0.5 text-[13px] text-fg-muted">
            The data plane checks the TLS ClientHello and skips decryption for matching hosts. Only host-level allow and block rules apply to this traffic.
          </p>
        </div>
        {!canEdit && (
          <Callout tone="neutral" className="mb-3">
            You can view the exceptions. Only InfoSec Approvers and Super Admins can add, pause or delete them.
          </Callout>
        )}
        <DataTable
          rows={rows}
          columns={columns}
          getRowId={(t) => t.id}
          getSearchText={(t) => `${t.pattern} ${t.category} ${t.reason} ${t.added_by}`}
          searchPlaceholder="Search hosts, reasons…"
          search={f.search}
          onSearchChange={f.setSearch}
          facetValues={f.values}
          onFacetChange={f.onChange}
          facets={[
            {
              id: 'status',
              label: 'Status',
              getValue: (t) => statusOf(t, now),
              options: [
                { value: 'active', label: 'Active' },
                { value: 'disabled', label: 'Turned off' },
                { value: 'expired', label: 'Expired' },
              ],
            },
            { id: 'category', label: 'Category', getValue: (t) => t.category, options: categories.map((c) => ({ value: c, label: c })) },
            {
              id: 'scope',
              label: 'Applies to',
              getValue: (t) => ((t.group_ids ?? []).length || (t.server_ids ?? []).length ? ['scoped', ...(t.group_ids ?? [])] : ['global']),
              options: [
                { value: 'global', label: 'All servers' },
                { value: 'scoped', label: 'Selected groups or servers' },
                ...(state.groups ?? []).map((g) => ({ value: g.id, label: g.name })),
              ],
            },
          ]}
          initialSort={{ id: 'pattern', dir: 'asc' }}
          mobileCard={(t) => (
            <div className="min-w-0 space-y-2">
              <div className="flex items-start justify-between gap-3">
                <PatternText host={t.pattern} wrap className="min-w-0" />
                <Switch checked={t.enabled && !isExpired(t, now)} disabled={!canEdit || isExpired(t, now)} onChange={(v) => toggle(t, v)} />
              </div>
              {t.reason && <p className="line-clamp-2 text-[12.5px] text-fg-muted">{t.reason}</p>}
              <div className="flex flex-wrap items-center gap-1.5">
                {t.category && <Badge tone="neutral">{t.category}</Badge>}
                {t.expires_at && <CountdownChip due={t.expires_at} kind="expiry" />}
                <ScopeChips t={t} max={2} />
              </div>
              <div className="flex items-center justify-between gap-2 text-[12px] text-fg-subtle">
                <span className="truncate">
                  Added by {t.added_by || '—'} · {formatDateTime(t.created_at)}
                </span>
                {canEdit && (
                  <Button size="xs" variant="danger-ghost" icon={Trash2} onClick={() => remove(t)}>
                    Delete
                  </Button>
                )}
              </div>
            </div>
          )}
          empty={
            <EmptyState
              icon={Lock}
              title="Every HTTPS connection is inspected"
              description="Add an exception only for destinations that break under inspection, such as certificate-pinned update agents or mutual-TLS APIs."
              action={
                canEdit ? (
                  <Button variant="primary" icon={Plus} onClick={() => setAdding(true)}>
                    Add exception
                  </Button>
                ) : undefined
              }
            />
          }
          aria-label="TLS exceptions"
        />
      </section>

      <RootCaCard />

      {canEdit && <TlsExceptionDrawer open={adding} onClose={() => setAdding(false)} />}
    </>
  );
};
