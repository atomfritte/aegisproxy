import React, { useMemo, useState } from 'react';
import { Download, History, ShieldCheck } from 'lucide-react';
import { api } from '../../api';
import { useConsoleState, usePermissions } from '../../data/AppData';
import { useLookups } from '../../data/lookups';
import { cn } from '../../lib/cn';
import { formatDateTime, formatNumber, pluralize, toTime } from '../../lib/format';
import { useDocumentTitle, useNow } from '../../lib/hooks';
import { Link, useQueryParam } from '../../lib/router';
import { useUrlFilters } from '../../lib/useUrlFilters';
import type { AuditEvent, AuditVerifyResult } from '../../types';
import {
  Avatar,
  Badge,
  Button,
  buttonClass,
  Callout,
  Column,
  ConfirmDialog,
  DataTable,
  EmptyState,
  Field,
  Input,
  PageHeader,
  RelativeTime,
  SegmentedControl,
  Tooltip,
  useToast,
} from '../../ui';
import { UserName } from '../../components/common/EntityChips';
import { AuditEventDrawer } from './audit/AuditEventDrawer';
import {
  actionLabel,
  actionTone,
  CATEGORY_META,
  CATEGORY_ORDER,
  categoryMeta,
  entityHref,
  entityLabel,
  RANGE_MS,
  roleLabel,
  TimeRange,
} from './audit/auditMeta';
import { TeamLeadScopeNotice } from '../../components/common/ScopeNotice';

const FILTERS = ['category', 'actor', 'entity', 'action'];
const RANGES: Array<{ value: TimeRange; label: string }> = [
  { value: '24h', label: '24h' },
  { value: '7d', label: '7 days' },
  { value: '30d', label: '30 days' },
  { value: 'all', label: 'All' },
];

/** Hash-chained audit trail: filters (URL), integrity check, JSONL export, event details. */
export const AuditTrailPage: React.FC = () => {
  useDocumentTitle('Audit trail');
  const state = useConsoleState();
  const { userName } = useLookups();
  const toast = useToast();
  const now = useNow();
  const f = useUrlFilters(FILTERS);
  const [rangeParam, setRange] = useQueryParam('range', 'all');
  const range = (RANGES.some((r) => r.value === rangeParam) ? rangeParam : 'all') as TimeRange;
  const [eventId, setEventId] = useQueryParam('event');
  const [verifying, setVerifying] = useState(false);
  const [verify, setVerify] = useState<(AuditVerifyResult & { at: string }) | null>(null);
  const legacyEvents = verify?.legacy_events ?? 0;
  const perms = usePermissions();
  const [accepting, setAccepting] = useState(false);
  const [acceptCount, setAcceptCount] = useState('');
  const [acceptHead, setAcceptHead] = useState('');

  const events = state.audit_events ?? [];
  const rules = state.rules ?? [];

  const inRange = useMemo(() => {
    if (range === 'all') return events;
    const min = now - RANGE_MS[range];
    return events.filter((e) => (toTime(e.timestamp) ?? 0) >= min);
  }, [events, range, now]);

  const counts = useMemo(() => {
    const c = new Map<string, number>();
    for (const e of inRange) c.set(e.category, (c.get(e.category) || 0) + 1);
    return c;
  }, [inRange]);

  const selected = eventId ? events.find((e) => e.id === eventId) ?? null : null;

  const runVerify = async () => {
    setVerifying(true);
    try {
      const r = await api.audit.verify();
      setVerify({ ...r, at: new Date().toISOString() });
      if (r.valid && (r.legacy_events ?? 0) > 0)
        toast.warning(`Hash chain intact`, {
          description: `${formatNumber(r.events_checked)} events checked, ${formatNumber(r.legacy_events ?? 0)} of them legacy (unkeyed).`,
        });
      else if (r.valid) toast.success(`Hash chain intact`, { description: `${formatNumber(r.events_checked)} events checked.` });
    } catch (err) {
      toast.error(err, { title: 'Verification failed' });
    } finally {
      setVerifying(false);
    }
  };

  const openAccept = () => {
    setAcceptCount('');
    setAcceptHead('');
    setAccepting(true);
  };

  // The values come from the operator's archived copy (export taken before the upgrade, SIEM); the
  // server accepts only an exact match with the sealed prefix.
  const acceptLegacy = async () => {
    const n = Number(acceptCount.trim());
    if (acceptCount.trim() === '' || !Number.isInteger(n) || n < 0) throw new Error('Enter the number of legacy events in your archived copy.');
    if (!/^[0-9a-f]{64}$/i.test(acceptHead.trim())) throw new Error('Enter the event_hash of the last legacy event (64 hex characters).');
    const r = await api.audit.acceptLegacy(n, acceptHead.trim().toLowerCase());
    setVerify({ ...r, at: new Date().toISOString() });
  };

  const catFilter = f.values.category;
  const toggleCategory = (c: string) => f.onChange('category', catFilter.includes(c) ? catFilter.filter((x) => x !== c) : [...catFilter, c]);

  const columns: Column<AuditEvent>[] = [
    {
      id: 'time',
      header: 'When',
      width: 132,
      sortValue: (e) => toTime(e.timestamp) ?? 0,
      cell: (e) => (
        <div className="leading-tight">
          <RelativeTime value={e.timestamp} className="text-fg" />
          <div className="mt-0.5 font-mono text-[11.5px] text-fg-subtle">#{e.revision}</div>
        </div>
      ),
    },
    {
      id: 'event',
      header: 'Event',
      cell: (e) => {
        const cat = categoryMeta(e.category);
        return (
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-1.5">
              <button type="button" onClick={() => setEventId(e.id)} className="text-left font-medium text-fg hover:text-accent hover:underline">
                {actionLabel(e.action)}
              </button>
              <Badge tone={cat.tone} icon={cat.icon} className="h-[20px]! text-[11px]">
                {cat.label}
              </Badge>
            </div>
            <p className="mt-0.5 line-clamp-2 max-w-[640px] text-[12.5px] leading-5 text-fg-muted">{e.summary}</p>
          </div>
        );
      },
    },
    {
      id: 'entity',
      header: 'Target',
      width: '24%',
      sortValue: (e) => (e.entity_name || e.entity_id || '').toLowerCase(),
      cell: (e) => {
        const link = entityHref(e, rules);
        const name = e.entity_name || e.entity_id || '—';
        return (
          <div className="min-w-0">
            {link ? (
              <Link to={link.to} className="block truncate font-medium text-fg hover:text-accent hover:underline" title={link.label}>
                {name}
              </Link>
            ) : (
              <span className="block truncate text-fg" title={name}>
                {name}
              </span>
            )}
            <span className="text-[12px] text-fg-subtle">{entityLabel(e.entity_type)}</span>
          </div>
        );
      },
    },
    {
      id: 'actor',
      header: 'Actor',
      width: 190,
      hideBelow: 'lg',
      sortValue: (e) => e.actor.toLowerCase(),
      cell: (e) => (
        <div className="min-w-0 leading-tight">
          <UserName username={e.actor} className="max-w-full" />
          {e.actor_role && <div className="mt-0.5 truncate pl-6 text-[11.5px] text-fg-subtle">{roleLabel(e.actor_role)}</div>}
        </div>
      ),
    },
  ];

  const actors = [...new Set(events.map((e) => e.actor))].sort();
  const entityTypes = [...new Set(events.map((e) => e.entity_type).filter(Boolean))].sort((a, b) => entityLabel(a).localeCompare(entityLabel(b)));

  return (
    <>
      <PageHeader
        title="Audit trail"
        description="Every change, approval and sign-in, chained with SHA-256 hashes so tampering is detectable. Export the ledger as JSON Lines for your archive or SIEM."
        meta={
          <>
            <Badge tone="neutral" icon={History}>
              {pluralize(events.length, 'event')}
            </Badge>
            {state.revision ? <span className="text-[12.5px] text-fg-subtle">Configuration revision #{state.revision}</span> : null}
          </>
        }
        actions={
          <>
            <Button icon={ShieldCheck} loading={verifying} onClick={runVerify}>
              Verify hash chain
            </Button>
            <Tooltip content="Streams every audit event ever recorded (not only the latest 2,000 shown here) as JSON Lines">
              <a href={api.audit.exportUrl()} download className={buttonClass('secondary', 'md')} data-testid="audit-export">
                <Download className="h-4 w-4 shrink-0" aria-hidden />
                Export full audit trail (JSONL)
              </a>
            </Tooltip>
          </>
        }
      />
      <TeamLeadScopeNotice what="the audit events" className="mb-5" />

      {verify && (
        <Callout
          tone={verify.legacy_pending ? 'warning' : !verify.valid ? 'danger' : legacyEvents > 0 ? 'warning' : 'success'}
          className="mb-5"
          title={verify.legacy_pending ? 'Legacy events await acceptance' : verify.valid ? 'Hash chain intact' : 'Hash chain broken'}
          action={
            <div className="flex flex-wrap gap-2">
              {verify.legacy_pending && perms.isSuperAdmin && (
                <Button size="sm" variant="secondary" onClick={openAccept}>
                  Review and accept…
                </Button>
              )}
              <Button size="sm" variant="ghost" onClick={() => setVerify(null)}>
                Dismiss
              </Button>
            </div>
          }
        >
          {verify.legacy_pending ? (
            <>
              {formatNumber(legacyEvents)} events at the start of the trail use the unkeyed hash from before 2.1, which anyone with access to the data can
              recompute. The trail is not trusted — verification and the security posture fail — until a Super Admin compares these events with an independent
              copy (the trail exported before the upgrade, your SIEM) and accepts them. Last legacy event:{' '}
              <code className="break-all font-mono text-[12px]">{verify.legacy_head}</code>.
              {!perms.isSuperAdmin && ' Ask a Super Admin to review them.'} If no such copy exists or it differs, restore the data from a backup instead.
            </>
          ) : verify.valid ? (
            `All ${formatNumber(verify.events_checked)} events link to their predecessor${
              verify.starts_at_genesis === false ? ', starting at the sealed retention point' : ' from the first event'
            } up to the newest one${
              verify.checkpoint_matches ? ', which matches the sealed head checkpoint (event count and configuration revision)' : ''
            }. Checked ${formatDateTime(verify.at)}.${
              legacyEvents > 0
                ? ` ${formatNumber(legacyEvents)} legacy events from before 2.1 use the unkeyed hash, which anyone can recompute: a Super Admin accepted them after comparing them with an independent copy — keep that copy as evidence.`
                : ''
            }`
          ) : (
            `The chain breaks after ${formatNumber(verify.events_checked)} events${verify.error ? `: ${verify.error}` : ''}. Export the ledger and compare it with your archived copy; a recorded integrity violation stays until the data is restored from a backup.`
          )}
        </Callout>
      )}

      <ConfirmDialog
        open={accepting}
        onClose={() => setAccepting(false)}
        tone="danger"
        title="Accept the legacy audit events?"
        description="Only accept events you compared with an independent copy. The acceptance is recorded in the audit trail and raises a high-severity security alert."
        body={
          <>
            <div className="rounded-md border border-border bg-surface-2 p-3 text-[12.5px] leading-5 text-fg-muted">
              The control-plane holds <strong className="text-fg">{formatNumber(legacyEvents)}</strong> legacy events; the last one has the hash
              <code className="mt-1 block break-all font-mono text-[12px] text-fg">{verify?.legacy_head}</code>
            </div>
            <Field label="Number of legacy events in your copy" required>
              <Input value={acceptCount} onChange={(e) => setAcceptCount(e.target.value)} inputMode="numeric" autoComplete="off" data-autofocus />
            </Field>
            <Field label="event_hash of the last legacy event in your copy" required>
              <Input value={acceptHead} onChange={(e) => setAcceptHead(e.target.value)} mono autoComplete="off" spellCheck={false} />
            </Field>
          </>
        }
        confirmLabel="Accept legacy events"
        onConfirm={acceptLegacy}
        onDone={() => toast.success('Legacy events accepted', { description: 'Recorded in the audit trail and raised as a security alert.' })}
      />

      <div className="scroll-thin -mx-1 mb-4 overflow-x-auto px-1 pb-1" role="group" aria-label="Filter by category">
        <div className="flex min-w-max gap-1.5">
          <button
            type="button"
            aria-pressed={catFilter.length === 0}
            onClick={() => f.onChange('category', [])}
            className={cn(
              'inline-flex h-8 items-center gap-1.5 rounded-full border px-3 text-[12.5px] font-medium transition-colors',
              catFilter.length === 0 ? 'border-accent bg-accent-soft text-accent' : 'border-border bg-surface text-fg-muted hover:border-border-strong hover:text-fg'
            )}
          >
            All
            <span className="tabular text-fg-subtle">{inRange.length}</span>
          </button>
          {CATEGORY_ORDER.filter((c) => c !== 'RULE' || counts.get(c)).map((c) => {
            const m = CATEGORY_META[c];
            const Icon = m.icon;
            const active = catFilter.includes(c);
            return (
              <Tooltip key={c} content={m.description}>
                <button
                  type="button"
                  aria-pressed={active}
                  onClick={() => toggleCategory(c)}
                  className={cn(
                    'inline-flex h-8 items-center gap-1.5 rounded-full border px-3 text-[12.5px] font-medium transition-colors',
                    active ? 'border-accent bg-accent-soft text-accent' : 'border-border bg-surface text-fg-muted hover:border-border-strong hover:text-fg'
                  )}
                >
                  <Icon className="h-3.5 w-3.5" aria-hidden />
                  {m.label}
                  <span className={cn('tabular', active ? 'text-accent' : 'text-fg-subtle')}>{counts.get(c) || 0}</span>
                </button>
              </Tooltip>
            );
          })}
        </div>
      </div>

      <DataTable
        rows={inRange}
        columns={columns}
        getRowId={(e) => e.id}
        onRowClick={(e) => setEventId(e.id)}
        rowClassName={(e) => (e.id === eventId ? 'bg-accent-soft/60' : undefined)}
        getSearchText={(e) => `${e.actor} ${userName(e.actor)} ${e.action} ${actionLabel(e.action)} ${e.entity_name} ${e.entity_id} ${e.summary} ${e.id}`}
        searchPlaceholder="Search summary, actor, entity…"
        search={f.search}
        onSearchChange={f.setSearch}
        facetValues={f.values}
        onFacetChange={f.onChange}
        facets={[
          {
            id: 'category',
            label: 'Category',
            getValue: (e) => e.category,
            options: CATEGORY_ORDER.map((c) => ({ value: c, label: CATEGORY_META[c].label })),
          },
          { id: 'actor', label: 'Actor', getValue: (e) => e.actor, options: actors.map((a) => ({ value: a, label: userName(a) === a ? a : `${userName(a)} (${a})` })) },
          { id: 'entity', label: 'Entity', getValue: (e) => e.entity_type, options: entityTypes.map((t) => ({ value: t, label: entityLabel(t) })) },
          { id: 'action', label: 'Action', getValue: (e) => e.action, optionLabel: actionLabel },
        ]}
        toolbar={
          <SegmentedControl<TimeRange>
            size="sm"
            aria-label="Time range"
            value={range}
            onChange={(v) => setRange(v)}
            options={RANGES}
          />
        }
        mobileCard={(e) => {
          const cat = categoryMeta(e.category);
          const link = entityHref(e, rules);
          return (
            <div className="min-w-0 space-y-1.5">
              <div className="flex items-start justify-between gap-2">
                <button type="button" onClick={() => setEventId(e.id)} className="min-w-0 text-left font-medium text-fg">
                  {actionLabel(e.action)}
                </button>
                <RelativeTime value={e.timestamp} className="shrink-0 text-[12px] text-fg-subtle" />
              </div>
              <p className="line-clamp-3 text-[12.5px] leading-5 text-fg-muted">{e.summary}</p>
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[12px] text-fg-subtle">
                <Badge tone={cat.tone} icon={cat.icon} className="h-[20px]! text-[11px]">
                  {cat.label}
                </Badge>
                <span className="inline-flex min-w-0 items-center gap-1.5">
                  <Avatar name={userName(e.actor)} size="xs" />
                  <span className="truncate">{e.actor}</span>
                </span>
                {link && (
                  <Link to={link.to} className="truncate font-medium text-accent hover:underline">
                    {e.entity_name || entityLabel(e.entity_type)}
                  </Link>
                )}
              </div>
            </div>
          );
        }}
        empty={
          <EmptyState
            icon={History}
            title={range === 'all' ? 'No audit events yet' : 'No events in this time range'}
            description={
              range === 'all'
                ? 'Changes to policy sets, approvals, fleet and settings appear here as soon as they happen.'
                : 'Choose a longer time range to see older events.'
            }
            action={
              range !== 'all' ? (
                <Button size="sm" onClick={() => setRange('all')}>
                  Show all events
                </Button>
              ) : undefined
            }
          />
        }
        aria-label="Audit events"
      />
      <p className="mt-3 text-[12px] leading-5 text-fg-subtle">
        This view shows the latest 2,000 events; the JSON Lines export contains the complete, hash-chained trail. To archive it continuously, stream the audit log to
        your SIEM with a{' '}
        <Link to="/settings/log-export" className="font-medium text-accent hover:underline">
          log export destination
        </Link>
        . Roll back policy changes from a policy set's History tab.
      </p>

      <AuditEventDrawer event={selected} events={events} onClose={() => setEventId(null)} />
    </>
  );
};

