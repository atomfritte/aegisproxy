import React, { useMemo, useState } from 'react';
import { ArrowRight, Link2, Link2Off, ShieldCheck } from 'lucide-react';
import { useConsoleState } from '../../../data/AppData';
import { cn } from '../../../lib/cn';
import { formatDateTime } from '../../../lib/format';
import type { AuditEvent } from '../../../types';
import {
  Badge,
  ButtonLink,
  Callout,
  CodeBlock,
  CopyButton,
  DescriptionList,
  Drawer,
  RelativeTime,
  SegmentedControl,
  StatusChip,
  Tooltip,
} from '../../../ui';
import { ChipList, GroupChip, UserName } from '../../../components/common/EntityChips';
import { actionLabel, actionTone, categoryMeta, entityHref, entityLabel, roleLabel } from './auditMeta';
import { arrayDelta, diffStates, FieldChange, pretty } from './jsonDiff';

const HashRow: React.FC<{ label: string; value?: string }> = ({ label, value }) => (
  <div className="min-w-0">
    <div className="text-[12px] font-medium text-fg-subtle">{label}</div>
    {value ? (
      <div className="mt-1 flex min-w-0 items-center gap-1">
        <code className="min-w-0 flex-1 truncate rounded-md border border-border bg-surface-2 px-2 py-1 font-mono text-[11.5px] text-fg" title={value}>
          {value}
        </code>
        <CopyButton text={value} label={`Copy ${label.toLowerCase()}`} size="xs" />
      </div>
    ) : (
      <div className="mt-1 text-[12.5px] text-fg-subtle">—</div>
    )}
  </div>
);

const ChangeRow: React.FC<{ c: FieldChange; mode: 'diff' | 'created' | 'deleted' }> = ({ c, mode }) => {
  const valueCls = 'min-w-0 whitespace-pre-wrap break-all rounded-md px-2 py-1 font-mono text-[12px] leading-5';
  const delta = mode === 'diff' && c.kind === 'changed' ? arrayDelta(c.before, c.after) : null;
  return (
    <li className="px-3 py-2.5">
      <div className="flex items-center gap-2">
        <span className="min-w-0 break-all font-mono text-[12px] font-medium text-fg-muted">{c.path}</span>
        {mode === 'diff' && c.kind !== 'same' && c.kind !== 'changed' && (
          <Badge tone={c.kind === 'added' ? 'success' : 'danger'} className="h-[18px]! text-[10.5px]">
            {c.kind === 'added' ? 'Added' : 'Removed'}
          </Badge>
        )}
      </div>
      {mode === 'created' || c.kind === 'same' ? (
        <div className={cn(valueCls, 'mt-1 bg-surface-2 text-fg')}>{(mode === 'deleted' ? c.before : c.after ?? c.before) || '""'}</div>
      ) : mode === 'deleted' ? (
        <div className={cn(valueCls, 'mt-1 bg-danger-soft text-fg')}>{c.before || '""'}</div>
      ) : delta && c.kind === 'changed' ? (
        <ul className="mt-1 flex flex-wrap gap-1">
          {delta.map((d, i) => (
            <li
              key={`${d.kind}-${d.value}-${i}`}
              className={cn(
                'max-w-full break-all rounded-md px-1.5 py-0.5 font-mono text-[12px] leading-5',
                d.kind === 'added' ? 'bg-success-soft text-fg' : d.kind === 'removed' ? 'bg-danger-soft text-fg line-through decoration-danger/60' : 'bg-surface-2 text-fg-muted'
              )}
            >
              <span className={cn('mr-1 select-none', d.kind === 'added' ? 'text-success' : d.kind === 'removed' ? 'text-danger' : 'text-fg-subtle')} aria-hidden>
                {d.kind === 'added' ? '+' : d.kind === 'removed' ? '−' : '·'}
              </span>
              <span className="sr-only">{d.kind === 'added' ? 'Added: ' : d.kind === 'removed' ? 'Removed: ' : ''}</span>
              {d.value}
            </li>
          ))}
        </ul>
      ) : (
        <div className="mt-1 grid gap-1 sm:grid-cols-[1fr_auto_1fr] sm:items-start">
          <div className={cn(valueCls, 'bg-danger-soft text-fg', c.before === undefined && 'italic text-fg-subtle')}>
            <span className="mr-1 select-none text-danger" aria-hidden>
              −
            </span>
            {c.before ?? 'not set'}
          </div>
          <ArrowRight className="mx-auto hidden h-3.5 w-3.5 self-center text-fg-subtle sm:block" aria-hidden />
          <div className={cn(valueCls, 'bg-success-soft text-fg', c.after === undefined && 'italic text-fg-subtle')}>
            <span className="mr-1 select-none text-success" aria-hidden>
              +
            </span>
            {c.after ?? 'not set'}
          </div>
        </div>
      )}
    </li>
  );
};

/** Snapshot section: field-level diff (or recorded values) with a raw JSON view. */
const StateSection: React.FC<{ ev: AuditEvent }> = ({ ev }) => {
  const [view, setView] = useState<'fields' | 'raw'>('fields');
  const [showSame, setShowSame] = useState(false);
  const changes = useMemo(() => diffStates(ev.before_state, ev.after_state), [ev.before_state, ev.after_state]);
  const hasBefore = !!ev.before_state;
  const hasAfter = !!ev.after_state;
  if (!hasBefore && !hasAfter) {
    return <p className="text-[13px] text-fg-subtle">This event recorded no configuration snapshot. The summary above describes the change.</p>;
  }
  const mode: 'diff' | 'created' | 'deleted' = hasBefore && hasAfter ? 'diff' : hasAfter ? 'created' : 'deleted';
  const visible = (changes ?? []).filter((c) => mode !== 'diff' || showSame || c.kind !== 'same');
  const same = (changes ?? []).filter((c) => c.kind === 'same').length;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-[12.5px] text-fg-muted">
          {mode === 'diff'
            ? `${(changes ?? []).filter((c) => c.kind !== 'same').length} changed fields`
            : mode === 'created'
              ? 'Values recorded with this event'
              : 'State before this event'}
        </p>
        {changes && (
          <SegmentedControl
            size="sm"
            aria-label="Snapshot view"
            value={view}
            onChange={setView}
            options={[
              { value: 'fields', label: 'Fields' },
              { value: 'raw', label: 'Raw JSON' },
            ]}
          />
        )}
      </div>
      {changes && view === 'fields' ? (
        <>
          {visible.length === 0 ? (
            <p className="rounded-lg border border-border bg-surface-2 px-3 py-3 text-[12.5px] text-fg-subtle">No field differs between the two snapshots.</p>
          ) : (
            <ul className="divide-y divide-border overflow-hidden rounded-lg border border-border">
              {visible.map((c) => (
                <ChangeRow key={c.path} c={c} mode={mode} />
              ))}
            </ul>
          )}
          {mode === 'diff' && same > 0 && (
            <button type="button" className="text-[12.5px] font-medium text-accent hover:underline" onClick={() => setShowSame((s) => !s)}>
              {showSame ? 'Hide unchanged fields' : `Show ${same} unchanged fields`}
            </button>
          )}
        </>
      ) : (
        <div className="grid gap-3">
          {hasBefore && <CodeBlock title="Before" code={pretty(ev.before_state)} maxHeight={260} wrap />}
          {hasAfter && <CodeBlock title="After" code={pretty(ev.after_state)} maxHeight={260} wrap />}
        </div>
      )}
    </div>
  );
};

const Section: React.FC<{ title: React.ReactNode; aside?: React.ReactNode; children: React.ReactNode }> = ({ title, aside, children }) => (
  <section className="border-t border-border pt-5">
    <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
      <h3 className="text-[13.5px] font-semibold text-fg">{title}</h3>
      {aside}
    </div>
    {children}
  </section>
);

/** Detail panel of one audit event: who / what / when, snapshot diff, hash-chain link. */
export const AuditEventDrawer: React.FC<{ event: AuditEvent | null; events: AuditEvent[]; onClose: () => void }> = ({ event, events, onClose }) => {
  const state = useConsoleState();
  if (!event) return <Drawer open={false} onClose={onClose} title="">{null}</Drawer>;
  const ev = event;
  const cat = categoryMeta(ev.category);
  const link = entityHref(ev, state.rules ?? []);
  const idx = events.findIndex((e) => e.id === ev.id);
  const older = idx >= 0 && idx + 1 < events.length ? events[idx + 1] : null;
  const chain: 'linked' | 'mismatch' | 'unknown' | 'none' = !ev.event_hash
    ? 'none'
    : older
      ? older.event_hash && ev.prev_hash === older.event_hash
        ? 'linked'
        : 'mismatch'
      : 'unknown';

  return (
    <Drawer
      open
      onClose={onClose}
      width="lg"
      title={actionLabel(ev.action)}
      titleAside={
        <Badge tone={cat.tone} icon={cat.icon}>
          {cat.label}
        </Badge>
      }
      description={ev.summary}
      footer={
        link ? (
          <ButtonLink to={link.to} variant="primary" iconRight={ArrowRight} onClick={onClose}>
            {link.label}
          </ButtonLink>
        ) : undefined
      }
    >
      <div className="space-y-5">
        <DescriptionList
          items={[
            {
              label: 'When',
              value: (
                <span>
                  {formatDateTime(ev.timestamp)} <span className="text-fg-subtle">(<RelativeTime value={ev.timestamp} />)</span>
                </span>
              ),
            },
            {
              label: 'Actor',
              value: (
                <span className="flex min-w-0 flex-wrap items-center gap-2">
                  <UserName username={ev.actor} />
                  {ev.actor_role && <span className="text-[12px] text-fg-subtle">{roleLabel(ev.actor_role)}</span>}
                </span>
              ),
            },
            {
              label: entityLabel(ev.entity_type),
              value: (
                <span className="block min-w-0">
                  <span className="block break-words font-medium">{ev.entity_name || ev.entity_id || '—'}</span>
                  {ev.entity_id && ev.entity_id !== ev.entity_name && <span className="block break-all font-mono text-[11.5px] text-fg-subtle">{ev.entity_id}</span>}
                </span>
              ),
            },
            {
              label: 'Action',
              value: (
                <span className="flex flex-wrap items-center gap-2">
                  <Badge tone={actionTone(ev.action)}>{actionLabel(ev.action)}</Badge>
                  <span className="font-mono text-[11.5px] text-fg-subtle">{ev.action}</span>
                </span>
              ),
            },
            {
              label: 'Revision',
              value: (
                <Tooltip content="Configuration revision after this change">
                  <span className="font-mono tabular">#{ev.revision}</span>
                </Tooltip>
              ),
            },
            {
              label: 'Event ID',
              value: (
                <span className="flex min-w-0 items-center gap-1">
                  <span className="truncate font-mono text-[12px]">{ev.id}</span>
                  <CopyButton text={ev.id} label="Copy event ID" size="xs" />
                </span>
              ),
            },
            {
              label: 'Affected groups',
              full: true,
              hidden: !(ev.scope_groups ?? []).length,
              value: (
                <ChipList max={8}>
                  {(ev.scope_groups ?? []).map((g) =>
                    g === '*' ? (
                      <Badge key={g} tone="violet">
                        All groups
                      </Badge>
                    ) : (
                      <GroupChip key={g} id={g} />
                    )
                  )}
                </ChipList>
              ),
            },
          ]}
        />

        {ev.entity_type === 'policy_set' && (
          <Callout tone="info" title="Roll back from the version history">
            Policy sets keep their last 30 published versions. Compare versions and roll back on the policy set's History tab.
          </Callout>
        )}

        <Section title="Configuration snapshot">
          <StateSection ev={ev} />
        </Section>

        <Section
          title="Hash chain"
          aside={
            chain === 'linked' ? (
              <StatusChip tone="success" icon={Link2} label="Linked to previous event" />
            ) : chain === 'mismatch' ? (
              <StatusChip tone="danger" icon={Link2Off} label="Does not match previous event" />
            ) : chain === 'unknown' ? (
              <StatusChip tone="neutral" label="Previous event not loaded" />
            ) : (
              <StatusChip tone="neutral" label="Not hashed" />
            )
          }
        >
          <div className="space-y-3">
            <p className="flex items-start gap-2 text-[12.5px] leading-5 text-fg-muted">
              <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-fg-subtle" aria-hidden />
              Each event stores the SHA-256 hash of its predecessor, so removing or editing an entry breaks the chain. Use “Verify hash chain” to check the
              whole ledger on the server.
            </p>
            <HashRow label="Event hash" value={ev.event_hash} />
            <HashRow label="Previous hash" value={ev.prev_hash} />
          </div>
        </Section>
      </div>
    </Drawer>
  );
};
