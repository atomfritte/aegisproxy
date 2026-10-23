import React, { useEffect, useMemo, useState } from 'react';
import { ArrowLeft, FlaskConical, Layers, Pencil, Play, Radar, RefreshCw, Repeat, Square, Upload } from 'lucide-react';
import { api } from '../../api';
import { useAction, useConsole, useConsoleState, usePermissions } from '../../data/AppData';
import { cn } from '../../lib/cn';
import { formatDateTime, pluralize } from '../../lib/format';
import { useDocumentTitle, useIsMobile, useNow } from '../../lib/hooks';
import { Link, useQueryParam } from '../../lib/router';
import type { CompiledRuleCandidate, LearningSession } from '../../types';
import {
  Badge,
  Button,
  Callout,
  Card,
  CardHeader,
  Checkbox,
  CountdownChip,
  DescriptionList,
  EmptyState,
  IconButton,
  Menu,
  MethodList,
  PageHeader,
  PatternText,
  RelativeTime,
  SegmentedControl,
  StatusChip,
  Tooltip,
  useConfirm,
  useToast,
} from '../../ui';
import { UserName } from '../../components/common/EntityChips';
import { MembershipChip } from '../../components/fleet/FleetChips';
import { CandidateDrawer } from './CandidateDrawer';
import { PublishDialog } from './PublishDialog';
import { canManageSession, canStartOn, MODE_META, PHASE_META, SCENARIOS, sessionPhase, SessionPhase, setsFromSession } from './sessionUtils';
import { StartSessionDrawer } from './StartSessionDrawer';

type Filter = 'all' | 'recording' | 'review' | 'published';

/** /learning — sessions list, recording status, candidate review and publishing into policy sets. */
export const LearningSessionsPage: React.FC = () => {
  useDocumentTitle('Learning sessions');
  const state = useConsoleState();
  const perms = usePermissions();
  const now = useNow();
  const [selectedId, setSelectedId] = useQueryParam('session');
  const [filter, setFilter] = useState<Filter>('all');
  const [startOpen, setStartOpen] = useState(false);

  const sessions = useMemo(() => [...state.sessions].sort((a, b) => b.started_at.localeCompare(a.started_at)), [state.sessions]);
  const visible = sessions.filter((s) => {
    const p = sessionPhase(s, now);
    return filter === 'all' || (filter === 'recording' ? p === 'recording' : filter === 'review' ? p === 'ended' || p === 'stopped' : p === 'published');
  });
  const isMobile = useIsMobile();
  // desktop shows the newest session when none is chosen; phones start with the list
  const selected = sessions.find((s) => s.id === selectedId) ?? (!isMobile && !selectedId ? sessions[0] ?? null : null);
  const canStart = state.servers.some((s) => canStartOn(perms, s));
  const recording = sessions.filter((s) => sessionPhase(s, now) === 'recording').length;

  return (
    <>
      <PageHeader
        title="Learning sessions"
        description="Record what a reference server needs, review the compiled rule candidates, then publish them into a policy set."
        actions={
          canStart && (
            <Button variant="primary" icon={Play} onClick={() => setStartOpen(true)}>
              Start session
            </Button>
          )
        }
      />

      {sessions.length === 0 ? (
        <Card>
          <EmptyState
            icon={Radar}
            title="No learning sessions yet"
            description="Start a session on a reference server, run the workload (package installs, builds, model downloads) and turn the recorded traffic into rules."
            action={
              canStart && (
                <Button variant="primary" icon={Play} onClick={() => setStartOpen(true)}>
                  Start session
                </Button>
              )
            }
          />
        </Card>
      ) : (
        <div className="grid items-start gap-6 lg:grid-cols-[320px_minmax(0,1fr)]">
          <section aria-label="Sessions" className={cn('min-w-0 space-y-3', selected && 'hidden lg:block')}>
            <SegmentedControl<Filter>
              aria-label="Filter sessions"
              size="sm"
              value={filter}
              onChange={setFilter}
              className="flex w-full [&>button]:flex-auto [&>button]:justify-center [&>button]:whitespace-nowrap [&>button]:px-2"
              options={[
                { value: 'all', label: 'All' },
                { value: 'recording', label: recording ? `Recording · ${recording}` : 'Recording' },
                { value: 'review', label: 'To review' },
                { value: 'published', label: 'Published' },
              ]}
            />
            {visible.length === 0 ? (
              <p className="rounded-lg border border-dashed border-border-strong px-4 py-6 text-center text-[12.5px] text-fg-subtle">No sessions in this view.</p>
            ) : (
              <ul className="space-y-2">
                {visible.map((s) => (
                  <li key={s.id}>
                    <SessionListItem session={s} active={s.id === selected?.id} onSelect={() => setSelectedId(s.id)} />
                  </li>
                ))}
              </ul>
            )}
          </section>
          <section aria-label="Session details" className={cn('min-w-0', !selected && 'hidden lg:block')}>
            {selected ? (
              <SessionDetail key={selected.id} session={selected} onBack={() => setSelectedId(null)} />
            ) : (
              <Card>
                <EmptyState icon={Radar} title="Select a session" description="Pick a session on the left to review its captured traffic and rule candidates." />
              </Card>
            )}
          </section>
        </div>
      )}

      <StartSessionDrawer open={startOpen} onClose={() => setStartOpen(false)} onStarted={(s) => setSelectedId(s.id)} />
    </>
  );
};

const PhaseChip: React.FC<{ session: LearningSession }> = ({ session }) => {
  const now = useNow();
  const p = sessionPhase(session, now);
  const m = PHASE_META[p];
  return <StatusChip tone={m.tone} label={m.label} pulse={p === 'recording'} />;
};

const SessionListItem: React.FC<{ session: LearningSession; active: boolean; onSelect: () => void }> = ({ session: s, active, onSelect }) => {
  const now = useNow();
  const p = sessionPhase(s, now);
  const candidates = (s.compiled_candidates ?? []).length;
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-current={active || undefined}
      className={cn(
        'block w-full rounded-lg border bg-surface p-3 text-left shadow-card transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring/60',
        active ? 'border-accent ring-1 ring-accent' : 'border-border hover:border-border-strong hover:bg-surface-2'
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <span className="min-w-0 text-[13px] font-semibold leading-5 text-fg">{s.name}</span>
        <PhaseChip session={s} />
      </div>
      <div className="mt-1 truncate text-[12px] text-fg-muted">{s.server_hostname || s.server_ip}</div>
      <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px] text-fg-subtle">
        <span className="tabular">{pluralize(s.captured_flow_count, 'request')}</span>
        <span className="tabular">{pluralize(candidates, 'candidate')}</span>
        {p === 'recording' ? <CountdownChip due={s.expires_at} kind="expiry" warnWithinMs={5 * 60_000} /> : <RelativeTime value={s.started_at} />}
      </div>
    </button>
  );
};

const SessionDetail: React.FC<{ session: LearningSession; onBack: () => void }> = ({ session: s, onBack }) => {
  const state = useConsoleState();
  const perms = usePermissions();
  const { run, pending } = useAction();
  const confirm = useConfirm();
  const toast = useToast();
  const now = useNow();
  const phase: SessionPhase = sessionPhase(s, now);
  const can = canManageSession(perms, s);
  const { demoMode, refresh } = useConsole();

  // Local, editable copy of the compiled candidates. It follows the server while untouched.
  const [cands, setCands] = useState<CompiledRuleCandidate[]>(() => (s.compiled_candidates ?? []).map((c) => ({ ...c })));
  const [dirty, setDirty] = useState(false);
  const serverKey = JSON.stringify(s.compiled_candidates ?? []);
  const [syncedKey, setSyncedKey] = useState(serverKey);
  useEffect(() => {
    if (serverKey !== syncedKey && !dirty) {
      setCands((s.compiled_candidates ?? []).map((c) => ({ ...c })));
      setSyncedKey(serverKey);
    }
  }, [serverKey, syncedKey, dirty, s.compiled_candidates]);
  const stale = serverKey !== syncedKey && dirty;

  const [editing, setEditing] = useState<CompiledRuleCandidate | null>(null);
  const [publishOpen, setPublishOpen] = useState(false);
  const selectedCount = cands.filter((c) => c.selected).length;
  const allSelected = cands.length > 0 && selectedCount === cands.length;
  const update = (next: CompiledRuleCandidate[]) => {
    setCands(next);
    setDirty(true);
  };
  const published = setsFromSession(state, s.id);

  const stop = () =>
    confirm({
      title: 'Stop recording?',
      description: `${s.server_hostname} returns to its normal policy immediately. The recorded candidates stay available for review.`,
      confirmLabel: 'Stop session',
      onConfirm: async () => {
        await api.sessions.stop(s.id);
        await refresh();
        toast.success('Session stopped');
      },
    });

  const simulate = (scenario: string) =>
    run(() => api.sessions.simulateTraffic(s.id, scenario), {
      key: 'simulate',
      success: (r) => `Recorded ${pluralize(r.recorded, 'sample request')}`,
      errorTitle: 'The simulation failed',
    });

  return (
    <div className="flex flex-col gap-6">
      <Button variant="ghost" size="sm" icon={ArrowLeft} onClick={onBack} className="-ml-2 self-start lg:hidden">
        All sessions
      </Button>

      <Card>
        <div className="flex flex-col gap-3 px-[var(--card-p)] pb-3 pt-[calc(var(--card-p)-2px)] sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-[16px] font-semibold leading-6 text-fg">{s.name}</h2>
              <PhaseChip session={s} />
            </div>
            {s.description && <p className="mt-1 text-[13px] leading-5 text-fg-muted">{s.description}</p>}
          </div>
          <div className="flex shrink-0 flex-wrap items-center gap-2">
            {demoMode && can && phase === 'recording' && (
              <Menu
                items={SCENARIOS.map((sc) => ({ id: sc.id, label: sc.label, description: sc.description, icon: FlaskConical, onSelect: () => simulate(sc.id) }))}
                header={<span className="text-[12px] text-fg-subtle">Demo mode: inject sample traffic</span>}
                trigger={(p) => (
                  <Button {...p} size="sm" icon={FlaskConical} loading={pending === 'simulate'}>
                    Simulate traffic
                  </Button>
                )}
              />
            )}
            {phase === 'recording' && can && (
              <Button size="sm" variant="danger" icon={Square} onClick={stop}>
                Stop
              </Button>
            )}
          </div>
        </div>
        <div className="border-t border-border px-[var(--card-p)] py-4">
          <DescriptionList
            columns={3}
            items={[
              {
                label: 'Reference server',
                value: state.servers.some((x) => x.id === s.server_id) ? (
                  <Link to={`/servers/${encodeURIComponent(s.server_id)}`} className="text-accent [overflow-wrap:anywhere] hover:underline">
                    {s.server_hostname}
                  </Link>
                ) : (
                  s.server_hostname || s.server_ip
                ),
              },
              { label: 'Groups', value: <span className="flex flex-wrap gap-1">{(s.group_ids ?? []).length ? s.group_ids.map((g) => <MembershipChip key={g} id={g} />) : '—'}</span> },
              { label: 'Mode', value: <Tooltip content={MODE_META[s.mode]?.description}><span>{MODE_META[s.mode]?.label ?? s.mode}</span></Tooltip> },
              {
                label: 'Started',
                value: (
                  <span className="inline-flex flex-wrap items-center gap-1">
                    <UserName username={s.started_by} avatar={false} /> <RelativeTime value={s.started_at} />
                  </span>
                ),
              },
              { label: phase === 'recording' ? 'Ends' : 'Ended', value: phase === 'recording' ? <CountdownChip due={s.expires_at} kind="expiry" warnWithinMs={5 * 60_000} /> : formatDateTime(s.expires_at) },
              { label: 'Captured requests', value: <span className="tabular">{s.captured_flow_count}</span> },
            ]}
          />
        </div>
      </Card>

      {phase === 'recording' && (
        <Callout tone="info" icon={Radar} title="Recording">
          Run the workload on {s.server_hostname} now. Candidates update every time the console refreshes (about every 30 seconds).
        </Callout>
      )}
      {published.length > 0 && (
        <Callout tone="success" icon={Layers} title="Rules from this session are in policy sets">
          {published.map((p, i) => (
            <React.Fragment key={p.id}>
              {i > 0 && ', '}
              <Link to={`/policies/${encodeURIComponent(p.id)}`} className="font-medium text-accent hover:underline">
                {p.name}
              </Link>
              {p.draft && <span className="text-fg-subtle"> (draft)</span>}
            </React.Fragment>
          ))}
          . You can publish further candidates.
        </Callout>
      )}

      <Card>
        <CardHeader
          title="Rule candidates"
          description="Compiled from the recorded requests: paths are generalized and redirect targets are folded into their parent rule."
          divider
          actions={
            cands.length > 0 && (
              <span className="text-[12.5px] tabular text-fg-muted">
                {selectedCount} of {cands.length} selected
              </span>
            )
          }
        />
        {stale && (
          <div className="flex flex-wrap items-center gap-2 border-b border-border bg-info-soft px-[var(--card-p)] py-2 text-[12.5px] text-fg">
            New traffic was recorded. Your edits are kept until you reload the candidates.
            <Button
              size="xs"
              variant="secondary"
              icon={RefreshCw}
              onClick={() => {
                setCands((s.compiled_candidates ?? []).map((c) => ({ ...c })));
                setSyncedKey(serverKey);
                setDirty(false);
              }}
            >
              Reload candidates
            </Button>
          </div>
        )}
        {cands.length === 0 ? (
          <EmptyState
            icon={Radar}
            size="sm"
            title={phase === 'recording' ? 'Waiting for traffic' : 'No candidates'}
            description={
              phase === 'recording'
                ? `Nothing was recorded yet. Run the workload on ${s.server_hostname}${demoMode ? ', or simulate sample traffic' : ''}.`
                : 'The session recorded no requests that could be turned into rules.'
            }
          />
        ) : (
          <>
            <div className="flex items-center gap-3 border-b border-border bg-surface-2 px-[var(--card-p)] py-2">
              <Checkbox
                label={<span className="text-[12.5px] font-medium text-fg-muted">Select all</span>}
                checked={allSelected}
                indeterminate={!allSelected && selectedCount > 0}
                disabled={!can}
                onChange={() => update(cands.map((c) => ({ ...c, selected: !allSelected })))}
              />
            </div>
            <ul className="divide-y divide-border">
              {cands.map((c) => (
                <CandidateRow
                  key={c.id}
                  candidate={c}
                  disabled={!can}
                  onToggle={() => update(cands.map((x) => (x.id === c.id ? { ...x, selected: !x.selected } : x)))}
                  onEdit={() => setEditing(c)}
                />
              ))}
            </ul>
          </>
        )}
        {cands.length > 0 && (
          <div className="sticky bottom-0 flex flex-wrap items-center justify-between gap-3 rounded-b-lg border-t border-border bg-surface-2 px-[var(--card-p)] py-3">
            <span className="text-[12.5px] text-fg-muted">
              {!can
                ? 'You cannot publish sessions of these groups.'
                : phase === 'recording'
                  ? 'Stop the recording to publish its rules.'
                  : state.governance?.require_policy_review
                    ? 'Four-eyes review is on: rules are saved as a draft.'
                    : 'Publish into a new or an existing policy set.'}
            </span>
            {can && (
              <Button variant="primary" icon={Upload} disabled={selectedCount === 0 || phase === 'recording'} onClick={() => setPublishOpen(true)}>
                Publish {selectedCount ? pluralize(selectedCount, 'rule') : 'rules'}
              </Button>
            )}
          </div>
        )}
      </Card>

      <CandidateDrawer
        candidate={editing}
        onClose={() => setEditing(null)}
        onSave={(c) => {
          update(cands.map((x) => (x.id === c.id ? c : x)));
          setEditing(null);
        }}
      />
      <PublishDialog
        open={publishOpen}
        onClose={() => setPublishOpen(false)}
        session={s}
        candidates={cands}
        onPublished={() => {
          setDirty(false);
          setSyncedKey('');
        }}
      />
    </div>
  );
};

const CandidateRow: React.FC<{ candidate: CompiledRuleCandidate; disabled: boolean; onToggle: () => void; onEdit: () => void }> = ({ candidate: c, disabled, onToggle, onEdit }) => (
  <li className={cn('flex items-start gap-3 px-[var(--card-p)] py-3', !c.selected && 'bg-surface-2/50')}>
    <Checkbox aria-label={`Select ${c.host_pattern}${c.path_pattern}`} checked={c.selected} disabled={disabled} onChange={onToggle} className="mt-1" />
    <div className={cn('min-w-0 flex-1 space-y-1', !c.selected && 'opacity-70')}>
      <PatternText host={c.host_pattern} path={c.path_pattern} wrap className="block text-[13px]" />
      <div className="flex flex-wrap items-center gap-1.5">
        <MethodList methods={c.methods} />
        {c.follow_redirects && (
          <Badge tone="info" icon={Repeat}>
            Follows redirects
          </Badge>
        )}
        {(c.companion_rules ?? []).length > 0 && (
          <Tooltip content={<span className="font-mono text-[11.5px]">{(c.companion_rules ?? []).join(', ')}</span>}>
            <Badge tone="neutral">+{(c.companion_rules ?? []).length} companions</Badge>
          </Tooltip>
        )}
        {c.is_redirect_child && <Badge tone="violet">Redirect target</Badge>}
        {(c.redirect_targets ?? []).length > 0 && <span className="text-[12px] text-fg-subtle">→ {(c.redirect_targets ?? []).join(', ')}</span>}
      </div>
      {(c.sample_urls ?? [])[0] && (
        <p className="truncate font-mono text-[11.5px] text-fg-subtle" title={(c.sample_urls ?? []).join('\n')}>
          {(c.sample_urls ?? [])[0]}
          {(c.sample_urls ?? []).length > 1 && ` (+${(c.sample_urls ?? []).length - 1})`}
        </p>
      )}
    </div>
    <div className="flex shrink-0 flex-col items-end gap-1">
      <span className="text-[12px] tabular text-fg-subtle">{pluralize(c.hit_count, 'hit')}</span>
      {!disabled && <IconButton icon={Pencil} label="Edit candidate" size="sm" onClick={onEdit} />}
    </div>
  </li>
);
