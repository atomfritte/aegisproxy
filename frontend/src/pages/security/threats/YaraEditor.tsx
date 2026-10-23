import React, { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, ArrowLeft, FileCode2, Info, Save, Trash2, Wand2 } from 'lucide-react';
import { api, ApiError, errorMessage } from '../../../api';
import { useConsole } from '../../../data/AppData';
import { formatBytes } from '../../../lib/format';
import { Link, navigate, useNavigationBlocker } from '../../../lib/router';
import type { YaraRuleSet } from '../../../types';
import { Badge, Button, Callout, Card, CardHeader, CodeEditor, EmptyState, Field, Input, RelativeTime, Skeleton, StatusChip, Switch, Textarea, Tooltip, useConfirm, useToast } from '../../../ui';
import { UserName } from '../../../components/common/EntityChips';
import { ModeBadge } from './components';
import { useThreatData } from './useThreatData';
import { countRules, errorForSet, setsInError, yaraFleet, yaraPath, YARA_TEMPLATE } from './yara';
import type { YaraData } from './YaraTab';

const MAX_SOURCE = 256 * 1024;

interface Draft {
  name: string;
  description: string;
  source: string;
  enabled: boolean;
}

const toDraft = (r?: YaraRuleSet | null): Draft => ({ name: r?.name ?? '', description: r?.description ?? '', source: r?.source ?? '', enabled: r?.enabled ?? true });

/** Basic client-side checks only; the server lints the rules (line-accurate) and workers compile them (YARA-X). */
function validate(d: Draft) {
  const bytes = new Blob([d.source]).size;
  let source: string | null = null;
  if (!d.source.trim()) source = 'Paste at least one YARA rule.';
  else if (bytes > MAX_SOURCE) source = `At most 256 KiB per rule set (currently ${formatBytes(bytes)}).`;
  return {
    name: !d.name.trim() ? 'Give the rule set a name.' : d.name.length > 120 ? 'At most 120 characters.' : null,
    description: d.description.length > 1000 ? 'At most 1000 characters.' : null,
    source,
  };
}

/** Line numbers mentioned in a compiler message ("line 12", ":12:", "--> line:col"). */
function errorLinesOf(msg: string): number[] {
  const out = new Set<number>();
  for (const m of msg.matchAll(/line[:\s]+(\d+)/gi)) out.add(Number(m[1]));
  for (const m of msg.matchAll(/:(\d+):\d+/g)) out.add(Number(m[1]));
  return [...out].filter((n) => n > 0 && n < 100000);
}

export const YaraEditor: React.FC<{ id: string; data: YaraData }> = ({ id, data }) => {
  const d = useThreatData();
  const { refresh } = useConsole();
  const toast = useToast();
  const confirm = useConfirm();
  const isNew = id === 'new';
  const existing = useMemo(() => (data.data?.rule_sets ?? []).find((r) => r.id === id) ?? null, [data.data, id]);
  const [draft, setDraft] = useState<Draft>(() => (isNew ? { ...toDraft(null), source: '' } : toDraft(existing)));
  const [loadedFor, setLoadedFor] = useState<string | null>(isNew ? 'new' : existing ? existing.id : null);
  const [attempted, setAttempted] = useState(false);
  const [saving, setSaving] = useState(false);
  const [serverError, setServerError] = useState<string | null>(null);
  const ro = !d.canManage;

  // adopt the loaded rule set once (and after navigating between sets)
  useEffect(() => {
    if (isNew && loadedFor !== 'new') {
      setDraft(toDraft(null));
      setLoadedFor('new');
    } else if (!isNew && existing && loadedFor !== existing.id) {
      setDraft(toDraft(existing));
      setLoadedFor(existing.id);
      setServerError(null);
      setAttempted(false);
    }
  }, [isNew, existing, loadedFor]);

  const base = isNew ? toDraft(null) : toDraft(existing);
  const dirty = JSON.stringify(draft) !== JSON.stringify(base);
  useNavigationBlocker(dirty && !ro && !saving, 'Discard unsaved changes to this YARA rule set?');

  if (!isNew && !existing) {
    if (!data.data && !data.error) return <Skeleton className="h-96" />;
    return (
      <Card>
        <EmptyState
          icon={FileCode2}
          title={data.error ? 'The rule set could not be loaded' : 'Rule set not found'}
          description={data.error || 'It may have been deleted.'}
          action={<Link to={yaraPath()} className="text-[13px] font-medium text-accent hover:underline">Back to YARA rule sets</Link>}
        />
      </Card>
    );
  }

  const errors = validate(draft);
  const invalid = Object.values(errors).some(Boolean);
  const show = (k: keyof typeof errors) => (attempted || (k === 'source' && draft.source.trim() !== '') ? errors[k] : null);
  const set = (p: Partial<Draft>) => {
    setDraft((x) => ({ ...x, ...p }));
    if (p.source !== undefined || p.name !== undefined) setServerError(null);
  };

  const fleet = yaraFleet(data.data?.data_planes ?? d.planes);
  // errors that name this set; otherwise (unattributable) every error while this set is enabled
  const ownErrors = existing ? fleet.errors.filter((e) => setsInError(e.st.error || '', [existing]).length > 0) : [];
  const shownCompile = ownErrors.length ? ownErrors : existing?.enabled ? fleet.errors : [];
  const compileMsgs = shownCompile.map((e) => ({ plane: e.plane.id, msg: existing && ownErrors.length ? errorForSet(e.st.error || '', existing) : e.st.error || '' }));
  const keptPrevious = compileMsgs.every((m) => m.msg.includes('previous version stays active'));
  const errorLines = [...(serverError ? errorLinesOf(serverError) : []), ...(dirty ? [] : compileMsgs.flatMap((m) => errorLinesOf(m.msg)))];
  const lintError = !!serverError && /invalid YARA rules|source /i.test(serverError);
  const rules = countRules(draft.source);
  const bytes = new Blob([draft.source]).size;

  const save = async () => {
    setAttempted(true);
    if (invalid) return;
    setSaving(true);
    setServerError(null);
    const body = { name: draft.name.trim(), description: draft.description.trim(), source: draft.source, enabled: draft.enabled };
    try {
      const saved = isNew ? await api.yara.create(body) : await api.yara.update(id, { ...existing, ...body });
      toast.success(isNew ? `Created rule set “${saved.name}”` : `Saved rule set “${saved.name}”`, { description: 'Workers compile the rules with their next bundle sync.' });
      await data.reload();
      refresh();
      setAttempted(false);
      if (isNew) {
        setLoadedFor(saved.id);
        navigate(yaraPath(saved.id), { replace: true });
      } else {
        setDraft(toDraft(saved));
      }
    } catch (e) {
      setServerError(errorMessage(e));
      if (!(e instanceof ApiError) || e.status >= 500) toast.error(e, { title: 'The rule set could not be saved' });
    } finally {
      setSaving(false);
    }
  };

  const remove = () =>
    existing &&
    confirm({
      title: `Delete rule set “${existing.name}”?`,
      description: 'Workers stop matching its rules with their next bundle sync.',
      tone: 'danger',
      confirmLabel: 'Delete rule set',
      typeToConfirm: existing.name,
      onConfirm: async () => {
        await api.yara.remove(existing.id);
        setLoadedFor(null);
        toast.success(`Deleted rule set “${existing.name}”`);
        await data.reload();
        navigate(yaraPath(), { replace: true });
      },
    });

  return (
    <div className="space-y-5">
      <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <div className="min-w-0">
          <Link to={yaraPath()} className="mb-1 inline-flex items-center gap-1 text-[12.5px] font-medium text-fg-muted hover:text-accent">
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden />
            YARA rule sets
          </Link>
          <h2 className="flex flex-wrap items-center gap-2 text-[17px] font-semibold text-fg">
            <span className="break-all">{isNew ? 'New YARA rule set' : existing?.name}</span>
            {!isNew && (existing?.enabled ? <StatusChip tone="success" label="Enabled" /> : <StatusChip tone="neutral" label="Disabled" />)}
          </h2>
          {existing?.updated_at && (
            <p className="mt-0.5 text-[12.5px] text-fg-subtle">
              Changed <RelativeTime value={existing.updated_at} />
              {existing.updated_by && (
                <>
                  {' '}by <UserName username={existing.updated_by} avatar={false} />
                </>
              )}
            </p>
          )}
        </div>
        {!ro && (
          <div className="flex shrink-0 flex-wrap gap-2">
            {!isNew && (
              <Button variant="danger-ghost" icon={Trash2} onClick={remove} disabled={saving}>
                Delete
              </Button>
            )}
            <Button variant="primary" icon={Save} loading={saving} onClick={save} disabled={!dirty && !isNew}>
              {isNew ? 'Create rule set' : 'Save changes'}
            </Button>
          </div>
        )}
      </div>

      {ro && <Callout tone="neutral">You can view this rule set. Only InfoSec Approvers and Super Admins can change YARA rules.</Callout>}
      {serverError && !lintError && (
        <Callout tone="danger" title="The rule set was not saved" icon={AlertTriangle}>
          <span className="font-mono text-[12px] text-fg [overflow-wrap:anywhere]" data-testid="yara-server-error">
            {serverError}
          </span>
        </Callout>
      )}
      {compileMsgs.length > 0 && !dirty && (
        <Callout
          tone={keptPrevious ? 'warning' : 'danger'}
          title={`Workers could not compile this rule set (${compileMsgs.length} ${compileMsgs.length === 1 ? 'worker' : 'workers'})`}
        >
          {keptPrevious ? 'The previous version stays active until the error is fixed; other rule sets are not affected.' : 'The rule set is skipped until the error is fixed; other rule sets are not affected.'}
          {compileMsgs.slice(0, 3).map((m) => (
            <span key={m.plane} className="mt-1 block font-mono text-[12px] text-fg [overflow-wrap:anywhere]">
              {m.plane}: {m.msg}
            </span>
          ))}
        </Callout>
      )}

      <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_300px]">
        <Card className="min-w-0">
          <div className="space-y-5 p-[var(--card-p)]">
            <fieldset disabled={ro} className="min-w-0 space-y-5">
              <div className="grid gap-4 md:grid-cols-2">
                <Field label="Name" required error={show('name')}>
                  <Input value={draft.name} onChange={(e) => set({ name: e.target.value })} placeholder="In-house malware families" maxLength={120} data-autofocus={isNew || undefined} />
                </Field>
                <div className="flex items-end md:pb-1.5">
                  <Switch checked={draft.enabled} onChange={(v) => set({ enabled: v })} label="Enabled" description="Disabled sets are kept but not compiled." className="w-full" />
                </div>
              </div>
              <Field label="Description" optional error={show('description')}>
                <Textarea rows={2} value={draft.description} onChange={(e) => set({ description: e.target.value })} placeholder="What these rules detect, source and owner" />
              </Field>
              <Field
                label="Rules"
                required
                error={
                  show('source') ||
                  (lintError ? (
                    <span className="font-mono text-[12px] [overflow-wrap:anywhere]" data-testid="yara-lint-error">
                      {serverError}
                    </span>
                  ) : null)
                }
                labelAside={
                  <span className="ml-auto flex items-center gap-2 text-[12px] text-fg-subtle">
                    <span className="tabular">
                      {rules} {rules === 1 ? 'rule' : 'rules'} · {formatBytes(bytes)} of 256 KiB
                    </span>
                    {!ro && !draft.source.trim() && (
                      <Button size="xs" variant="ghost" icon={Wand2} onClick={() => set({ source: YARA_TEMPLATE })}>
                        Insert example
                      </Button>
                    )}
                  </span>
                }
              >
                {({ id: fid, describedBy, invalid: inv }) => (
                  <CodeEditor
                    id={fid}
                    aria-describedby={describedBy}
                    aria-invalid={inv || undefined}
                    aria-label="YARA rules source"
                    value={draft.source}
                    onChange={(v) => set({ source: v })}
                    readOnly={ro}
                    rows={24}
                    errorLines={errorLines}
                    placeholder="Paste YARA rules here — or insert the example to start from a template."
                  />
                )}
              </Field>
            </fieldset>
          </div>
        </Card>
        <aside className="min-w-0 space-y-4">
          <Card>
            <CardHeader icon={Info} title="How rules are applied" />
            <ul className="space-y-2 p-[var(--card-p)] pt-2 text-[12.5px] leading-5 text-fg-muted">
              <li>
                Mode: <ModeBadge mode={d.policy?.yara_mode ?? 'off'} className="align-middle" />{' '}
                <Link to="/threats/policy#yara" className="font-medium text-accent hover:underline">
                  change
                </Link>
              </li>
              <li>Downloads up to {formatBytes(d.policy?.yara_max_bytes || 0)} are scanned; a match creates a security event (and blocks in block mode).</li>
              <li>Syntax is YARA-X (compatible with most YARA 4 rules). Modules such as pe, elf, math and hash are available; include is not.</li>
              <li>If a rule set fails to compile, workers keep the previous rules and report the error here.</li>
            </ul>
          </Card>
          <Card>
            <CardHeader title="Keyboard" />
            <p className="p-[var(--card-p)] pt-2 text-[12.5px] leading-5 text-fg-muted">
              <Badge tone="neutral">Tab</Badge> indents, <Badge tone="neutral">Shift+Tab</Badge> outdents.{' '}
              <Tooltip content="Esc releases the Tab key so you can move focus out of the editor.">
                <span className="underline decoration-dotted">Esc</span>
              </Tooltip>{' '}
              then Tab leaves the editor.
            </p>
          </Card>
        </aside>
      </div>
    </div>
  );
};
