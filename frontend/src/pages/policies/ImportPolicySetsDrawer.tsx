import React, { useEffect, useRef, useState } from 'react';
import { AlertTriangle, CheckCircle2, FileJson, FileUp, MinusCircle, PlusCircle, RefreshCw, SkipForward, XCircle } from 'lucide-react';
import { api, ApiError, errorMessage } from '../../api';
import { useConsole } from '../../data/AppData';
import { cn } from '../../lib/cn';
import { formatBytes, formatDateTime, pluralize } from '../../lib/format';
import { Link } from '../../lib/router';
import type { PolicySetBundle, PolicySetDocument, PolicySetImportResult } from '../../types';
import { Badge, Button, Callout, Drawer, Spinner, Tone, useToast } from '../../ui';
import { PolicyKindBadge } from '../../components/policy/PolicyBadges';

const FORMAT = 'aegisproxy.policy-sets/v1';
const MAX_FILE = 10 * 1024 * 1024;

const ACTION_META: Record<PolicySetImportResult['action'], { label: string; count: string; tone: Tone; icon: React.ElementType }> = {
  create: { label: 'New set', count: 'new', tone: 'success', icon: PlusCircle },
  update: { label: 'Update draft', count: 'to update', tone: 'info', icon: RefreshCw },
  unchanged: { label: 'Unchanged', count: 'unchanged', tone: 'neutral', icon: MinusCircle },
  skip: { label: 'Skipped', count: 'skipped', tone: 'neutral', icon: SkipForward },
  error: { label: 'Error', count: 'with errors', tone: 'danger', icon: XCircle },
};

/** Accepts an export bundle, or a bare array of policy set documents. */
function parseBundle(text: string): PolicySetBundle {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new Error('The file is not valid JSON.');
  }
  if (Array.isArray(raw)) raw = { format: FORMAT, policy_sets: raw };
  const b = raw as Partial<PolicySetBundle>;
  if (!b || typeof b !== 'object' || !Array.isArray(b.policy_sets)) throw new Error('No policy_sets array found — export a bundle from Policy sets → Export.');
  if (b.format && b.format !== FORMAT) throw new Error(`Unsupported format “${b.format}” (expected ${FORMAT}).`);
  if (b.policy_sets.length === 0) throw new Error('The bundle contains no policy sets.');
  if (b.policy_sets.length > 200) throw new Error('At most 200 policy sets per import.');
  return { format: b.format || FORMAT, exported_at: b.exported_at || '', exported_by: b.exported_by || '', policy_sets: b.policy_sets as PolicySetDocument[] };
}

const diffText = (r: PolicySetImportResult) => {
  const d = r.diff;
  if (!d) return null;
  const parts: string[] = [];
  if (d.added) parts.push(`+${pluralize(d.added, 'rule')}`);
  if (d.removed) parts.push(`−${pluralize(d.removed, 'rule')}`);
  if (d.modified) parts.push(`${d.modified} changed`);
  if (d.metadata?.length) parts.push(`settings: ${d.metadata.map((m) => m.replace(/_/g, ' ')).join(', ')}`);
  return parts.join(' · ');
};

/** Policy as code: upload a bundle, preview the plan (dry run), then import the changes as drafts. */
export const ImportPolicySetsDrawer: React.FC<{ open: boolean; onClose: () => void }> = ({ open, onClose }) => {
  const { refresh } = useConsole();
  const toast = useToast();
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<{ name: string; size: number } | null>(null);
  const [bundle, setBundle] = useState<PolicySetBundle | null>(null);
  const [results, setResults] = useState<PolicySetImportResult[] | null>(null);
  const [applied, setApplied] = useState<PolicySetImportResult[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<'plan' | 'apply' | null>(null);
  const [drag, setDrag] = useState(false);

  useEffect(() => {
    if (open) {
      setFile(null);
      setBundle(null);
      setResults(null);
      setApplied(null);
      setError(null);
    }
  }, [open]);

  const plan = async (b: PolicySetBundle) => {
    setBusy('plan');
    setError(null);
    setResults(null);
    try {
      const r = await api.policySets.importBundle(b, true);
      setResults(r.results ?? []);
    } catch (e) {
      const rows = e instanceof ApiError ? (e.data?.results as PolicySetImportResult[] | undefined) : undefined;
      if (rows) setResults(rows);
      setError(errorMessage(e));
    } finally {
      setBusy(null);
    }
  };

  const load = async (f: File | undefined) => {
    if (!f) return;
    setApplied(null);
    setFile({ name: f.name, size: f.size });
    if (f.size > MAX_FILE) {
      setBundle(null);
      setResults(null);
      setError(`The file is too large (${formatBytes(f.size)}, at most 10 MiB).`);
      return;
    }
    try {
      const b = parseBundle(await f.text());
      setBundle(b);
      await plan(b);
    } catch (e) {
      setBundle(null);
      setResults(null);
      setError(errorMessage(e));
    }
  };

  const apply = async () => {
    if (!bundle) return;
    setBusy('apply');
    setError(null);
    try {
      const r = await api.policySets.importBundle(bundle, false);
      const rows = r.results ?? [];
      setApplied(rows);
      const n = rows.filter((x) => x.action === 'create' || x.action === 'update').length;
      toast.success(`Imported ${pluralize(n, 'policy set')} as drafts`, { description: 'Review the drafts, then publish or submit them for review.' });
      await refresh();
    } catch (e) {
      const rows = e instanceof ApiError ? (e.data?.results as PolicySetImportResult[] | undefined) : undefined;
      if (rows) setResults(rows);
      setError(errorMessage(e));
      toast.error(e, { title: 'Nothing was imported' });
    } finally {
      setBusy(null);
    }
  };

  const rows = applied ?? results ?? [];
  const count = (a: PolicySetImportResult['action']) => rows.filter((r) => r.action === a).length;
  const errors = count('error');
  const changes = count('create') + count('update');
  const docs = new Map((bundle?.policy_sets ?? []).map((d, i) => [i, d]));

  return (
    <Drawer
      open={open}
      onClose={onClose}
      dismissible={busy !== 'apply'}
      width="lg"
      title="Import policy sets"
      description="Policy as code: apply a bundle exported from this or another AegisProxy installation. Changes land in drafts — publishing follows the normal review workflow."
      footer={
        applied ? (
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        ) : (
          <>
            <Button onClick={onClose} disabled={busy === 'apply'}>
              Cancel
            </Button>
            <Button variant="primary" icon={FileUp} loading={busy === 'apply'} disabled={!bundle || !results || errors > 0 || changes === 0 || !!busy} onClick={apply}>
              {changes > 0 ? `Import ${pluralize(changes, 'set')} as drafts` : 'Import'}
            </Button>
          </>
        )
      }
    >
      <div className="space-y-5">
        {!applied && (
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDrag(true);
            }}
            onDragLeave={() => setDrag(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDrag(false);
              load(e.dataTransfer.files?.[0]);
            }}
            className={cn(
              'flex flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed px-4 py-7 text-center transition-colors',
              drag ? 'border-accent bg-accent-soft' : 'border-border-strong bg-surface-2'
            )}
          >
            <FileJson className="h-7 w-7 text-fg-subtle" aria-hidden />
            {file ? (
              <p className="text-[13px] text-fg">
                <span className="font-medium">{file.name}</span> <span className="text-fg-subtle">({formatBytes(file.size)})</span>
              </p>
            ) : (
              <p className="text-[13px] text-fg-muted">Drop an exported JSON bundle here, or</p>
            )}
            <Button size="sm" icon={FileUp} onClick={() => input.current?.click()} disabled={!!busy}>
              {file ? 'Choose another file' : 'Choose file'}
            </Button>
            <input
              ref={input}
              type="file"
              accept="application/json,.json"
              className="sr-only"
              aria-label="Policy set bundle (JSON)"
              data-testid="import-file"
              onChange={(e) => {
                load(e.target.files?.[0]);
                e.target.value = '';
              }}
            />
          </div>
        )}

        {bundle && !applied && (
          <p className="text-[12.5px] text-fg-muted">
            {pluralize(bundle.policy_sets.length, 'policy set')}
            {bundle.exported_by ? ` exported by ${bundle.exported_by}` : ''}
            {bundle.exported_at ? ` on ${formatDateTime(bundle.exported_at)}` : ''}. Sets are matched by id, then by name.
          </p>
        )}

        {busy === 'plan' && (
          <div className="flex items-center gap-2 text-[13px] text-fg-muted" role="status">
            <Spinner className="h-4 w-4" /> Checking the bundle against the current policy…
          </div>
        )}

        {error && (
          <Callout tone="danger" title={results ? 'The import cannot be applied' : 'The file cannot be imported'}>
            {error}
          </Callout>
        )}

        {applied && (
          <Callout tone="success" icon={CheckCircle2} title="Imported as drafts">
            Open each set to review the draft diff and impact, then publish it or submit it for review.
          </Callout>
        )}

        {rows.length > 0 && (
          <div data-testid="import-preview">
            <div className="mb-2 flex flex-wrap items-center gap-1.5">
              <span className="mr-1 text-[13px] font-semibold text-fg">{applied ? 'Result' : 'Preview'}</span>
              {(['create', 'update', 'unchanged', 'skip', 'error'] as const).map((a) =>
                count(a) ? (
                  <Badge key={a} tone={ACTION_META[a].tone}>
                    {count(a)} {ACTION_META[a].count}
                  </Badge>
                ) : null
              )}
            </div>
            {!applied && errors > 0 && (
              <Callout tone="warning" icon={AlertTriangle} className="mb-3">
                The import is all-or-nothing. Fix or remove the sets marked as error, then choose the file again.
              </Callout>
            )}
            <ul className="divide-y divide-border rounded-lg border border-border">
              {rows.map((r, i) => {
                const m = ACTION_META[r.action] ?? ACTION_META.skip;
                const Icon = m.icon;
                const doc = docs.get(i);
                const changed = diffText(r);
                return (
                  <li key={`${r.id}-${i}`} className="flex gap-3 px-3.5 py-3">
                    <Icon
                      className={cn('mt-0.5 h-4 w-4 shrink-0', { success: 'text-success', info: 'text-info', danger: 'text-danger', neutral: 'text-fg-subtle' }[m.tone as string])}
                      aria-hidden
                    />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-1.5">
                        {applied && (r.action === 'create' || r.action === 'update') && r.id ? (
                          <Link to={`/policies/${encodeURIComponent(r.id)}/draft`} className="font-medium text-fg hover:text-accent hover:underline" onClick={onClose}>
                            {r.name || r.id}
                          </Link>
                        ) : (
                          <span className="font-medium text-fg">{r.name || r.id || `Set ${i + 1}`}</span>
                        )}
                        {doc?.kind && (doc.kind === 'baseline' || doc.kind === 'standard' || doc.kind === 'approvals') && <PolicyKindBadge kind={doc.kind} />}
                        <Badge tone={m.tone}>{m.label}</Badge>
                      </div>
                      {r.id && <div className="font-mono text-[11.5px] text-fg-subtle">{r.id}</div>}
                      {changed && <p className="mt-0.5 text-[12.5px] text-fg-muted">{changed}</p>}
                      {r.error && <p className="mt-0.5 text-[12.5px] text-danger [overflow-wrap:anywhere]">{r.error}</p>}
                    </div>
                  </li>
                );
              })}
            </ul>
          </div>
        )}

        {!bundle && !error && !applied && (
          <div className="rounded-lg border border-border bg-surface-2 p-3.5 text-[12.5px] leading-5 text-fg-muted">
            <p className="font-medium text-fg">Typical workflow</p>
            <ol className="mt-1 list-decimal space-y-0.5 pl-5">
              <li>Export the policy sets (Export) and keep the JSON in Git.</li>
              <li>Change rules through pull requests and review them like code.</li>
              <li>Import the merged bundle here or with a service account (POST /api/policy-sets/import).</li>
              <li>Publish the drafts — four-eyes review applies as usual.</li>
            </ol>
          </div>
        )}
      </div>
    </Drawer>
  );
};
