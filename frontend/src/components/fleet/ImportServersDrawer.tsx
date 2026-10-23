import React, { useEffect, useMemo, useRef, useState } from 'react';
import { CheckCircle2, Download, FileUp, FlaskConical, Upload } from 'lucide-react';
import { api, ApiError } from '../../api';
import { useConsole } from '../../data/AppData';
import { pluralize } from '../../lib/format';
import type { ServerImportResult } from '../../types';
import { Badge, Button, Callout, CodeBlock, Column, DataTable, Drawer, Field, Textarea, useToast } from '../../ui';
import { CSV_COLUMNS, saveBlob } from './fleetUtils';

const EXAMPLE = `${CSV_COLUMNS.join(',')}
srv-app-17,app-17.internal.corp,10.30.17.4,10.30.17.0/24,svc-app-17,grp-linux-core,env=prod;tier=app,RHEL 9.4,Engineering,Core Linux Operations,Billing API node
`;

interface Outcome {
  dryRun: boolean;
  results: ServerImportResult[];
  error?: string;
  /** CSV text the outcome belongs to (a dry run is only valid for the exact text). */
  text: string;
}

/** Bulk import: paste or upload CSV, dry run with per-row results, then apply (all-or-nothing). */
export const ImportServersDrawer: React.FC<{ open: boolean; onClose: () => void }> = ({ open, onClose }) => {
  const { refresh } = useConsole();
  const toast = useToast();
  const [text, setText] = useState('');
  const [fileName, setFileName] = useState<string | null>(null);
  const [busy, setBusy] = useState<'dry' | 'apply' | null>(null);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setText('');
      setFileName(null);
      setOutcome(null);
    }
  }, [open]);

  const counts = useMemo(() => {
    const c = { create: 0, update: 0, error: 0 };
    for (const r of outcome?.results ?? []) c[r.action]++;
    return c;
  }, [outcome]);

  const call = async (dryRun: boolean) => {
    setBusy(dryRun ? 'dry' : 'apply');
    try {
      const res = await api.servers.importCsv(text, dryRun);
      setOutcome({ dryRun, results: res.results ?? [], error: res.error, text });
      if (!dryRun) {
        const created = (res.results ?? []).filter((r) => r.action === 'create').length;
        const updated = (res.results ?? []).filter((r) => r.action === 'update').length;
        toast.success(`Imported ${pluralize(created + updated, 'server')}`, { description: `${created} created, ${updated} updated.` });
        await refresh();
        onClose();
      }
    } catch (err) {
      if (err instanceof ApiError && err.data && Array.isArray(err.data.results)) {
        // 422: all-or-nothing import rejected with per-row errors
        setOutcome({ dryRun, results: err.data.results, error: err.data.error || err.message, text });
        toast.error(err, { title: 'Import rejected' });
      } else {
        setOutcome(null);
        toast.error(err, { title: dryRun ? 'The dry run failed' : 'The import failed' });
      }
    } finally {
      setBusy(null);
    }
  };

  const onFile = async (file: File | undefined) => {
    if (!file) return;
    if (file.size > 900 * 1024) {
      toast.error('The file is larger than 900 KB. Split it into several imports.');
      return;
    }
    setText(await file.text());
    setFileName(file.name);
    setOutcome(null);
  };

  const dryValid = !!outcome && outcome.dryRun && outcome.text === text && counts.error === 0 && outcome.results.length > 0;
  const rows = text.trim() ? text.trim().split(/\r?\n/).length - 1 : 0;

  const columns: Column<ServerImportResult>[] = [
    { id: 'row', header: 'Row', width: 56, sortValue: (r) => r.row, cell: (r) => <span className="tabular text-fg-muted">{r.row}</span> },
    {
      id: 'server',
      header: 'Server',
      cell: (r) => (
        <div className="min-w-0">
          <div className="truncate font-medium text-fg">{r.hostname || <span className="italic text-fg-subtle">no host name</span>}</div>
          <div className="truncate font-mono text-[11.5px] text-fg-subtle">{r.id || 'id generated'}</div>
        </div>
      ),
    },
    {
      id: 'action',
      header: 'Result',
      width: '45%',
      sortValue: (r) => (r.action === 'error' ? 0 : r.action === 'create' ? 1 : 2),
      cell: (r) =>
        r.action === 'error' ? (
          <div className="min-w-0">
            <Badge tone="danger">Error</Badge>
            <p className="mt-1 break-words text-[12px] leading-5 text-danger">{r.error}</p>
          </div>
        ) : r.action === 'create' ? (
          <Badge tone="success">Create</Badge>
        ) : (
          <Badge tone="info">Update</Badge>
        ),
    },
  ];

  return (
    <Drawer
      open={open}
      onClose={onClose}
      dismissible={!busy}
      width="xl"
      title="Import servers"
      description="Create or update many servers from a CMDB export. The import is all-or-nothing: if a row fails, nothing changes."
      footer={
        <>
          <Button onClick={onClose} disabled={!!busy}>
            Cancel
          </Button>
          <Button icon={FlaskConical} onClick={() => call(true)} loading={busy === 'dry'} disabled={!text.trim() || !!busy}>
            Run dry run
          </Button>
          <Button variant="primary" icon={Upload} onClick={() => call(false)} loading={busy === 'apply'} disabled={!dryValid || !!busy}>
            {dryValid ? `Apply import (${counts.create + counts.update})` : 'Apply import'}
          </Button>
        </>
      }
    >
      <div className="space-y-5">
        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,320px)]">
          <Field
            label="CSV"
            hint={fileName ? `Loaded ${fileName} (${pluralize(rows, 'row')})` : rows > 0 ? pluralize(rows, 'data row') : 'Paste CSV including the header row, or upload a .csv file.'}
          >
            <Textarea
              value={text}
              onChange={(e) => {
                setText(e.target.value);
                setFileName(null);
              }}
              rows={10}
              mono
              spellCheck={false}
              placeholder={EXAMPLE}
              className="min-h-[200px] whitespace-pre"
              data-autofocus
            />
          </Field>
          <div className="space-y-3">
            <div>
              <p className="label mb-1.5">Upload</p>
              <input ref={fileRef} type="file" accept=".csv,text/csv" className="sr-only" onChange={(e) => onFile(e.target.files?.[0])} aria-label="Choose CSV file" />
              <Button icon={FileUp} onClick={() => fileRef.current?.click()} fullWidth>
                Choose .csv file
              </Button>
            </div>
            <div className="rounded-lg border border-border bg-surface-2 p-3 text-[12.5px] leading-5 text-fg-muted">
              <p className="font-medium text-fg">Expected columns</p>
              <p className="mt-1 break-words font-mono text-[11.5px]">{CSV_COLUMNS.join(', ')}</p>
              <ul className="mt-2 list-disc space-y-0.5 pl-4">
                <li>Only hostname is required; unknown columns are ignored.</li>
                <li>
                  group_ids: static groups separated by <span className="font-mono">;</span>
                </li>
                <li>
                  labels: <span className="font-mono">key=value;key=value</span>
                </li>
                <li>An existing id updates that server (full replace).</li>
              </ul>
              <Button
                size="sm"
                variant="link"
                icon={Download}
                className="mt-2"
                onClick={() => saveBlob(new Blob([EXAMPLE], { type: 'text/csv' }), 'aegis-servers-template.csv')}
              >
                Download template
              </Button>
            </div>
          </div>
        </div>

        {outcome && (
          <section aria-label="Import results" className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="mr-1 text-[13.5px] font-semibold text-fg">{outcome.dryRun ? 'Dry run' : 'Import'} results</h3>
              <Badge tone="success">{counts.create} create</Badge>
              <Badge tone="info">{counts.update} update</Badge>
              <Badge tone={counts.error ? 'danger' : 'neutral'}>{counts.error} error</Badge>
              {outcome.text !== text && <Badge tone="warning">CSV changed since this run</Badge>}
            </div>
            {counts.error > 0 ? (
              <Callout tone="danger" title={outcome.error || 'Fix the rows marked as error'}>
                Nothing was changed. Correct the CSV and run the dry run again.
              </Callout>
            ) : dryValid ? (
              <Callout tone="success" icon={CheckCircle2} title="Ready to import">
                {counts.create} servers will be created and {counts.update} updated. Updates replace all fields of the existing server (quarantine and tokens are kept).
              </Callout>
            ) : null}
            <DataTable rows={outcome.results} columns={columns} getRowId={(r) => String(r.row)} hideToolbar pageSize={100} maxHeight={420} aria-label="Import results" />
          </section>
        )}

        {!outcome && (
          <CodeBlock title="Example" code={EXAMPLE} wrap maxHeight={140} />
        )}
      </div>
    </Drawer>
  );
};
