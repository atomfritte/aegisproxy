import React, { useEffect, useState } from 'react';
import { FileCheck2, Plus, ScanSearch, Trash2 } from 'lucide-react';
import { api } from '../../../api';
import { useAction, useConsole } from '../../../data/AppData';
import { Link, useSearchParams } from '../../../lib/router';
import { useUrlFilters } from '../../../lib/useUrlFilters';
import type { ThreatException } from '../../../types';
import { Badge, Button, Callout, Column, DataTable, Drawer, EmptyState, Field, IconButton, Input, RelativeTime, SegmentedControl, Textarea, useConfirm, useToast } from '../../../ui';
import { UserName } from '../../../components/common/EntityChips';
import { MonoValue } from './components';
import { EXCEPTION_TYPES, validateIndicatorValue } from './meta';
import { useThreatData } from './useThreatData';

type ExType = ThreatException['type'];
const typeLabel = (t: string) => EXCEPTION_TYPES.find((x) => x.value === t)?.label ?? t;

const ExceptionDrawer: React.FC<{ open: boolean; prefill: { type?: string; value?: string; reason?: string }; onClose: () => void }> = ({ open, prefill, onClose }) => {
  const { run, pending } = useAction();
  const [type, setType] = useState<ExType>('domain');
  const [value, setValue] = useState('');
  const [reason, setReason] = useState('');
  const [touched, setTouched] = useState(false);
  useEffect(() => {
    if (!open) return;
    setType(EXCEPTION_TYPES.find((t) => t.value === prefill.type)?.value ?? 'domain');
    setValue(prefill.value ?? '');
    setReason(prefill.reason ?? '');
    setTouched(false);
  }, [open, prefill.type, prefill.value, prefill.reason]);

  const meta = EXCEPTION_TYPES.find((t) => t.value === type)!;
  const valueErr = validateIndicatorValue(type, value);
  const reasonErr = reason.trim() ? null : 'Explain why this is a false positive.';
  const save = async () => {
    setTouched(true);
    if (valueErr || reasonErr) return;
    const r = await run(() => api.security.addException({ type, value: value.trim(), reason: reason.trim() }), {
      key: 'ex-add',
      success: `Added an exception for ${value.trim()}`,
      errorTitle: 'The exception could not be added',
    });
    if (r) onClose();
  };

  return (
    <Drawer
      open={open}
      onClose={onClose}
      dismissible={pending !== 'ex-add'}
      title="Add exception"
      description="Stops threat-intel matches for a known-good destination or file."
      footer={
        <>
          <Button onClick={onClose} disabled={pending === 'ex-add'}>
            Cancel
          </Button>
          <Button variant="primary" loading={pending === 'ex-add'} onClick={save}>
            Add exception
          </Button>
        </>
      }
    >
      <form
        className="space-y-5"
        onSubmit={(e) => {
          e.preventDefault();
          save();
        }}
      >
        <Field label="Type">
          {() => <SegmentedControl<ExType> aria-label="Exception type" value={type} onChange={setType} options={EXCEPTION_TYPES.map((t) => ({ value: t.value, label: t.label }))} />}
        </Field>
        <Field label="Value" required error={touched ? valueErr : null} hint={meta.hint}>
          <Input value={value} onChange={(e) => setValue(e.target.value)} mono placeholder={meta.placeholder} autoComplete="off" spellCheck={false} data-autofocus />
        </Field>
        <Field label="Reason" required error={touched ? reasonErr : null} hint="Reviewers and auditors see this in the audit trail.">
          <Textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={3} placeholder="Vendor CDN, confirmed clean by the SOC (TICKET-123)" />
        </Field>
        <Callout tone="neutral">Exceptions only affect threat intelligence (and antivirus for SHA-256). They never open the allow list, DLP or download control.</Callout>
        <button type="submit" hidden />
      </form>
    </Drawer>
  );
};

/** /threats/exceptions — false-positive exceptions. `?new=1&kind=&value=&reason=` opens the drawer prefilled. */
export const ExceptionsTab: React.FC = () => {
  const d = useThreatData();
  const { refresh } = useConsole();
  const toast = useToast();
  const confirm = useConfirm();
  const f = useUrlFilters(['type']);
  const [params, setParams] = useSearchParams();
  const adding = params.get('new') === '1' && d.canManage;

  const remove = (x: ThreatException) =>
    confirm({
      title: `Remove the exception for ${x.value}?`,
      description: 'Threat-intel matches for this value are enforced again after the next sync.',
      tone: 'danger',
      confirmLabel: 'Remove exception',
      onConfirm: async () => {
        await api.security.deleteException(x.id);
        toast.success(`Removed the exception for ${x.value}`);
        await refresh();
      },
    });

  const columns: Column<ThreatException>[] = [
    { id: 'type', header: 'Type', width: 120, sortValue: (x) => x.type, cell: (x) => <Badge tone="success">{typeLabel(x.type)}</Badge> },
    { id: 'value', header: 'Value', width: '32%', sortValue: (x) => x.value, cell: (x) => <MonoValue value={x.value} /> },
    { id: 'reason', header: 'Reason', cell: (x) => <p className="line-clamp-2 text-[12.5px] leading-5 text-fg-muted">{x.reason}</p> },
    {
      id: 'added',
      header: 'Added',
      width: 160,
      sortValue: (x) => x.created_at,
      cell: (x) => (
        <div className="leading-tight">
          <UserName username={x.added_by} />
          <div className="mt-0.5 text-[12px] text-fg-subtle">
            <RelativeTime value={x.created_at} />
          </div>
        </div>
      ),
    },
    {
      id: 'actions',
      header: <span className="sr-only">Actions</span>,
      width: 84,
      align: 'right',
      hideOnMobile: true,
      cell: (x) => (
        <span className="inline-flex gap-1">
          <Link to={`/threats/lookup?value=${encodeURIComponent(x.value)}`} aria-label={`Look up ${x.value}`} className="inline-flex h-[var(--control-h-sm)] w-[var(--control-h-sm)] items-center justify-center rounded-md text-fg-muted hover:bg-surface-3 hover:text-fg">
            <ScanSearch className="h-4 w-4" aria-hidden />
          </Link>
          {d.canManage && <IconButton icon={Trash2} label={`Remove ${x.value}`} size="sm" variant="danger-ghost" onClick={() => remove(x)} />}
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-5">
      <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <p className="max-w-3xl text-[13px] leading-6 text-fg-muted">
          Suppress threat-intel matches for a known-good domain, URL, IP or file hash. A SHA-256 exception also overrides an antivirus verdict for exactly that file; the event
          trail is kept.
        </p>
        {d.canManage && (
          <Button variant="primary" icon={Plus} className="shrink-0" onClick={() => setParams({ new: '1' })}>
            Add exception
          </Button>
        )}
      </div>
      {!d.canManage && <Callout tone="neutral">Only InfoSec Approvers and Super Admins can add or remove exceptions.</Callout>}
      <DataTable
        aria-label="Exceptions"
        rows={d.exceptions}
        columns={columns}
        getRowId={(x) => x.id}
        getSearchText={(x) => `${x.value} ${x.reason} ${x.added_by}`}
        searchPlaceholder="Search value or reason…"
        search={f.search}
        onSearchChange={f.setSearch}
        facets={[{ id: 'type', label: 'Type', getValue: (x) => x.type, options: EXCEPTION_TYPES.map((t) => ({ value: t.value, label: t.label })) }]}
        facetValues={f.values}
        onFacetChange={f.onChange}
        initialSort={{ id: 'added', dir: 'desc' }}
        mobileCard={(x) => (
          <div className="min-w-0 space-y-1.5">
            <div className="flex items-start justify-between gap-2">
              <MonoValue value={x.value} />
              {d.canManage && <IconButton icon={Trash2} label={`Remove ${x.value}`} size="sm" variant="danger-ghost" onClick={() => remove(x)} className="-mr-1 -mt-1 shrink-0" />}
            </div>
            <Badge tone="success">{typeLabel(x.type)}</Badge>
            <p className="text-[12px] leading-5 text-fg-muted">{x.reason}</p>
          </div>
        )}
        empty={
          <EmptyState
            icon={FileCheck2}
            title="No exceptions"
            description="When a legitimate destination or file is flagged, add an exception here — or use “Report a false positive” on the security event."
            action={
              d.canManage && (
                <Button variant="primary" icon={Plus} onClick={() => setParams({ new: '1' })}>
                  Add exception
                </Button>
              )
            }
          />
        }
      />
      <ExceptionDrawer
        open={adding}
        prefill={{ type: params.get('kind') || undefined, value: params.get('value') || undefined, reason: params.get('reason') || undefined }}
        onClose={() => setParams({ new: null, kind: null, value: null, reason: null })}
      />
    </div>
  );
};
