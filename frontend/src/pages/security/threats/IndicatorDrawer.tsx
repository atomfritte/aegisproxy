import React, { useEffect, useState } from 'react';
import { api } from '../../../api';
import { useAction } from '../../../data/AppData';
import { formatDateTime } from '../../../lib/format';
import type { IndicatorType } from '../../../types';
import { Button, Drawer, Field, Input, Select, SegmentedControl, Textarea } from '../../../ui';
import { categoryOptions, IOC_TYPES, localToISO, toLocalInput, validateIndicatorValue } from './meta';

export interface IndicatorPrefill {
  type?: string;
  value?: string;
  category?: string;
  reason?: string;
}

const EXPIRY = [
  { value: 'never', label: 'Never' },
  { value: '24h', label: '24 hours' },
  { value: '7d', label: '7 days' },
  { value: '30d', label: '30 days' },
  { value: '90d', label: '90 days' },
  { value: 'custom', label: 'Custom date…' },
];
const EXPIRY_MS: Record<string, number> = { '24h': 864e5, '7d': 7 * 864e5, '30d': 30 * 864e5, '90d': 90 * 864e5 };

/** Adds a custom indicator of compromise (blocked on every server in block mode). */
export const IndicatorDrawer: React.FC<{ open: boolean; prefill?: IndicatorPrefill; onClose: () => void }> = ({ open, prefill, onClose }) => {
  const { run, pending } = useAction();
  const [type, setType] = useState<IndicatorType>('domain');
  const [value, setValue] = useState('');
  const [category, setCategory] = useState('malware');
  const [reason, setReason] = useState('');
  const [expiry, setExpiry] = useState('never');
  const [custom, setCustom] = useState('');
  const [touched, setTouched] = useState(false);

  useEffect(() => {
    if (!open) return;
    const t = IOC_TYPES.find((x) => x.value === prefill?.type)?.value ?? 'domain';
    setType(t);
    setValue(prefill?.value ?? '');
    setCategory(prefill?.category || 'malware');
    setReason(prefill?.reason ?? '');
    setExpiry('never');
    setCustom(toLocalInput(new Date(Date.now() + 7 * 864e5)));
    setTouched(false);
  }, [open, prefill?.type, prefill?.value, prefill?.category, prefill?.reason]);

  const meta = IOC_TYPES.find((t) => t.value === type)!;
  const valueErr = validateIndicatorValue(type, value);
  const reasonErr = reason.trim() ? null : 'Explain why — e.g. the incident or advisory reference.';
  const expiresAt = expiry === 'never' ? undefined : expiry === 'custom' ? localToISO(custom) : new Date(Date.now() + EXPIRY_MS[expiry]).toISOString();
  const expiryErr = expiry === 'custom' && (!expiresAt || new Date(expiresAt).getTime() <= Date.now()) ? 'Pick a date in the future.' : null;

  const save = async () => {
    setTouched(true);
    if (valueErr || reasonErr || expiryErr) return;
    const r = await run(
      () => api.security.addIndicator({ type, value: value.trim(), category, reason: reason.trim(), ...(expiresAt ? { expires_at: expiresAt } : {}) }),
      { key: 'ioc-add', success: `Added indicator ${value.trim()} — workers enforce it after their next threat-intel sync`, errorTitle: 'The indicator could not be added' }
    );
    if (r) onClose();
  };

  return (
    <Drawer
      open={open}
      onClose={onClose}
      dismissible={pending !== 'ioc-add'}
      title="Add indicator"
      description="A domain, URL, IP, network or file hash that every server treats as malicious."
      footer={
        <>
          <Button onClick={onClose} disabled={pending === 'ioc-add'}>
            Cancel
          </Button>
          <Button variant="primary" loading={pending === 'ioc-add'} onClick={save}>
            Add indicator
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
          {() => (
            <div className="scroll-thin -mx-1 overflow-x-auto px-1">
              <SegmentedControl<IndicatorType> aria-label="Indicator type" value={type} onChange={setType} options={IOC_TYPES.map((t) => ({ value: t.value, label: t.label }))} />
            </div>
          )}
        </Field>
        <Field label="Value" required error={touched ? valueErr : null} hint={meta.hint}>
          <Input value={value} onChange={(e) => setValue(e.target.value)} mono placeholder={meta.placeholder} autoComplete="off" spellCheck={false} data-autofocus />
        </Field>
        <Field label="Category" hint="Shown on events and lookups; sets the event severity.">
          <Select value={category} onChange={(e) => setCategory(e.target.value)} options={categoryOptions(category)} />
        </Field>
        <Field label="Reason" required error={touched ? reasonErr : null}>
          <Textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={2} placeholder="INC-4711 — C2 domain from the vendor advisory" />
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Expires" hint={expiry !== 'never' && expiresAt && !expiryErr ? `Removed ${formatDateTime(expiresAt)}` : 'Temporary blocks clean up after themselves.'}>
            <Select value={expiry} onChange={(e) => setExpiry(e.target.value)} options={EXPIRY} />
          </Field>
          {expiry === 'custom' && (
            <Field label="Expiry date" error={expiryErr}>
              <Input type="datetime-local" value={custom} onChange={(e) => setCustom(e.target.value)} />
            </Field>
          )}
        </div>
        <button type="submit" hidden />
      </form>
    </Drawer>
  );
};
