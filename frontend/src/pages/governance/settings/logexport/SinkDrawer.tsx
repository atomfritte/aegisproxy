import React, { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, ArrowLeft, CheckCircle2, ChevronDown, ChevronRight, KeyRound, Lock, Plus, Send, Trash2, Undo2 } from 'lucide-react';
import { api, errorMessage } from '../../../../api';
import { cn } from '../../../../lib/cn';
import type { ExportSink, ExportSinkType } from '../../../../types';
import {
  Badge,
  Button,
  Callout,
  Checkbox,
  Drawer,
  Field,
  IconButton,
  Input,
  KeyValueEditor,
  Select,
  Spinner,
  Switch,
  Textarea,
  useToast,
} from '../../../../ui';
import { endpointLabel, FACILITIES, FORMAT_LABELS, SECRET_REQUIRED, SEVERITIES, STREAMS, TRAFFIC_FILTERS, TYPE_HELP, TYPE_ICONS, TYPE_SHORT, typeId } from './catalog';
import { destinationChanged, fromSink, newForm, toPayload, usesSecret, usesTLS, validateForm, type HeaderRow, type SinkForm } from './form';

type TestResult = { ok: boolean; error?: string; at: number } | null;

/** "Bearer token (optional; or use headers)" → "Or use headers." */
const AZURE_AUTH_OPTIONS = [
  { value: 'client_secret', label: 'App registration with client secret' },
  { value: 'managed_identity', label: 'Managed identity (Azure VM, VM scale set)' },
  { value: 'workload_identity', label: 'Workload identity (AKS)' },
];

const AZURE_AUTH_HINTS: Record<SinkForm['azure_auth'], string> = {
  client_secret: 'Grant the app registration "Monitoring Metrics Publisher" on the data collection rule.',
  managed_identity: 'No secret: the control-plane host\'s managed identity needs "Monitoring Metrics Publisher" on the DCR.',
  workload_identity: 'No secret: label the control-plane pods azure.workload.identity/use=true and federate their service account.',
};

function secretHint(label: string): string | undefined {
  const m = /\((.*)\)$/.exec(label);
  if (!m) return 'Write-only: never shown again after saving.';
  const rest = m[1].replace(/^optional;?\s*/i, '').trim();
  return rest ? `${rest.charAt(0).toUpperCase()}${rest.slice(1)}.` : 'Write-only: never shown again after saving.';
}

const Section: React.FC<{ title: string; description?: React.ReactNode; children: React.ReactNode }> = ({ title, description, children }) => (
  <section className="space-y-4 border-t border-border pt-5 first:border-t-0 first:pt-0">
    <div>
      <h3 className="text-[13.5px] font-semibold text-fg">{title}</h3>
      {description && <p className="mt-0.5 text-[12.5px] text-fg-muted">{description}</p>}
    </div>
    {children}
  </section>
);

/** Write-only value: "Stored ••••" with Replace / Clear, or a password input. */
const SecretInput: React.FC<{
  label: string;
  form: SinkForm;
  set: (p: Partial<SinkForm>) => void;
  required: boolean;
  error?: string;
  disabled?: boolean;
  hint?: string;
}> = ({ label, form, set, required, error, disabled, hint }) => {
  const mode = form.secretMode;
  return (
    <Field label={label} required={required} optional={!required} error={error} hint={hint}>
      {({ id, describedBy, invalid }) =>
        mode === 'keep' || mode === 'clear' ? (
          <div className={cn('flex flex-wrap items-center gap-2 rounded-md border px-3 py-1.5', mode === 'clear' ? 'border-warning-border bg-warning-soft' : 'border-border bg-surface-2')}>
            <KeyRound className="h-4 w-4 shrink-0 text-fg-subtle" aria-hidden />
            {mode === 'keep' ? (
              <span className="text-[13px] text-fg" id={id}>
                Stored <span className="font-mono tracking-widest text-fg-muted">••••••••</span>
              </span>
            ) : (
              <span className="text-[13px] text-warning" id={id}>
                Will be removed on save
              </span>
            )}
            {!disabled && (
              <span className="ml-auto flex gap-1">
                {mode === 'keep' ? (
                  <>
                    <Button size="xs" variant="ghost" onClick={() => set({ secretMode: 'replace', secret: '' })}>
                      Replace
                    </Button>
                    {!required && (
                      <Button size="xs" variant="danger-ghost" onClick={() => set({ secretMode: 'clear' })}>
                        Clear
                      </Button>
                    )}
                  </>
                ) : (
                  <Button size="xs" variant="ghost" icon={Undo2} onClick={() => set({ secretMode: 'keep' })}>
                    Undo
                  </Button>
                )}
              </span>
            )}
          </div>
        ) : (
          <div className="flex items-center gap-2">
            <Input
              id={id}
              aria-describedby={describedBy}
              aria-invalid={invalid || undefined}
              type="password"
              autoComplete="new-password"
              value={form.secret}
              disabled={disabled}
              placeholder={mode === 'replace' ? 'New value' : ''}
              onChange={(e) => set({ secret: e.target.value })}
              className="flex-1"
            />
            {mode === 'replace' && (
              <Button size="sm" variant="ghost" onClick={() => set({ secretMode: 'keep', secret: '' })}>
                Keep stored
              </Button>
            )}
          </div>
        )
      }
    </Field>
  );
};

const HeadersEditor: React.FC<{ rows: HeaderRow[]; onChange: (r: HeaderRow[]) => void; errors: Partial<Record<string, string>>; disabled?: boolean }> = ({ rows, onChange, errors, disabled }) => (
  <div className="space-y-2">
    <div className="flex items-center justify-between gap-2">
      <span className="label">HTTP headers</span>
      <span className="text-[11.5px] text-fg-subtle">Values are write-only</span>
    </div>
    {rows.length === 0 && <p className="text-[12.5px] text-fg-subtle">No extra headers.</p>}
    {rows.map((r, i) => (
      <div key={i}>
        <div className="flex items-start gap-2">
          <Input
            aria-label={`Header ${i + 1} name`}
            mono
            value={r.name}
            disabled={disabled || r.stored}
            placeholder="Authorization"
            onChange={(e) => onChange(rows.map((x, j) => (j === i ? { ...x, name: e.target.value } : x)))}
            className="min-w-0 flex-1"
          />
          <Input
            aria-label={`Header ${i + 1} value`}
            mono
            type="password"
            autoComplete="new-password"
            value={r.value}
            disabled={disabled}
            placeholder={r.stored ? 'Stored — empty keeps it' : 'Value'}
            onChange={(e) => onChange(rows.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)))}
            className="min-w-0 flex-[1.3]"
          />
          {!disabled && <IconButton icon={Trash2} label="Remove header" variant="danger-ghost" onClick={() => onChange(rows.filter((_, j) => j !== i))} />}
        </div>
        {errors[`headers.${i}`] && <p className="mt-1 text-[11.5px] text-danger">{errors[`headers.${i}`]}</p>}
      </div>
    ))}
    {errors.headers && <p className="text-[12px] text-danger">{errors.headers}</p>}
    {!disabled && (
      <Button size="sm" variant="ghost" icon={Plus} onClick={() => onChange([...rows, { name: '', value: '', stored: false }])}>
        Add header
      </Button>
    )}
  </div>
);

/** Step 1: choose a destination type. */
const TypePicker: React.FC<{ types: ExportSinkType[]; onPick: (t: string) => void }> = ({ types, onPick }) => (
  <div className="grid gap-2.5 sm:grid-cols-2">
    {types.map((t) => {
      const id = typeId(t);
      const Icon = TYPE_ICONS[id] ?? Send;
      return (
        <button
          key={id}
          type="button"
          onClick={() => onPick(id)}
          className="group flex items-start gap-3 rounded-lg border border-border bg-surface p-3 text-left transition-colors hover:border-accent hover:bg-accent-soft/50 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring/60"
        >
          <span className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-surface-3 text-fg-muted group-hover:bg-accent-soft group-hover:text-accent">
            <Icon className="h-[18px] w-[18px]" aria-hidden />
          </span>
          <span className="min-w-0">
            <span className="block text-[13px] font-semibold text-fg">{TYPE_SHORT[id] ?? t.label}</span>
            <span className="mt-0.5 block text-[12px] leading-[18px] text-fg-muted">{t.description}</span>
            <span className="mt-1.5 flex flex-wrap gap-1">
              {(t.formats ?? []).map((f) => (
                <span key={f} className="rounded bg-surface-3 px-1.5 py-px font-mono text-[10.5px] uppercase text-fg-muted">
                  {f}
                </span>
              ))}
            </span>
          </span>
        </button>
      );
    })}
  </div>
);

export const SinkDrawer: React.FC<{
  open: boolean;
  onClose: () => void;
  sink: ExportSink | null;
  types: ExportSinkType[];
  canEdit: boolean;
  exportDir: string;
  onSaved: (s: ExportSink, created: boolean) => void;
}> = ({ open, onClose, sink, types, canEdit, exportDir, onSaved }) => {
  const toast = useToast();
  const [form, setForm] = useState<SinkForm | null>(null);
  const [attempted, setAttempted] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [test, setTest] = useState<TestResult>(null);
  const [advanced, setAdvanced] = useState(false);
  const [initialKey, setInitialKey] = useState('');

  useEffect(() => {
    if (!open) return;
    const f = sink ? fromSink(sink) : null;
    setForm(f);
    setInitialKey(f ? JSON.stringify(f) : '');
    setAttempted(false);
    setTest(null);
    setAdvanced(false);
  }, [open, sink]);

  const catalog = useMemo(() => (form ? types.find((t) => typeId(t) === form.type) : undefined), [types, form?.type]); // eslint-disable-line react-hooks/exhaustive-deps
  const fields = catalog?.fields ?? [];
  const errors = useMemo(() => (form ? validateForm(form, catalog, sink) : {}), [form, catalog, sink]);
  const shown = attempted ? errors : Object.fromEntries(Object.entries(errors).filter(([k]) => !['name', 'endpoint', 'secret', 'tenant_id', 'client_id', 'dcr_immutable_id'].includes(k) || form?.[k as keyof SinkForm]));
  const ro = !canEdit;
  const dirty = !!form && JSON.stringify(form) !== initialKey;

  const set = (p: Partial<SinkForm>) => {
    setForm((f) => (f ? { ...f, ...p } : f));
    setTest(null);
  };

  const pickType = (type: string) => {
    const t = types.find((x) => typeId(x) === type);
    if (!t) return;
    const f = newForm(t, type);
    setForm(f);
    setInitialKey(JSON.stringify(f));
    setAttempted(false);
  };

  const close = () => {
    if (dirty && canEdit && !window.confirm('Discard the changes to this destination?')) return;
    onClose();
  };

  const runTest = async () => {
    if (!form) return;
    setAttempted(true);
    const blocking = Object.keys(errors).filter((k) => !['name'].includes(k));
    if (blocking.length > 0) {
      setTest({ ok: false, error: `Fix the form first: ${errors[blocking[0]]}`, at: Date.now() });
      return;
    }
    setTesting(true);
    setTest(null);
    try {
      const res = await api.exports.test({ ...toPayload(form, fields), name: form.name.trim() || 'Connection test' });
      setTest({ ok: res.ok, error: res.error, at: Date.now() });
    } catch (err) {
      setTest({ ok: false, error: errorMessage(err), at: Date.now() });
    } finally {
      setTesting(false);
    }
  };

  const save = async () => {
    if (!form || !canEdit) return;
    setAttempted(true);
    if (Object.keys(errors).length > 0) {
      toast.error(Object.values(errors)[0] || 'Check the highlighted fields.', { title: 'Destination not saved' });
      return;
    }
    setSaving(true);
    try {
      const payload = toPayload(form, fields);
      const saved = form.id ? await api.exports.update(form.id, payload) : await api.exports.create(payload);
      onSaved(saved, !form.id);
    } catch (err) {
      toast.error(err, { title: 'Destination not saved' });
    } finally {
      setSaving(false);
    }
  };

  // A changed destination never reuses stored credentials (they stay with the saved host), neither
  // for a test nor when saving; validateForm flags the fields that need a new value.
  const credentialsError =
    form && form.secretMode === 'keep' && destinationChanged(form, sink)
      ? errors.secret
      : test && !test.ok && /enter the credentials again/i.test(test.error || '')
        ? 'The destination changed — enter the secret again to test it.'
        : null;
  const typeLabel = form ? TYPE_SHORT[form.type] ?? catalog?.label ?? form.type : '';
  const Icon = form ? TYPE_ICONS[form.type] ?? Send : Send;
  const ep = form ? endpointLabel(form.type) : { label: '', hint: '' };
  const tls = form ? usesTLS(form, fields) : false;
  const hasStream = (s: string) => !!form?.streams.includes(s as never);

  return (
    <Drawer
      open={open}
      onClose={close}
      dismissible={!saving}
      width="lg"
      title={!form ? 'Add a log destination' : sink ? (canEdit ? `Edit ${sink.name}` : sink.name) : `New ${typeLabel} destination`}
      description={!form ? 'Choose where AegisProxy sends audit, traffic and security records.' : catalog?.label}
      footer={
        form ? (
          <>
            <Button icon={Send} onClick={runTest} loading={testing} className="mr-auto" title="Sends one synthetic audit record with the settings below">
              Send test record
            </Button>
            <Button onClick={close} disabled={saving}>
              {canEdit ? 'Cancel' : 'Close'}
            </Button>
            {canEdit && (
              <Button variant="primary" onClick={save} loading={saving}>
                {sink ? 'Save destination' : 'Create destination'}
              </Button>
            )}
          </>
        ) : undefined
      }
    >
      {!form ? (
        <TypePicker types={types} onPick={pickType} />
      ) : (
        <div className="space-y-5">
          <div className="flex items-start gap-3 rounded-lg border border-border bg-surface-2 p-3">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-accent-soft text-accent">
              <Icon className="h-[18px] w-[18px]" aria-hidden />
            </span>
            <div className="min-w-0 flex-1 text-[12.5px] leading-5 text-fg-muted">
              <div className="mb-0.5 flex items-center justify-between gap-2">
                <span className="text-[13px] font-semibold text-fg">{typeLabel}</span>
                {!sink && (
                  <Button size="xs" variant="ghost" icon={ArrowLeft} onClick={() => setForm(null)}>
                    Change type
                  </Button>
                )}
              </div>
              {TYPE_HELP[form.type]}
            </div>
          </div>

          {ro && (
            <Callout tone="neutral" icon={Lock}>
              Only Super Admins can change destinations — they decide where all logs go. You can send test records to the saved destination.
            </Callout>
          )}

          {test && (
            <Callout tone={test.ok ? 'success' : 'danger'} title={test.ok ? 'Test record delivered' : 'Test failed'} icon={test.ok ? CheckCircle2 : AlertTriangle}>
              {test.ok ? `The destination accepted a synthetic audit record (${new Date(test.at).toLocaleTimeString('en-US')}). Look for action EXPORT_TEST.` : test.error}
            </Callout>
          )}

          <fieldset disabled={ro} className="min-w-0 space-y-6">
            <Section title="General">
              <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end">
                <Field label="Name" required error={shown.name}>
                  <Input value={form.name} onChange={(e) => set({ name: e.target.value })} placeholder={`e.g. ${typeLabel} – production`} data-autofocus />
                </Field>
                <div className="pb-1.5">
                  <Switch checked={form.enabled} onChange={(v) => set({ enabled: v })} disabled={ro} label="Enabled" />
                </div>
              </div>
            </Section>

            <Section title="Destination">
              <Field label={ep.label} required={form.type !== 'datadog'} error={shown.endpoint} hint={form.type === 'file' && exportDir ? `${ep.hint} Directory: ${exportDir}` : ep.hint}>
                <Input mono value={form.endpoint} onChange={(e) => set({ endpoint: e.target.value })} placeholder={catalog?.endpoint_hint} />
              </Field>

              {['transport', 'syslog_protocol', 'syslog_facility', 'syslog_framing'].some((k) => fields.includes(k)) && (
                <div className="grid gap-4 sm:grid-cols-2">
                  {fields.includes('transport') && (
                    <Field label="Transport" hint={form.transport === 'udp' ? 'Records above 64 KB are truncated.' : form.transport === 'tls' ? 'Encrypted; certificate settings below.' : 'Reliable, unencrypted.'}>
                      <Select
                        value={form.transport}
                        onChange={(e) => set({ transport: e.target.value })}
                        options={[
                          { value: 'tcp', label: 'TCP' },
                          { value: 'tls', label: 'TLS' },
                          { value: 'udp', label: 'UDP' },
                        ]}
                      />
                    </Field>
                  )}
                  {fields.includes('syslog_protocol') && (
                    <Field label="Protocol">
                      <Select
                        value={form.syslog_protocol}
                        onChange={(e) => set({ syslog_protocol: e.target.value })}
                        options={[
                          { value: 'rfc5424', label: 'RFC 5424 (structured, recommended)' },
                          { value: 'rfc3164', label: 'RFC 3164 (BSD, legacy)' },
                        ]}
                      />
                    </Field>
                  )}
                  {fields.includes('syslog_facility') && (
                    <Field label="Facility">
                      <Select value={form.syslog_facility} onChange={(e) => set({ syslog_facility: e.target.value })} options={FACILITIES.map((f) => ({ value: f, label: f }))} />
                    </Field>
                  )}
                  {fields.includes('syslog_framing') && (
                    <Field label="Framing" hint={form.transport === 'udp' ? 'Not used with UDP.' : 'Octet-counting (RFC 6587) is robust for multi-line records.'}>
                      <Select
                        value={form.syslog_framing}
                        disabled={ro || form.transport === 'udp'}
                        onChange={(e) => set({ syslog_framing: e.target.value })}
                        options={[
                          { value: 'octet-counting', label: 'Octet counting' },
                          { value: 'newline', label: 'Newline' },
                        ]}
                      />
                    </Field>
                  )}
                </div>
              )}

              {(fields.includes('index') || fields.includes('source_type') || fields.includes('username')) && (
                <div className="grid gap-4 sm:grid-cols-2">
                  {fields.includes('index') && (
                    <Field label="Index" optional hint={form.type === 'elasticsearch' ? 'Default logs-aegisproxy.{stream}-default' : 'Splunk index; may contain {stream}.'}>
                      <Input mono value={form.index} onChange={(e) => set({ index: e.target.value })} placeholder={form.type === 'elasticsearch' ? 'logs-aegisproxy.{stream}-default' : 'security'} />
                    </Field>
                  )}
                  {fields.includes('source_type') && (
                    <Field label="Source type prefix" optional hint="Default aegisproxy → aegisproxy:traffic …">
                      <Input mono value={form.source_type} onChange={(e) => set({ source_type: e.target.value })} placeholder="aegisproxy" />
                    </Field>
                  )}
                  {fields.includes('username') && (
                    <Field label="User name" optional hint={form.type === 'loki' ? 'Basic auth (Grafana Cloud: instance ID).' : 'Basic auth; leave empty to use an API key.'}>
                      <Input value={form.username} autoComplete="off" onChange={(e) => set({ username: e.target.value })} />
                    </Field>
                  )}
                </div>
              )}

              {['tenant_id', 'client_id', 'dcr_immutable_id'].some((k) => fields.includes(k)) && (
                <div className="grid gap-4 sm:grid-cols-2">
                  <Field label="Authentication" className="sm:col-span-2" hint={AZURE_AUTH_HINTS[form.azure_auth]}>
                    <Select
                      value={form.azure_auth}
                      onChange={(e) => set({ azure_auth: e.target.value as SinkForm['azure_auth'] })}
                      options={AZURE_AUTH_OPTIONS}
                      disabled={ro}
                    />
                  </Field>
                  <Field
                    label="Tenant ID"
                    required={form.azure_auth === 'client_secret'}
                    optional={form.azure_auth !== 'client_secret'}
                    error={shown.tenant_id}
                    hint={form.azure_auth === 'workload_identity' ? 'Empty: AZURE_TENANT_ID injected into the pod.' : form.azure_auth === 'managed_identity' ? 'Not needed for managed identities.' : undefined}
                  >
                    <Input mono value={form.tenant_id} onChange={(e) => set({ tenant_id: e.target.value })} placeholder="00000000-0000-…" />
                  </Field>
                  <Field
                    label="Client ID"
                    required={form.azure_auth === 'client_secret'}
                    optional={form.azure_auth !== 'client_secret'}
                    error={shown.client_id}
                    hint={
                      form.azure_auth === 'managed_identity'
                        ? 'User-assigned identity; empty uses the system-assigned identity.'
                        : form.azure_auth === 'workload_identity'
                          ? 'Empty: AZURE_CLIENT_ID injected into the pod.'
                          : 'Application ID of the app registration.'
                    }
                  >
                    <Input mono value={form.client_id} onChange={(e) => set({ client_id: e.target.value })} />
                  </Field>
                  <Field label="DCR immutable ID" required error={shown.dcr_immutable_id}>
                    <Input mono value={form.dcr_immutable_id} onChange={(e) => set({ dcr_immutable_id: e.target.value })} placeholder="dcr-…" />
                  </Field>
                  <Field label="Stream name" error={shown.stream_name} hint="Declared in the DCR.">
                    <Input mono value={form.stream_name} onChange={(e) => set({ stream_name: e.target.value })} placeholder="Custom-AegisProxy_CL" />
                  </Field>
                  <Field
                    label="Authority URL"
                    optional
                    error={shown.authority_url}
                    hint="Azure Government and Azure China are detected from the endpoint; set this only for a different Entra ID host."
                    className="sm:col-span-2"
                  >
                    <Input mono value={form.authority_url} onChange={(e) => set({ authority_url: e.target.value })} placeholder="https://login.microsoftonline.com" />
                  </Field>
                </div>
              )}

              {catalog?.secret_label && usesSecret(form) && (
                <SecretInput
                  label={catalog.secret_label.replace(/\s*\(.*\)$/, '')}
                  hint={secretHint(catalog.secret_label)}
                  form={form}
                  set={set}
                  required={SECRET_REQUIRED.includes(form.type)}
                  error={shown.secret || credentialsError || undefined}
                  disabled={ro}
                />
              )}

              {fields.includes('headers') && <HeadersEditor rows={form.headers} onChange={(headers) => set({ headers })} errors={shown} disabled={ro} />}

              {fields.includes('labels') && (
                <div>
                  <div className="mb-1.5 flex items-center justify-between gap-2">
                    <span className="label">{form.type === 'datadog' ? 'Tags' : form.type === 'otlp' ? 'Resource attributes' : 'Labels'}</span>
                    <span className="text-[11.5px] text-fg-subtle">Static, low-cardinality values such as env=prod</span>
                  </div>
                  <KeyValueEditor value={form.labels} onChange={(labels) => set({ labels })} disabled={ro} addLabel="Add label" keyPlaceholder="env" valuePlaceholder="prod" />
                  {shown.labels && <p className="mt-1 text-[12px] text-danger">{shown.labels}</p>}
                </div>
              )}
            </Section>

            <Section title="Records" description="What is sent and in which format.">
              <fieldset className="min-w-0">
                <legend className="label mb-1.5">Streams</legend>
                <div className="grid gap-2 sm:grid-cols-3">
                  {STREAMS.map((s) => {
                    const on = hasStream(s.value);
                    return (
                      <label key={s.value} className={cn('flex cursor-pointer items-start gap-2.5 rounded-md border px-3 py-2.5', on ? 'border-accent-border bg-accent-soft' : 'border-border hover:border-border-strong')}>
                        <Checkbox checked={on} disabled={ro} onChange={() => set({ streams: on ? form.streams.filter((x) => x !== s.value) : [...form.streams, s.value] })} className="mt-0.5" />
                        <span className="min-w-0 text-[13px] leading-5">
                          <span className="font-medium text-fg">{s.label}</span>
                          <span className="block text-[12px] text-fg-muted">{s.description}</span>
                        </span>
                      </label>
                    );
                  })}
                </div>
                {shown.streams && <p className="mt-1.5 text-[12px] text-danger">{shown.streams}</p>}
              </fieldset>

              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Format" hint={FORMAT_LABELS[form.format]?.hint}>
                  {(catalog?.formats ?? []).length > 1 ? (
                    <Select value={form.format} onChange={(e) => set({ format: e.target.value })} options={(catalog?.formats ?? []).map((f) => ({ value: f, label: FORMAT_LABELS[f]?.label ?? f }))} />
                  ) : (
                    <Input value={FORMAT_LABELS[form.format]?.label ?? form.format} disabled readOnly />
                  )}
                </Field>
                {hasStream('traffic') && (
                  <Field label="Traffic records" hint="Traffic is the highest-volume stream.">
                    <Select value={form.traffic_filter} onChange={(e) => set({ traffic_filter: e.target.value as SinkForm['traffic_filter'] })} options={TRAFFIC_FILTERS} />
                  </Field>
                )}
                {hasStream('security') && (
                  <Field label="Security events" hint="Minimum severity of exported security events.">
                    <Select value={form.min_severity} onChange={(e) => set({ min_severity: e.target.value as SinkForm['min_severity'] })} options={SEVERITIES} />
                  </Field>
                )}
              </div>
              {hasStream('traffic') && (
                <Switch
                  checked={form.redact_query}
                  onChange={(v) => set({ redact_query: v })}
                  disabled={ro}
                  label="Remove URL query strings"
                  description="Strips ?… from URLs before export, so tokens in query strings never leave the proxy."
                />
              )}
            </Section>

            {fields.includes('tls') && (
              <Section title="TLS" description={tls ? 'Certificate validation is on by default.' : 'Used when the transport is TLS.'}>
                {tls ? (
                  <>
                    <Field label="Private CA certificates" optional error={shown.ca_cert_pem} hint="PEM bundle to trust in addition to the system roots (internal SIEM collectors).">
                      <Textarea mono rows={3} value={form.ca_cert_pem} onChange={(e) => set({ ca_cert_pem: e.target.value })} placeholder="-----BEGIN CERTIFICATE-----" />
                    </Field>
                    <div className="grid gap-4 sm:grid-cols-2">
                      <Field label="Client certificate" optional error={shown.client_cert_pem} hint="Mutual TLS.">
                        <Textarea mono rows={3} value={form.client_cert_pem} onChange={(e) => set({ client_cert_pem: e.target.value })} placeholder="-----BEGIN CERTIFICATE-----" />
                      </Field>
                      <Field
                        label="Client key"
                        optional
                        error={shown.client_key_pem}
                        hint={form.hasStoredKey && !form.client_cert_pem.trim() ? 'Removing the certificate also removes the stored key.' : 'Write-only.'}
                      >
                        {({ id }) =>
                          form.keyMode === 'keep' ? (
                            <div id={id} className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-surface-2 px-3 py-1.5">
                              <KeyRound className="h-4 w-4 shrink-0 text-fg-subtle" aria-hidden />
                              <span className="text-[13px] text-fg">
                                Stored <span className="font-mono tracking-widest text-fg-muted">••••••••</span>
                              </span>
                              {!ro && (
                                <Button size="xs" variant="ghost" className="ml-auto" onClick={() => set({ keyMode: 'replace', client_key_pem: '' })}>
                                  Replace
                                </Button>
                              )}
                            </div>
                          ) : (
                            <div className="space-y-1.5">
                              <Textarea id={id} mono rows={3} value={form.client_key_pem} onChange={(e) => set({ client_key_pem: e.target.value })} placeholder="-----BEGIN PRIVATE KEY-----" />
                              {form.hasStoredKey && !ro && (
                                <Button size="xs" variant="ghost" icon={Undo2} onClick={() => set({ keyMode: 'keep', client_key_pem: '' })}>
                                  Keep the stored key
                                </Button>
                              )}
                            </div>
                          )
                        }
                      </Field>
                    </div>
                    <div className={cn('rounded-md border px-3 py-3', form.tls_skip_verify ? 'border-danger-border bg-danger-soft' : 'border-border')}>
                      <Switch
                        checked={form.tls_skip_verify}
                        onChange={(v) => set({ tls_skip_verify: v })}
                        disabled={ro}
                        label="Skip certificate verification"
                        description={
                          form.tls_skip_verify
                            ? 'Insecure: anyone on the network path can read and alter exported logs. Use for lab setups only — paste the private CA instead.'
                            : 'Lab setups only.'
                        }
                      />
                    </div>
                  </>
                ) : (
                  <p className="text-[12.5px] text-fg-subtle">Choose the TLS transport to configure certificates.</p>
                )}
              </Section>
            )}

            <section className="border-t border-border pt-4">
              <button
                type="button"
                onClick={() => setAdvanced((a) => !a)}
                aria-expanded={advanced}
                className="flex w-full items-center gap-1.5 text-left text-[13.5px] font-semibold text-fg hover:text-accent"
              >
                {advanced ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                Advanced delivery
                <span className="ml-2 text-[12px] font-normal text-fg-subtle">
                  {form.batch_size} per batch · every {form.flush_seconds}s · {form.spool_mb} MB spool
                </span>
              </button>
              {advanced && (
                <div className="mt-4 space-y-3">
                  <div className="grid gap-4 sm:grid-cols-3">
                    <Field label="Batch size" error={shown.batch_size} hint="Records per request (1–5000).">
                      <Input type="number" min={1} max={5000} value={form.batch_size} onChange={(e) => set({ batch_size: Number(e.target.value) })} />
                    </Field>
                    <Field label="Flush interval" error={shown.flush_seconds} hint="Seconds (1–300).">
                      <Input type="number" min={1} max={300} value={form.flush_seconds} onChange={(e) => set({ flush_seconds: Number(e.target.value) })} trailing={<span className="text-[12px] text-fg-subtle">s</span>} />
                    </Field>
                    <Field label="Disk spool" error={shown.spool_mb} hint="When the destination is down (16–102400).">
                      <Input type="number" min={16} max={102400} value={form.spool_mb} onChange={(e) => set({ spool_mb: Number(e.target.value) })} trailing={<span className="text-[12px] text-fg-subtle">MB</span>} />
                    </Field>
                  </div>
                  <p className="text-[12px] leading-5 text-fg-subtle">
                    Batches that cannot be delivered are written to the spool and replayed in order (at least once). When the spool is full, the oldest records are
                    dropped and counted.
                  </p>
                </div>
              )}
            </section>
          </fieldset>
          {testing && (
            <p className="flex items-center gap-2 text-[12.5px] text-fg-muted">
              <Spinner className="h-3.5 w-3.5" /> Sending a test record…
            </p>
          )}
          {sink?.updated_at && (
            <p className="text-[12px] text-fg-subtle">
              Last changed {new Date(sink.updated_at).toLocaleString('en-US')} by {sink.updated_by}
              {dirty && <Badge tone="warning" className="ml-2">Unsaved</Badge>}
            </p>
          )}
        </div>
      )}
    </Drawer>
  );
};
