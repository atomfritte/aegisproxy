import React, { useEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, CheckCircle2, Laptop, Lock, PlugZap, RefreshCw, ShieldBan, ShieldHalf, XCircle } from 'lucide-react';
import { api } from '../../../api';
import { useConsole, useConsoleState, usePermissions } from '../../../data/AppData';
import { formatNumber } from '../../../lib/format';
import { useAsync } from '../../../lib/hooks';
import { Link, useNavigationBlocker } from '../../../lib/router';
import type { DefenderConfig, DefenderIndicatorAction, DefenderTestResult } from '../../../types';
import {
  Badge,
  Button,
  Callout,
  Card,
  CardHeader,
  Checkbox,
  Field,
  Input,
  RelativeTime,
  SegmentedControl,
  Select,
  Skeleton,
  StatTile,
  StatusChip,
  Switch,
  useToast,
} from '../../../ui';
import { UserName } from '../../../components/common/EntityChips';
import { SecretField } from '../../../components/common/Secrets';
import { DEFENDER_ACTOR } from '../../../components/fleet/DefenderDevice';
import { RestrictedSection, SaveBar, SectionTitle } from './shared';

const CLOUDS = [
  { id: 'commercial', label: 'Commercial (worldwide)', api: 'https://api.security.microsoft.com', authority: 'https://login.microsoftonline.com' },
  { id: 'gcc', label: 'US Government (GCC)', api: 'https://api-gcc.securitycenter.microsoft.us', authority: 'https://login.microsoftonline.com' },
  { id: 'gcc-high', label: 'US Government (GCC High / DoD)', api: 'https://api-gov.securitycenter.microsoft.us', authority: 'https://login.microsoftonline.us' },
] as const;

const ACTIONS: Array<{ value: DefenderIndicatorAction; label: string; hint: string }> = [
  { value: 'Block', label: 'Block', hint: 'Blocked on endpoints' },
  { value: 'AlertAndBlock', label: 'Alert and block', hint: 'Blocked and alerted' },
  { value: 'BlockAndRemediate', label: 'Block and remediate', hint: 'Files: blocked and remediated' },
  { value: 'Warn', label: 'Warn', hint: 'Users see a warning (still blocked at the proxy)' },
  { value: 'Alert', label: 'Alert only', hint: 'Detection only in Defender' },
  { value: 'Audit', label: 'Audit', hint: 'Audit only in Defender' },
];
const DEFAULT_ACTIONS: DefenderIndicatorAction[] = ['Block', 'AlertAndBlock', 'BlockAndRemediate'];
const TENANT_RE = /^[A-Za-z0-9.-]{3,128}$/;

interface Form {
  enabled: boolean;
  tenant_id: string;
  client_id: string;
  client_secret: string;
  cloud: string;
  api_base_url: string;
  authority_url: string;
  import_indicators: boolean;
  indicator_actions: DefenderIndicatorAction[];
  device_sync: boolean;
  quarantine_on_risk: 'off' | 'high' | 'medium';
  quarantine_on_isolation: boolean;
  auto_release: boolean;
  sync_minutes: string;
}

// Installations before 2.1 stored the legacy commercial host; it still works and maps to the same cloud.
const LEGACY_COMMERCIAL_API = 'https://api.securitycenter.microsoft.com';

function cloudOf(api: string, authority: string): string {
  const raw = (api || CLOUDS[0].api).replace(/\/+$/, '');
  const a = raw === LEGACY_COMMERCIAL_API ? CLOUDS[0].api : raw;
  const au = (authority || CLOUDS[0].authority).replace(/\/+$/, '');
  return CLOUDS.find((c) => c.api === a && c.authority === au)?.id ?? 'custom';
}

function toForm(c?: DefenderConfig): Form {
  return {
    enabled: !!c?.enabled,
    tenant_id: c?.tenant_id ?? '',
    client_id: c?.client_id ?? '',
    client_secret: '',
    cloud: cloudOf(c?.api_base_url ?? '', c?.authority_url ?? ''),
    api_base_url: c?.api_base_url || CLOUDS[0].api,
    authority_url: c?.authority_url || CLOUDS[0].authority,
    import_indicators: !!c?.import_indicators,
    indicator_actions: c?.indicator_actions?.length ? [...c.indicator_actions] : [...DEFAULT_ACTIONS],
    device_sync: !!c?.device_sync,
    quarantine_on_risk: c?.quarantine_on_risk === 'high' || c?.quarantine_on_risk === 'medium' ? c.quarantine_on_risk : 'off',
    quarantine_on_isolation: !!c?.quarantine_on_isolation,
    auto_release: !!c?.auto_release,
    sync_minutes: String(c?.sync_minutes || 5),
  };
}

function toPayload(f: Form): DefenderConfig {
  const cloud = CLOUDS.find((c) => c.id === f.cloud);
  const out: DefenderConfig = {
    enabled: f.enabled,
    tenant_id: f.tenant_id.trim(),
    client_id: f.client_id.trim(),
    api_base_url: (cloud?.api ?? f.api_base_url).trim(),
    authority_url: (cloud?.authority ?? f.authority_url).trim(),
    import_indicators: f.import_indicators,
    indicator_actions: [...f.indicator_actions],
    device_sync: f.device_sync,
    quarantine_on_risk: f.quarantine_on_risk,
    quarantine_on_isolation: f.quarantine_on_isolation,
    auto_release: f.auto_release,
    sync_minutes: Number(f.sync_minutes),
    last_sync_devices: 0,
    matched_servers: 0,
  };
  if (f.client_secret) out.client_secret = f.client_secret;
  return out;
}

const fingerprint = (f: Form) => JSON.stringify({ ...toPayload(f), client_secret: undefined });

/** Settings → Microsoft Defender: indicators import, device risk/isolation sync, automatic quarantine. */
export const DefenderSection: React.FC = () => {
  const perms = usePermissions();
  if (!perms.canManageSystem) {
    return (
      <RestrictedSection
        title="Microsoft Defender for Endpoint"
        description="Imports Defender custom indicators into threat intelligence and quarantines servers that Defender rates as high risk or isolates."
      />
    );
  }
  return <Defender />;
};

const Defender: React.FC = () => {
  const state = useConsoleState();
  const { refresh } = useConsole();
  const toast = useToast();
  const data = useAsync(() => api.defender.get(), []);
  const cfg = data.data?.config;
  const canEdit = !!data.data?.can_edit;
  const base = useMemo(() => toForm(cfg), [JSON.stringify(cfg)]); // eslint-disable-line react-hooks/exhaustive-deps
  const [f, setF] = useState<Form>(base);
  const [attempted, setAttempted] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [test, setTest] = useState<(DefenderTestResult & { error?: string }) | null>(null);
  const [savedAt, setSavedAt] = useState(0);
  const [serverError, setServerError] = useState<string | null>(null);
  const dirty = !!data.data && (fingerprint(f) !== fingerprint(base) || !!f.client_secret);
  // adopt server data (first load, refresh) unless the form has local edits
  const prevBase = useRef(base);
  useEffect(() => {
    if (fingerprint(f) === fingerprint(prevBase.current) && !f.client_secret) setF(base);
    prevBase.current = base;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [base]);
  useNavigationBlocker(dirty && canEdit, 'Discard unsaved Defender settings?');
  const set = (p: Partial<Form>) => {
    setF((x) => ({ ...x, ...p }));
    setServerError(null);
  };

  const mins = Number(f.sync_minutes);
  const errors = {
    tenant_id: f.tenant_id.trim() && !TENANT_RE.test(f.tenant_id.trim()) ? 'Use the directory (tenant) ID.' : f.enabled && !f.tenant_id.trim() ? 'Required when the integration is enabled.' : null,
    client_id: f.enabled && !f.client_id.trim() ? 'Required when the integration is enabled.' : null,
    client_secret: f.enabled && !cfg?.has_client_secret && !f.client_secret ? 'Required when the integration is enabled.' : null,
    sync_minutes: !Number.isInteger(mins) || mins < 1 || mins > 1440 ? 'Between 1 and 1440 minutes.' : null,
    urls:
      f.cloud === 'custom' && (!/^https:\/\//i.test(f.api_base_url.trim()) || !/^https:\/\//i.test(f.authority_url.trim())) ? 'Both endpoints must be https:// URLs.' : null,
    actions: f.import_indicators && f.indicator_actions.length === 0 ? 'Select at least one indicator action.' : null,
  };
  const invalid = Object.values(errors).some(Boolean);
  // server answers that belong to a field (test: secret must be re-entered; save: non-Microsoft endpoints)
  const testMsg = test && !test.ok ? test.error || '' : '';
  const secretServerError = /enter the client secret/i.test(testMsg) ? 'The tenant, application or endpoints changed — enter the client secret again to test them.' : null;
  const urlServerError = serverError && /Microsoft cloud endpoints|must be an https URL/i.test(serverError) ? serverError : null;
  const err = (k: keyof typeof errors) => (attempted || k === 'tenant_id' || k === 'sync_minutes' || k === 'urls' ? errors[k] : null);

  const save = async () => {
    setAttempted(true);
    if (invalid) return;
    setSaving(true);
    setServerError(null);
    try {
      const saved = await api.defender.update(toPayload(f));
      data.setData(data.data ? { ...data.data, config: saved } : data.data);
      setF({ ...toForm(saved) });
      setSavedAt(Date.now());
      setAttempted(false);
      toast.success('Defender integration saved', {
        description: saved.enabled ? (saved.device_sync ? 'Devices are synchronized within a minute.' : 'Indicators are imported with the next feed refresh.') : 'The integration is off.',
      });
      refresh();
    } catch (e) {
      setServerError(e instanceof Error ? e.message : String(e));
      toast.error(e, { title: 'Defender integration not saved' });
    } finally {
      setSaving(false);
    }
  };

  const runTest = async () => {
    setTesting(true);
    setTest(null);
    try {
      const p = toPayload(f);
      setTest(await api.defender.test({ ...p, client_secret: f.client_secret || undefined }));
    } catch (e) {
      setTest({ ok: false, error: e instanceof Error ? e.message : String(e) });
    } finally {
      setTesting(false);
    }
  };

  const syncNow = async () => {
    setSyncing(true);
    try {
      const r = await api.defender.sync();
      data.setData(data.data ? { ...data.data, config: r.config } : data.data);
      toast.success('Defender sync finished', { description: `${formatNumber(r.config.last_sync_devices)} devices, ${formatNumber(r.config.matched_servers)} matched servers.` });
      refresh();
    } catch (e) {
      toast.error(e, { title: 'Defender sync failed' });
      data.reload();
    } finally {
      setSyncing(false);
    }
  };

  const defenderQuarantined = (state.servers ?? []).filter((s) => s.quarantined && s.quarantined_by === DEFENDER_ACTOR);
  const withDevice = (state.servers ?? []).filter((s) => s.defender);
  const feed = (state.security?.feeds ?? []).find((x) => x.format === 'mde');

  let status: React.ReactNode = <StatusChip tone="neutral" label="Not connected" />;
  if (cfg?.enabled) {
    if (cfg.last_sync_error) status = <StatusChip tone="danger" label="Sync failing" />;
    else if (cfg.device_sync && !cfg.last_sync_at) status = <StatusChip tone="warning" label="Waiting for first sync" />;
    else status = <StatusChip tone="success" label="Connected" />;
  }

  return (
    <>
      <SectionTitle
        title="Microsoft Defender for Endpoint"
        description="Share verdicts between endpoint and network: Defender custom indicators are blocked at the proxy, and servers that Defender rates as high risk or isolates are quarantined automatically."
        actions={
          data.data ? (
            <>
              {status}
              <Button icon={RefreshCw} onClick={syncNow} loading={syncing} disabled={!cfg?.enabled || dirty}>
                Sync now
              </Button>
            </>
          ) : null
        }
      />
      {data.error && !data.data && (
        <Callout tone="danger" title="The Defender integration could not be loaded" action={<Button size="sm" onClick={() => data.reload()}>Try again</Button>}>
          {data.error}
        </Callout>
      )}
      {!data.data && !data.error && (
        <div className="space-y-3">
          <Skeleton className="h-24" />
          <Skeleton className="h-64" />
        </div>
      )}
      {data.data && cfg && (
        <div className="space-y-5">
          {!canEdit && (
            <Callout tone="neutral" icon={Lock}>
              Only Super Admins can change this integration: it holds tenant credentials and can quarantine servers automatically. You can test the connection and run a sync.
            </Callout>
          )}
          {cfg.enabled && cfg.last_sync_error && (
            <Callout tone="danger" icon={AlertTriangle} title="The last device sync failed">
              <span className="block font-mono text-[12px] text-fg [overflow-wrap:anywhere]">{cfg.last_sync_error}</span>
              <span className="mt-1 block text-[12px]">Servers keep their last known Defender state. Check the client secret and the Machine.Read.All permission (Machine.ReadWrite.All with quarantine on isolation).</span>
            </Callout>
          )}
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <StatTile label="Defender devices" value={cfg.enabled && cfg.device_sync ? formatNumber(cfg.last_sync_devices) : '—'} icon={Laptop} hint={cfg.last_sync_at ? <RelativeTime value={cfg.last_sync_at} prefix="synced" /> : 'Not synchronized yet'} />
            <StatTile label="Matched servers" value={cfg.enabled && cfg.device_sync ? formatNumber(cfg.matched_servers) : '—'} icon={ShieldHalf} hint={`${withDevice.length} of ${(state.servers ?? []).length} servers carry Defender data`} to="/servers" />
            <StatTile
              label="Quarantined by Defender"
              value={formatNumber(defenderQuarantined.length)}
              icon={ShieldBan}
              tone={defenderQuarantined.length ? 'danger' : 'neutral'}
              attention={defenderQuarantined.length > 0}
              hint={cfg.enabled && cfg.device_sync && ((cfg.quarantine_on_risk && cfg.quarantine_on_risk !== 'off') || cfg.quarantine_on_isolation) ? 'Automatic quarantine on' : 'Automatic quarantine off'}
              to={defenderQuarantined.length ? '/servers?quarantined=1' : undefined}
            />
            <StatTile
              label="Imported indicators"
              value={cfg.enabled && cfg.import_indicators && feed ? formatNumber(feed.entry_count) : '—'}
              icon={ShieldHalf}
              hint={feed?.last_error ? <span className="text-danger">Last import failed</span> : feed?.last_success_at ? <RelativeTime value={feed.last_success_at} prefix="updated" /> : cfg.enabled && cfg.import_indicators ? 'Not imported yet' : 'Import off'}
              to={feed ? '/threats/feeds' : undefined}
            />
          </div>

          <div className="min-w-0 space-y-5">
            <Card>
              <CardHeader icon={PlugZap} title="Connection" description="An Entra application with application permissions on the WindowsDefenderATP API." divider />
              <div className="space-y-5 p-[var(--card-p)]">
                <fieldset disabled={!canEdit} className="min-w-0 space-y-5">
                <Switch checked={f.enabled} onChange={(v) => set({ enabled: v })} label="Enable the integration" description="Turning it off keeps the settings but stops imports, device sync and automatic quarantine." />
                <div className="grid gap-4 md:grid-cols-2">
                  <Field label="Directory (tenant) ID" required={f.enabled} error={err('tenant_id')}>
                    <Input mono value={f.tenant_id} onChange={(e) => set({ tenant_id: e.target.value })} placeholder="00000000-0000-0000-0000-000000000000" spellCheck={false} />
                  </Field>
                  <Field label="Application (client) ID" required={f.enabled} error={err('client_id')}>
                    <Input mono value={f.client_id} onChange={(e) => set({ client_id: e.target.value })} placeholder="00000000-0000-0000-0000-000000000000" spellCheck={false} />
                  </Field>
                  <SecretField
                    label="Client secret"
                    stored={!!cfg.has_client_secret}
                    value={f.client_secret}
                    onChange={(v) => set({ client_secret: v })}
                    required={f.enabled && !cfg.has_client_secret}
                    error={err('client_secret') || secretServerError}
                    disabled={!canEdit}
                    resetKey={savedAt}
                  />
                  <Field label="Cloud" hint="Government clouds use their own API and sign-in endpoints.">
                    <Select value={f.cloud} onChange={(e) => set({ cloud: e.target.value })} options={[...CLOUDS.map((c) => ({ value: c.id, label: c.label })), { value: 'custom', label: 'Custom endpoints' }]} />
                  </Field>
                </div>
                {f.cloud === 'custom' && (
                  <div className="grid gap-4 md:grid-cols-2">
                    <Field label="API base URL" error={err('urls') || urlServerError} hint="Microsoft cloud endpoints only (commercial, GCC / GCC High, China).">
                      <Input mono value={f.api_base_url} onChange={(e) => set({ api_base_url: e.target.value })} placeholder={CLOUDS[0].api} />
                    </Field>
                    <Field label="Authority URL">
                      <Input mono value={f.authority_url} onChange={(e) => set({ authority_url: e.target.value })} placeholder={CLOUDS[0].authority} />
                    </Field>
                  </div>
                )}
                </fieldset>
                <div className="rounded-lg border border-border bg-surface-2 p-3 text-[12.5px] leading-5 text-fg-muted">
                  <span className="font-medium text-fg">Required API permissions</span> (application, admin consent):{' '}
                  {(data.data.permissions ?? []).map((p, i) => {
                    const m = /^(\S+)\s*(?:\((.*)\))?$/.exec(p);
                    return (
                      <React.Fragment key={p}>
                        {i > 0 && ', '}
                        <code className="font-mono text-fg">{m ? m[1] : p}</code>
                        {m?.[2] ? ` (${m[2]})` : ''}
                      </React.Fragment>
                    );
                  })}
                  .
                </div>
                <div className="flex flex-col gap-3 border-t border-border pt-4 sm:flex-row sm:items-center">
                  <Button icon={PlugZap} loading={testing} onClick={runTest} disabled={!f.tenant_id.trim() || !f.client_id.trim() || (!cfg.has_client_secret && !f.client_secret)}>
                    Test connection
                  </Button>
                  <span className="text-[12.5px] text-fg-muted">
                    {canEdit
                      ? 'Signs in with the entered credentials and reads indicators and devices. After changing the tenant, application or endpoints, enter the client secret again. Nothing is saved.'
                      : 'Tests the saved configuration: signs in and reads indicators and devices. Nothing is changed.'}
                  </span>
                </div>
                {test && <TestResult r={test} />}
              </div>
            </Card>

            <Card>
              <CardHeader icon={ShieldHalf} title="Custom indicators" description="What your SOC blocks on endpoints is blocked at the proxy too — also for servers without a Defender sensor." divider />
              <fieldset disabled={!canEdit} className="min-w-0 space-y-4 p-[var(--card-p)]">
                <Switch
                  checked={f.import_indicators}
                  onChange={(v) => set({ import_indicators: v })}
                  label="Import Defender indicators into threat intelligence"
                  description={
                    <>
                      Domains, URLs, IP addresses and SHA-256 hashes become the built-in feed “Microsoft Defender for Endpoint indicators” (
                      <Link to="/threats/feeds" className="text-accent hover:underline">
                        Threat protection → Feeds
                      </Link>
                      ), enforced in the threat intelligence mode of the protection policy.
                    </>
                  }
                />
                {f.import_indicators && (
                  <Field label="Indicator actions to import" error={err('actions')} hint="Only indicators with these actions are blocked by the proxy. Expired indicators are skipped.">
                    {() => (
                      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3" role="group" aria-label="Indicator actions">
                        {ACTIONS.map((a) => (
                          <Checkbox
                            key={a.value}
                            checked={f.indicator_actions.includes(a.value)}
                            onChange={(e) => set({ indicator_actions: e.target.checked ? [...f.indicator_actions, a.value] : f.indicator_actions.filter((x) => x !== a.value) })}
                            label={a.label}
                            description={a.hint}
                          />
                        ))}
                      </div>
                    )}
                  </Field>
                )}
              </fieldset>
            </Card>

            <Card>
              <CardHeader icon={ShieldBan} title="Device sync and automatic quarantine" description="Maps Defender devices to registered servers by host name, then by IP address." divider />
              <div className="space-y-5 p-[var(--card-p)]">
                <fieldset disabled={!canEdit} className="min-w-0 space-y-5">
                <Switch
                  checked={f.device_sync}
                  onChange={(v) => set({ device_sync: v })}
                  label="Synchronize devices"
                  description="Shows risk, exposure, sensor health and isolation on every matched server."
                />
                <div className={f.device_sync ? 'space-y-5' : 'pointer-events-none space-y-5 opacity-60'} aria-disabled={!f.device_sync || undefined}>
                  <Field label="Quarantine servers when Defender rates their risk" hint="A quarantined server cannot reach any destination until it is released.">
                    {() => (
                      <SegmentedControl<'off' | 'high' | 'medium'>
                        aria-label="Quarantine on risk"
                        value={f.quarantine_on_risk}
                        onChange={(v) => set({ quarantine_on_risk: v })}
                        options={[
                          { value: 'off', label: 'Never' },
                          { value: 'high', label: 'High' },
                          { value: 'medium', label: 'Medium or high' },
                        ]}
                      />
                    )}
                  </Field>
                  <Switch
                    checked={f.quarantine_on_isolation}
                    onChange={(v) => set({ quarantine_on_isolation: v })}
                    label="Quarantine servers isolated in Defender"
                    description="Enforces the SOC’s isolation decision on the network path as well, even if the sensor is tampered with."
                  />
                  <Switch
                    checked={f.auto_release}
                    onChange={(v) => set({ auto_release: v })}
                    label="Release automatically when the condition clears"
                    description="Only quarantines applied by this integration are released; manual quarantines always stay."
                  />
                  <Field label="Sync interval" error={err('sync_minutes')} hint={err('sync_minutes') ? undefined : 'Indicators refresh at least every 15 minutes.'} className="max-w-[240px]">
                    <Input type="number" min={1} max={1440} value={f.sync_minutes} onChange={(e) => set({ sync_minutes: e.target.value })} trailing={<span className="text-[12px] text-fg-subtle">minutes</span>} />
                  </Field>
                </div>
                </fieldset>
                {defenderQuarantined.length > 0 && (
                  <div className="border-t border-border pt-4">
                    <span className="label mb-2">Currently quarantined by Defender</span>
                    <ul className="divide-y divide-border rounded-md border border-border">
                      {defenderQuarantined.map((s) => (
                        <li key={s.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-[13px]">
                          <Link to={`/servers/${encodeURIComponent(s.id)}`} className="font-medium text-fg hover:text-accent hover:underline">
                            {s.hostname}
                          </Link>
                          <span className="min-w-0 flex-1 truncate text-[12px] text-fg-muted" title={s.quarantine_reason}>
                            {s.quarantine_reason}
                          </span>
                          {s.quarantined_at && <RelativeTime value={s.quarantined_at} className="text-[12px] text-fg-subtle" />}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </Card>
          </div>

          {cfg.updated_at && (
            <p className="text-[12px] text-fg-subtle">
              Last changed <RelativeTime value={cfg.updated_at} />
              {cfg.updated_by && (
                <>
                  {' '}by <UserName username={cfg.updated_by} avatar={false} />
                </>
              )}
            </p>
          )}

          {canEdit && (
            <SaveBar
              dirty={dirty}
              saving={saving}
              onSave={save}
              onReset={() => {
                setF(base);
                setAttempted(false);
              }}
              note={attempted && invalid ? 'Fix the highlighted fields.' : undefined}
            />
          )}
        </div>
      )}
    </>
  );
};

const TestResult: React.FC<{ r: DefenderTestResult & { error?: string } }> = ({ r }) => {
  if (r.error) {
    return (
      <Callout tone="danger" icon={XCircle} title="The connection test failed">
        <span className="block font-mono text-[12px] text-fg [overflow-wrap:anywhere]" data-testid="defender-test-error">
          {r.error}
        </span>
      </Callout>
    );
  }
  const row = (label: string, count?: number, error?: string) => (
    <li className="flex items-start gap-2">
      {error ? <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-danger" aria-hidden /> : <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-success" aria-hidden />}
      <span className="min-w-0">
        <span className="font-medium text-fg">{label}</span>{' '}
        {error ? <span className="font-mono text-[12px] text-fg-muted [overflow-wrap:anywhere]">{error}</span> : <Badge tone="success">{formatNumber(count ?? 0)} readable</Badge>}
      </span>
    </li>
  );
  return (
    <Callout tone={r.ok ? 'success' : 'danger'} title={r.ok ? 'Connected to Microsoft Defender' : 'Some permissions are missing'}>
      <ul className="mt-1 space-y-1.5 text-[12.5px]" data-testid="defender-test-result">
        {row('Indicators (Ti.ReadWrite.All)', r.indicators, r.indicators_error)}
        {row('Devices (Machine.Read.All)', r.devices, r.devices_error)}
      </ul>
      {!r.ok && (
        <span className="mt-2 block text-[12px]">Add the missing application permissions to the app registration and grant admin consent.</span>
      )}
    </Callout>
  );
};
