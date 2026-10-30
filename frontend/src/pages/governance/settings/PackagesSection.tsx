import React, { useEffect, useMemo, useState } from 'react';
import { Boxes, Clock, Database, FlaskConical, PackageCheck } from 'lucide-react';
import { api } from '../../../api';
import { useConsole, useConsoleState, usePermissions } from '../../../data/AppData';
import { useAsync } from '../../../lib/hooks';
import { useNavigationBlocker } from '../../../lib/router';
import type { PackageAuditSource, PackageSettings } from '../../../types';
import { Badge, Button, Callout, Card, CardBody, CardHeader, Field, Input, MultiSelect, SegmentedControl, Select, Skeleton, Switch, TagInput, useToast } from '../../../ui';
import { SecretField } from '../../../components/common/Secrets';
import { ECOSYSTEM_META, ECOSYSTEMS, humanHours } from '../../../components/packages/packageUtils';
import { RestrictedSection, SaveBar, SectionTitle } from './shared';

const MB = 1024 * 1024;

const AUDIT_CATALOG: Array<{ id: string; label: string; hint: string; token: boolean; account?: string; url?: boolean }> = [
  { id: 'osv', label: 'OSV', hint: 'Open Source Vulnerabilities — no credentials needed.', token: false },
  { id: 'github', label: 'GitHub Advisories', hint: 'GHSA database via the GitHub API.', token: true },
  { id: 'npm', label: 'npm audit', hint: 'The npm registry advisory endpoint.', token: false },
  { id: 'pypi', label: 'PyPI advisories', hint: 'PyPI / OSV advisories for Python packages.', token: false },
  { id: 'nuget', label: 'NuGet audit', hint: 'The NuGet vulnerability feed.', token: false },
  { id: 'depsdev', label: 'deps.dev', hint: 'Google deps.dev metadata and advisories.', token: false, url: true },
  { id: 'ossindex', label: 'Sonatype OSS Index', hint: 'Reputation and advisories.', token: true, account: 'User name' },
  { id: 'socket', label: 'Socket', hint: 'Supply-chain behaviour analysis.', token: true, url: true },
  { id: 'snyk', label: 'Snyk', hint: 'Snyk vulnerability database.', token: true, account: 'Organization ID', url: true },
];

const SEVERITY_OPTIONS = [
  { value: '', label: 'Never revoke automatically' },
  { value: 'high', label: 'High or above' },
  { value: 'critical', label: 'Critical or above' },
  { value: 'malware', label: 'Malware only' },
];

interface EcoForm {
  mode: string;
  hosts: string[];
  file_hosts: string[];
  group_ids: string[];
  upstream: string;
}
interface AuditForm {
  enabled: boolean;
  token: string;
  has_token: boolean;
  account: string;
  url: string;
}
interface Form {
  ecosystems: Record<string, EcoForm>;
  default_cooldown_hours: string;
  auto_request_discovered: boolean;
  reaudit_hours: string;
  watch_hours: string;
  revoke_on_severity: string;
  max_graph_size: string;
  sandbox: { enabled: boolean; scenarios: string[]; timeout_seconds: string; max_artifact_mb: string; required: boolean };
  audit: Record<string, AuditForm>;
}

function toForm(s?: PackageSettings): Form {
  const ecosystems: Record<string, EcoForm> = {};
  for (const id of ECOSYSTEMS) {
    const e = s?.ecosystems?.[id];
    ecosystems[id] = {
      mode: e?.mode ?? 'off',
      hosts: e?.hosts ?? [],
      file_hosts: e?.file_hosts ?? [],
      group_ids: e?.group_ids ?? ['*'],
      upstream: e?.upstream ?? '',
    };
  }
  const audit: Record<string, AuditForm> = {};
  for (const c of AUDIT_CATALOG) {
    const stored = (s?.audit_sources ?? []).find((x) => x.id === c.id);
    audit[c.id] = { enabled: stored?.enabled ?? false, token: '', has_token: !!stored?.has_token, account: stored?.account ?? '', url: stored?.url ?? '' };
  }
  return {
    ecosystems,
    default_cooldown_hours: String(s?.default_cooldown_hours ?? 72),
    auto_request_discovered: s?.auto_request_discovered ?? false,
    reaudit_hours: String(s?.reaudit_hours ?? 24),
    watch_hours: String(s?.watch_hours ?? 6),
    revoke_on_severity: s?.revoke_on_severity ?? '',
    max_graph_size: String(s?.max_graph_size ?? 2000),
    sandbox: {
      enabled: s?.sandbox?.enabled ?? false,
      scenarios: s?.sandbox?.scenarios ?? ['static', 'install', 'load'],
      timeout_seconds: String(s?.sandbox?.timeout_seconds ?? 300),
      max_artifact_mb: String(Math.round((s?.sandbox?.max_artifact_bytes ?? 256 * MB) / MB)),
      required: s?.sandbox?.required ?? false,
    },
    audit,
  };
}

function toPayload(f: Form): PackageSettings {
  const ecosystems: PackageSettings['ecosystems'] = {};
  for (const id of ECOSYSTEMS) {
    const e = f.ecosystems[id];
    ecosystems[id] = {
      mode: e.mode as PackageSettings['ecosystems'][string]['mode'],
      hosts: e.hosts,
      file_hosts: e.file_hosts,
      group_ids: e.group_ids.length ? e.group_ids : ['*'],
      upstream: e.upstream.trim(),
    };
  }
  const audit_sources: PackageAuditSource[] = AUDIT_CATALOG.map((c) => {
    const a = f.audit[c.id];
    const out: PackageAuditSource = { id: c.id, enabled: a.enabled, has_token: a.has_token };
    if (c.account && a.account.trim()) out.account = a.account.trim();
    if (c.url && a.url.trim()) out.url = a.url.trim();
    if (a.token) out.token = a.token; // write-only: only when newly typed
    return out;
  });
  return {
    ecosystems,
    default_cooldown_hours: Number(f.default_cooldown_hours) || 0,
    auto_request_discovered: f.auto_request_discovered,
    reaudit_hours: Number(f.reaudit_hours) || 0,
    watch_hours: Number(f.watch_hours) || 0,
    revoke_on_severity: f.revoke_on_severity,
    max_graph_size: Number(f.max_graph_size) || 0,
    sandbox: {
      enabled: f.sandbox.enabled,
      scenarios: f.sandbox.scenarios,
      timeout_seconds: Number(f.sandbox.timeout_seconds) || 0,
      max_artifact_bytes: (Number(f.sandbox.max_artifact_mb) || 0) * MB,
      required: f.sandbox.required,
    },
    audit_sources,
  };
}

/** Strips write-only tokens so the dirty check does not depend on them. */
function fingerprint(f: Form): string {
  const clone = toPayload(f);
  clone.audit_sources = (clone.audit_sources ?? []).map((a) => ({ ...a, token: undefined }));
  return JSON.stringify(clone);
}

/** Settings → Package firewall: per-ecosystem mode and hosts, cooldown/watch/reaudit, sandbox and advisory sources. */
export const PackagesSection: React.FC = () => {
  const perms = usePermissions();
  if (!perms.canManageSystem) {
    return (
      <RestrictedSection
        title="Package firewall"
        description="Per-ecosystem enforcement, cooldown (Karenz), the sandbox and advisory sources for npm, PyPI, NuGet and PowerShell Gallery."
      />
    );
  }
  return <PackagesSettings />;
};

const PackagesSettings: React.FC = () => {
  const state = useConsoleState();
  const { refresh } = useConsole();
  const toast = useToast();
  const data = useAsync(() => api.packages.overview(), []);
  const settings = data.data?.settings;
  const base = useMemo(() => toForm(settings), [JSON.stringify(settings)]); // eslint-disable-line react-hooks/exhaustive-deps
  const [f, setF] = useState<Form>(base);
  const [saving, setSaving] = useState(false);
  const [savedAt, setSavedAt] = useState(0);
  useEffect(() => setF(base), [base]);

  const anyTokenTyped = Object.values(f.audit).some((a) => !!a.token);
  const dirty = !!data.data && (fingerprint(f) !== fingerprint(base) || anyTokenTyped);
  useNavigationBlocker(dirty, 'Discard unsaved package firewall settings?');

  const groupOptions = useMemo(
    () => [{ value: '*', label: 'All groups', description: 'Every client, registered or not' }, ...state.groups.map((g) => ({ value: g.id, label: g.name, description: g.environment || g.id, color: g.color }))],
    [state.groups]
  );

  const setEco = (id: string, p: Partial<EcoForm>) => setF((x) => ({ ...x, ecosystems: { ...x.ecosystems, [id]: { ...x.ecosystems[id], ...p } } }));
  const setAudit = (id: string, p: Partial<AuditForm>) => setF((x) => ({ ...x, audit: { ...x.audit, [id]: { ...x.audit[id], ...p } } }));
  const setSandbox = (p: Partial<Form['sandbox']>) => setF((x) => ({ ...x, sandbox: { ...x.sandbox, ...p } }));

  const num = (v: string) => Number.isFinite(Number(v)) && Number(v) >= 0;
  const invalid = !num(f.default_cooldown_hours) || !num(f.reaudit_hours) || !num(f.watch_hours) || !num(f.max_graph_size) || !num(f.sandbox.timeout_seconds) || !num(f.sandbox.max_artifact_mb);

  const save = async () => {
    if (invalid) return;
    setSaving(true);
    try {
      await api.packages.settings.update(toPayload(f));
      setSavedAt(Date.now());
      toast.success('Package firewall settings saved');
      await data.reload();
      refresh();
    } catch (e) {
      toast.error(e, { title: 'Settings were not saved' });
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <SectionTitle
        title="Package firewall"
        description="Approve registry packages transparently: filter metadata to approved versions, deliver only hash-pinned, analyzed artifacts, and keep clients on the public registries."
      />

      {data.error && !data.data && (
        <Callout tone="danger" title="Settings could not be loaded" action={<Button size="sm" onClick={() => data.reload()}>Try again</Button>}>
          {data.error}
        </Callout>
      )}
      {!data.data && !data.error && (
        <div className="space-y-3">
          <Skeleton className="h-40" />
          <Skeleton className="h-56" />
        </div>
      )}

      {data.data && (
        <div className="space-y-5">
          <Card>
            <CardHeader icon={Boxes} title="Ecosystems" description="Per-registry enforcement mode, the hosts the gate covers and the groups it applies to." divider />
            <CardBody className="space-y-5">
              {ECOSYSTEMS.map((id) => {
                const e = f.ecosystems[id];
                const Icon = ECOSYSTEM_META[id].icon;
                return (
                  <div key={id} className="rounded-lg border border-border bg-surface-2 p-3.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="flex items-center gap-2 text-[13px] font-semibold text-fg">
                        <Icon className="h-4 w-4 text-fg-muted" aria-hidden /> {ECOSYSTEM_META[id].label}
                        <span className="text-[11.5px] font-normal text-fg-subtle">{ECOSYSTEM_META[id].clients}</span>
                      </span>
                      <SegmentedControl
                        size="sm"
                        aria-label={`${ECOSYSTEM_META[id].label} mode`}
                        value={e.mode}
                        onChange={(v) => setEco(id, { mode: v })}
                        options={[
                          { value: 'off', label: 'Off' },
                          { value: 'monitor', label: 'Monitor' },
                          { value: 'enforce', label: 'Enforce' },
                        ]}
                      />
                    </div>
                    {e.mode !== 'off' && (
                      <div className="mt-3 grid gap-4 md:grid-cols-2">
                        <Field label="Registry hosts" hint="Hosts serving metadata and artifacts">
                          <TagInput value={e.hosts} onChange={(v) => setEco(id, { hosts: v })} placeholder="registry.npmjs.org" mono />
                        </Field>
                        <Field label="File hosts" hint="Hosts serving artifacts only (CDNs)" optional>
                          <TagInput value={e.file_hosts} onChange={(v) => setEco(id, { file_hosts: v })} placeholder="files.pythonhosted.org" mono />
                        </Field>
                        <Field label="Upstream" hint="Registry base URL for metadata and analysis">
                          <Input mono value={e.upstream} onChange={(ev) => setEco(id, { upstream: ev.target.value })} placeholder="https://registry.npmjs.org" spellCheck={false} />
                        </Field>
                        <Field label="Group scope" hint="Groups the gate applies to (All = every client)">
                          <MultiSelect value={e.group_ids} onChange={(v) => setEco(id, { group_ids: v })} options={groupOptions} placeholder="All groups" />
                        </Field>
                      </div>
                    )}
                  </div>
                );
              })}
            </CardBody>
          </Card>

          <Card>
            <CardHeader icon={Clock} title="Cooldown and lifecycle" description="Karenz for new approvals, discovery, and the watch / re-audit loops." divider />
            <CardBody className="space-y-5">
              <div className="grid gap-4 md:grid-cols-3">
                <Field label="Default cooldown" error={!num(f.default_cooldown_hours) ? 'Enter hours (0+).' : undefined} hint={num(f.default_cooldown_hours) ? humanHours(Number(f.default_cooldown_hours)) : undefined}>
                  <Input type="number" min={0} value={f.default_cooldown_hours} onChange={(e) => setF({ ...f, default_cooldown_hours: e.target.value })} trailing={<Unit>hours</Unit>} />
                </Field>
                <Field label="Watch interval" error={!num(f.watch_hours) ? 'Enter hours (0+).' : undefined} hint="New upstream versions of approved packages (0 = off)">
                  <Input type="number" min={0} value={f.watch_hours} onChange={(e) => setF({ ...f, watch_hours: e.target.value })} trailing={<Unit>hours</Unit>} />
                </Field>
                <Field label="Re-audit interval" error={!num(f.reaudit_hours) ? 'Enter hours (0+).' : undefined} hint="Re-check approved versions against advisories (0 = off)">
                  <Input type="number" min={0} value={f.reaudit_hours} onChange={(e) => setF({ ...f, reaudit_hours: e.target.value })} trailing={<Unit>hours</Unit>} />
                </Field>
                <Field label="Revoke on new advisory" hint="Automatically revoke approvals when a new advisory applies">
                  <Select value={f.revoke_on_severity} onChange={(e) => setF({ ...f, revoke_on_severity: e.target.value })} options={SEVERITY_OPTIONS} />
                </Field>
                <Field label="Max graph size" error={!num(f.max_graph_size) ? 'Enter a count (0+).' : undefined} hint="Bounds dependency resolution">
                  <Input type="number" min={0} value={f.max_graph_size} onChange={(e) => setF({ ...f, max_graph_size: e.target.value })} trailing={<Unit>nodes</Unit>} />
                </Field>
              </div>
              <Switch
                checked={f.auto_request_discovered}
                onChange={(v) => setF({ ...f, auto_request_discovered: v })}
                label="Open a request for discovered downloads"
                description="When a client tries to download an unapproved package, open a request (and start analysis) so rules can approve it without a human."
              />
            </CardBody>
          </Card>

          <Card>
            <CardHeader icon={FlaskConical} title="Sandbox analysis" description="Disposable sandboxes run and inspect each artifact before approval." divider />
            <CardBody className="space-y-5">
              <Switch checked={f.sandbox.enabled} onChange={(v) => setSandbox({ enabled: v })} label="Enable sandbox analysis" description="Record the URLs, system calls, processes and file access of every artifact." />
              <fieldset disabled={!f.sandbox.enabled} className={f.sandbox.enabled ? 'space-y-5' : 'space-y-5 opacity-60'}>
                <Field label="Scenarios" hint="static: unpack & inspect · install: run install hooks · load: import the module">
                  <MultiSelect
                    value={f.sandbox.scenarios}
                    onChange={(v) => setSandbox({ scenarios: v })}
                    options={[{ value: 'static', label: 'Static' }, { value: 'install', label: 'Install' }, { value: 'load', label: 'Load' }]}
                    placeholder="Select scenarios"
                  />
                </Field>
                <div className="grid gap-4 md:grid-cols-2">
                  <Field label="Timeout" error={!num(f.sandbox.timeout_seconds) ? 'Enter seconds (0+).' : undefined}>
                    <Input type="number" min={0} value={f.sandbox.timeout_seconds} onChange={(e) => setSandbox({ timeout_seconds: e.target.value })} trailing={<Unit>seconds</Unit>} />
                  </Field>
                  <Field label="Max artifact size" error={!num(f.sandbox.max_artifact_mb) ? 'Enter MB (0+).' : undefined}>
                    <Input type="number" min={0} value={f.sandbox.max_artifact_mb} onChange={(e) => setSandbox({ max_artifact_mb: e.target.value })} trailing={<Unit>MB</Unit>} />
                  </Field>
                </div>
                <Switch checked={f.sandbox.required} onChange={(v) => setSandbox({ required: v })} label="Require a completed analysis before approval" description="Manual approvals of unanalyzed versions are then flagged as overrides." />
              </fieldset>
            </CardBody>
          </Card>

          <Card>
            <CardHeader icon={Database} title="Advisory sources" description="Vulnerability, malware and reputation feeds consulted during assessment. Tokens are write-only." divider />
            <CardBody className="space-y-4">
              {AUDIT_CATALOG.map((c) => {
                const a = f.audit[c.id];
                return (
                  <div key={c.id} className="rounded-lg border border-border bg-surface-2 p-3.5">
                    <Switch checked={a.enabled} onChange={(v) => setAudit(c.id, { enabled: v })} label={<span className="flex items-center gap-2">{c.label}{!c.token && <Badge tone="neutral" size="sm">no token</Badge>}</span>} description={c.hint} />
                    {a.enabled && (c.token || c.account || c.url) && (
                      <div className="mt-3 grid gap-4 md:grid-cols-2">
                        {c.account && (
                          <Field label={c.account}>
                            <Input value={a.account} onChange={(e) => setAudit(c.id, { account: e.target.value })} spellCheck={false} />
                          </Field>
                        )}
                        {c.token && (
                          <SecretField
                            label="API token"
                            stored={a.has_token}
                            value={a.token}
                            onChange={(v) => setAudit(c.id, { token: v })}
                            optional
                            resetKey={savedAt}
                          />
                        )}
                        {c.url && (
                          <Field label="URL override" optional hint="Mirror or on-premises instance">
                            <Input mono value={a.url} onChange={(e) => setAudit(c.id, { url: e.target.value })} placeholder="https://" spellCheck={false} />
                          </Field>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </CardBody>
          </Card>

          <SaveBar dirty={dirty} saving={saving} onSave={save} onReset={() => setF(base)} disabled={invalid} note={invalid ? 'Fix the highlighted fields.' : undefined} label="Save settings" />
        </div>
      )}
    </>
  );
};

const Unit: React.FC<{ children: React.ReactNode }> = ({ children }) => <span className="text-[12px] text-fg-subtle">{children}</span>;
