import React, { useEffect, useState } from 'react';
import { PackageSearch, Search, ServerCog } from 'lucide-react';
import { api } from '../../api';
import { useConsoleState } from '../../data/AppData';
import { formatBytes, formatNumber } from '../../lib/format';
import { useAsync, useDocumentTitle } from '../../lib/hooks';
import { Link, useSearchParams } from '../../lib/router';
import type { PackageEcosystem } from '../../types';
import { Badge, Button, Callout, Card, CardBody, CardHeader, EmptyState, Field, Input, PageHeader, Select, Spinner, Tone } from '../../ui';
import { RelativeTime } from '../../ui/Time';
import { GroupChip } from '../../components/common/EntityChips';
import { EcosystemBadge } from '../../components/packages';
import { ECOSYSTEM_META, ECOSYSTEMS } from '../../components/packages/packageUtils';

const DECISION_META: Record<string, { label: string; tone: Tone }> = {
  approved: { label: 'Approved', tone: 'success' },
  filtered: { label: 'Filtered', tone: 'info' },
  not_approved: { label: 'Not approved', tone: 'warning' },
  blocked: { label: 'Blocked', tone: 'danger' },
  hash_mismatch: { label: 'Hash mismatch', tone: 'danger' },
  monitor: { label: 'Monitored', tone: 'neutral' },
  service: { label: 'Service', tone: 'neutral' },
};

function decisionMeta(d?: string): { label: string; tone: Tone } {
  return DECISION_META[d ?? ''] ?? { label: d || 'Unknown', tone: 'neutral' };
}

function transferTone(s?: string): Tone {
  return s === 'complete' ? 'success' : s === 'reset' ? 'danger' : s === 'partial' ? 'warning' : 'neutral';
}

/** /packages/receivers — which servers obtained a package (incident / investigation view). */
export const PackageReceiversPage: React.FC = () => {
  useDocumentTitle('Package receivers');
  const state = useConsoleState();
  const [params, setParams] = useSearchParams();
  const q = {
    ecosystem: (params.get('ecosystem') as PackageEcosystem) || 'npm',
    name: params.get('name') || '',
    version: params.get('version') || '',
    sha256: params.get('sha256') || '',
  };
  const [form, setForm] = useState(q);
  useEffect(() => setForm(q), [params]); // eslint-disable-line react-hooks/exhaustive-deps

  const committedName = q.name.trim();
  const { data, error, loading } = useAsync(
    () => (committedName ? api.packages.receivers({ ecosystem: q.ecosystem, name: committedName, version: q.version || undefined, sha256: q.sha256 || undefined }) : Promise.resolve(undefined)),
    [q.ecosystem, committedName, q.version, q.sha256, state.revision]
  );

  const submit = () => {
    if (!form.name.trim()) return;
    setParams({ ecosystem: form.ecosystem, name: form.name.trim(), version: form.version.trim() || null, sha256: form.sha256.trim() || null });
  };

  const receivers = data?.receivers ?? [];

  return (
    <>
      <PageHeader
        title="Package receivers"
        description="Which servers obtained a package — reconstructed from the package field on flow telemetry. Answers “who downloaded a version now known to be affected?”"
      />

      <Card padded className="mb-5">
        <form
          className="grid gap-3 sm:grid-cols-2 lg:grid-cols-[160px_minmax(0,1fr)_160px_minmax(0,1fr)_auto] lg:items-end"
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          <Field label="Ecosystem">
            <Select value={form.ecosystem} onChange={(e) => setForm({ ...form, ecosystem: e.target.value as PackageEcosystem })} options={ECOSYSTEMS.map((id) => ({ value: id, label: ECOSYSTEM_META[id].label }))} selectSize="sm" />
          </Field>
          <Field label="Package name">
            <Input inputSize="sm" mono value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="e.g. lodash" spellCheck={false} />
          </Field>
          <Field label="Version" hint="Optional">
            <Input inputSize="sm" mono value={form.version} onChange={(e) => setForm({ ...form, version: e.target.value })} placeholder="any" spellCheck={false} />
          </Field>
          <Field label="SHA-256" hint="Optional — pin one artifact">
            <Input inputSize="sm" mono value={form.sha256} onChange={(e) => setForm({ ...form, sha256: e.target.value })} placeholder="hex digest" spellCheck={false} />
          </Field>
          <Button type="submit" variant="primary" icon={Search} loading={loading} disabled={!form.name.trim()}>
            Search
          </Button>
        </form>
      </Card>

      <Callout tone="warning" className="mb-5" title="A download is an investigation lead, not proof of install">
        Telemetry shows which servers fetched the artifact through the proxy. It does not prove the package was installed, imported or executed — a cached copy, a failed install or a mirror can all skew the picture. Treat results as a starting point and confirm on the host.
      </Callout>

      {error && <Callout tone="danger" title="The search failed" className="mb-5">{error}</Callout>}

      {!committedName && (
        <EmptyState icon={PackageSearch} title="Search for a package" description="Enter a package name (and optionally a version or artifact SHA-256) to see which servers obtained it." />
      )}

      {committedName && loading && !data && (
        <Card padded className="flex items-center gap-2 text-[13px] text-fg-muted">
          <Spinner /> Searching flow telemetry…
        </Card>
      )}

      {data && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2 text-[13px] text-fg-muted">
            <EcosystemBadge ecosystem={data.ecosystem} />
            <span className="font-mono font-medium text-fg">{data.name}{data.version ? `@${data.version}` : ''}</span>
            <Badge tone={receivers.length ? 'info' : 'neutral'}>{formatNumber(receivers.length)} {receivers.length === 1 ? 'server' : 'servers'}</Badge>
          </div>

          {data.monitored === false && (
            <Callout tone="neutral" title="This ecosystem is not monitored">
              The {ECOSYSTEM_META[data.ecosystem]?.label ?? data.ecosystem} gate is off, so no package telemetry is recorded. Results are limited to whatever other flow records captured.
            </Callout>
          )}
          {data.partial && (
            <Callout tone="warning" title="Evidence is partial">
              {data.note || 'Telemetry only covers requests that passed through the proxy and is subject to retention — older or offline downloads may be missing.'}
            </Callout>
          )}

          {receivers.length === 0 ? (
            <Card>
              <EmptyState icon={ServerCog} title="No servers obtained this package" description="No flow telemetry records a download of this package within the retention window." />
            </Card>
          ) : (
            <div className="space-y-3">
              {receivers.map((r, idx) => {
                const dm = decisionMeta(r.decision);
                const registered = r.server_id ? state.servers.find((s) => s.id === r.server_id) : undefined;
                return (
                  <Card key={r.server_id || r.server_ip || idx}>
                    <CardHeader
                      icon={ServerCog}
                      title={
                        registered ? (
                          <Link to={`/servers/${encodeURIComponent(registered.id)}`} className="hover:text-accent hover:underline">
                            {registered.hostname}
                          </Link>
                        ) : (
                          <span className="break-all">{r.server_hostname || r.server_ip}</span>
                        )
                      }
                      description={
                        <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
                          <span className="font-mono">{r.server_ip}</span>
                          {r.owner_team && <span>{r.owner_team}</span>}
                          {(r.group_ids ?? []).map((g) => (
                            <GroupChip key={g} id={g} />
                          ))}
                        </span>
                      }
                      actions={<Badge tone={dm.tone}>{dm.label}</Badge>}
                    />
                    <CardBody className="pt-2">
                      <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-[12px] text-fg-muted">
                        <span>First seen <RelativeTime value={r.first_seen} /></span>
                        <span>Last seen <RelativeTime value={r.last_seen} /></span>
                        <span>{formatNumber(r.request_count)} {r.request_count === 1 ? 'download' : 'downloads'}</span>
                        {r.transfer_status && <Badge tone={transferTone(r.transfer_status)} size="sm">transfer {r.transfer_status}</Badge>}
                      </div>
                      {(r.files ?? []).length > 0 && (
                        <ul className="divide-y divide-border rounded-lg border border-border">
                          {(r.files ?? []).map((fl, i) => {
                            const fdm = decisionMeta(fl.decision);
                            return (
                              <li key={`${fl.filename}-${i}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-[12px]">
                                <span className="min-w-0 flex-1 break-all font-mono text-fg">{fl.filename}</span>
                                {fl.version && <Badge tone="neutral" size="sm">{fl.version}</Badge>}
                                <Badge tone={fdm.tone} size="sm">{fdm.label}</Badge>
                                {fl.transfer_status && <Badge tone={transferTone(fl.transfer_status)} size="sm">{fl.transfer_status}</Badge>}
                                {fl.bytes ? <span className="text-fg-subtle">{formatBytes(fl.bytes)}</span> : null}
                                {(fl.sha256 || fl.sha512) && <span className="w-full break-all font-mono text-[11px] text-fg-subtle">{fl.sha256 ? `sha256:${fl.sha256}` : `sha512:${fl.sha512}`}</span>}
                              </li>
                            );
                          })}
                        </ul>
                      )}
                    </CardBody>
                  </Card>
                );
              })}
            </div>
          )}
        </div>
      )}
    </>
  );
};
