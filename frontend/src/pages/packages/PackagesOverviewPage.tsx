import React, { useMemo } from 'react';
import {
  Ban,
  Boxes,
  CheckCircle2,
  Clock,
  FlaskConical,
  Inbox,
  PackageCheck,
  PackageSearch,
  RefreshCw,
  ScrollText,
  Settings,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { api } from '../../api';
import { useConsoleState, usePermissions } from '../../data/AppData';
import { formatNumber } from '../../lib/format';
import { useAsync, useDocumentTitle } from '../../lib/hooks';
import { Link } from '../../lib/router';
import type { PackageDecisionEvent, PackageEcosystemOverview, PackagesOverview } from '../../types';
import {
  Badge,
  Button,
  ButtonLink,
  Callout,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  PageHeader,
  Skeleton,
  StatTile,
  StatusChip,
  Timeline,
  Tone,
} from '../../ui';
import { RelativeTime } from '../../ui/Time';
import { EcosystemBadge, ModeChip, RiskBadge } from '../../components/packages';
import { ECOSYSTEMS, humanHours } from '../../components/packages/packageUtils';

const DECISION_TONE: Record<string, Tone> = {
  approved: 'success',
  auto_approved: 'success',
  rejected: 'danger',
  blocked: 'danger',
  revoked: 'danger',
  analyzed: 'info',
  discovered: 'warning',
};

const DECISION_LABEL: Record<string, string> = {
  approved: 'Approved',
  auto_approved: 'Auto-approved',
  rejected: 'Rejected',
  blocked: 'Blocked',
  revoked: 'Revoked',
  analyzed: 'Analyzed',
  discovered: 'Discovered',
};

/** Builds the per-ecosystem rows from the overview, or from the settings when the backend omits them. */
function ecosystemRows(ov: PackagesOverview): PackageEcosystemOverview[] {
  if (ov.ecosystems && ov.ecosystems.length) return ov.ecosystems;
  const eco = ov.settings?.ecosystems ?? {};
  return ECOSYSTEMS.map((id) => ({
    ecosystem: id,
    mode: eco[id]?.mode ?? 'off',
    approvals: 0,
    blocks: 0,
    open_requests: 0,
    hosts: eco[id]?.hosts ?? null,
    file_hosts: eco[id]?.file_hosts ?? null,
    group_ids: eco[id]?.group_ids ?? null,
  }));
}

/** /packages — package firewall overview: ecosystems, work queues, sandbox health, recent decisions. */
export const PackagesOverviewPage: React.FC = () => {
  useDocumentTitle('Package firewall');
  const state = useConsoleState();
  const perms = usePermissions();
  const { data, error, loading, reload } = useAsync(() => api.packages.overview(), [state.revision]);

  return (
    <>
      <PageHeader
        title="Package firewall"
        description="Transparent approval of npm, PyPI, NuGet and PowerShell Gallery packages: metadata is filtered to approved versions and only hash-pinned, analyzed artifacts are delivered."
        actions={
          <>
            <Button icon={RefreshCw} variant="secondary" onClick={() => reload()} loading={loading && !!data}>
              Refresh
            </Button>
            {perms.canManageSystem && (
              <ButtonLink to="/settings/packages" icon={Settings} variant="primary">
                Settings
              </ButtonLink>
            )}
          </>
        }
      />

      {error && !data && (
        <Callout tone="danger" title="The package firewall could not be loaded" action={<Button size="sm" onClick={() => reload()}>Try again</Button>}>
          {error}
        </Callout>
      )}

      {!data && !error && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-24" />
            ))}
          </div>
          <Skeleton className="h-56" />
        </div>
      )}

      {data && !data.enabled && (
        <Card>
          <EmptyState
            icon={PackageCheck}
            title="The package firewall is off"
            description="Turn on at least one ecosystem to filter registry metadata to approved versions and deliver only analyzed, hash-pinned artifacts. Clients keep using the public registries through the proxy."
            action={
              perms.canManageSystem ? (
                <ButtonLink to="/settings/packages" icon={Settings} variant="primary">
                  Open package settings
                </ButtonLink>
              ) : (
                <span className="text-[12.5px] text-fg-subtle">Ask an InfoSec Approver or Super Admin to enable it.</span>
              )
            }
          />
        </Card>
      )}

      {data && data.enabled && <OverviewBody ov={data} />}
    </>
  );
};

const OverviewBody: React.FC<{ ov: PackagesOverview }> = ({ ov }) => {
  const rows = useMemo(() => ecosystemRows(ov), [ov]);
  const t = ov.totals ?? { open_requests: 0, approvals: 0, blocks: 0, rules: 0 };
  const sandbox = ov.sandbox;
  const recent = ov.recent ?? [];

  return (
    <div className="space-y-6">
      <section aria-label="Package firewall queues">
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <StatTile
            label="Open requests"
            value={formatNumber(t.open_requests)}
            icon={Inbox}
            tone={t.open_requests > 0 ? 'warning' : 'neutral'}
            attention={t.open_requests > 0}
            hint="Waiting for a decision"
            to="/packages/requests?status=ready"
          />
          <StatTile label="Approvals" value={formatNumber(t.approvals)} icon={CheckCircle2} tone="success" hint="Active approved versions" to="/packages/approvals" />
          <StatTile label="Block list" value={formatNumber(t.blocks)} icon={Ban} tone={t.blocks > 0 ? 'danger' : 'neutral'} hint="Explicitly denied" to="/packages/blocks" />
          <StatTile label="Rules" value={formatNumber(t.rules)} icon={ScrollText} hint="Cooldown / auto-approve / review" to="/packages/rules" />
        </div>
      </section>

      <section aria-label="Ecosystems">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {rows.map((e) => (
            <Card key={e.ecosystem} padded>
              <div className="flex items-center justify-between gap-2">
                <EcosystemBadge ecosystem={e.ecosystem} />
                <ModeChip mode={e.mode} />
              </div>
              <dl className="mt-3 grid grid-cols-3 gap-2 text-center">
                <Link to={`/packages/approvals?ecosystem=${e.ecosystem}`} className="rounded-md border border-border bg-surface-2 py-2 hover:border-border-strong">
                  <dt className="text-[11px] text-fg-subtle">Approvals</dt>
                  <dd className="text-[16px] font-semibold text-fg">{formatNumber(e.approvals)}</dd>
                </Link>
                <Link to={`/packages/requests?ecosystem=${e.ecosystem}&status=ready`} className="rounded-md border border-border bg-surface-2 py-2 hover:border-border-strong">
                  <dt className="text-[11px] text-fg-subtle">Open</dt>
                  <dd className={`text-[16px] font-semibold ${e.open_requests ? 'text-warning' : 'text-fg'}`}>{formatNumber(e.open_requests)}</dd>
                </Link>
                <Link to={`/packages/blocks?ecosystem=${e.ecosystem}`} className="rounded-md border border-border bg-surface-2 py-2 hover:border-border-strong">
                  <dt className="text-[11px] text-fg-subtle">Blocks</dt>
                  <dd className={`text-[16px] font-semibold ${e.blocks ? 'text-danger' : 'text-fg'}`}>{formatNumber(e.blocks)}</dd>
                </Link>
              </dl>
              {e.mode === 'off' && <p className="mt-2 text-[11.5px] text-fg-subtle">Not enforced — registry traffic follows the ordinary egress rules.</p>}
            </Card>
          ))}
        </div>
      </section>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader icon={FlaskConical} title="Sandbox workers" description="Disposable sandboxes that analyze artifacts before approval." />
          <CardBody className="pt-2">
            {sandbox?.enabled ? (
              <div className="space-y-3">
                <StatusChip
                  tone={sandbox.healthy && sandbox.workers > 0 ? 'success' : sandbox.workers > 0 ? 'warning' : 'danger'}
                  label={sandbox.workers > 0 ? (sandbox.healthy ? 'Healthy' : 'Degraded') : 'No workers connected'}
                />
                <dl className="grid grid-cols-3 gap-2 text-center text-[13px]">
                  <div className="rounded-md border border-border bg-surface-2 py-2">
                    <dt className="text-[11px] text-fg-subtle">Workers</dt>
                    <dd className="text-[16px] font-semibold text-fg">{formatNumber(sandbox.workers)}</dd>
                  </div>
                  <div className="rounded-md border border-border bg-surface-2 py-2">
                    <dt className="text-[11px] text-fg-subtle">Queued</dt>
                    <dd className="text-[16px] font-semibold text-fg">{formatNumber(sandbox.queued ?? 0)}</dd>
                  </div>
                  <div className="rounded-md border border-border bg-surface-2 py-2">
                    <dt className="text-[11px] text-fg-subtle">Running</dt>
                    <dd className="text-[16px] font-semibold text-fg">{formatNumber(sandbox.running ?? 0)}</dd>
                  </div>
                </dl>
                {(sandbox.drivers ?? []).length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="text-[12px] text-fg-subtle">Drivers</span>
                    {(sandbox.drivers ?? []).map((d) => (
                      <Badge key={d} tone="neutral" size="sm">{d}</Badge>
                    ))}
                  </div>
                )}
                {sandbox.last_seen_at && (
                  <p className="text-[12px] text-fg-subtle">
                    Last worker <RelativeTime value={sandbox.last_seen_at} prefix="seen" />
                  </p>
                )}
                {sandbox.workers === 0 && (
                  <Callout tone="warning" icon={ShieldAlert}>
                    No sandbox worker is connected. Analyses stay queued, and approvals that require a completed analysis wait.
                  </Callout>
                )}
              </div>
            ) : (
              <Callout tone="neutral" icon={FlaskConical} title="Sandbox analysis is off">
                Artifacts are approved without behaviour analysis. Enable the sandbox in settings to record the URLs, system calls and file access of every package.
              </Callout>
            )}
          </CardBody>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader
            icon={Clock}
            title="Recent decisions"
            description="Approvals, blocks and analyses across every ecosystem."
            actions={
              <Link to="/packages/requests?status=all" className="text-[12.5px] font-medium text-accent hover:underline">
                All requests
              </Link>
            }
          />
          <CardBody className="pt-2">
            {recent.length === 0 ? (
              <EmptyState size="sm" icon={PackageSearch} title="No decisions yet" description="Approvals, blocks and sandbox analyses show up here as they happen." />
            ) : (
              <Timeline
                items={recent.slice(0, 12).map((d: PackageDecisionEvent) => ({
                  id: d.id,
                  tone: DECISION_TONE[d.decision] ?? 'neutral',
                  icon: d.decision === 'blocked' || d.decision === 'rejected' || d.decision === 'revoked' ? Ban : d.decision === 'analyzed' ? FlaskConical : ShieldCheck,
                  title: (
                    <span className="flex flex-wrap items-center gap-1.5">
                      <EcosystemBadge ecosystem={d.ecosystem} short />
                      {d.request_id ? (
                        <Link to={`/packages/requests/${encodeURIComponent(d.request_id)}`} className="font-mono text-[12.5px] font-medium text-fg hover:text-accent hover:underline">
                          {d.name}{d.version ? `@${d.version}` : ''}
                        </Link>
                      ) : (
                        <span className="font-mono text-[12.5px] font-medium text-fg">{d.name}{d.version ? `@${d.version}` : ''}</span>
                      )}
                      <Badge tone={DECISION_TONE[d.decision] ?? 'neutral'} size="sm">{DECISION_LABEL[d.decision] ?? d.decision}</Badge>
                      {d.risk && <RiskBadge risk={d.risk} />}
                    </span>
                  ),
                  meta: <RelativeTime value={d.at} />,
                  body:
                    d.via || d.rule_name || d.actor ? (
                      <span className="text-[12px] text-fg-subtle">
                        {d.via === 'rule' && d.rule_name ? `Rule ${d.rule_name}` : d.via === 'dependency' ? 'Pulled in as a dependency' : d.via ? `via ${d.via}` : ''}
                        {d.actor ? `${d.via ? ' · ' : ''}${d.actor}` : ''}
                      </span>
                    ) : undefined,
                }))}
              />
            )}
          </CardBody>
        </Card>
      </div>

      <p className="text-[12px] text-fg-subtle">
        Global cooldown (Karenz) for new approvals: {humanHours(ov.settings?.default_cooldown_hours)}
        {ov.settings?.sandbox?.required ? ' · a completed sandbox analysis is required before approval' : ''}
        {rows.some((e) => e.mode !== 'off') ? '' : ' · no ecosystem is enforced yet'}.
      </p>
    </div>
  );
};
