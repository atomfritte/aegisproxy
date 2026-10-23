import React, { useMemo } from 'react';
import {
  Activity,
  AlertOctagon,
  ArrowRight,
  CalendarClock,
  Cpu,
  FileEdit,
  GitPullRequestArrow,
  Inbox,
  Layers,
  Plus,
  ServerCrash,
  ShieldAlert,
  ShieldOff,
  Server as ServerIcon,
  WifiOff,
} from 'lucide-react';
import { useConsoleState, usePermissions } from '../../data/AppData';
import { useSession } from '../../data/session';
import { cn } from '../../lib/cn';
import { formatBytes, formatCompact, formatNumber } from '../../lib/format';
import { useDocumentTitle, useNow } from '../../lib/hooks';
import { Link } from '../../lib/router';
import type { AuditEvent, SecurityEvent } from '../../types';
import { Avatar, Badge, ButtonLink, Card, CardHeader, EmptyState, RelativeTime, Sparkline, StatTile, Tone } from '../../ui';
import { UserName } from '../../components/common/EntityChips';
import { PostureCard } from './PostureCard';

const SEVERITY_TONE: Record<string, Tone> = { critical: 'danger', high: 'danger', medium: 'warning', low: 'neutral' };

/** First name from a display name like "Dr. Markus Vance (Chief Architect)". */
function firstName(display: string): string {
  const words = display.replace(/\(.*?\)/g, ' ').split(/\s+/).filter(Boolean);
  const w = words.find((x) => !/^(dr|prof|mr|mrs|ms|sir)\.?$/i.test(x));
  return w || '';
}

function greeting(now: number): string {
  const h = new Date(now).getHours();
  if (h >= 5 && h < 12) return 'Good morning';
  if (h >= 12 && h < 18) return 'Good afternoon';
  return 'Good evening';
}

/** A row in a health card: label, value, optional link and tone. */
const HealthRow: React.FC<{ label: React.ReactNode; value: React.ReactNode; to?: string; tone?: Tone; icon?: React.ElementType; hint?: React.ReactNode }> = ({
  label,
  value,
  to,
  tone,
  icon: Icon,
  hint,
}) => {
  const valueCls = cn(
    'text-[15px] font-semibold tabular',
    tone === 'danger' ? 'text-danger' : tone === 'warning' ? 'text-warning' : tone === 'success' ? 'text-success' : 'text-fg'
  );
  const body = (
    <>
      {Icon && <Icon className="h-4 w-4 shrink-0 text-fg-subtle" aria-hidden />}
      <span className="min-w-0 flex-1">
        <span className="block truncate text-[13px] text-fg">{label}</span>
        {hint && <span className="block truncate text-[12px] text-fg-subtle">{hint}</span>}
      </span>
      <span className={valueCls}>{value}</span>
      {to && <ArrowRight className="h-3.5 w-3.5 shrink-0 text-fg-subtle opacity-0 transition-opacity group-hover:opacity-100" aria-hidden />}
    </>
  );
  const cls = 'group flex items-center gap-3 px-[var(--card-p)] py-2.5';
  return (
    <li className="border-t border-border first:border-t-0">
      {to ? (
        <Link to={to} className={cn(cls, 'hover:bg-surface-2')}>
          {body}
        </Link>
      ) : (
        <div className={cls}>{body}</div>
      )}
    </li>
  );
};

const auditTone = (a: AuditEvent): Tone =>
  /DELETED|REJECTED|REVOKED|QUARANTIN/.test(a.action) ? 'danger' : /PUBLISH|APPROVED|CREATED|REGISTERED/.test(a.action) ? 'success' : 'neutral';

/** Home page: work queues, policy / fleet health, traffic, security events, recent activity. */
export const OverviewPage: React.FC = () => {
  useDocumentTitle('Overview');
  const state = useConsoleState();
  const perms = usePermissions();
  const { user } = useSession();
  const now = useNow();
  const o = state.overview || {};
  const n = (v?: number) => v ?? 0;

  const sets = state.policy_sets ?? [];
  const kindCounts = useMemo(() => {
    const c = { baseline: 0, standard: 0, approvals: 0 };
    for (const s of sets) c[s.kind] = (c[s.kind] || 0) + 1;
    return c;
  }, [sets]);

  const servers = state.servers ?? [];
  const planes = state.data_planes ?? [];
  const healthyPlanes = planes.filter((p) => p.healthy).length;
  const events: SecurityEvent[] = useMemo(
    () => (state.security?.events ?? []).filter((e) => !e.acknowledged).sort((a, b) => b.timestamp.localeCompare(a.timestamp)).slice(0, 5),
    [state.security]
  );
  const audit = useMemo(() => [...(state.audit_events ?? [])].sort((a, b) => b.timestamp.localeCompare(a.timestamp)).slice(0, 6), [state.audit_events]);

  const series = useMemo(
    () => (state.bandwidth?.time_series ?? []).map((s) => ({ label: s.time_label, value: Math.round(s.requests_per_sec * 60) })),
    [state.bandwidth]
  );
  const latestRpm = series.length ? series[series.length - 1].value : 0;
  const stats = state.stats;
  const recentTotal = stats ? stats.allowed + stats.blocked + stats.bypass + stats.learning : 0;
  const blockedShare = recentTotal ? Math.round((stats.blocked / recentTotal) * 100) : 0;

  const scope =
    perms.isTeamLead && user
      ? `Requests and approvals for ${(user.allowed_groups ?? []).map((g) => state.groups.find((x) => x.id === g)?.name || g).join(', ')}.`
      : 'What needs attention across policy, access requests and the fleet.';

  return (
    <>
      <header className="mb-6 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div className="min-w-0">
          <h1 className="text-[22px] font-semibold leading-8 tracking-[-0.01em] text-fg">
            {greeting(now)}
            {firstName(user?.display_name || user?.username || '') ? `, ${firstName(user?.display_name || user?.username || '')}` : ''}
          </h1>
          <p className="mt-1 max-w-3xl text-[13.5px] leading-6 text-fg-muted">{scope}</p>
        </div>
        {!perms.isReadOnly && (
          <div className="flex flex-wrap gap-2">
            <ButtonLink to="/changes" icon={GitPullRequestArrow}>
              Review changes
            </ButtonLink>
            <ButtonLink to="/policies/new" variant="primary" icon={Plus}>
              New policy set
            </ButtonLink>
          </div>
        )}
      </header>

      {/* Work queues */}
      <section aria-labelledby="queues-h" className="mb-6">
        <h2 id="queues-h" className="sr-only">
          Work queues
        </h2>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <StatTile
            label="Access requests waiting"
            value={formatNumber(n(o.pending_requests))}
            icon={Inbox}
            tone={n(o.overdue_requests) > 0 ? 'danger' : n(o.pending_requests) > 0 ? 'warning' : 'neutral'}
            attention={n(o.overdue_requests) > 0}
            hint={
              n(o.pending_requests) === 0
                ? 'Queue is empty'
                : [n(o.overdue_requests) && `${n(o.overdue_requests)} past SLA`, n(o.assigned_to_me) && `${n(o.assigned_to_me)} assigned to you`].filter(Boolean).join(', ') ||
                  `Within the ${state.governance?.request_sla_hours ?? 24} h SLA`
            }
            to="/requests?status=pending"
          />
          <StatTile
            label="Changes to review"
            value={formatNumber(n(o.changes_to_review))}
            icon={GitPullRequestArrow}
            tone={n(o.changes_to_review) > 0 ? 'warning' : 'neutral'}
            hint={`${formatNumber(n(o.open_change_requests))} open in total${state.governance?.require_policy_review ? ', four-eyes review on' : ''}`}
            to="/changes"
          />
          <StatTile
            label="Recertification overdue"
            value={formatNumber(n(o.recertification_overdue))}
            icon={CalendarClock}
            tone={n(o.recertification_overdue) > 0 ? 'danger' : 'neutral'}
            attention={n(o.recertification_overdue) > 0}
            hint={`${formatNumber(n(o.recertification_due_soon))} due within 14 days`}
            to="/policies?review=overdue"
          />
          <StatTile
            label="Unpublished drafts"
            value={formatNumber(n(o.drafts))}
            icon={FileEdit}
            tone={n(o.drafts) > 0 ? 'info' : 'neutral'}
            hint="Policy sets with pending edits"
            to="/policies?state=draft"
          />
        </div>
      </section>

      {perms.canManageSystem && <PostureCard />}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        {/* Traffic */}
        <Card className="xl:col-span-2">
          <CardHeader
            title="Traffic"
            description="Requests per minute across all data-plane workers"
            actions={
              <Link to="/bandwidth" className="text-[12.5px] font-medium text-accent hover:underline">
                Bandwidth details
              </Link>
            }
          />
          <div className="grid grid-cols-2 gap-x-6 gap-y-4 px-[var(--card-p)] pt-3 sm:grid-cols-4">
            <div>
              <div className="text-[12px] text-fg-subtle">Requests per minute</div>
              <div className="text-[20px] font-semibold text-fg">{formatCompact(latestRpm)}</div>
            </div>
            <div>
              <div className="text-[12px] text-fg-subtle">Throughput now</div>
              <div className="text-[20px] font-semibold text-fg">
                {formatNumber(Math.round(state.bandwidth?.current_mbps ?? 0))} <span className="text-[13px] font-normal text-fg-muted">Mbps</span>
              </div>
            </div>
            <div>
              <div className="text-[12px] text-fg-subtle">Volume, 24 h</div>
              <div className="text-[20px] font-semibold text-fg">{formatBytes(state.bandwidth?.total_bytes_24h ?? 0)}</div>
            </div>
            <div>
              <div className="text-[12px] text-fg-subtle">Blocked, recent flows</div>
              <div className="text-[20px] font-semibold text-fg">
                {blockedShare}
                <span className="text-[13px] font-normal text-fg-muted">%</span>
              </div>
            </div>
          </div>
          <div className="px-[var(--card-p)] pb-[var(--card-p)] pt-6">
            <Sparkline data={series} height={120} ariaLabel="Requests per minute" format={(v) => `${formatNumber(v)} req/min`} />
            {series.length > 1 && (
              <div className="mt-2 flex justify-between text-[11.5px] text-fg-subtle tabular">
                <span>{series[0].label}</span>
                <span>{series[Math.floor(series.length / 2)].label}</span>
                <span>{series[series.length - 1].label}</span>
              </div>
            )}
          </div>
        </Card>

        {/* Policy health */}
        <Card>
          <CardHeader
            title="Policy health"
            description={`${sets.length} policy sets, ${formatNumber((state.rules ?? []).length)} effective rules`}
            actions={
              <Link to="/policies" className="text-[12.5px] font-medium text-accent hover:underline">
                All sets
              </Link>
            }
          />
          <ul className="mt-2">
            <HealthRow icon={AlertOctagon} label="Recertification overdue" value={n(o.recertification_overdue)} tone={n(o.recertification_overdue) ? 'danger' : undefined} to="/policies?review=overdue" />
            <HealthRow icon={CalendarClock} label="Recertification due soon" value={n(o.recertification_due_soon)} tone={n(o.recertification_due_soon) ? 'warning' : undefined} to="/policies?review=due_soon" />
            <HealthRow icon={FileEdit} label="Drafts" value={n(o.drafts)} to="/policies?state=draft" />
            <HealthRow icon={GitPullRequestArrow} label="Open change requests" value={n(o.open_change_requests)} to="/changes?tab=all" />
            <HealthRow
              icon={Layers}
              label="Sets by kind"
              value={
                <span className="flex gap-1.5 text-[12px] font-medium">
                  <Badge tone="violet">{kindCounts.baseline} baseline</Badge>
                  <Badge tone="accent">{kindCounts.standard} standard</Badge>
                </span>
              }
              hint={`${kindCounts.approvals} approvals sets`}
            />
          </ul>
        </Card>

        {/* Fleet health */}
        <Card>
          <CardHeader
            title="Fleet health"
            description={`${formatNumber(servers.length)} registered servers in ${state.groups.length} groups`}
            actions={
              <Link to="/servers" className="text-[12.5px] font-medium text-accent hover:underline">
                Servers
              </Link>
            }
          />
          <ul className="mt-2">
            <HealthRow icon={ServerIcon} label="Registered servers" value={formatNumber(servers.length)} to="/servers" />
            <HealthRow icon={ShieldOff} label="Quarantined" value={n(o.quarantined_servers)} tone={n(o.quarantined_servers) ? 'danger' : undefined} to="/servers?quarantined=1" />
            <HealthRow icon={WifiOff} label="Not seen for 24 h" value={n(o.stale_servers)} tone={n(o.stale_servers) ? 'warning' : undefined} to="/servers?stale=1" />
            <HealthRow
              icon={Cpu}
              label="Data-plane workers"
              value={planes.length === 0 ? '0' : `${healthyPlanes}/${planes.length}`}
              tone={planes.length === 0 ? 'warning' : healthyPlanes < planes.length ? 'danger' : 'success'}
              hint={planes.length === 0 ? 'No worker has checked in yet' : healthyPlanes < planes.length ? `${planes.length - healthyPlanes} unhealthy` : 'All workers healthy'}
            />
          </ul>
          {planes.length > 0 && (
            <ul className="border-t border-border px-[var(--card-p)] py-3 text-[12.5px]">
              {planes.slice(0, 4).map((p) => (
                <li key={p.id} className="flex items-center gap-2 py-1">
                  <span className={cn('h-2 w-2 rounded-full', p.healthy ? 'bg-success-solid' : 'bg-danger-solid')} aria-hidden />
                  <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-fg">{p.id}</span>
                  <span className="text-fg-subtle">
                    <RelativeTime value={p.last_seen_at} />
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>

        {/* Security events */}
        <Card>
          <CardHeader
            title="Security events"
            description={`${formatNumber(state.stats?.open_security_events ?? 0)} not acknowledged`}
            actions={
              <Link to="/threats" className="text-[12.5px] font-medium text-accent hover:underline">
                Threat protection
              </Link>
            }
          />
          {events.length === 0 ? (
            <EmptyState size="sm" icon={ShieldAlert} title="No open security events" description="Threat intel, antivirus and DLP detections that need acknowledgement show up here." />
          ) : (
            <ul className="mt-2">
              {events.map((e) => (
                <li key={e.id} className="border-t border-border first:border-t-0">
                  <Link to="/threats" className="flex items-start gap-3 px-[var(--card-p)] py-2.5 hover:bg-surface-2">
                    <Badge tone={SEVERITY_TONE[e.severity] || 'neutral'} className="mt-0.5 capitalize">
                      {e.severity}
                    </Badge>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-[13px] text-fg">{e.detail || e.type}</span>
                      <span className="block truncate text-[12px] text-fg-subtle">
                        {e.server_hostname || e.server_ip}
                        {e.host ? `, ${e.host}` : ''}
                      </span>
                    </span>
                    <span className="shrink-0 text-[12px] text-fg-subtle">
                      <RelativeTime value={e.timestamp} />
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>

        {/* Recent activity */}
        <Card>
          <CardHeader
            title="Recent activity"
            description="Latest audit trail entries"
            actions={
              <Link to="/audit" className="text-[12.5px] font-medium text-accent hover:underline">
                Audit trail
              </Link>
            }
          />
          {audit.length === 0 ? (
            <EmptyState size="sm" icon={Activity} title="No activity yet" />
          ) : (
            <ul className="mt-2">
              {audit.map((a) => (
                <li key={a.id} className="flex items-start gap-3 border-t border-border px-[var(--card-p)] py-2.5 first:border-t-0">
                  <Avatar name={a.actor} size="sm" className="mt-0.5" />
                  <div className="min-w-0 flex-1">
                    <p className="line-clamp-2 text-[13px] leading-5 text-fg">{a.summary}</p>
                    <p className="mt-0.5 flex flex-wrap items-center gap-x-2 text-[12px] text-fg-subtle">
                      <UserName username={a.actor} avatar={false} />
                      <RelativeTime value={a.timestamp} />
                      <Badge tone={auditTone(a)} className="h-[18px]! text-[10.5px]">
                        {a.category}
                      </Badge>
                    </p>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
      {servers.length === 0 && (
        <Card className="mt-4">
          <EmptyState
            icon={ServerCrash}
            title="No servers registered yet"
            description="Register servers so policy sets, quarantine and per-server reports can apply to them."
            action={<ButtonLink to="/servers">Register servers</ButtonLink>}
          />
        </Card>
      )}
    </>
  );
};
