import React, { useMemo, useState } from 'react';
import { Ban, CheckCheck, Globe, Hourglass, Inbox, Radar, Server as ServerIcon, ShieldAlert, XCircle } from 'lucide-react';
import { api } from '../../api';
import { useConsole, useConsoleState, usePermissions } from '../../data/AppData';
import { useLookups } from '../../data/lookups';
import { ROLE_LABELS } from '../../data/permissions';
import { DURATION_LABELS, formatDateTime, toTime } from '../../lib/format';
import { useDocumentTitle } from '../../lib/hooks';
import { Link, useParams } from '../../lib/router';
import type { AccessDuration, AccessRequest, Role } from '../../types';
import {
  Badge,
  Button,
  ButtonLink,
  Callout,
  Card,
  CardHeader,
  CopyButton,
  CountdownChip,
  DescriptionList,
  MethodList,
  Modal,
  PageHeader,
  PatternText,
  RelativeTime,
  useConfirm,
  useToast,
} from '../../ui';
import { UserName } from '../../components/common/EntityChips';
import { MembershipChip } from '../../components/fleet/FleetChips';
import { AssignCard } from '../../components/requests/AssignCard';
import { clampDuration, DurationPicker, expiryText } from '../../components/requests/DurationPicker';
import { DeadlineChip, RequestStateChip, ScopeBadge, VerifiedBadge } from '../../components/requests/RequestBadges';
import { RequestActivity } from '../../components/requests/RequestActivity';
import { Assignee } from '../../components/requests/RequestsTable';
import { approvalsSetId, canHandle, createdRules, durationBlockedReason, requestTitle, SCOPE_META } from '../../components/requests/requestUtils';
import { ReviewPanel } from '../../components/requests/ReviewPanel';
import { NotFoundPage } from '../system/NotFoundPage';

/** /requests/:id — facts, suggested rule review, outcome (extend / revoke), assignment and activity. */
export const AccessRequestDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const state = useConsoleState();
  const perms = usePermissions();
  const req = state.requests.find((r) => r.id === id);
  useDocumentTitle(req ? `Request ${requestTitle(req, 40)}` : 'Access request');
  if (!req) {
    const description = perms.isTeamLead
      ? 'It does not exist or belongs to server groups outside your scope. Old requests are pruned after the retention limit.'
      : 'Old requests are pruned after the retention limit; decisions remain in the audit trail.';
    return <NotFoundPage title="Access request not found" description={description} backTo="/requests" backLabel="All access requests" />;
  }
  return <RequestDetail key={req.id} request={req} />;
};

const RequestDetail: React.FC<{ request: AccessRequest }> = ({ request: r }) => {
  const state = useConsoleState();
  const { perms } = useConsole();
  const confirm = useConfirm();
  const toast = useToast();
  const { refresh } = useConsole();
  const [extendOpen, setExtendOpen] = useState(false);
  const can = canHandle(perms, r);
  const learning = r.requested_scope === 'learning_session_15m';
  const registered = state.servers.find((s) => s.id === r.server_id);

  const revoke = () =>
    confirm({
      title: 'Revoke access?',
      description: learning
        ? 'The learning session of this server is stopped immediately.'
        : 'The rules created by this approval are removed from the approvals sets and stop being enforced within seconds.',
      tone: 'danger',
      confirmLabel: 'Revoke access',
      reason: { label: 'Reason', required: true, placeholder: 'Why is the access no longer needed or allowed?', hint: 'Added to the activity and the audit trail.' },
      onConfirm: async (reason) => {
        await api.requests.revoke(r.id, reason);
        await refresh();
        toast.success('Access revoked');
      },
    });

  return (
    <>
      <PageHeader
        breadcrumbs={[{ label: 'Access requests', to: '/requests' }, { label: r.id }]}
        leading={
          <span className="mt-0.5 hidden h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-accent-soft text-accent sm:flex">
            {learning ? <Radar className="h-5 w-5" aria-hidden /> : <Globe className="h-5 w-5" aria-hidden />}
          </span>
        }
        title={
          <span className="font-mono text-[19px] [overflow-wrap:anywhere] sm:text-[20px]">
            <span className="font-semibold">{r.host}</span>
            <span className="font-normal text-fg-muted">{r.path !== '/' ? r.path : ''}</span>
          </span>
        }
        meta={
          <>
            <RequestStateChip request={r} />
            <VerifiedBadge verified={r.verified} />
            <ScopeBadge scope={r.requested_scope} />
            <DeadlineChip request={r} />
            {r.assigned_to && r.status === 'pending' && <Assignee username={r.assigned_to} />}
          </>
        }
        actions={
          r.status === 'approved' &&
          can && (
            <>
              {!learning && (
                <Button icon={Hourglass} onClick={() => setExtendOpen(true)}>
                  Extend
                </Button>
              )}
              <Button variant="danger" icon={Ban} onClick={revoke}>
                Revoke
              </Button>
            </>
          )
        }
      />

      <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="min-w-0 space-y-6">
          <FactsCard request={r} />
          {r.status === 'pending' ? (
            can ? (
              <ReviewPanel request={r} />
            ) : (
              <Callout tone="info" title={perms.isReadOnly ? 'Read-only access' : 'Outside your groups'}>
                {perms.isReadOnly
                  ? 'You can follow this request but not decide on it.'
                  : 'Only InfoSec or a Team Lead of every target group can decide on this request. Assign it or ask InfoSec.'}
              </Callout>
            )
          ) : (
            <OutcomeCard request={r} canAct={can} onExtend={() => setExtendOpen(true)} onRevoke={revoke} />
          )}
          <RequestActivity request={r} />
        </div>
        <aside className="min-w-0 space-y-6">
          {r.status === 'pending' && (
            <Card>
              <CardHeader title="Service level" icon={Hourglass} />
              <div className="space-y-2 px-[var(--card-p)] pb-[var(--card-p)] pt-2 text-[13px]">
                {r.due_at ? <CountdownChip due={r.due_at} kind="due" /> : <span className="text-fg-subtle">No SLA configured</span>}
                <p className="text-[12px] text-fg-subtle">
                  Submitted {formatDateTime(r.created_at)}
                  {r.due_at && <>, due {formatDateTime(r.due_at)}</>}.
                </p>
              </div>
            </Card>
          )}
          <AssignCard request={r} />
          <Card>
            <CardHeader title="Server" icon={ServerIcon} />
            <div className="space-y-3 px-[var(--card-p)] pb-[var(--card-p)] pt-2 text-[13px]">
              {registered ? (
                <Link to={`/servers/${encodeURIComponent(registered.id)}`} className="block font-medium text-fg [overflow-wrap:anywhere] hover:text-accent hover:underline">
                  {registered.hostname}
                </Link>
              ) : (
                <div>
                  <span className="font-medium text-fg">{r.server_hostname || r.server_ip}</span>
                  <p className="mt-1 text-[12px] text-fg-subtle">Not a registered server.</p>
                </div>
              )}
              <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1.5 text-[12.5px]">
                <dt className="text-fg-subtle">Server IP</dt>
                <dd className="font-mono text-[12px] text-fg">{r.server_ip || '—'}</dd>
                <dt className="text-fg-subtle">Source IP</dt>
                <dd className="font-mono text-[12px] text-fg">
                  {r.source_ip || '—'}
                  {r.source_ip && r.server_ip && r.source_ip !== r.server_ip && (
                    <Badge tone="warning" className="ml-1.5">
                      differs
                    </Badge>
                  )}
                </dd>
              </dl>
              <div>
                <p className="mb-1 text-[12px] text-fg-subtle">Target groups</p>
                <div className="flex flex-wrap gap-1">
                  {(r.target_group_ids ?? []).length ? (r.target_group_ids ?? []).map((g) => <MembershipChip key={g} id={g} />) : <span className="text-[12.5px] text-fg-subtle">None</span>}
                </div>
              </div>
              {!r.verified && (
                <p className="flex gap-2 text-[12px] leading-5 text-warning">
                  <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
                  Unverified: the server identity was resolved from the submitting IP, not from a signed block token.
                </p>
              )}
            </div>
          </Card>
        </aside>
      </div>

      <ExtendDialog open={extendOpen} onClose={() => setExtendOpen(false)} request={r} />
    </>
  );
};

const FactsCard: React.FC<{ request: AccessRequest }> = ({ request: r }) => (
  <Card>
    <CardHeader title="Request" icon={Inbox} divider />
    <div className="space-y-5 p-[var(--card-p)]">
      <div className="flex items-start gap-2 rounded-lg border border-border bg-surface-2 px-3 py-2.5">
        <span className="mt-0.5 shrink-0 rounded border border-border bg-surface px-1 font-mono text-[10.5px] font-medium leading-4 text-fg-muted">{r.method || 'GET'}</span>
        <span className="min-w-0 flex-1 break-all font-mono text-[12.5px] leading-5 text-fg">{r.requested_url}</span>
        <CopyButton text={r.requested_url} label="Copy URL" size="xs" />
      </div>
      <figure className="border-l-2 border-accent-border pl-3">
        <blockquote className="whitespace-pre-wrap text-[13.5px] leading-6 text-fg">{r.reason}</blockquote>
        <figcaption className="mt-1 text-[12px] text-fg-subtle">
          {r.requester} · <RelativeTime value={r.created_at} />
        </figcaption>
      </figure>
      <DescriptionList
        columns={2}
        items={[
          { label: 'Requested scope', value: <span title={SCOPE_META[r.requested_scope]?.description}>{SCOPE_META[r.requested_scope]?.label ?? r.requested_scope}</span> },
          { label: 'Requested duration', value: r.requested_scope === 'learning_session_15m' ? '15 minutes' : DURATION_LABELS[r.duration] ?? r.duration },
          {
            label: 'Suggested rule',
            value: (
              <span className="inline-flex flex-wrap items-center gap-1.5">
                <PatternText host={r.suggested_host_pattern} path={r.suggested_path_pattern} wrap />
                {r.follow_redirects && <Badge tone="info">follows redirects</Badge>}
              </span>
            ),
            hidden: r.requested_scope === 'learning_session_15m',
          },
          { label: 'Block token', value: r.verified ? 'Verified by the data plane' : 'Missing or invalid' },
          { label: 'User agent', value: <span className="break-all font-mono text-[12px]">{r.user_agent || '—'}</span>, full: true },
          { label: 'Trace id', value: <span className="break-all font-mono text-[12px]">{r.trace_id || '—'}</span>, hidden: !r.trace_id },
          { label: 'Request id', value: <span className="font-mono text-[12px]">{r.id}</span> },
        ]}
      />
    </div>
  </Card>
);

const OutcomeCard: React.FC<{ request: AccessRequest; canAct: boolean; onExtend: () => void; onRevoke: () => void }> = ({ request: r, canAct, onExtend, onRevoke }) => {
  const state = useConsoleState();
  const { groupName } = useLookups();
  const rules = useMemo(() => createdRules(state, r), [state, r]);
  const learning = r.requested_scope === 'learning_session_15m';
  const session = useMemo(() => {
    if (!learning) return null;
    const at = toTime(r.reviewed_at) ?? 0;
    return state.sessions.find((s) => s.server_id === r.server_id && Math.abs((toTime(s.started_at) ?? 0) - at) < 60_000) ?? null;
  }, [learning, r, state.sessions]);
  const approved = r.status === 'approved' || (r.status === 'revoked' && !!r.reviewed_at);
  const tone = r.status === 'approved' ? 'success' : 'danger';
  const Icon = r.status === 'approved' ? CheckCheck : r.status === 'revoked' ? Ban : XCircle;

  return (
    <Card>
      <CardHeader title="Decision" icon={Icon} divider />
      <div className="space-y-5 p-[var(--card-p)]">
        <div className={tone === 'success' ? 'rounded-lg border border-success-border bg-success-soft p-3.5' : 'rounded-lg border border-danger-border bg-danger-soft p-3.5'}>
          <p className="text-[13.5px] font-semibold text-fg">
            {r.status === 'approved' ? 'Approved' : r.status === 'rejected' ? 'Rejected' : 'Revoked'}
            {r.status === 'revoked' && r.revoked_by ? (
              <>
                {' '}
                by <UserName username={r.revoked_by} avatar={false} /> <RelativeTime value={r.revoked_at} />
              </>
            ) : r.reviewed_by ? (
              <>
                {' '}
                by <UserName username={r.reviewed_by} avatar={false} /> <RelativeTime value={r.reviewed_at} />
              </>
            ) : null}
          </p>
          {r.reviewer_role && r.status !== 'revoked' && <p className="text-[12px] text-fg-muted">{ROLE_LABELS[r.reviewer_role as Role] ?? r.reviewer_role}</p>}
          {r.review_comment && <p className="mt-2 whitespace-pre-wrap text-[13px] text-fg-muted">“{r.review_comment}”</p>}
        </div>

        {approved && (
          <DescriptionList
            columns={2}
            items={[
              {
                label: 'Access',
                value:
                  r.status === 'revoked' ? (
                    <span className="text-fg-muted">Revoked</span>
                  ) : r.expires_at ? (
                    <CountdownChip due={r.expires_at} kind="expiry" warnWithinMs={24 * 3600_000} />
                  ) : (
                    <Badge tone="violet">Permanent</Badge>
                  ),
              },
              { label: 'Ends', value: r.expires_at ? formatDateTime(r.expires_at) : 'Never', hidden: r.status === 'revoked' },
              { label: 'Approved by', value: <UserName username={r.reviewed_by} />, hidden: r.status !== 'revoked' },
            ]}
          />
        )}

        {learning && approved && (
          <Callout
            tone="violet"
            icon={Radar}
            title="A 15-minute learning session was started"
            action={
              <ButtonLink size="sm" to={session ? `/learning?session=${encodeURIComponent(session.id)}` : '/learning'}>
                Open session
              </ButtonLink>
            }
          >
            Review the captured candidates and publish them as rules.
          </Callout>
        )}

        {!learning && approved && (
          <div>
            <h3 className="mb-2 text-[13px] font-semibold text-fg">Rules created</h3>
            {rules.length === 0 ? (
              <p className="text-[13px] text-fg-subtle">{r.status === 'revoked' ? 'The rules were removed when the access was revoked.' : 'The rules are no longer in the approvals sets (expired and pruned, or removed).'}</p>
            ) : (
              <ul className="divide-y divide-border rounded-lg border border-border">
                {rules.map(({ set, rule }) => (
                  <li key={`${set.id}-${rule.id}`} className="space-y-1.5 px-3 py-2.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <PatternText host={rule.host_pattern} path={rule.path_pattern} wrap className="min-w-0" />
                      <MethodList methods={rule.methods} />
                    </div>
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px] text-fg-subtle">
                      <Link to={`/policies/${encodeURIComponent(set.id)}`} className="font-medium text-accent hover:underline">
                        {set.name}
                      </Link>
                      {(rule.companion_rules ?? []).length > 0 && <span>+{(rule.companion_rules ?? []).length} companion hosts</span>}
                      {rule.follow_redirects && <span>follows redirects</span>}
                      {rule.expires_at && <CountdownChip due={rule.expires_at} kind="expiry" />}
                    </div>
                  </li>
                ))}
              </ul>
            )}
            {(r.target_group_ids ?? []).length > 0 && (
              <p className="mt-2 text-[12px] text-fg-subtle">
                Approvals sets:{' '}
                {(r.target_group_ids ?? []).map((g, i) => (
                  <React.Fragment key={g}>
                    {i > 0 && ', '}
                    <Link to={`/policies/${encodeURIComponent(approvalsSetId(g))}`} className="text-accent hover:underline">
                      {groupName(g)}
                    </Link>
                  </React.Fragment>
                ))}
              </p>
            )}
          </div>
        )}

        {r.status === 'approved' && canAct && (
          <div className="flex flex-col-reverse gap-2 border-t border-border pt-4 sm:flex-row sm:justify-end">
            <Button variant="danger-ghost" icon={Ban} onClick={onRevoke}>
              Revoke access
            </Button>
            {!learning && (
              <Button icon={Hourglass} onClick={onExtend}>
                Extend access
              </Button>
            )}
          </div>
        )}
      </div>
    </Card>
  );
};

const ExtendDialog: React.FC<{ open: boolean; onClose: () => void; request: AccessRequest }> = ({ open, onClose, request: r }) => {
  const state = useConsoleState();
  const { perms, refresh } = useConsole();
  const toast = useToast();
  const maxDays = state.governance?.max_temporary_access_days ?? 0;
  const [d, setD] = useState<AccessDuration>(() => clampDuration('7d', (x) => durationBlockedReason(x, perms, maxDays)));
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    setBusy(true);
    try {
      await api.requests.extend(r.id, d);
      await refresh();
      toast.success('Access extended', { description: `Now ${expiryText(d)}.` });
      onClose();
    } catch (err) {
      toast.error(err, { title: 'The access was not extended' });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open={open}
      onClose={onClose}
      dismissible={!busy}
      size="sm"
      title="Extend access"
      description="Sets a new expiry, counted from now, on every rule this approval created."
      icon={
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-accent-soft text-accent">
          <Hourglass className="h-4 w-4" />
        </span>
      }
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" onClick={submit} loading={busy} disabled={!!durationBlockedReason(d, perms, maxDays)}>
            Extend
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <p className="text-[12.5px] text-fg-muted">Currently {r.expires_at ? `until ${formatDateTime(r.expires_at)}` : 'permanent'}.</p>
        <DurationPicker value={d} onChange={setD} maxDays={maxDays} />
        <p className="text-[13px] text-fg">
          New expiry: <strong className="font-semibold">{d === 'permanent' ? 'none (permanent)' : expiryText(d).replace(/^until /, '')}</strong>
        </p>
        {!perms.canManageSystem && maxDays > 0 && <p className="text-[12px] text-fg-subtle">Team Leads can extend by at most {maxDays} days; permanent access needs InfoSec.</p>}
      </div>
    </Modal>
  );
};
