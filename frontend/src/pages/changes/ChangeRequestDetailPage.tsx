import React, { useState } from 'react';
import { Ban, Check, CheckCheck, FileText, GitPullRequestArrow, MessageSquare, Send, Undo2, XCircle } from 'lucide-react';
import { api, ApiError } from '../../api';
import { useConsole, useConsoleState } from '../../data/AppData';
import { useSession } from '../../data/session';
import { formatDateTime } from '../../lib/format';
import { useAsync, useDocumentTitle } from '../../lib/hooks';
import { Link, useParams } from '../../lib/router';
import type { ChangeRequest, PolicySetSpec } from '../../types';
import {
  Badge,
  Button,
  ButtonLink,
  Callout,
  Card,
  CardHeader,
  DescriptionList,
  PageHeader,
  PageSkeleton,
  RelativeTime,
  Textarea,
  Timeline,
  TimelineItem,
  useConfirm,
  useToast,
} from '../../ui';
import { AssignmentChips, ChangeRequestStatusChip, PolicyKindBadge } from '../../components/policy/PolicyBadges';
import { ImpactSummaryView } from '../../components/policy/ImpactSummaryView';
import { PolicyDiffView } from '../../components/policy/PolicyDiffView';
import { UserName } from '../../components/common/EntityChips';
import { ROLE_LABELS } from '../../data/permissions';
import { NotFoundPage } from '../system/NotFoundPage';

/** /changes/:id — diff, impact, discussion and the four-eyes decision. */
export const ChangeRequestDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  return <ChangeRequestDetail id={id} key={id} />;
};

const ChangeRequestDetail: React.FC<{ id: string }> = ({ id }) => {
  const state = useConsoleState();
  const { perms, refresh } = useConsole();
  const { user } = useSession();
  const toast = useToast();
  const confirm = useConfirm();
  const cr = useAsync<ChangeRequest>(() => api.changeRequests.get(id), [id, state.revision]);
  const c = cr.data;
  const base = useAsync<PolicySetSpec | null>(
    async () => {
      if (!c || c.base_version === 0) return null;
      try {
        return (await api.policySets.version(c.policy_set_id, c.base_version)).spec;
      } catch {
        return null; // version pruned or set deleted: show the diff without old values
      }
    },
    [c?.policy_set_id, c?.base_version]
  );
  const [comment, setComment] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  useDocumentTitle(c?.title ?? 'Change request');

  if (cr.loading && !c) return <PageSkeleton />;
  if (!c) {
    return cr.error && !/not found/i.test(cr.error) ? (
      <Callout tone="danger" title="The change request could not be loaded">
        {cr.error}
      </Callout>
    ) : (
      <NotFoundPage title="Change request not found" backTo="/changes" backLabel="All change requests" />
    );
  }

  const set = state.policy_sets.find((s) => s.id === c.policy_set_id);
  const me = (user?.username || '').toLowerCase();
  const isAuthor = c.submitted_by.toLowerCase() === me;
  const isLastEditor = !!set?.draft && set.draft.change_request_id === c.id && set.draft.updated_by.toLowerCase() === me;
  const inScope = set ? perms.canManageSetScope(set.kind, c.spec.group_ids ?? [], c.spec.server_ids ?? [], state.servers) && perms.canManageSet(set, state.servers) : perms.canManageSystem;
  const open = c.status === 'open';

  let decideBlocked: string | null = null;
  if (perms.isReadOnly) decideBlocked = 'Your role is read-only. A reviewer with approval rights for this policy set must decide.';
  else if (isAuthor) decideBlocked = 'You submitted this change. Four-eyes principle: another approver must decide.';
  else if (!inScope) decideBlocked = 'This change affects groups you cannot approve for.';
  const approveBlocked = decideBlocked || (isLastEditor ? 'You edited this draft last, so another reviewer must approve it.' : null);
  const canWithdraw = open && (isAuthor || perms.canManageSystem);
  // Comments are part of the review: they need the rights to manage the set (or InfoSec).
  const canComment = open && !perms.isReadOnly && inScope;

  const reloadAll = async () => {
    await refresh();
    await cr.reload();
  };

  const handleSuperseded = async (err: unknown) => {
    if (err instanceof ApiError && err.status === 409) {
      toast.error('This change request is superseded', {
        description: 'The policy set changed after it was submitted. The author has to resubmit the draft.',
      });
      await reloadAll();
      return true;
    }
    return false;
  };

  const approve = () =>
    confirm({
      title: 'Approve and publish?',
      description: `Approving publishes "${c.policy_set_name}" as v${(set?.version ?? c.base_version) + 1} immediately.`,
      confirmLabel: 'Approve and publish',
      reason: { label: 'Comment', placeholder: 'Optional note for the history', defaultValue: comment, multiline: true },
      onConfirm: async (text) => {
        try {
          const res = await api.changeRequests.review(c.id, 'approve', text);
          setComment('');
          await reloadAll();
          toast.success('Approved and published', { description: res.published_version ? `${c.policy_set_name} v${res.published_version} is now enforced.` : undefined });
        } catch (err) {
          if (!(await handleSuperseded(err))) throw err;
        }
      },
    });

  const reject = () =>
    confirm({
      title: 'Reject this change?',
      description: 'The draft is unlocked so the author can rework it.',
      confirmLabel: 'Reject',
      tone: 'danger',
      reason: { label: 'Reason', required: true, placeholder: 'What needs to change before this can be approved?', defaultValue: comment },
      onConfirm: async (text) => {
        await api.changeRequests.review(c.id, 'reject', text);
        setComment('');
        await reloadAll();
        toast.success('Change request rejected');
      },
    });

  const withdraw = () =>
    confirm({
      title: 'Withdraw this change request?',
      description: 'The draft is unlocked and can be edited again. The request stays in the history as withdrawn.',
      confirmLabel: 'Withdraw',
      tone: 'danger',
      onConfirm: async () => {
        await api.changeRequests.withdraw(c.id);
        await reloadAll();
        toast.success('Change request withdrawn');
      },
    });

  const postComment = async () => {
    if (!comment.trim()) return;
    setBusy('comment');
    try {
      await api.changeRequests.review(c.id, 'comment', comment.trim());
      setComment('');
      await reloadAll();
      toast.success('Comment added');
    } catch (err) {
      toast.error(err, { title: 'Comment not added' });
    } finally {
      setBusy(null);
    }
  };

  const timeline: TimelineItem[] = [
    {
      id: 'submitted',
      icon: Send,
      tone: 'accent',
      title: (
        <span>
          <UserName username={c.submitted_by} avatar={false} /> submitted the change
        </span>
      ),
      meta: <RelativeTime value={c.submitted_at} />,
    },
    ...(c.reviews ?? []).map((r, i) => ({
      id: `r${i}`,
      icon: r.decision === 'approve' ? CheckCheck : r.decision === 'reject' ? XCircle : MessageSquare,
      tone: (r.decision === 'approve' ? 'success' : r.decision === 'reject' ? 'danger' : 'neutral') as TimelineItem['tone'],
      title: (
        <span className="inline-flex flex-wrap items-center gap-1.5">
          <UserName username={r.reviewer} avatar={false} />
          <span className="font-normal text-fg-muted">{r.decision === 'approve' ? 'approved' : r.decision === 'reject' ? 'rejected' : 'commented'}</span>
          <Badge tone="neutral">{ROLE_LABELS[r.role as keyof typeof ROLE_LABELS] || r.role}</Badge>
        </span>
      ),
      meta: <RelativeTime value={r.at} />,
      body: r.comment ? <p className="whitespace-pre-wrap rounded-md border border-border bg-surface-2 px-3 py-2 text-fg">{r.comment}</p> : undefined,
    })),
    ...(c.status === 'withdrawn' || c.status === 'superseded'
      ? [
          {
            id: 'final',
            icon: c.status === 'withdrawn' ? Undo2 : Ban,
            tone: 'neutral' as const,
            title: c.status === 'withdrawn' ? <span>{c.decided_by ? <UserName username={c.decided_by} avatar={false} /> : 'Someone'} withdrew the request</span> : 'Superseded by a newer version of the set',
            meta: c.decided_at ? <RelativeTime value={c.decided_at} /> : undefined,
          },
        ]
      : []),
  ];

  return (
    <>
      <PageHeader
        breadcrumbs={[{ label: 'Change requests', to: '/changes' }, { label: c.id }]}
        title={c.title}
        meta={
          <>
            <ChangeRequestStatusChip status={c.status} />
            <Link to={`/policies/${encodeURIComponent(c.policy_set_id)}`} className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface px-2 py-0.5 text-[12.5px] text-fg hover:border-border-strong">
              <GitPullRequestArrow className="h-3.5 w-3.5 text-fg-subtle" aria-hidden />
              {c.policy_set_name}
            </Link>
            {set && <PolicyKindBadge kind={set.kind} />}
            <span className="text-[12.5px] text-fg-muted">
              Based on v{c.base_version}
              {c.published_version ? `, published as v${c.published_version}` : ''}
            </span>
          </>
        }
        actions={
          canWithdraw && (
            <Button icon={Undo2} onClick={withdraw}>
              Withdraw
            </Button>
          )
        }
      />

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_380px]">
        <div className="min-w-0 space-y-6">
          {c.access_request_id && (
            <Callout tone="info" title="Access request approval">
              This change carries the approval of access request{' '}
              <Link to={`/requests/${encodeURIComponent(c.access_request_id)}`} className="font-medium text-accent hover:underline">
                {c.access_request_id}
              </Link>
              . Approving it grants the access; rejecting it returns the request to the queue.
            </Callout>
          )}
          {c.status === 'superseded' && (
            <Callout tone="warning" title="Superseded">
              The policy set changed after this request was submitted (for example an approved access request added a rule). The author needs to resubmit the draft.
            </Callout>
          )}
          {c.status === 'approved' && (
            <Callout tone="success" title={`Approved by ${c.decided_by} ${c.decided_at ? `on ${formatDateTime(c.decided_at)}` : ''}`}>
              Published as v{c.published_version}.{' '}
              <Link to={`/policies/${encodeURIComponent(c.policy_set_id)}/history`} className="font-medium text-accent hover:underline">
                View version history
              </Link>
            </Callout>
          )}
          {c.status === 'rejected' && (
            <Callout tone="danger" title={`Rejected by ${c.decided_by}`}>
              The draft was unlocked for rework.
            </Callout>
          )}

          <Card>
            <CardHeader title="Description" icon={FileText} />
            <div className="px-[var(--card-p)] pb-[var(--card-p)] pt-2">
              {c.description ? <p className="whitespace-pre-wrap text-[13.5px] leading-6 text-fg">{c.description}</p> : <p className="text-[13px] text-fg-subtle">No description provided.</p>}
              <DescriptionList
                className="mt-5 border-t border-border pt-4"
                columns={2}
                items={[
                  { label: 'Assignment after the change', value: <AssignmentChips kind={set?.kind ?? 'standard'} groupIds={c.spec.group_ids} serverIds={c.spec.server_ids} max={4} /> },
                  { label: 'Rules after the change', value: (c.spec.rules ?? []).length },
                ]}
              />
            </div>
          </Card>

          <Card>
            <CardHeader title="Changes" description={`Compared with v${c.base_version}${base.data ? '' : c.base_version ? ' (old values unavailable)' : ''}`} />
            <div className="p-[var(--card-p)]">
              <PolicyDiffView diff={c.diff} from={base.data ?? undefined} to={base.data ? c.spec : undefined} emptyTitle="No rule or setting changes" />
            </div>
          </Card>

          <Card>
            <CardHeader title="Impact on recorded traffic" description="Computed when the change was submitted." />
            <div className="p-[var(--card-p)]">
              {c.impact ? <ImpactSummaryView impact={c.impact} compact /> : <p className="text-[13px] text-fg-subtle">No impact simulation was recorded for this request.</p>}
            </div>
          </Card>
        </div>

        <aside className="space-y-6 xl:sticky xl:top-20 xl:self-start">
          {open && (
            <Card>
              <CardHeader title="Your decision" description="Approving publishes the change immediately." />
              <div className="space-y-3 p-[var(--card-p)]">
                {decideBlocked && <Callout tone="neutral">{decideBlocked}</Callout>}
                {!decideBlocked && approveBlocked && <Callout tone="warning">{approveBlocked}</Callout>}
                <div className="grid grid-cols-2 gap-2">
                  <Button variant="primary" icon={Check} onClick={approve} disabled={!!approveBlocked} title={approveBlocked || undefined}>
                    Approve
                  </Button>
                  <Button variant="danger" icon={XCircle} onClick={reject} disabled={!!decideBlocked} title={decideBlocked || undefined}>
                    Reject
                  </Button>
                </div>
              </div>
            </Card>
          )}

          <Card>
            <CardHeader title="Activity" description={`${(c.reviews ?? []).length} review${(c.reviews ?? []).length === 1 ? '' : 's'} and comments`} />
            <div className="p-[var(--card-p)]">
              <Timeline items={timeline} />
              {canComment && (
                <form
                  className="mt-5 border-t border-border pt-4"
                  onSubmit={(e) => {
                    e.preventDefault();
                    postComment();
                  }}
                >
                  <label htmlFor="cr-comment" className="label mb-1.5 block">
                    Add a comment
                  </label>
                  <Textarea
                    id="cr-comment"
                    rows={3}
                    value={comment}
                    onChange={(e) => setComment(e.target.value)}
                    placeholder="Questions or conditions for the author. Comments are visible to everyone."
                    onKeyDown={(e) => {
                      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') postComment();
                    }}
                  />
                  <div className="mt-2 flex justify-end">
                    <Button type="submit" icon={MessageSquare} loading={busy === 'comment'} disabled={!comment.trim()}>
                      Comment
                    </Button>
                  </div>
                </form>
              )}
            </div>
          </Card>

          <Card padded>
            <DescriptionList
              columns={1}
              items={[
                { label: 'Request id', value: <span className="font-mono text-[12px]">{c.id}</span> },
                { label: 'Submitted', value: formatDateTime(c.submitted_at) },
                { label: 'Decided', value: c.decided_at ? `${formatDateTime(c.decided_at)} by ${c.decided_by}` : '—' },
                {
                  label: 'Policy set',
                  value: set ? (
                    <ButtonLink to={`/policies/${encodeURIComponent(set.id)}`} size="sm">
                      Open {set.name}
                    </ButtonLink>
                  ) : (
                    <span className="text-fg-subtle">Deleted</span>
                  ),
                },
              ]}
            />
          </Card>
        </aside>
      </div>
    </>
  );
};
