import React, { useMemo, useState } from 'react';
import {
  BadgeCheck,
  FileEdit,
  FlaskConical,
  GitCompare,
  GitPullRequestArrow,
  History,
  ListChecks,
  Lock,
  MoreHorizontal,
  Siren,
  Trash2,
  Undo2,
  Upload,
} from 'lucide-react';
import { api } from '../../api';
import { useConsole, useConsoleState } from '../../data/AppData';
import { formatNumber } from '../../lib/format';
import { useAsync, useDocumentTitle } from '../../lib/hooks';
import { navigate, useNavigationBlocker, useParams } from '../../lib/router';
import type { PolicySetDetail } from '../../types';
import {
  Badge,
  Button,
  ButtonLink,
  Callout,
  Card,
  CountdownChip,
  Menu,
  PageHeader,
  PageSkeleton,
  RelativeTime,
  TabPanel,
  Tabs,
  Tooltip,
  useConfirm,
  useToast,
} from '../../ui';
import { UserName } from '../../components/common/EntityChips';
import { AssignmentChips, DraftIndicator, PolicyKindBadge, ReviewStateChip } from '../../components/policy/PolicyBadges';
import { SubmitChangeDialog } from '../../components/policy/SubmitChangeDialog';
import { NotFoundPage } from '../system/NotFoundPage';
import { ChangesTab } from './tabs/ChangesTab';
import { DraftTab } from './tabs/DraftTab';
import { HistoryTab } from './tabs/HistoryTab';
import { ImpactTab } from './tabs/ImpactTab';
import { RulesTab } from './tabs/RulesTab';
import { SetChangeRequestsTab } from './tabs/SetChangeRequestsTab';
import { useDraftEditor } from './useDraftEditor';

const TABS = ['rules', 'draft', 'changes', 'impact', 'history', 'requests'] as const;
type Tab = (typeof TABS)[number];

/** /policies/:id/:tab? — header with lifecycle actions and the Rules / Draft / Changes / Impact / History / Change requests tabs. */
export const PolicySetDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  // remount per set so local draft edits and loaded details never leak between sets
  return <PolicySetDetail key={id} />;
};

const PolicySetDetail: React.FC = () => {
  const { id, tab: rawTab } = useParams<{ id: string; tab?: string }>();
  const state = useConsoleState();
  const { perms, refresh } = useConsole();
  const toast = useToast();
  const confirm = useConfirm();
  const detail = useAsync<PolicySetDetail>(() => api.policySets.get(id), [id, state.revision]);
  const set = detail.data?.policy_set;
  const editor = useDraftEditor(set);
  const [submitOpen, setSubmitOpen] = useState(false);
  useDocumentTitle(set?.name ?? 'Policy set');

  useNavigationBlocker(editor.dirty, 'The draft has unsaved changes. Leave without saving?', (next) => next.pathname.startsWith(`/policies/${encodeURIComponent(id)}`));

  const tab: Tab = (TABS as readonly string[]).includes(rawTab || '') ? (rawTab as Tab) : 'rules';
  const go = (t: Tab) => navigate(`/policies/${encodeURIComponent(id)}${t === 'rules' ? '' : `/${t}`}`, { preserveScroll: true });

  const reload = async () => {
    await refresh();
    await detail.reload();
  };

  const draftChanges = useMemo(() => {
    const d = detail.data?.draft_diff;
    return d ? d.added + d.removed + d.modified + (d.metadata ?? []).length : 0;
  }, [detail.data]);

  if (detail.loading && !detail.data) return <PageSkeleton />;
  if (!set) {
    return detail.error && !/not found/i.test(detail.error) ? (
      <Callout tone="danger" title="The policy set could not be loaded">
        {detail.error}
      </Callout>
    ) : (
      <NotFoundPage title="Policy set not found" description="It may have been deleted. Versions of deleted sets remain in the audit trail." backTo="/policies" backLabel="All policy sets" />
    );
  }

  const isApprovals = set.kind === 'approvals';
  const canManage = perms.canManageSet(set, state.servers) && !isApprovals;
  // approvals sets are not edited here, but owners still recertify them
  const canRecertify = perms.canManageSet(set, state.servers) && set.version > 0;
  const requireReview = !!state.governance?.require_policy_review;
  const draft = set.draft;
  const editing = draft?.status === 'editing';
  const inReview = draft?.status === 'in_review';
  const openCRs = (detail.data?.change_requests ?? []).filter((c) => c.status === 'open').length;
  const dirtyHint = editor.dirty ? 'Save the draft first' : undefined;

  // ---- actions --------------------------------------------------------------------------------
  const publish = () =>
    confirm({
      title: `Publish ${set.name}?`,
      description: `Creates version v${set.version + 1}. Every data-plane worker enforces it within seconds.`,
      body: detail.data?.draft_diff ? (
        <div className="flex flex-wrap gap-1.5">
          <Badge tone="success">+{detail.data.draft_diff.added} added</Badge>
          <Badge tone="warning">{detail.data.draft_diff.modified} modified</Badge>
          <Badge tone="danger">-{detail.data.draft_diff.removed} removed</Badge>
          {(detail.data.draft_diff.metadata ?? []).length > 0 && <Badge tone="info">settings changed</Badge>}
        </div>
      ) : undefined,
      confirmLabel: 'Publish',
      reason: { label: 'Comment', placeholder: 'Change ticket or reason (recorded in the version history)', multiline: false },
      onConfirm: async (comment) => {
        const res = await api.policySets.publish(set.id, { comment });
        await reload();
        toast.success(`Published v${res.version}`, { description: `${set.name} is now enforced.` });
        go('rules');
      },
    });

  const emergencyPublish = () =>
    confirm({
      title: 'Emergency publish without review?',
      description: 'Bypasses four-eyes review. The version is flagged as an emergency change in the history and the audit trail.',
      confirmLabel: 'Publish now',
      tone: 'danger',
      reason: { label: 'Justification', required: true, minLength: 10, placeholder: 'Incident number and why this cannot wait for review' },
      onConfirm: async (comment) => {
        const res = await api.policySets.publish(set.id, { comment, emergency: true });
        await reload();
        toast.success(`Published v${res.version} as an emergency change`);
        go('rules');
      },
    });

  const submit = async (title: string, description: string) => {
    try {
      const cr = await api.policySets.submit(set.id, { title, description });
      await reload();
      toast.success('Submitted for review', { description: 'A second approver must approve it before it is published.' });
      navigate(`/changes/${encodeURIComponent(cr.id)}`);
      return true;
    } catch (err) {
      toast.error(err, { title: 'Not submitted' });
      return false;
    }
  };

  const recertify = () =>
    confirm({
      title: `Recertify ${set.name}?`,
      description: `Confirms the set is still needed. The next review is due in ${set.review_interval_days || state.governance?.default_review_interval_days || 90} days.`,
      confirmLabel: 'Recertify',
      reason: { label: 'Comment', placeholder: 'Who confirmed it, ticket number', multiline: false },
      onConfirm: async (comment) => {
        await api.policySets.recertify(set.id, comment);
        await reload();
        toast.success('Recertified', { description: 'Recorded in the audit trail.' });
      },
    });

  const discard = () =>
    confirm({
      title: 'Discard the draft?',
      description: 'All saved draft changes are deleted. The published version is not affected.',
      confirmLabel: 'Discard draft',
      tone: 'danger',
      onConfirm: async () => {
        await api.policySets.discardDraft(set.id);
        editor.expectReload();
        await reload();
        toast.success('Draft discarded');
        go('rules');
      },
    });

  const remove = () =>
    confirm({
      title: `Delete ${set.name}?`,
      description: 'Its rules stop being enforced immediately. Open change requests are withdrawn; versions are kept for the audit trail.',
      confirmLabel: 'Delete policy set',
      tone: 'danger',
      typeToConfirm: set.name,
      reason: { label: 'Reason', required: true, placeholder: 'Why is this set no longer needed?' },
      onConfirm: async (reason) => {
        await api.policySets.remove(set.id, reason);
        await refresh();
        toast.success(`Deleted ${set.name}`);
        navigate('/policies', { replace: true });
      },
    });

  // ---- header actions -------------------------------------------------------------------------
  let primary: React.ReactNode = null;
  if (inReview && draft?.change_request_id) {
    primary = (
      <ButtonLink to={`/changes/${encodeURIComponent(draft.change_request_id)}`} variant="primary" icon={GitPullRequestArrow}>
        Open change request
      </ButtonLink>
    );
  } else if (editing && canManage) {
    primary = (
      <Tooltip content={dirtyHint}>
        {requireReview ? (
          <Button variant="primary" icon={GitPullRequestArrow} onClick={() => setSubmitOpen(true)} disabled={editor.dirty}>
            Submit for review
          </Button>
        ) : (
          <Button variant="primary" icon={Upload} onClick={publish} disabled={editor.dirty}>
            Publish
          </Button>
        )}
      </Tooltip>
    );
  } else if (!draft && canManage) {
    primary = (
      <Button variant="primary" icon={FileEdit} onClick={() => go('draft')}>
        Edit draft
      </Button>
    );
  }

  const moreItems = [
    {
      id: 'emergency',
      label: 'Emergency publish',
      icon: Siren,
      description: 'Super Admin only, bypasses review',
      onSelect: emergencyPublish,
      hidden: !(perms.isSuperAdmin && requireReview && editing && canManage),
      disabled: editor.dirty,
    },
    { id: 'impact', label: 'Simulate impact', icon: FlaskConical, onSelect: () => go('impact'), hidden: isApprovals },
    { id: 'compare', label: 'Compare versions', icon: GitCompare, onSelect: () => go('history'), hidden: set.version === 0 },
    { id: 'discard', label: 'Discard draft', icon: Undo2, danger: true, separator: true, onSelect: discard, hidden: !(editing && canManage) },
    {
      id: 'delete',
      label: 'Delete policy set',
      icon: Trash2,
      danger: true,
      separator: !(editing && canManage),
      onSelect: remove,
      hidden: !perms.canManageSystem,
      disabled: isApprovals && (set.rules ?? []).length > 0,
      description: isApprovals && (set.rules ?? []).length > 0 ? 'Revoke the access requests instead' : undefined,
    },
  ];

  const ruleCount = (set.rules ?? []).length;

  return (
    <>
      <PageHeader
        breadcrumbs={[{ label: 'Policy sets', to: '/policies' }, { label: set.name }]}
        title={set.name}
        description={set.description || undefined}
        meta={
          <>
            <PolicyKindBadge kind={set.kind} />
            {set.version > 0 ? <Badge tone="neutral">v{set.version}</Badge> : <Badge tone="neutral">Unpublished</Badge>}
            {set.version > 0 && <ReviewStateChip set={set} />}
            <DraftIndicator set={set} />
            {!(set.version > 0 ? set.enabled : set.draft?.spec.enabled ?? true) && <Badge tone="neutral">Disabled</Badge>}
          </>
        }
        actions={
          <>
            {canRecertify && (
              <Button icon={BadgeCheck} onClick={recertify}>
                Recertify
              </Button>
            )}
            {moreItems.some((i) => !i.hidden) && (
              <Menu
                items={moreItems}
                trigger={(p) => (
                  <Button {...p} icon={MoreHorizontal} aria-label="More actions">
                    <span className="sr-only sm:not-sr-only">More</span>
                  </Button>
                )}
              />
            )}
            {primary}
          </>
        }
      />

      <Card className="mb-6 grid grid-cols-1 divide-y divide-border sm:grid-cols-2 sm:divide-y-0 lg:grid-cols-4 lg:divide-x">
        <Fact label="Assigned to">
          <AssignmentChips kind={set.kind} groupIds={set.group_ids} serverIds={set.server_ids} max={3} />
        </Fact>
        <Fact label="Published">
          {set.version > 0 ? (
            <span className="inline-flex flex-wrap items-center gap-1.5">
              v{set.version} by <UserName username={set.published_by} avatar={false} /> <RelativeTime value={set.published_at} />
            </span>
          ) : (
            <span className="text-fg-subtle">Never</span>
          )}
        </Fact>
        <Fact label="Owner">
          <span>{set.owner_team || <span className="text-fg-subtle">No owner team</span>}</span>
          <span className="mt-0.5 block text-[12px] text-fg-subtle">
            Priority {set.priority}, {formatNumber(ruleCount)} rule{ruleCount === 1 ? '' : 's'}
          </span>
        </Fact>
        <Fact label="Recertification">
          {set.review_due_at ? (
            <span className="flex flex-col items-start gap-1">
              <CountdownChip due={set.review_due_at} kind="review" />
              {set.last_reviewed_by && (
                <span className="text-[12px] text-fg-subtle">
                  Last by {set.last_reviewed_by} <RelativeTime value={set.last_reviewed_at} />
                </span>
              )}
            </span>
          ) : (
            <span className="text-fg-subtle">{set.version === 0 ? 'Starts when published' : 'Off'}</span>
          )}
        </Fact>
      </Card>

      {inReview && tab !== 'draft' && (
        <Callout
          tone="warning"
          icon={Lock}
          className="mb-6"
          title="A change to this set is waiting for review"
          action={
            draft?.change_request_id && (
              <ButtonLink size="sm" to={`/changes/${encodeURIComponent(draft.change_request_id)}`}>
                Review
              </ButtonLink>
            )
          }
        >
          The draft is locked until the change request is approved, rejected or withdrawn.
        </Callout>
      )}

      <Tabs<Tab>
        idPrefix="ps"
        className="mb-6"
        value={tab}
        onChange={go}
        aria-label="Policy set sections"
        tabs={[
          { id: 'rules', label: 'Rules', icon: ListChecks, count: ruleCount },
          {
            id: 'draft',
            label: editor.dirty ? (
              <span className="inline-flex items-center gap-1.5">
                Draft
                <span className="h-1.5 w-1.5 rounded-full bg-warning-solid" title="Unsaved changes" aria-label="unsaved changes" />
              </span>
            ) : (
              'Draft'
            ),
            icon: FileEdit,
            hidden: isApprovals,
          },
          { id: 'changes', label: 'Changes', icon: GitCompare, hidden: isApprovals, count: draft ? draftChanges : undefined, countTone: 'info' },
          { id: 'impact', label: 'Impact', icon: FlaskConical, hidden: isApprovals },
          { id: 'history', label: 'History', icon: History, count: (detail.data?.versions ?? []).length },
          { id: 'requests', label: 'Change requests', icon: GitPullRequestArrow, count: openCRs || undefined, countTone: 'warning' },
        ]}
      />

      <TabPanel id={tab} idPrefix="ps">
        {tab === 'rules' && <RulesTab set={set} canManage={canManage} />}
        {tab === 'draft' && !isApprovals && <DraftTab set={set} editor={editor} canManage={canManage} onSaved={reload} />}
        {tab === 'changes' && !isApprovals && <ChangesTab set={set} diff={detail.data?.draft_diff ?? null} canManage={canManage} unsaved={editor.dirty} />}
        {tab === 'impact' && !isApprovals && <ImpactTab set={set} unsavedSpec={editor.dirty ? editor.current : null} />}
        {tab === 'history' && <HistoryTab set={set} versions={detail.data?.versions ?? []} canManage={canManage} onChanged={reload} />}
        {tab === 'requests' && <SetChangeRequestsTab requests={detail.data?.change_requests ?? []} />}
        {isApprovals && (tab === 'draft' || tab === 'changes' || tab === 'impact') && <RulesTab set={set} canManage={false} />}
      </TabPanel>

      <SubmitChangeDialog open={submitOpen} onClose={() => setSubmitOpen(false)} setName={set.name} diff={detail.data?.draft_diff} onSubmit={submit} />
    </>
  );
};

const Fact: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div className="min-w-0 px-[var(--card-p)] py-3.5">
    <div className="mb-1 text-[12px] font-medium text-fg-subtle">{label}</div>
    <div className="min-w-0 text-[13px] text-fg">{children}</div>
  </div>
);
