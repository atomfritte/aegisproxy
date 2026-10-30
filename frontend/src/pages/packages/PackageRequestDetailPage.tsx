import React, { useEffect, useMemo, useState } from 'react';
import { Ban, CheckCheck, Loader2, PackageCheck, RefreshCw, ScrollText } from 'lucide-react';
import { api } from '../../api';
import { useConsole, useConsoleState, usePermissions } from '../../data/AppData';
import { useAsync, useDocumentTitle } from '../../lib/hooks';
import { Link, useParams, useQueryParam } from '../../lib/router';
import type { PackageNode, PackageRequest } from '../../types';
import {
  Badge,
  Button,
  Callout,
  Card,
  CardBody,
  CardHeader,
  DescriptionList,
  Field,
  MultiSelect,
  PageHeader,
  Skeleton,
  Spinner,
  Textarea,
  Modal,
  useConfirm,
  useToast,
} from '../../ui';
import { RelativeTime } from '../../ui/Time';
import { GroupChip, ChipList, UserName } from '../../components/common/EntityChips';
import { DependencyGraph, EcosystemBadge, RiskBadge } from '../../components/packages';
import { nameVersion, requestInFlight, requestStatusMeta } from '../../components/packages/packageUtils';
import { NodeDrawer } from './NodeDrawer';
import { NotFoundPage } from '../system/NotFoundPage';

/** /packages/requests/:id — status, dependency graph, per-node assessment and review. */
export const PackageRequestDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const state = useConsoleState();
  const { data, error, loading, reload } = useAsync(() => api.packages.requests.get(id), [id, state.revision]);

  // Poll while resolution / analysis is still running.
  useEffect(() => {
    if (!data || !requestInFlight(data.status)) return;
    const t = window.setInterval(() => reload(), 4000);
    return () => window.clearInterval(t);
  }, [data, reload]);

  useDocumentTitle(data ? `${data.display_name || data.name} · Package request` : 'Package request');

  if (error && !data) {
    return <NotFoundPage title="Package request not found" description={error} backTo="/packages/requests" backLabel="All package requests" />;
  }
  if (!data) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-10 w-80" />
        <Skeleton className="h-64" />
      </div>
    );
  }
  return <RequestDetail key={data.id} request={data} reload={reload} loading={loading} />;
};

const RequestDetail: React.FC<{ request: PackageRequest; reload: () => Promise<void>; loading: boolean }> = ({ request: r, reload, loading }) => {
  const perms = usePermissions();
  const { refresh } = useConsole();
  const toast = useToast();
  const confirm = useConfirm();
  const [nodeKey, setNodeKey] = useQueryParam('node');
  const [approveOpen, setApproveOpen] = useState(false);
  const [reanalyzing, setReanalyzing] = useState(false);

  const graph = r.graph ?? [];
  const byKey = useMemo(() => new Map(graph.map((n) => [n.key, n])), [graph]);
  const selectedNode = nodeKey ? byKey.get(nodeKey) ?? null : null;
  const resolveName = (key: string) => {
    const n = byKey.get(key);
    return n ? nameVersion(n.name, n.version, n.display_name) : key;
  };

  const status = requestStatusMeta(r.status);
  const inFlight = requestInFlight(r.status);
  const canReview = perms.canManageSystem && r.status === 'ready';

  const afterMutation = async () => {
    await reload();
    refresh();
  };

  const reject = () =>
    confirm({
      title: 'Reject this request?',
      description: `No approvals will be created for ${r.display_name || r.name}. The requester is notified.`,
      tone: 'danger',
      confirmLabel: 'Reject request',
      reason: { label: 'Reason', required: true, minLength: 3, placeholder: 'Why is this package not approved?', hint: 'Shown to the requester and recorded in the audit trail.' },
      onConfirm: async (reason) => {
        await api.packages.requests.decide(r.id, { decision: 'reject', note: reason });
        await afterMutation();
        toast.success('Request rejected');
      },
    });

  const reanalyze = async () => {
    setReanalyzing(true);
    try {
      await api.packages.requests.reanalyze(r.id);
      await afterMutation();
      toast.success('Re-analysis started', { description: 'The graph is resolved and analyzed again against the latest advisories and rules.' });
    } catch (e) {
      toast.error(e, { title: 'Re-analysis could not be started' });
    } finally {
      setReanalyzing(false);
    }
  };

  const counts = r.counts ?? {};

  return (
    <>
      <PageHeader
        breadcrumbs={[{ label: 'Package firewall', to: '/packages' }, { label: 'Requests', to: '/packages/requests' }, { label: r.display_name || r.name }]}
        leading={<span className="mt-0.5 hidden h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-accent-soft text-accent sm:flex"><PackageCheck className="h-5 w-5" aria-hidden /></span>}
        title={<span className="break-all font-mono text-[20px]">{nameVersion(r.name, r.version, r.display_name)}</span>}
        meta={
          <>
            <EcosystemBadge ecosystem={r.ecosystem} />
            <Badge tone={status.tone} dot={inFlight} pulse={inFlight}>{status.label}</Badge>
            <RiskBadge risk={r.risk} size="md" />
            {r.requested && r.requested !== r.version && <Badge tone="neutral">requested {r.requested}</Badge>}
            <span className="text-[12px] text-fg-subtle">opened by <UserName username={r.requested_by} avatar={false} /> <RelativeTime value={r.created_at} /></span>
          </>
        }
        actions={
          <>
            {perms.canManageSystem && !inFlight && (
              <Button icon={RefreshCw} onClick={reanalyze} loading={reanalyzing} variant="secondary">
                Re-analyze
              </Button>
            )}
            {canReview && (
              <>
                <Button icon={Ban} variant="danger-ghost" onClick={reject}>
                  Reject
                </Button>
                <Button icon={CheckCheck} variant="primary" onClick={() => setApproveOpen(true)}>
                  Approve
                </Button>
              </>
            )}
          </>
        }
      />

      {r.auto_rule_id && (
        <Callout tone={r.decision === 'reject' ? 'danger' : 'info'} icon={ScrollText} title="Decided automatically by a rule" className="mb-4">
          Rule{' '}
          <Link to={`/packages/rules?rule=${encodeURIComponent(r.auto_rule_id)}`} className="font-medium text-accent hover:underline">
            {r.auto_rule_name || r.auto_rule_id}
          </Link>{' '}
          {r.decision === 'reject' ? 'blocked this request' : 'approved this request'} without human review. First matching rule wins.
        </Callout>
      )}

      {r.status === 'failed' && (
        <Callout tone="danger" title="Resolution or analysis failed" className="mb-4" action={perms.canManageSystem ? <Button size="sm" onClick={reanalyze} loading={reanalyzing}>Retry</Button> : undefined}>
          {r.error || 'The dependency graph could not be fully resolved or analyzed.'}
        </Callout>
      )}

      {inFlight && (
        <Callout tone="info" icon={Loader2} className="mb-4">
          <span className="flex items-center gap-2">
            <Spinner className="h-4 w-4" />
            {r.status === 'resolving' ? 'Resolving the dependency graph…' : 'Analyzing every version (advisories, signatures, sandbox)…'} This view refreshes automatically.
          </span>
        </Callout>
      )}

      <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_300px]">
        <div className="min-w-0 space-y-5">
          <Card>
            <CardHeader
              title="Dependency graph"
              description="Root first, following the required-by edges. High-risk packages are surfaced and marked on their collapsed ancestors."
              actions={loading ? <Spinner className="h-4 w-4 text-fg-subtle" /> : undefined}
            />
            <CardBody className="pt-2">
              {graph.length === 0 && inFlight ? (
                <p className="text-[13px] text-fg-subtle">The graph will appear as soon as resolution completes.</p>
              ) : (
                <DependencyGraph nodes={graph} rootKey={r.root_key} selectedKey={nodeKey || undefined} onOpenNode={(n) => setNodeKey(n.key)} />
              )}
            </CardBody>
          </Card>
        </div>

        <aside className="min-w-0 space-y-5">
          <Card>
            <CardHeader title="Request" />
            <CardBody className="pt-2">
              <DescriptionList
                columns={1}
                items={[
                  { label: 'Status', value: <Badge tone={status.tone}>{status.label}</Badge> },
                  { label: 'Overall risk', value: <RiskBadge risk={r.risk} /> },
                  { label: 'Origin', value: <span className="capitalize">{r.origin || 'manual'}</span> },
                  {
                    label: 'Groups',
                    value: (
                      <ChipList max={4}>
                        {(r.group_ids ?? []).map((g) => (g === '*' ? <Badge key="*" tone="violet" size="sm">All groups</Badge> : <GroupChip key={g} id={g} />))}
                      </ChipList>
                    ),
                  },
                  { label: 'Requested', value: <span className="font-mono text-[12.5px]">{r.requested || r.version || '—'}</span> },
                  { label: 'Resolved version', value: <span className="font-mono text-[12.5px]">{r.version || '—'}</span> },
                  { label: 'Request id', value: <span className="font-mono text-[12px]">{r.id}</span> },
                ]}
              />
              {r.reason && (
                <figure className="mt-4 border-l-2 border-accent-border pl-3">
                  <blockquote className="whitespace-pre-wrap text-[13px] leading-5 text-fg">{r.reason}</blockquote>
                  <figcaption className="mt-1 text-[12px] text-fg-subtle">{r.requested_by}</figcaption>
                </figure>
              )}
            </CardBody>
          </Card>

          <Card>
            <CardHeader title="Graph summary" />
            <CardBody className="pt-2">
              <ul className="space-y-1.5 text-[13px]">
                <SummaryRow label="Packages" value={graph.length || Object.values(counts).reduce((a, b) => a + (b || 0), 0)} />
                <SummaryRow label="New" value={counts.new ?? 0} tone="info" />
                <SummaryRow label="Updates" value={counts.update ?? 0} tone="violet" />
                <SummaryRow label="Already approved" value={counts.approved ?? 0} tone="success" />
                <SummaryRow label="Blocked" value={counts.blocked ?? 0} tone="danger" />
              </ul>
            </CardBody>
          </Card>

          {(r.decided_at || r.decision) && (
            <Card>
              <CardHeader title="Decision" />
              <CardBody className="pt-2">
                <div className={`rounded-lg border p-3 ${r.decision === 'approve' ? 'border-success-border bg-success-soft' : 'border-danger-border bg-danger-soft'}`}>
                  <p className="text-[13px] font-semibold text-fg">
                    {r.decision === 'approve' ? 'Approved' : 'Rejected'}
                    {r.decided_by ? <> by <UserName username={r.decided_by} avatar={false} /></> : r.auto_rule_name ? <> by rule {r.auto_rule_name}</> : null} <RelativeTime value={r.decided_at} />
                  </p>
                  {r.decision_note && <p className="mt-1.5 whitespace-pre-wrap text-[12.5px] text-fg-muted">“{r.decision_note}”</p>}
                </div>
                {r.decision === 'approve' && (
                  <Link to={`/packages/approvals?q=${encodeURIComponent(r.name)}`} className="mt-3 inline-block text-[12.5px] font-medium text-accent hover:underline">
                    View the approvals this created →
                  </Link>
                )}
              </CardBody>
            </Card>
          )}

          {!perms.canManageSystem && r.status === 'ready' && (
            <Callout tone="info" title="Read-only">
              Only an InfoSec Approver or Super Admin can approve or reject package requests.
            </Callout>
          )}
        </aside>
      </div>

      <NodeDrawer node={selectedNode} onClose={() => setNodeKey(null)} resolveName={resolveName} />
      <ApproveDialog open={approveOpen} onClose={() => setApproveOpen(false)} request={r} onDone={afterMutation} />
    </>
  );
};

const SummaryRow: React.FC<{ label: string; value: number; tone?: 'info' | 'violet' | 'success' | 'danger' }> = ({ label, value, tone }) => (
  <li className="flex items-center justify-between">
    <span className="text-fg-muted">{label}</span>
    <span className={`font-semibold tabular ${value && tone === 'danger' ? 'text-danger' : value && tone === 'success' ? 'text-success' : 'text-fg'}`}>{value}</span>
  </li>
);

const ApproveDialog: React.FC<{ open: boolean; onClose: () => void; request: PackageRequest; onDone: () => Promise<void> }> = ({ open, onClose, request: r, onDone }) => {
  const state = useConsoleState();
  const toast = useToast();
  const [groupIds, setGroupIds] = useState<string[]>(r.group_ids ?? ['*']);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (open) {
      setGroupIds(r.group_ids ?? ['*']);
      setNote('');
      setBusy(false);
    }
  }, [open, r.group_ids]);

  const groupOptions = useMemo(
    () => [{ value: '*', label: 'All groups', description: 'Every client the ecosystem applies to' }, ...state.groups.map((g) => ({ value: g.id, label: g.name, description: g.environment || g.id, color: g.color }))],
    [state.groups]
  );

  const submit = async () => {
    if (groupIds.length === 0) return;
    setBusy(true);
    try {
      await api.packages.requests.decide(r.id, { decision: 'approve', note: note.trim(), group_ids: groupIds });
      await onDone();
      toast.success('Request approved', { description: 'Approvals were created for the whole graph.' });
      onClose();
    } catch (e) {
      toast.error(e, { title: 'The request was not approved' });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      dismissible={!busy}
      size="md"
      title="Approve request"
      description="Creates approvals for every new and updated package in the graph, pinned to the delivered artifact hashes."
      icon={<span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-success-soft text-success"><CheckCheck className="h-4 w-4" aria-hidden /></span>}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button variant="primary" onClick={submit} loading={busy} disabled={groupIds.length === 0}>Approve &amp; create approvals</Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Server groups" required hint="Override the requested scope if needed. Dependencies inherit it.">
          <MultiSelect value={groupIds} onChange={setGroupIds} options={groupOptions} placeholder="Select groups" />
        </Field>
        <Field label="Note" optional hint="Recorded with the approval and the audit trail.">
          <Textarea value={note} onChange={(e) => setNote(e.target.value)} rows={3} placeholder="e.g. Reviewed advisories; sandbox clean." />
        </Field>
      </div>
    </Modal>
  );
};
