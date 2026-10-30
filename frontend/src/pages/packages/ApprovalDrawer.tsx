import React, { useEffect, useState } from 'react';
import { Ban, CalendarClock, FileCheck2, Inbox } from 'lucide-react';
import { api } from '../../api';
import { formatBytes, formatDateTime } from '../../lib/format';
import { useAsync } from '../../lib/hooks';
import { Link } from '../../lib/router';
import type { PackageApproval } from '../../types';
import { Badge, Button, Callout, CountdownChip, DescriptionList, Drawer, Field, Input, Modal, Skeleton, useConfirm, useToast } from '../../ui';
import { RelativeTime } from '../../ui/Time';
import { GroupChip, ChipList, UserName } from '../../components/common/EntityChips';
import { EcosystemBadge, RiskBadge } from '../../components/packages';
import { nameVersion } from '../../components/packages/packageUtils';

/** Approval detail drawer: pinned files, origin, and Revoke / Extend for system role. */
export const ApprovalDrawer: React.FC<{ approval: PackageApproval | null; canManage: boolean; onClose: () => void; onChanged: () => void | Promise<void> }> = ({
  approval,
  canManage,
  onClose,
  onChanged,
}) => {
  const toast = useToast();
  const confirm = useConfirm();
  const [extendOpen, setExtendOpen] = useState(false);
  const detail = useAsync(() => (approval ? api.packages.approvals.get(approval.id) : Promise.resolve(undefined)), [approval?.id]);
  // Prefer the freshly loaded detail, fall back to the row data.
  const a = (approval && detail.data?.approval?.id === approval.id ? detail.data.approval : approval) as PackageApproval | null;
  const origin = detail.data?.request;
  const active = a?.status === 'approved';

  const revoke = () => {
    if (!a) return;
    confirm({
      title: 'Revoke this approval?',
      description: `${nameVersion(a.name, a.version, a.display_name)} stops being delivered within seconds; clients that pinned it will fail to resolve it.`,
      tone: 'danger',
      confirmLabel: 'Revoke approval',
      reason: { label: 'Reason', required: true, minLength: 3, placeholder: 'Why is this version no longer allowed?', hint: 'Recorded in the audit trail.' },
      onConfirm: async (reason) => {
        await api.packages.approvals.revoke(a.id, reason);
        await onChanged();
        toast.success('Approval revoked');
      },
    });
  };

  return (
    <>
      <Drawer
        open={!!approval}
        onClose={onClose}
        width="md"
        title={a ? <span className="break-all font-mono text-[15px]">{nameVersion(a.name, a.version, a.display_name)}</span> : ''}
        titleAside={a ? <span className="flex items-center gap-1.5"><RiskBadge risk={a.risk} />{a.status === 'revoked' && <Badge tone="danger">revoked</Badge>}</span> : undefined}
        footer={
          canManage && a && active ? (
            <>
              <Button variant="danger-ghost" icon={Ban} onClick={revoke}>Revoke</Button>
              <Button variant="primary" icon={CalendarClock} onClick={() => setExtendOpen(true)}>Extend / set expiry</Button>
            </>
          ) : undefined
        }
      >
        {a && (
          <div className="space-y-5">
            <DescriptionList
              columns={2}
              items={[
                { label: 'Ecosystem', value: <EcosystemBadge ecosystem={a.ecosystem} /> },
                { label: 'Version', value: <span className="font-mono text-[12.5px]">{a.version}</span> },
                { label: 'Status', value: a.status === 'approved' ? <Badge tone="success">Active</Badge> : <Badge tone="danger">Revoked</Badge> },
                { label: 'Via', value: <Badge tone={a.via === 'rule' ? 'info' : a.via === 'dependency' ? 'violet' : 'neutral'}>{a.via || 'manual'}</Badge> },
                {
                  label: 'Groups',
                  value: <ChipList max={4}>{(a.group_ids ?? []).map((g) => (g === '*' ? <Badge key="*" tone="violet" size="sm">All groups</Badge> : <GroupChip key={g} id={g} />))}</ChipList>,
                  full: true,
                },
                { label: 'Approved by', value: <UserName username={a.approved_by} avatar={false} /> },
                { label: 'Approved', value: <RelativeTime value={a.approved_at} /> },
                {
                  label: 'Expiry',
                  value: a.expires_at ? <CountdownChip due={a.expires_at} kind="expiry" /> : <Badge tone="violet">Permanent</Badge>,
                  hidden: a.status !== 'approved',
                },
              ]}
            />

            {a.unanalyzed && (
              <Callout tone="warning" title="Approved without sandbox analysis">
                This version was approved as an override before a sandbox analysis completed.
              </Callout>
            )}

            {a.required_by && (
              <p className="text-[12.5px] text-fg-muted">
                Pulled in as a dependency of <span className="font-mono text-fg">{a.required_by}</span>.
              </p>
            )}
            {a.reason && <p className="rounded-lg border border-border bg-surface-2 p-3 text-[12.5px] leading-5 text-fg">{a.reason}</p>}

            <section>
              <h3 className="mb-2 flex items-center gap-2 text-[13px] font-semibold text-fg"><FileCheck2 className="h-4 w-4 text-fg-muted" aria-hidden /> Pinned files</h3>
              {(a.files ?? []).length === 0 ? (
                <p className="text-[12.5px] text-fg-subtle">No files are pinned on this approval.</p>
              ) : (
                <ul className="space-y-1.5">
                  {(a.files ?? []).map((f) => (
                    <li key={f.filename} className="rounded-lg border border-border bg-surface-2 p-2.5 text-[12px]">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="break-all font-mono text-fg">{f.filename}</span>
                        {f.size ? <Badge tone="neutral" size="sm">{formatBytes(f.size)}</Badge> : null}
                      </div>
                      {f.sha256 && <div className="mt-1 break-all font-mono text-[11px] text-fg-subtle">sha256: {f.sha256}</div>}
                      {f.sha512 && <div className="mt-1 break-all font-mono text-[11px] text-fg-subtle">sha512: {f.sha512}</div>}
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <section>
              <h3 className="mb-2 flex items-center gap-2 text-[13px] font-semibold text-fg"><Inbox className="h-4 w-4 text-fg-muted" aria-hidden /> Origin</h3>
              {detail.loading && !detail.data ? (
                <Skeleton className="h-10" />
              ) : a.request_id ? (
                <Link to={`/packages/requests/${encodeURIComponent(a.request_id)}`} className="inline-flex items-center gap-1.5 text-[13px] font-medium text-accent hover:underline">
                  {origin ? `Request for ${nameVersion(origin.name, origin.version, origin.display_name)}` : `Request ${a.request_id}`}
                </Link>
              ) : a.rule_id ? (
                <Link to={`/packages/rules?rule=${encodeURIComponent(a.rule_id)}`} className="text-[13px] font-medium text-accent hover:underline">
                  Created by a rule
                </Link>
              ) : (
                <p className="text-[12.5px] text-fg-subtle">Created manually.</p>
              )}
            </section>

            {a.status === 'revoked' && (
              <Callout tone="danger" title="Revoked">
                {a.revoked_by && <>By <UserName username={a.revoked_by} avatar={false} /> </>}
                {a.revoked_at && <RelativeTime value={a.revoked_at} />}
                {a.revoke_reason && <span className="mt-1 block text-fg-muted">“{a.revoke_reason}”</span>}
              </Callout>
            )}
          </div>
        )}
      </Drawer>
      {a && <ExtendDialog open={extendOpen} onClose={() => setExtendOpen(false)} approval={a} onDone={onChanged} />}
    </>
  );
};

const ExtendDialog: React.FC<{ open: boolean; onClose: () => void; approval: PackageApproval; onDone: () => void | Promise<void> }> = ({ open, onClose, approval: a, onDone }) => {
  const toast = useToast();
  const [date, setDate] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (open) {
      setDate(a.expires_at ? a.expires_at.slice(0, 10) : '');
      setBusy(false);
    }
  }, [open, a.expires_at]);

  const submit = async (permanent: boolean) => {
    setBusy(true);
    try {
      const iso = permanent ? '' : date ? new Date(`${date}T23:59:59`).toISOString() : '';
      await api.packages.approvals.extend(a.id, iso);
      await onDone();
      toast.success(permanent || !iso ? 'Approval made permanent' : 'Expiry updated', { description: permanent || !iso ? undefined : `Now expires ${formatDateTime(iso)}.` });
      onClose();
    } catch (e) {
      toast.error(e, { title: 'The expiry was not changed' });
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
      title="Set approval expiry"
      description={`Currently ${a.expires_at ? `until ${formatDateTime(a.expires_at)}` : 'permanent'}.`}
      icon={<span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-accent-soft text-accent"><CalendarClock className="h-4 w-4" aria-hidden /></span>}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button variant="primary" onClick={() => submit(false)} loading={busy} disabled={!date}>Set expiry</Button>
        </>
      }
    >
      <div className="space-y-3">
        <Field label="Expiry date" hint="The approval stops permitting downloads after this date.">
          <Input type="date" value={date} onChange={(e) => setDate(e.target.value)} />
        </Field>
        <Button variant="ghost" size="sm" onClick={() => submit(true)} disabled={busy}>
          Make permanent instead
        </Button>
      </div>
    </Modal>
  );
};
