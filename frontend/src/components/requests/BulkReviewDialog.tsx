import React, { useEffect, useState } from 'react';
import { CheckCheck, CheckCircle2, XCircle } from 'lucide-react';
import { api } from '../../api';
import { useConsole } from '../../data/AppData';
import { DURATION_LABELS, pluralize } from '../../lib/format';
import { Link } from '../../lib/router';
import type { AccessRequest, BulkReviewResult } from '../../types';
import { Badge, Button, Callout, Field, Modal, Textarea, useToast } from '../../ui';
import { durationBlockedReason, requestTitle } from './requestUtils';

/** Approve or reject many pending requests with their requested scope and duration. */
export const BulkReviewDialog: React.FC<{
  open: boolean;
  onClose: () => void;
  approve: boolean;
  requests: AccessRequest[];
  onDone?: () => void;
}> = ({ open, onClose, approve, requests, onDone }) => {
  const { refresh, perms, state } = useConsole();
  const toast = useToast();
  const [comment, setComment] = useState('');
  const [busy, setBusy] = useState(false);
  const [results, setResults] = useState<BulkReviewResult[] | null>(null);

  useEffect(() => {
    if (open) {
      setComment('');
      setResults(null);
    }
  }, [open]);

  const byId = new Map(requests.map((r) => [r.id, r]));
  const permanent = requests.filter((r) => r.duration === 'permanent' && r.requested_scope !== 'learning_session_15m').length;
  const maxDays = state?.governance?.max_temporary_access_days ?? 0;
  const capped = requests.filter((r) => r.requested_scope !== 'learning_session_15m' && durationBlockedReason(r.duration, perms, maxDays)).length;
  const needComment = !approve && comment.trim().length === 0;

  const submit = async () => {
    setBusy(true);
    try {
      const res = await api.requests.bulkReview(
        requests.map((r) => r.id),
        approve,
        comment.trim()
      );
      setResults(res.results);
      await refresh();
      const failed = res.results.filter((r) => r.error).length;
      const ok = res.results.length - failed;
      if (failed === 0) toast.success(`${approve ? 'Approved' : 'Rejected'} ${pluralize(ok, 'request')}`);
      else toast.warning(`${approve ? 'Approved' : 'Rejected'} ${ok} of ${res.results.length} requests`, { description: 'See the results for the requests that failed.' });
      onDone?.();
    } catch (err) {
      toast.error(err, { title: approve ? 'The requests were not approved' : 'The requests were not rejected' });
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
      title={results ? 'Results' : `${approve ? 'Approve' : 'Reject'} ${pluralize(requests.length, 'request')}`}
      description={
        results
          ? undefined
          : approve
            ? 'Each request is approved as requested: suggested pattern, requested scope and duration, for its target groups.'
            : 'The requesters are notified with your comment.'
      }
      icon={
        <span className={approve ? 'flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-success-soft text-success' : 'flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-danger-soft text-danger'}>
          {approve ? <CheckCheck className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}
        </span>
      }
      footer={
        results ? (
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        ) : (
          <>
            <Button onClick={onClose} disabled={busy}>
              Cancel
            </Button>
            <Button variant={approve ? 'primary' : 'danger'} onClick={submit} loading={busy} disabled={needComment}>
              {approve ? `Approve ${requests.length}` : `Reject ${requests.length}`}
            </Button>
          </>
        )
      }
    >
      {results ? (
        <ul className="divide-y divide-border rounded-lg border border-border" aria-label="Review results">
          {results.map((r) => {
            const req = byId.get(r.id);
            return (
              <li key={r.id} className="flex items-start gap-2.5 px-3 py-2 text-[13px]">
                {r.error ? <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-danger" aria-hidden /> : <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-success" aria-hidden />}
                <div className="min-w-0 flex-1">
                  <Link to={`/requests/${encodeURIComponent(r.id)}`} className="block truncate font-mono text-[12px] text-fg hover:underline">
                    {req ? requestTitle(req, 56) : r.id}
                  </Link>
                  {r.error ? <p className="break-words text-[12px] text-danger">{r.error}</p> : <p className="text-[12px] text-fg-muted">{r.status}</p>}
                </div>
              </li>
            );
          })}
        </ul>
      ) : (
        <div className="space-y-4">
          <ul className="max-h-48 divide-y divide-border overflow-y-auto rounded-lg border border-border scroll-thin">
            {requests.map((r) => (
              <li key={r.id} className="flex items-center gap-2 px-3 py-1.5 text-[12.5px]">
                <span className="min-w-0 flex-1 truncate font-mono text-fg">{requestTitle(r, 60)}</span>
                <Badge tone={r.duration === 'permanent' ? 'violet' : 'neutral'}>{r.requested_scope === 'learning_session_15m' ? '15 min session' : DURATION_LABELS[r.duration] ?? r.duration}</Badge>
              </li>
            ))}
          </ul>
          {approve && capped > 0 && (
            <Callout tone="warning" title={`${capped} of these exceed your approval limit`}>
              Team Leads cannot grant permanent access{maxDays ? ` or more than ${maxDays} days` : ''}. Those requests will fail; open them individually to grant a shorter duration.
            </Callout>
          )}
          {approve && perms.canManageSystem && permanent > 0 && (
            <Callout tone="info">{pluralize(permanent, 'request')} asks for permanent access. Open a request to grant a shorter duration instead.</Callout>
          )}
          <Field label="Comment" required={!approve} hint={approve ? 'Recorded with each decision and sent to the requesters.' : 'Tell the requesters why, and what to do instead.'}>
            <Textarea value={comment} onChange={(e) => setComment(e.target.value)} rows={3} placeholder={approve ? 'Optional, e.g. ticket number' : 'Reason for the rejection'} data-autofocus />
          </Field>
        </div>
      )}
    </Modal>
  );
};
