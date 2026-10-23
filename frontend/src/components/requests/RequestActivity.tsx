import React, { useMemo, useState } from 'react';
import { Ban, CheckCheck, Clock3, Hourglass, MessageSquare, Send, UserCheck, XCircle } from 'lucide-react';
import { api } from '../../api';
import { useAction, useConsoleState, usePermissions } from '../../data/AppData';
import { useLookups } from '../../data/lookups';
import { formatDateTime, toTime } from '../../lib/format';
import type { AccessRequest } from '../../types';
import { Button, Card, CardHeader, Kbd, modKey, RelativeTime, Textarea, Timeline, TimelineItem } from '../../ui';
import { canHandle } from './requestUtils';

/** "Access revoked: <reason>" / "Access extended until <RFC3339>|permanent" → readable text. */
function systemText(text: string): string {
  if (text.startsWith('Access revoked: ')) return `Reason: ${text.slice('Access revoked: '.length)}`;
  const m = /^Access extended (?:until (\S+)|permanent)/.exec(text);
  if (m) return m[1] ? `New expiry: ${formatDateTime(m[1])}` : 'Access is now permanent.';
  return text;
}

/** Timeline (submitted, assignments, comments, decision, extensions, revocation) with a comment composer. */
export const RequestActivity: React.FC<{ request: AccessRequest }> = ({ request: r }) => {
  const state = useConsoleState();
  const perms = usePermissions();
  const { userName } = useLookups();
  const { run, pending } = useAction();
  const [text, setText] = useState('');
  const can = canHandle(perms, r);

  const items = useMemo(() => {
    const out: Array<TimelineItem & { at: number }> = [];
    const who = (u: string) => <span className="font-medium text-fg">{userName(u)}</span>;
    out.push({
      id: 'submitted',
      at: toTime(r.created_at) ?? 0,
      icon: Send,
      tone: 'info',
      title: (
        <>
          Submitted by <span className="font-medium text-fg">{r.requester}</span>
        </>
      ),
      meta: <RelativeTime value={r.created_at} />,
      body: r.verified ? 'From a block page with a signed block token.' : 'Without a block token (self-reported server identity).',
    });
    for (const e of state.audit_events) {
      if (e.entity_id !== r.id || e.action !== 'REQUEST_ASSIGNED') continue;
      const m = /to "([^"]*)"/.exec(e.summary);
      const to = m?.[1] ?? '';
      out.push({
        id: e.id,
        at: toTime(e.timestamp) ?? 0,
        icon: UserCheck,
        title: to ? (
          <>
            {who(e.actor)} assigned {to.toLowerCase() === e.actor.toLowerCase() ? 'it to themselves' : who(to)}
          </>
        ) : (
          <>{who(e.actor)} removed the assignee</>
        ),
        meta: <RelativeTime value={e.timestamp} />,
      });
    }
    (r.comments ?? []).forEach((c, i) => {
      const system = /^Access (revoked|extended)/.test(c.text);
      const revoked = c.text.startsWith('Access revoked');
      out.push({
        id: `c${i}`,
        at: toTime(c.at) ?? 0,
        icon: system ? (revoked ? Ban : Hourglass) : MessageSquare,
        tone: system ? (revoked ? 'danger' : 'warning') : 'neutral',
        title: system ? (
          <>
            {who(c.author)} {revoked ? 'revoked access' : 'extended access'}
          </>
        ) : (
          <>{who(c.author)} commented</>
        ),
        meta: <RelativeTime value={c.at} />,
        body: system ? systemText(c.text) : <span className="whitespace-pre-wrap text-fg">{c.text}</span>,
      });
    });
    if (r.reviewed_at && r.reviewed_by) {
      const approved = r.status === 'approved' || r.status === 'revoked';
      out.push({
        id: 'decision',
        at: toTime(r.reviewed_at) ?? 0,
        icon: approved ? CheckCheck : XCircle,
        tone: approved ? 'success' : 'danger',
        title: (
          <>
            {who(r.reviewed_by)} {approved ? 'approved' : 'rejected'} the request
          </>
        ),
        meta: <RelativeTime value={r.reviewed_at} />,
        body: r.review_comment || undefined,
      });
    }
    if (r.status === 'pending' && r.due_at) {
      out.push({ id: 'due', at: toTime(r.due_at) ?? 0, icon: Clock3, tone: 'warning', title: 'SLA deadline', meta: <RelativeTime value={r.due_at} />, current: true });
    }
    return out.sort((a, b) => a.at - b.at);
  }, [r, state.audit_events, userName]);

  const submit = async () => {
    if (!text.trim()) return;
    const res = await run(() => api.requests.comment(r.id, text.trim()), { key: 'comment', success: 'Comment added', errorTitle: 'The comment was not added' });
    if (res) setText('');
  };

  return (
    <Card>
      <CardHeader title="Activity" description="Discussion and decisions, oldest first." icon={MessageSquare} divider />
      <div className="p-[var(--card-p)]">
        <Timeline items={items} />
        {can ? (
          <form
            className="mt-5 space-y-2 border-t border-border pt-4"
            onSubmit={(e) => {
              e.preventDefault();
              submit();
            }}
          >
            <label htmlFor="req-comment" className="label">
              Add a comment
            </label>
            <Textarea
              id="req-comment"
              value={text}
              onChange={(e) => setText(e.target.value)}
              rows={3}
              maxLength={2000}
              placeholder="Ask the requester or other reviewers, note conditions…"
              onKeyDown={(e) => {
                if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
                  e.preventDefault();
                  submit();
                }
              }}
            />
            <div className="flex items-center justify-between gap-2">
              <span className="hidden text-[12px] text-fg-subtle sm:inline">
                <Kbd>{modKey()}</Kbd> <Kbd>Enter</Kbd> to send
              </span>
              <Button type="submit" size="sm" icon={Send} loading={pending === 'comment'} disabled={!text.trim()} className="ml-auto">
                Comment
              </Button>
            </div>
          </form>
        ) : (
          <p className="mt-5 border-t border-border pt-4 text-[12.5px] text-fg-subtle">
            {perms.isReadOnly ? 'Read-only access: you cannot comment.' : 'Only reviewers of the request’s groups can comment.'}
          </p>
        )}
      </div>
    </Card>
  );
};
