import React, { useMemo, useState } from 'react';
import { CheckCheck, Radar, RotateCcw, Sparkles, XCircle } from 'lucide-react';
import { api } from '../../api';
import { useConsole, useConsoleState } from '../../data/AppData';
import { useLookups } from '../../data/lookups';
import { DURATION_LABELS, pluralize } from '../../lib/format';
import { navigate } from '../../lib/router';
import type { AccessDuration, AccessRequest } from '../../types';
import { Badge, Button, Callout, Card, CardHeader, Checkbox, Field, Input, MultiSelect, Switch, Textarea, Tooltip, useToast } from '../../ui';
import { HTTP_METHODS, isBroadHostPattern, validateHostPattern, validatePathPattern } from '../policy/policyUtils';
import { effectiveGroups } from '../fleet/fleetUtils';
import { clampDuration, DurationPicker, expiryText } from './DurationPicker';
import { approvalsSetId, defaultMethods, durationBlockedReason } from './requestUtils';

/**
 * Review a pending request: adjust the suggested rule (patterns, methods, redirects, target groups,
 * duration), see what will be allowed, then approve or reject with a comment.
 */
export const ReviewPanel: React.FC<{ request: AccessRequest }> = ({ request: r }) => {
  const state = useConsoleState();
  const { perms, refresh } = useConsole();
  const { groupName } = useLookups();
  const toast = useToast();
  const maxDays = state.governance?.max_temporary_access_days ?? 0;
  const blocked = (d: string) => durationBlockedReason(d, perms, maxDays);
  const learning = r.requested_scope === 'learning_session_15m';

  const initial = useMemo(
    () => ({
      host: r.suggested_host_pattern,
      path: r.suggested_path_pattern,
      methods: defaultMethods(r),
      follow: r.follow_redirects,
      groups: [...(r.target_group_ids ?? [])],
      duration: clampDuration(r.duration, blocked),
    }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [r.id]
  );
  const [host, setHost] = useState(initial.host);
  const [path, setPath] = useState(initial.path);
  const [methods, setMethods] = useState<string[]>(initial.methods);
  const [follow, setFollow] = useState(initial.follow);
  const [groups, setGroups] = useState<string[]>(initial.groups);
  const [duration, setDuration] = useState<AccessDuration>(initial.duration);
  const [comment, setComment] = useState('');
  const [busy, setBusy] = useState<'approve' | 'reject' | null>(null);
  const [tried, setTried] = useState<'approve' | 'reject' | null>(null);

  const edited =
    host !== initial.host || path !== initial.path || follow !== initial.follow || methods.join() !== initial.methods.join() || groups.join() !== initial.groups.join() || duration !== initial.duration;
  const reset = () => {
    setHost(initial.host);
    setPath(initial.path);
    setMethods(initial.methods);
    setFollow(initial.follow);
    setGroups(initial.groups);
    setDuration(initial.duration);
  };

  const hostErr = validateHostPattern(host) || (!perms.canManageSystem && isBroadHostPattern(host) ? 'Team Leads cannot approve catch-all or top-level wildcards.' : host.trim() === '*' && !perms.isSuperAdmin ? 'Only Super Admins may allow every host.' : null);
  const pathErr = validatePathPattern(path);
  const groupsErr = groups.length === 0 ? 'Choose at least one target group.' : !perms.canApproveFor(groups) ? 'You can only approve for your own groups.' : null;
  const methodsErr = methods.length === 0 ? 'Select at least one method.' : null;
  const strict = learning && groups.some((g) => state.groups.find((x) => x.id === g)?.strict_isolation);
  const approveErrors = learning ? [groupsErr, strict ? 'Learning sessions are not permitted for strict-isolation groups.' : null] : [hostErr, pathErr, groupsErr, methodsErr, blocked(duration)];
  const canApprove = approveErrors.every((e) => !e);
  const rejectErr = comment.trim().length < 3 ? 'Explain the rejection to the requester (at least 3 characters).' : null;

  const servers = useMemo(() => state.servers.filter((s) => effectiveGroups(s).some((g) => groups.includes(g))).length, [state.servers, groups]);
  const groupOptions = state.groups.map((g) => ({
    value: g.id,
    label: g.name,
    description: perms.canApproveFor([g.id]) ? g.id : 'Outside your groups',
    color: g.color,
    disabled: !perms.canApproveFor([g.id]) && !groups.includes(g.id),
  }));
  const isGithub = host.trim().toLowerCase() === 'github.com' && /^\/[^*/]+/.test(path);
  const anyMethod = methods.includes('*');

  const decide = async (approve: boolean) => {
    setTried(approve ? 'approve' : 'reject');
    if (approve ? !canApprove : !!rejectErr) return;
    setBusy(approve ? 'approve' : 'reject');
    try {
      const res = await api.requests.review(
        r.id,
        approve
          ? learning
            ? { approve: true, comment: comment.trim(), target_group_ids: groups }
            : { approve: true, comment: comment.trim(), host_pattern: host.trim(), path_pattern: path.trim(), follow_redirects: follow, target_group_ids: groups, duration, methods }
          : { approve: false, comment: comment.trim() }
      );
      await refresh();
      if (!approve) toast.success('Request rejected', { description: 'The requester is notified with your comment.' });
      else if (learning)
        toast.success('Learning session started', {
          description: `${r.server_hostname || r.server_ip} records and allows traffic for 15 minutes.`,
          action: { label: 'Open learning sessions', onClick: () => navigate('/learning') },
        });
      else {
        const n = (res.rules ?? []).length || groups.length;
        toast.success(`Approved — ${pluralize(n, 'rule')} added`, {
          description: `Enforced within seconds, ${expiryText(duration)}.`,
          action: groups.length === 1 ? { label: 'Open approvals set', onClick: () => navigate(`/policies/${encodeURIComponent(approvalsSetId(groups[0]))}`) } : undefined,
        });
      }
    } catch (err) {
      toast.error(err, { title: approve ? 'The request was not approved' : 'The request was not rejected' });
    } finally {
      setBusy(null);
    }
  };

  return (
    <Card>
      <CardHeader
        title={learning ? 'Decision' : 'Review the rule'}
        description={learning ? 'This request asks for a learning session instead of a rule.' : 'The suggestion is derived from the blocked URL. Narrow it down if possible.'}
        icon={learning ? Radar : Sparkles}
        divider
        actions={
          edited && !learning ? (
            <Button size="sm" variant="ghost" icon={RotateCcw} onClick={reset}>
              Reset to suggestion
            </Button>
          ) : undefined
        }
      />
      <div className="space-y-5 p-[var(--card-p)]">
        {learning ? (
          <Callout tone="violet" icon={Radar} title="Approving starts a 15-minute learning session">
            {r.server_hostname || r.server_ip} records and allows its outbound traffic (record &amp; allow) for 15 minutes. Afterwards, review the captured candidates on the Learning sessions page and
            publish them as rules.
          </Callout>
        ) : (
          <>
            <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)]">
              <Field label="Host pattern" error={hostErr} hint={!hostErr ? 'Leading *. matches subdomains.' : undefined}>
                <Input value={host} onChange={(e) => setHost(e.target.value)} mono spellCheck={false} autoComplete="off" />
              </Field>
              <Field label="Path pattern" error={pathErr} hint={!pathErr ? '* matches one segment, ** any depth.' : undefined}>
                <Input value={path} onChange={(e) => setPath(e.target.value)} mono spellCheck={false} autoComplete="off" />
              </Field>
            </div>
            <Field label="Methods" error={methodsErr} hint={!methodsErr ? `Least privilege: read-only plus the requested method (${r.method || 'GET'}).` : undefined}>
              {({ id }) => (
                <div id={id} className="flex flex-wrap gap-x-4 gap-y-2">
                  {HTTP_METHODS.filter((m) => m !== 'CONNECT').map((m) => (
                    <Checkbox
                      key={m}
                      label={<span className="font-mono text-[12px]">{m}</span>}
                      checked={anyMethod || methods.includes(m)}
                      disabled={anyMethod}
                      onChange={() => setMethods((cur) => (cur.includes(m) ? cur.filter((x) => x !== m) : [...cur, m]))}
                    />
                  ))}
                  <Checkbox label="Any" checked={anyMethod} onChange={() => setMethods(anyMethod ? defaultMethods(r) : ['*'])} />
                </div>
              )}
            </Field>
            <Switch
              checked={follow}
              onChange={setFollow}
              label="Follow redirects"
              description="Also allows the object a matching response redirects to (e.g. release downloads on a CDN), for two minutes per redirect."
            />
          </>
        )}

        <Field label="Target groups" error={tried === 'approve' ? groupsErr : null} hint={learning ? 'Groups the session is scoped to.' : 'One rule is added to the approvals set of each group.'}>
          <MultiSelect value={groups} onChange={setGroups} options={groupOptions} placeholder="Choose groups" />
        </Field>

        {!learning && (
          <Field
            label="Grant access for"
            hint={
              perms.canManageSystem
                ? `Requested: ${DURATION_LABELS[r.duration] ?? r.duration}.`
                : `Requested: ${DURATION_LABELS[r.duration] ?? r.duration}. Team Leads grant temporary access only${maxDays > 0 ? `, up to ${maxDays} days` : ''} (governance setting).`
            }
          >
            {({ id }) => <DurationPicker id={id} value={duration} onChange={setDuration} maxDays={maxDays} requested={r.duration} />}
          </Field>
        )}

        {!learning && (
          <div className="rounded-lg border border-accent-border bg-accent-soft/60 p-3.5" aria-live="polite">
            <p className="text-[11.5px] font-semibold text-accent">What will be allowed</p>
            <p className="mt-1 text-[13px] leading-6 text-fg">
              Allow <span className="font-mono text-[12.5px]">{anyMethod ? 'any method' : methods.join(', ') || '—'}</span> to{' '}
              <span className="break-all rounded bg-surface px-1 py-0.5 font-mono text-[12.5px] font-semibold ring-1 ring-border">
                {host || '…'}
                {path && path !== '/**' ? path : path === '/**' ? '/**' : ''}
              </span>{' '}
              from <strong className="font-semibold">{groups.length ? groups.map(groupName).join(', ') : 'no group'}</strong> ({pluralize(servers, 'registered server')}){' '}
              {duration === 'permanent' ? <strong className="font-semibold">permanently</strong> : <>for {DURATION_LABELS[duration]?.toLowerCase()} ({expiryText(duration)})</>}.
            </p>
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              {follow && <Badge tone="info">+ redirect targets</Badge>}
              {isGithub && (
                <Tooltip content="codeload.github.com, api.github.com/repos and raw.githubusercontent.com for the same organisation">
                  <Badge tone="info">+ GitHub companion hosts</Badge>
                </Tooltip>
              )}
              {groups.map((g) => (
                <Badge key={g} tone="neutral">
                  → {approvalsSetId(g)}
                </Badge>
              ))}
            </div>
          </div>
        )}

        <Field label="Comment" error={tried === 'reject' ? rejectErr : null} hint="Sent to the requester and recorded in the audit trail.">
          <Textarea value={comment} onChange={(e) => setComment(e.target.value)} rows={2} placeholder="Ticket number, conditions, or why the request is rejected" />
        </Field>

        {tried === 'approve' && !canApprove && (
          <Callout tone="danger" title="Fix the highlighted fields before approving">
            {approveErrors.filter(Boolean).join(' ')}
          </Callout>
        )}

        <div className="flex flex-col-reverse gap-2 border-t border-border pt-4 sm:flex-row sm:justify-end">
          <Button variant="danger-ghost" icon={XCircle} onClick={() => decide(false)} loading={busy === 'reject'} disabled={!!busy}>
            Reject
          </Button>
          <Button variant="primary" icon={learning ? Radar : CheckCheck} onClick={() => decide(true)} loading={busy === 'approve'} disabled={!!busy}>
            {learning ? 'Approve and start session' : edited ? 'Approve with changes' : 'Approve'}
          </Button>
        </div>
      </div>
    </Card>
  );
};
