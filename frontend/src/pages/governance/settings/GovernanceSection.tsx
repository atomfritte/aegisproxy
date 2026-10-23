import React, { useEffect, useState } from 'react';
import { CalendarClock, MessageSquareText, ShieldCheck } from 'lucide-react';
import { api } from '../../../api';
import { useAction, useConsoleState, usePermissions } from '../../../data/AppData';
import { useNavigationBlocker } from '../../../lib/router';
import type { GovernanceSettings } from '../../../types';
import { ButtonLink, Callout, Card, CardHeader, Field, HelpTip, Input, RelativeTime, Switch } from '../../../ui';
import { SaveBar, SectionTitle } from './shared';

type Editable = Pick<
  GovernanceSettings,
  'require_policy_review' | 'request_sla_hours' | 'default_review_interval_days' | 'max_temporary_access_days' | 'daily_digest' | 'prune_expired_after_days'
>;

function editable(g: GovernanceSettings): Editable {
  return {
    require_policy_review: !!g.require_policy_review,
    request_sla_hours: g.request_sla_hours,
    default_review_interval_days: g.default_review_interval_days,
    max_temporary_access_days: g.max_temporary_access_days,
    daily_digest: g.daily_digest ?? true,
    prune_expired_after_days: g.prune_expired_after_days ?? 7,
  };
}

const RANGES: Record<string, [number, number]> = {
  request_sla_hours: [1, 720],
  default_review_interval_days: [0, 730],
  max_temporary_access_days: [1, 365],
  prune_expired_after_days: [0, 3650],
};

/** Change governance: four-eyes review, SLAs, recertification, temporary access, daily digest. */
export const GovernanceSection: React.FC = () => {
  const state = useConsoleState();
  const perms = usePermissions();
  const { run, pending } = useAction();
  const server = editable(state.governance);
  const [g, setG] = useState<Editable>(server);
  const serverKey = JSON.stringify(server);
  useEffect(() => setG(editable(state.governance)), [serverKey]); // eslint-disable-line react-hooks/exhaustive-deps
  const dirty = JSON.stringify(g) !== serverKey;
  const ro = !perms.canManageSystem;
  useNavigationBlocker(dirty && !ro, 'Discard unsaved governance settings?');

  const errors: Partial<Record<keyof Editable, string>> = {};
  for (const [k, [min, max]] of Object.entries(RANGES)) {
    const v = g[k as keyof Editable] as number;
    if (!Number.isFinite(v) || !Number.isInteger(v) || v < min || v > max) errors[k as keyof Editable] = `Enter a whole number from ${min} to ${max}.`;
  }
  const invalid = Object.keys(errors).length > 0;

  const num = (k: keyof Editable) => (e: React.ChangeEvent<HTMLInputElement>) => setG({ ...g, [k]: e.target.value === '' ? NaN : Number(e.target.value) });
  const unit = (s: string) => <span className="text-[12px] text-fg-subtle">{s}</span>;
  const save = () => run(() => api.governance.update({ ...state.governance, ...g }), { key: 'gov', success: 'Governance settings saved' });

  return (
    <>
      <SectionTitle
        title="Governance"
        description="How policy changes are reviewed and how long access requests and temporary access may take. Applies to every policy set and request."
        actions={
          state.governance.updated_at ? (
            <span className="text-[12.5px] text-fg-subtle">
              Updated <RelativeTime value={state.governance.updated_at} /> by {state.governance.updated_by}
            </span>
          ) : null
        }
      />
      {ro && (
        <Callout tone="neutral" className="mb-5">
          Only InfoSec Approvers and Super Admins can change these settings.
        </Callout>
      )}
      <div className="space-y-5">
        <Card>
          <CardHeader icon={ShieldCheck} title="Policy changes" description="Four-eyes review and recertification of policy sets." divider />
          <div className="space-y-5 p-[var(--card-p)]">
            <Switch
              checked={g.require_policy_review}
              onChange={(v) => setG({ ...g, require_policy_review: v })}
              disabled={ro}
              label="Require four-eyes review for policy changes"
              description="Drafts are published only through a change request approved by someone other than the author. Super Admins can still publish emergency changes with a justification."
            />
            <Field
              label="Default recertification interval"
              labelAside={<HelpTip content="New policy sets must be re-confirmed by an owner after this many days. 0 disables recertification for new sets." />}
              hint={errors.default_review_interval_days ?? 'Days (0–730). Pre-filled for new policy sets; each set can override it.'}
              error={errors.default_review_interval_days}
              className="max-w-sm"
            >
              <Input type="number" min={0} max={730} value={Number.isNaN(g.default_review_interval_days) ? '' : g.default_review_interval_days} onChange={num('default_review_interval_days')} disabled={ro} trailing={unit('days')} />
            </Field>
          </div>
        </Card>

        <Card>
          <CardHeader icon={CalendarClock} title="Access requests and temporary access" description="Deadlines for reviewers and limits for granted access." divider />
          <div className="grid gap-5 p-[var(--card-p)] sm:grid-cols-3">
            <Field label="Review SLA" hint="Hours until a pending request is overdue (1–720)." error={errors.request_sla_hours}>
              <Input type="number" min={1} max={720} value={Number.isNaN(g.request_sla_hours) ? '' : g.request_sla_hours} onChange={num('request_sla_hours')} disabled={ro} trailing={unit('hours')} />
            </Field>
            <Field label="Longest temporary access for Team Leads" hint="Days (1–365). Team Leads cannot grant permanent access." error={errors.max_temporary_access_days}>
              <Input type="number" min={1} max={365} value={Number.isNaN(g.max_temporary_access_days) ? '' : g.max_temporary_access_days} onChange={num('max_temporary_access_days')} disabled={ro} trailing={unit('days')} />
            </Field>
            <Field
              label="Remove expired access after"
              labelAside={<HelpTip content="Expired temporary rules stop matching immediately. They stay in the group's approvals policy set for this many days (useful for audits and extensions) and are then removed. 0 keeps them." />}
              hint="Days (0–3650). 0 keeps expired rules."
              error={errors.prune_expired_after_days}
            >
              <Input type="number" min={0} max={3650} value={Number.isNaN(g.prune_expired_after_days ?? 0) ? '' : g.prune_expired_after_days} onChange={num('prune_expired_after_days')} disabled={ro} trailing={unit('days')} />
            </Field>
          </div>
        </Card>

        <Card>
          <CardHeader icon={MessageSquareText} title="Daily digest" description="One summary per day in Teams and Slack instead of hunting through queues." divider />
          <div className="space-y-4 p-[var(--card-p)]">
            <Switch
              checked={!!g.daily_digest}
              onChange={(v) => setG({ ...g, daily_digest: v })}
              disabled={ro}
              label="Send a daily digest"
              description="Overdue and pending access requests, policy changes awaiting review, recertifications due, temporary access expiring within 24 hours and quarantined servers. Sent once a day after 08:00 server time to the channels configured under Notifications."
            />
            <div className="flex flex-wrap items-center justify-between gap-2 rounded-md bg-surface-2 px-3 py-2 text-[12.5px] text-fg-muted">
              <span>
                Last digest:{' '}
                {state.governance.last_digest_at ? <RelativeTime value={state.governance.last_digest_at} className="font-medium text-fg" /> : <span className="text-fg-subtle">not sent yet</span>}
              </span>
              <ButtonLink to="/settings/notifications" size="xs" variant="ghost">
                Notification channels
              </ButtonLink>
            </div>
          </div>
        </Card>
      </div>
      {!ro && <SaveBar dirty={dirty} saving={pending === 'gov'} onSave={save} disabled={invalid} note={invalid ? 'Fix the highlighted values' : undefined} onReset={() => setG(editable(state.governance))} label="Save settings" />}
    </>
  );
};
