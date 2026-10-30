import React, { useMemo, useState } from 'react';
import { CopyPlus, FilePlus2, Globe2, Layers, Sparkles } from 'lucide-react';
import { api } from '../../api';
import { useConsole, useConsoleState } from '../../data/AppData';
import { useDocumentTitle } from '../../lib/hooks';
import { navigate, useNavigationBlocker, useSearchParams } from '../../lib/router';
import type { PolicySetKind, PolicySetSpecInput, RuleInput } from '../../types';
import {
  Button,
  Callout,
  Card,
  CardHeader,
  Combobox,
  Field,
  HelpTip,
  Input,
  MultiSelect,
  PageHeader,
  PatternText,
  RadioCards,
  SegmentedControl,
  Switch,
  TagInput,
  Textarea,
  useToast,
} from '../../ui';
import { RuleActionBadge } from '../../components/policy/PolicyBadges';
import { cloneRulesForNewSet, emptyRule, validateHostPattern, validatePathPattern } from '../../components/policy/policyUtils';

type Start = 'empty' | 'clone' | 'trace';

/** /policies/new — creates a policy set whose content starts as a draft (version 0). */
export const PolicySetCreatePage: React.FC = () => {
  useDocumentTitle('New policy set');
  const state = useConsoleState();
  const { perms, refresh } = useConsole();
  const toast = useToast();
  const [params] = useSearchParams();

  // Prefill from a recorded flow (Live traffic › "Create policy rule from this trace").
  const traceRule = useMemo<RuleInput | null>(() => {
    const host = params.get('host');
    if (!host) return null;
    return { ...emptyRule(), name: params.get('name') || host, host_pattern: host, path_pattern: params.get('path') || '/**', follow_redirects: true };
  }, [params]);

  const allowedGroups = useMemo(
    () => state.groups.filter((g) => perms.canApproveFor([g.id])).map((g) => g.id),
    [state.groups, perms]
  );
  const prefillGroups = params.getAll('group').filter((g) => allowedGroups.includes(g));

  const [kind, setKind] = useState<Exclude<PolicySetKind, 'approvals'>>('standard');
  const [name, setName] = useState(traceRule ? `Access: ${params.get('name') || ''}` : '');
  const [description, setDescription] = useState('');
  const [owner, setOwner] = useState(perms.user?.department || '');
  const [tags, setTags] = useState<string[]>([]);
  const [groups, setGroups] = useState<string[]>(prefillGroups);
  const [servers, setServers] = useState<string[]>(prefillGroups.length ? [] : params.getAll('server').filter((s) => state.servers.some((x) => x.id === s)));
  const [priority, setPriority] = useState(0);
  const [reviewDays, setReviewDays] = useState(state.governance?.default_review_interval_days || 90);
  const [enabled, setEnabled] = useState(true);
  const [start, setStart] = useState<Start>(traceRule ? 'trace' : 'empty');
  const [cloneFrom, setCloneFrom] = useState('');
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState(false);

  const dirty = !created && (!!name || !!description || groups.length > 0 || tags.length > 0);
  useNavigationBlocker(dirty && !busy, 'Discard this new policy set?');

  const source = state.policy_sets.find((s) => s.id === cloneFrom);
  const rules: RuleInput[] = start === 'clone' ? cloneRulesForNewSet(source?.rules) : start === 'trace' && traceRule ? [traceRule] : [];
  const blockedRules = !perms.canEditBlockRules && rules.some((r) => r.action === 'BLOCK');

  const nameTaken = state.policy_sets.some((s) => s.name.toLowerCase() === name.trim().toLowerCase());
  const errors = {
    name: !name.trim() ? 'Enter a name.' : nameTaken ? 'A policy set with this name already exists.' : name.length > 120 ? 'At most 120 characters.' : null,
    assignment: kind === 'standard' && groups.length === 0 && servers.length === 0 ? 'Assign at least one group or server.' : null,
    interval: reviewDays < 1 || reviewDays > 730 ? 'Between 1 and 730 days.' : null,
    clone: start === 'clone' && !cloneFrom ? 'Choose the set to copy rules from.' : blockedRules ? 'The selected set contains BLOCK rules, which only InfoSec can create.' : null,
    trace:
      start === 'trace' && traceRule ? validateHostPattern(traceRule.host_pattern) || validatePathPattern(traceRule.path_pattern) : null,
  };
  const valid = Object.values(errors).every((e) => !e);

  const ownerSuggestions = [...new Set([...state.policy_sets.map((s) => s.owner_team), ...state.groups.map((g) => g.owner_team)].filter(Boolean))];
  const tagSuggestions = [...new Set(state.policy_sets.flatMap((s) => s.tags ?? []))].sort((a, b) => String(a).localeCompare(String(b)));

  const submit = async () => {
    setTouched(true);
    if (!valid) return;
    const spec: PolicySetSpecInput = {
      name: name.trim(),
      description: description.trim(),
      owner_team: owner.trim(),
      tags,
      priority,
      enabled,
      group_ids: kind === 'baseline' ? [] : groups,
      server_ids: kind === 'baseline' ? [] : servers,
      review_interval_days: reviewDays,
      rules,
    };
    setBusy(true);
    try {
      const set = await api.policySets.create(kind, spec);
      setCreated(true);
      toast.success('Draft created', { description: `"${set.name}" is not enforced until you publish it.` });
      await refresh();
      navigate(`/policies/${encodeURIComponent(set.id)}/draft`, { replace: true });
    } catch (err) {
      toast.error(err, { title: 'Policy set not created' });
    } finally {
      setBusy(false);
    }
  };

  const groupOptions = state.groups.map((g) => ({
    value: g.id,
    label: g.name,
    description: g.match_labels && Object.keys(g.match_labels).length ? `Dynamic: ${Object.entries(g.match_labels).map(([k, v]) => `${k}=${v}`).join(', ')}` : g.id,
    color: g.color,
    disabled: !allowedGroups.includes(g.id),
  }));
  const serverOptions = state.servers.map((s) => ({
    value: s.id,
    label: s.hostname,
    description: `${s.ip} · ${s.id}`,
    disabled: !perms.canApproveFor(s.effective_group_ids ?? s.group_ids ?? []),
  }));

  if (perms.isReadOnly) {
    return (
      <>
        <PageHeader title="New policy set" breadcrumbs={[{ label: 'Policy sets', to: '/policies' }, { label: 'New' }]} />
        <Callout tone="neutral">Your role is read-only. Ask an InfoSec Approver or a Team Lead to create policy sets.</Callout>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="New policy set"
        description="The set starts as a draft. Nothing is enforced until you publish it."
        breadcrumbs={[{ label: 'Policy sets', to: '/policies' }, { label: 'New' }]}
      />
      <form
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
        className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_340px]"
      >
        <div className="min-w-0 space-y-6">
          <Card>
            <CardHeader title="Kind" description="Decides which servers the rules apply to." />
            <div className="p-[var(--card-p)]">
              <RadioCards
                aria-label="Policy set kind"
                className="sm:grid-cols-2"
                value={kind}
                onChange={setKind}
                options={[
                  { value: 'standard', title: 'Standard', icon: Layers, description: 'Applies to the server groups and servers you assign. Team Leads manage the sets of their groups.' },
                  {
                    value: 'baseline',
                    title: 'Baseline',
                    icon: Globe2,
                    description: 'Applies to every registered server. Use it for global guardrails and universally allowed sources.',
                    disabled: !perms.canManageSystem,
                    disabledReason: 'Only InfoSec Approvers and Super Admins manage baseline sets.',
                  },
                ]}
              />
            </div>
          </Card>

          <Card>
            <CardHeader title="Details" />
            <div className="grid gap-5 p-[var(--card-p)] sm:grid-cols-2">
              <Field label="Name" required error={touched || nameTaken ? errors.name : null} className="sm:col-span-2">
                <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="CI runners: source hosting" maxLength={120} data-autofocus />
              </Field>
              <Field label="Description" optional className="sm:col-span-2" hint="What the set is for and who relies on it. Reviewers read this.">
                <Textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={3} maxLength={2000} />
              </Field>
              <Field label="Owner team" optional hint="Responsible for recertification.">
                <Input value={owner} onChange={(e) => setOwner(e.target.value)} list="owner-teams" placeholder="DevOps & Release Engineering" />
              </Field>
              <datalist id="owner-teams">
                {ownerSuggestions.map((o) => (
                  <option key={o} value={o} />
                ))}
              </datalist>
              <Field label="Tags" optional>
                <TagInput value={tags} onChange={setTags} suggestions={tagSuggestions} max={20} validate={(t) => (t.length > 40 ? 'At most 40 characters.' : null)} placeholder="ci, containers…" />
              </Field>
            </div>
          </Card>

          <Card>
            <CardHeader
              title="Assignment"
              description={kind === 'baseline' ? 'Baseline sets apply to every registered server.' : 'Rules apply to servers in these groups and to the listed servers.'}
            />
            <div className="grid gap-5 p-[var(--card-p)] sm:grid-cols-2">
              {kind === 'baseline' ? (
                <Callout tone="violet" icon={Globe2} className="sm:col-span-2">
                  Every registered server and every source that belongs to a group is covered. Unknown sources stay default-deny.
                </Callout>
              ) : (
                <>
                  <Field
                    label="Server groups"
                    error={touched ? errors.assignment : null}
                    hint={perms.isTeamLead ? 'You can assign the groups you approve for.' : 'Dynamic groups follow server labels automatically.'}
                  >
                    <MultiSelect value={groups} onChange={setGroups} options={groupOptions} placeholder="Choose groups" searchPlaceholder="Search groups…" />
                  </Field>
                  <Field label="Individual servers" optional hint="For one-off exceptions; prefer groups.">
                    <MultiSelect value={servers} onChange={setServers} options={serverOptions} placeholder="Choose servers" searchPlaceholder="Search servers…" />
                  </Field>
                </>
              )}
            </div>
          </Card>

          <Card>
            <CardHeader title="Settings" />
            <div className="grid gap-5 p-[var(--card-p)] sm:grid-cols-3">
              <Field
                label="Priority"
                labelAside={<HelpTip content="Sets with a higher priority are evaluated first. BLOCK rules always win regardless of priority." />}
                hint="Higher runs first."
              >
                <Input type="number" value={priority} onChange={(e) => setPriority(Number(e.target.value) || 0)} />
              </Field>
              <Field
                label="Recertification interval"
                error={errors.interval}
                labelAside={<HelpTip content="Owners confirm the set is still needed after this many days. Overdue sets are flagged on the overview page." />}
              >
                <Input type="number" min={1} max={730} value={reviewDays} onChange={(e) => setReviewDays(Number(e.target.value) || 0)} trailing={<span className="text-[12px] text-fg-subtle">days</span>} />
              </Field>
              <div className="pt-6">
                <Switch checked={enabled} onChange={setEnabled} label="Enabled" description="Disabled sets are kept but not enforced." />
              </div>
            </div>
          </Card>

          <Card>
            <CardHeader title="Starting rules" description="You can add and edit rules in the draft afterwards." />
            <div className="space-y-4 p-[var(--card-p)]">
              <SegmentedControl<Start>
                aria-label="Starting rules"
                value={start}
                onChange={setStart}
                options={[
                  { value: 'empty', label: 'Start empty', icon: FilePlus2 },
                  { value: 'clone', label: 'Copy from a set', icon: CopyPlus },
                  ...(traceRule ? [{ value: 'trace' as Start, label: 'From traffic', icon: Sparkles }] : []),
                ]}
              />
              {start === 'clone' && (
                <Field label="Copy rules from" error={touched || blockedRules ? errors.clone : null}>
                  <Combobox
                    value={cloneFrom}
                    onChange={setCloneFrom}
                    placeholder="Choose a policy set"
                    options={state.policy_sets.map((s) => ({ value: s.id, label: s.name, description: `${s.kind}, ${(s.rules ?? []).length} rules`, group: s.kind.charAt(0).toUpperCase() + s.kind.slice(1) }))}
                  />
                </Field>
              )}
              {start === 'trace' && traceRule && errors.trace && <Callout tone="warning">{errors.trace}</Callout>}
              {rules.length > 0 && (
                <ul className="divide-y divide-border rounded-lg border border-border">
                  {rules.slice(0, 8).map((r, i) => (
                    <li key={i} className="flex items-center gap-3 px-3 py-2">
                      <RuleActionBadge action={r.action} />
                      <span className="min-w-0 flex-1 truncate text-[13px] text-fg">{r.name}</span>
                      <PatternText host={r.host_pattern} path={r.path_pattern} className="max-w-[45%]" />
                    </li>
                  ))}
                  {rules.length > 8 && <li className="px-3 py-2 text-[12.5px] text-fg-subtle">and {rules.length - 8} more</li>}
                </ul>
              )}
            </div>
          </Card>
        </div>

        <aside className="space-y-4 xl:sticky xl:top-20 xl:self-start">
          <Card padded>
            <h2 className="text-[14px] font-semibold text-fg">What happens next</h2>
            <ol className="mt-3 space-y-3 text-[13px] text-fg-muted">
              <li className="flex gap-2.5">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-accent-soft text-[11px] font-semibold text-accent">1</span>
                The set is created as a draft (version 0). Nothing is enforced yet.
              </li>
              <li className="flex gap-2.5">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-accent-soft text-[11px] font-semibold text-accent">2</span>
                Add or adjust rules and check the impact against recorded traffic.
              </li>
              <li className="flex gap-2.5">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-accent-soft text-[11px] font-semibold text-accent">3</span>
                {state.governance?.require_policy_review
                  ? 'Submit it for four-eyes review. A second approver publishes it.'
                  : 'Publish it. Every data-plane worker picks up the new version within seconds.'}
              </li>
            </ol>
            <div className="mt-5 flex flex-col gap-2">
              <Button type="submit" variant="primary" loading={busy} fullWidth>
                Create draft
              </Button>
              <Button onClick={() => navigate('/policies')} disabled={busy} fullWidth variant="ghost">
                Cancel
              </Button>
            </div>
            {touched && !valid && <p className="mt-3 text-[12.5px] text-danger">Fix the highlighted fields to continue.</p>}
          </Card>
        </aside>
      </form>
    </>
  );
};
