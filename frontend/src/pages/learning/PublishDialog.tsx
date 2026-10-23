import React, { useEffect, useMemo, useState } from 'react';
import { FilePlus2, FileEdit, Layers, Upload } from 'lucide-react';
import { api } from '../../api';
import { useConsole, useConsoleState } from '../../data/AppData';
import { useLookups } from '../../data/lookups';
import { pluralize } from '../../lib/format';
import { navigate } from '../../lib/router';
import type { CompiledRuleCandidate, LearningSession } from '../../types';
import { Badge, Button, Callout, Combobox, Field, Input, Modal, MultiSelect, RadioCards, useToast } from '../../ui';

type Target = 'existing' | 'new';

/** Session name shortened at a word boundary (rule names become "<prefix>: host/path"). */
function shortPrefix(name: string): string {
  const n = name.replace(/^Learning Session:\s*/i, '').trim();
  if (n.length <= 32) return n || 'Learned';
  const cut = n.slice(0, 32);
  const i = cut.lastIndexOf(' ');
  return (i > 12 ? cut.slice(0, i) : cut).replace(/[\s+&,:;/-]+$/, '');
}
type Mode = 'publish' | 'draft';

/** Publish selected candidates into an existing standard set or a new set, now or as a draft for review. */
export const PublishDialog: React.FC<{ open: boolean; onClose: () => void; session: LearningSession; candidates: CompiledRuleCandidate[]; onPublished: () => void }> = ({
  open,
  onClose,
  session,
  candidates,
  onPublished,
}) => {
  const state = useConsoleState();
  const { perms, refresh } = useConsole();
  const { groupName } = useLookups();
  const toast = useToast();
  const requireReview = !!state.governance?.require_policy_review;
  const selected = candidates.filter((c) => c.selected);

  const sets = useMemo(
    () => state.policy_sets.filter((p) => p.kind === 'standard' && perms.canManageSet(p, state.servers)).sort((a, b) => a.name.localeCompare(b.name)),
    [state.policy_sets, state.servers, perms]
  );
  const suggested = useMemo(
    () => sets.find((p) => p.draft?.status !== 'in_review' && (p.group_ids ?? []).some((g) => (session.group_ids ?? []).includes(g)))?.id ?? '',
    [sets, session.group_ids]
  );

  const [prefix, setPrefix] = useState('');
  const [target, setTarget] = useState<Target>('new');
  const [setId, setSetId] = useState('');
  const [newName, setNewName] = useState('');
  const [groups, setGroups] = useState<string[]>([]);
  const [servers, setServers] = useState<string[]>([]);
  const [mode, setMode] = useState<Mode>(requireReview ? 'draft' : 'publish');
  const [busy, setBusy] = useState(false);
  const [tried, setTried] = useState(false);

  useEffect(() => {
    if (!open) return;
    setPrefix(shortPrefix(session.name));
    setTarget(sets.length ? 'existing' : 'new');
    setSetId(suggested);
    setNewName(`${session.name.slice(0, 80)}`);
    setGroups([...(session.group_ids ?? [])]);
    setServers([]);
    setMode(requireReview ? 'draft' : 'publish');
    setTried(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const chosen = sets.find((p) => p.id === setId);
  const locked = chosen?.draft?.status === 'in_review';
  const errors = {
    prefix: !prefix.trim() ? 'Enter a prefix for the rule names.' : prefix.length > 80 ? 'At most 80 characters.' : null,
    set: target === 'existing' ? (!setId ? 'Choose a policy set.' : locked ? 'This set is locked while a change request is in review.' : null) : null,
    name: target === 'new' && !newName.trim() ? 'Name the new policy set.' : null,
    scope: target === 'new' && groups.length + servers.length === 0 ? 'Assign the set to at least one group or server.' : null,
  };
  const invalid = Object.values(errors).some(Boolean);

  const submit = async () => {
    setTried(true);
    if (invalid || selected.length === 0) return;
    setBusy(true);
    try {
      const res = await api.sessions.publish(session.id, {
        candidates,
        rule_prefix: prefix.trim(),
        ...(target === 'existing' ? { policy_set_id: setId } : { new_set_name: newName.trim(), target_group_ids: groups, target_server_ids: servers }),
        publish: mode === 'publish',
      });
      await refresh();
      const to = `/policies/${encodeURIComponent(res.policy_set.id)}${res.published ? '' : '/draft'}`;
      if (res.published) toast.success(`Published ${pluralize(res.published_count, 'rule')} to ${res.policy_set.name}`, { description: `Version v${res.policy_set.version} is enforced within seconds.`, action: { label: 'Open policy set', onClick: () => navigate(to) } });
      else
        toast.success(`Saved ${pluralize(res.published_count, 'rule')} as a draft of ${res.policy_set.name}`, {
          description: requireReview ? 'Submit the draft for four-eyes review to publish it.' : 'Review the draft and publish it.',
          action: { label: 'Open draft', onClick: () => navigate(to) },
        });
      onPublished();
      onClose();
    } catch (err) {
      toast.error(err, { title: 'The rules were not published' });
    } finally {
      setBusy(false);
    }
  };

  const groupOptions = state.groups.map((g) => ({ value: g.id, label: g.name, color: g.color, disabled: !perms.canApproveFor([g.id]) && !groups.includes(g.id), description: perms.canApproveFor([g.id]) ? g.id : 'Outside your groups' }));
  const serverOptions = state.servers.map((s) => ({ value: s.id, label: s.hostname, description: s.ip || s.id }));

  return (
    <Modal
      open={open}
      onClose={onClose}
      dismissible={!busy}
      size="lg"
      title={`Publish ${pluralize(selected.length, 'rule')}`}
      description="Selected candidates become ALLOW rules with a source link to this learning session."
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" icon={mode === 'publish' ? Upload : FileEdit} onClick={submit} loading={busy} disabled={selected.length === 0 || (tried && invalid)}>
            {mode === 'publish' ? 'Publish now' : 'Save as draft'}
          </Button>
        </>
      }
    >
      <form
        className="space-y-5"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <Field label="Rule name prefix" required error={tried ? errors.prefix : null} hint={`Rules are named “${prefix.trim() || 'Prefix'}: host/path”.`}>
          <Input value={prefix} onChange={(e) => setPrefix(e.target.value)} maxLength={80} data-autofocus />
        </Field>

        <Field label="Target">
          {() => (
            <RadioCards<Target>
              aria-label="Target"
              value={target}
              onChange={setTarget}
              className="sm:grid-cols-2"
              options={[
                {
                  value: 'existing',
                  title: 'Existing policy set',
                  description: 'Add the rules to the draft of a standard set you manage.',
                  icon: Layers,
                  disabled: sets.length === 0,
                  disabledReason: 'You do not manage any standard policy set.',
                },
                { value: 'new', title: 'New policy set', description: 'Create a standard set assigned to groups or servers.', icon: FilePlus2 },
              ]}
            />
          )}
        </Field>

        {target === 'existing' ? (
          <Field label="Policy set" required error={tried || locked ? errors.set : null}>
            {({ id }) => (
              <Combobox
                id={id}
                value={setId}
                onChange={setSetId}
                placeholder="Choose a policy set"
                searchPlaceholder="Search policy sets…"
                options={sets.map((p) => ({
                  value: p.id,
                  label: p.name,
                  description: `${p.version ? `v${p.version}` : 'unpublished'} · ${(p.group_ids ?? []).map(groupName).join(', ') || 'no group'}${p.draft ? (p.draft.status === 'in_review' ? ' · in review' : ' · has a draft') : ''}`,
                  disabled: p.draft?.status === 'in_review',
                }))}
              />
            )}
          </Field>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Set name" required error={tried ? errors.name : null} className="sm:col-span-2">
              <Input value={newName} onChange={(e) => setNewName(e.target.value)} maxLength={120} />
            </Field>
            <Field label="Target groups" error={tried ? errors.scope : null} hint="Defaults to the reference server's groups.">
              <MultiSelect value={groups} onChange={setGroups} options={groupOptions} placeholder="No group" />
            </Field>
            <Field label="Target servers" optional>
              <MultiSelect value={servers} onChange={setServers} options={serverOptions} placeholder="No individual server" searchPlaceholder="Search servers…" />
            </Field>
          </div>
        )}

        {target === 'existing' && chosen?.draft?.status === 'editing' && (
          <Callout tone="warning" title={`${chosen.name} already has a draft`}>
            The rules are appended to it{chosen.draft.updated_by ? ` (last edited by ${chosen.draft.updated_by})` : ''}. Publishing now publishes the whole draft, including those changes.
          </Callout>
        )}

        <Field label="Publishing">
          {() => (
            <RadioCards<Mode>
              aria-label="Publishing"
              value={mode}
              onChange={setMode}
              className="sm:grid-cols-2"
              options={[
                {
                  value: 'publish',
                  title: 'Publish now',
                  description: 'A new version is enforced within seconds.',
                  icon: Upload,
                  disabled: requireReview,
                  disabledReason: 'Four-eyes review is required (governance): save a draft and submit it for review.',
                },
                { value: 'draft', title: 'Save as draft for review', description: 'Review the impact and publish or submit the draft later.', icon: FileEdit },
              ]}
            />
          )}
        </Field>

        <div className="rounded-lg border border-border bg-surface-2 p-3 text-[12.5px] text-fg-muted">
          <span className="font-medium text-fg">{pluralize(selected.length, 'rule')}</span> from {session.server_hostname}:{' '}
          {selected.slice(0, 4).map((c, i) => (
            <React.Fragment key={c.id}>
              {i > 0 && ', '}
              <span className="font-mono text-[11.5px] text-fg">
                {c.host_pattern}
                {c.path_pattern !== '/**' ? c.path_pattern : ''}
              </span>
            </React.Fragment>
          ))}
          {selected.length > 4 && ` and ${selected.length - 4} more`}
          {requireReview && (
            <Badge tone="warning" className="ml-2">
              review required
            </Badge>
          )}
        </div>
        <button type="submit" hidden />
      </form>
    </Modal>
  );
};
