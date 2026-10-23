import React, { useState } from 'react';
import { Lock, Plus, RotateCcw, Save, Undo2 } from 'lucide-react';
import { api } from '../../../api';
import { useConsole, useConsoleState } from '../../../data/AppData';
import type { PolicySet, RuleInput } from '../../../types';
import {
  Button,
  ButtonLink,
  Callout,
  Card,
  CardHeader,
  DescriptionList,
  EmptyState,
  Field,
  HelpTip,
  Input,
  MultiSelect,
  PatternText,
  RelativeTime,
  Switch,
  TagInput,
  Textarea,
  useToast,
} from '../../../ui';
import { UserName } from '../../../components/common/EntityChips';
import { AssignmentChips, RuleActionBadge } from '../../../components/policy/PolicyBadges';
import { RuleDetailDrawer } from '../../../components/policy/RuleDetailDrawer';
import { RuleFormDrawer } from '../../../components/policy/RuleFormDrawer';
import { RuleRow, RulesTable } from '../../../components/policy/RulesTable';
import type { DraftEditor } from '../useDraftEditor';

export interface DraftTabProps {
  set: PolicySet;
  editor: DraftEditor;
  canManage: boolean;
  /** Reloads the detail + console state. */
  onSaved: () => Promise<void>;
}

/** Draft editor: rules (add / edit / duplicate / disable / delete) and set settings, saved with PUT /draft. */
export const DraftTab: React.FC<DraftTabProps> = ({ set, editor, canManage, onSaved }) => {
  const state = useConsoleState();
  const { perms } = useConsole();
  const toast = useToast();
  const [editing, setEditing] = useState<{ key: string | null; rule: RuleInput | null } | null>(null);
  const [viewing, setViewing] = useState<RuleInput | null>(null);
  const [saving, setSaving] = useState(false);
  // guardrail errors (Team Leads cannot disable / re-scope sets with enabled BLOCK rules) stay visible inline
  const [saveError, setSaveError] = useState<string | null>(null);
  const inReview = set.draft?.status === 'in_review';
  const readOnly = !canManage || inReview || set.kind === 'approvals';
  const meta = editor.meta;

  if (!meta) return null;

  const ruleRows: RuleRow[] = editor.rows.map((r) => ({ key: r.key, rule: r.rule, mark: editor.markOf(r.rule) }));
  const canEditRule = (row: RuleRow) => !readOnly && (perms.canEditBlockRules || row.rule.action !== 'BLOCK');

  const save = async () => {
    if (!editor.current) return;
    setSaving(true);
    setSaveError(null);
    try {
      await api.policySets.saveDraft(set.id, editor.current);
      editor.expectReload();
      await onSaved();
      toast.success('Draft saved', {
        description: state.governance?.require_policy_review ? 'Submit it for review when you are ready.' : 'Publish it to enforce the changes.',
      });
    } catch (err) {
      if (err instanceof Error && /guardrail/i.test(err.message)) setSaveError(err.message);
      toast.error(err, { title: 'Draft not saved' });
    } finally {
      setSaving(false);
    }
  };

  const removeRow = (row: RuleRow) => {
    const before = editor.rows;
    editor.setRows(before.filter((r) => r.key !== row.key));
    toast.info(`Removed "${row.rule.name}" from the draft`, {
      action: { label: 'Undo', onClick: () => editor.setRows(before) },
    });
  };

  const groupOptions = state.groups.map((g) => ({ value: g.id, label: g.name, color: g.color, description: g.id, disabled: !perms.canApproveFor([g.id]) }));
  const serverOptions = state.servers.map((s) => ({
    value: s.id,
    label: s.hostname,
    description: s.ip,
    disabled: !perms.canApproveFor(s.effective_group_ids ?? s.group_ids ?? []),
  }));

  return (
    <div className="space-y-6 pb-20">
      {saveError && (
        <Callout tone="danger" title="This change would withdraw a guardrail">
          {saveError}
          <span className="mt-1 block text-[12px]">Keep the set enabled and its scope, or ask InfoSec to make the change.</span>
        </Callout>
      )}
      {inReview && (
        <Callout
          tone="warning"
          icon={Lock}
          title="The draft is locked while it is in review"
          action={
            set.draft?.change_request_id && (
              <ButtonLink size="sm" to={`/changes/${encodeURIComponent(set.draft.change_request_id)}`}>
                Open change request
              </ButtonLink>
            )
          }
        >
          Withdraw the change request to edit it again.
        </Callout>
      )}
      {!inReview && !canManage && set.kind !== 'approvals' && (
        <Callout tone="neutral" title="Read only">
          {perms.isReadOnly ? 'Your role cannot edit policy sets.' : 'You can only edit sets assigned to the groups you approve for.'}
        </Callout>
      )}
      {!inReview && canManage && (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[12.5px] text-fg-muted">
          {set.draft ? (
            <span>
              Draft based on {set.draft.base_version ? `v${set.draft.base_version}` : 'an unpublished set'}, last saved by{' '}
              <UserName username={set.draft.updated_by} avatar={false} /> <RelativeTime value={set.draft.updated_at} />.
            </span>
          ) : (
            <span>No draft yet. You are editing a copy of the published version v{set.version}; saving creates the draft.</span>
          )}
        </div>
      )}

      <section aria-labelledby="draft-rules-h">
        <div className="mb-3 flex flex-wrap items-end justify-between gap-2">
          <div>
            <h2 id="draft-rules-h" className="text-[15px] font-semibold text-fg">
              Rules
            </h2>
            <p className="text-[12.5px] text-fg-muted">
              {readOnly ? 'Rules in the draft, as submitted.' : 'Rules apply to the servers the set is assigned to. Changes are local until you save the draft.'}
            </p>
          </div>
        </div>
        <RulesTable
          rows={ruleRows}
          showHits={false}
          onOpen={(row) => (canEditRule(row) ? setEditing({ key: row.key, rule: row.rule as RuleInput }) : setViewing(row.rule as RuleInput))}
          actions={
            readOnly
              ? undefined
              : {
                  canEdit: canEditRule,
                  lockedReason: 'BLOCK guardrails are managed by InfoSec.',
                  onEdit: (row) => (canEditRule(row) ? setEditing({ key: row.key, rule: row.rule as RuleInput }) : setViewing(row.rule as RuleInput)),
                  onDuplicate: (row) =>
                    editor.addRule({
                      ...(row.rule as RuleInput),
                      id: '',
                      name: `${row.rule.name} (copy)`,
                      methods: [...(row.rule.methods ?? [])],
                      companion_rules: [...(row.rule.companion_rules ?? [])],
                    }),
                  onToggle: (row) => editor.setRows(editor.rows.map((r) => (r.key === row.key ? { ...r, rule: { ...r.rule, enabled: !r.rule.enabled } } : r))),
                  onDelete: removeRow,
                }
          }
          toolbar={
            !readOnly && (
              <Button variant="primary" size="sm" icon={Plus} onClick={() => setEditing({ key: null, rule: null })}>
                Add rule
              </Button>
            )
          }
          empty={
            <EmptyState
              title="No rules in this draft"
              description={readOnly ? undefined : 'Add the first rule: a host and path pattern this set should allow or block.'}
              action={
                !readOnly && (
                  <Button variant="primary" icon={Plus} onClick={() => setEditing({ key: null, rule: null })}>
                    Add rule
                  </Button>
                )
              }
            />
          }
        />
        {editor.removed.length > 0 && (
          <div className="mt-3 rounded-lg border border-danger-border bg-danger-soft/60 px-4 py-3">
            <p className="text-[12.5px] font-medium text-fg">Removed in this draft ({editor.removed.length})</p>
            <ul className="mt-2 space-y-1.5">
              {editor.removed.map((r) => (
                <li key={r.id} className="flex flex-wrap items-center gap-2 text-[13px]">
                  <RuleActionBadge action={r.action} />
                  <span className="text-fg line-through decoration-fg-subtle">{r.name}</span>
                  <PatternText host={r.host_pattern} path={r.path_pattern} className="!inline max-w-[320px]" />
                  {!readOnly && (perms.canEditBlockRules || r.action !== 'BLOCK') && (
                    <Button size="xs" variant="ghost" icon={Undo2} onClick={() => editor.addRule({ ...r } as unknown as RuleInput)}>
                      Restore
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>

      <Card>
        <CardHeader title="Settings and assignment" description="Set-level fields are versioned together with the rules." />
        {readOnly ? (
          <div className="p-[var(--card-p)]">
            <DescriptionList
              columns={3}
              items={[
                { label: 'Name', value: meta.name },
                { label: 'Owner team', value: meta.owner_team || '—' },
                { label: 'Tags', value: meta.tags.length ? meta.tags.join(', ') : '—' },
                { label: 'Assigned to', value: <AssignmentChips kind={set.kind} groupIds={meta.group_ids} serverIds={meta.server_ids} max={6} />, full: true },
                { label: 'Priority', value: meta.priority },
                { label: 'Recertification interval', value: meta.review_interval_days ? `${meta.review_interval_days} days` : 'Off' },
                { label: 'Enabled', value: meta.enabled ? 'Yes' : 'No' },
                { label: 'Description', value: meta.description || '—', full: true },
              ]}
            />
          </div>
        ) : (
          <div className="grid gap-5 p-[var(--card-p)] md:grid-cols-2">
            <Field label="Name" required error={!meta.name.trim() ? 'Enter a name.' : null}>
              <Input value={meta.name} onChange={(e) => editor.setMeta({ name: e.target.value })} maxLength={120} />
            </Field>
            <Field label="Owner team" optional>
              <Input value={meta.owner_team} onChange={(e) => editor.setMeta({ owner_team: e.target.value })} maxLength={120} />
            </Field>
            <Field label="Description" optional className="md:col-span-2">
              <Textarea value={meta.description} onChange={(e) => editor.setMeta({ description: e.target.value })} rows={2} maxLength={2000} />
            </Field>
            {set.kind === 'standard' && (
              <>
                <Field label="Server groups" hint="Rules apply to every server in these groups.">
                  <MultiSelect value={meta.group_ids} onChange={(v) => editor.setMeta({ group_ids: v })} options={groupOptions} placeholder="Choose groups" />
                </Field>
                <Field label="Individual servers" optional>
                  <MultiSelect value={meta.server_ids} onChange={(v) => editor.setMeta({ server_ids: v })} options={serverOptions} placeholder="Choose servers" />
                </Field>
              </>
            )}
            {set.kind === 'baseline' && (
              <Callout tone="violet" className="md:col-span-2">
                Baseline sets apply to every registered server; they have no assignment.
              </Callout>
            )}
            <Field label="Tags" optional>
              <TagInput value={meta.tags} onChange={(v) => editor.setMeta({ tags: v })} max={20} />
            </Field>
            <div className="grid grid-cols-2 gap-4">
              <Field label="Priority" labelAside={<HelpTip content="Higher sets are evaluated first. BLOCK rules always win." />}>
                <Input type="number" value={meta.priority} onChange={(e) => editor.setMeta({ priority: Number(e.target.value) || 0 })} />
              </Field>
              <Field label="Recertify every" hint="0 turns recertification off.">
                <Input
                  type="number"
                  min={0}
                  max={730}
                  value={meta.review_interval_days}
                  onChange={(e) => editor.setMeta({ review_interval_days: Math.max(0, Number(e.target.value) || 0) })}
                  trailing={<span className="text-[12px] text-fg-subtle">days</span>}
                />
              </Field>
            </div>
            <Switch
              className="md:col-span-2"
              checked={meta.enabled}
              onChange={(v) => editor.setMeta({ enabled: v })}
              label="Enabled"
              description="A disabled set keeps its rules but nothing is enforced after publishing."
            />
          </div>
        )}
      </Card>

      {!readOnly && editor.dirty && (
        <div className="sticky bottom-4 z-20 flex flex-wrap items-center gap-3 rounded-lg border border-border-strong bg-surface px-4 py-3 shadow-pop animate-toast-in">
          <span className="h-2 w-2 rounded-full bg-warning-solid" aria-hidden />
          <span className="text-[13px] font-medium text-fg">Unsaved changes</span>
          <span className="hidden text-[12.5px] text-fg-muted sm:inline">They are not part of the draft until you save.</span>
          <div className="ml-auto flex gap-2">
            <Button size="sm" icon={RotateCcw} onClick={editor.reset} disabled={saving}>
              Discard
            </Button>
            <Button size="sm" variant="primary" icon={Save} onClick={save} loading={saving} disabled={!meta.name.trim()}>
              Save draft
            </Button>
          </div>
        </div>
      )}

      <RuleFormDrawer
        open={!!editing}
        rule={editing?.rule ?? null}
        setKind={set.kind}
        onClose={() => setEditing(null)}
        onSave={(rule) => {
          if (editing?.key) editor.setRows(editor.rows.map((r) => (r.key === editing.key ? { ...r, rule } : r)));
          else editor.addRule(rule);
          setEditing(null);
        }}
      />
      <RuleDetailDrawer rule={viewing} onClose={() => setViewing(null)} />
    </div>
  );
};
