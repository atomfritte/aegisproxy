import React, { useEffect, useMemo, useState } from 'react';
import { api } from '../../api';
import { useConsoleState } from '../../data/AppData';
import type { PackageRule, PackageRuleAction, PackageRuleTrigger } from '../../types';
import { Badge, Button, Callout, Drawer, Field, Input, MultiSelect, RadioCards, SegmentedControl, Select, Switch, TagInput, Textarea, useToast } from '../../ui';
import { ECOSYSTEM_META, ECOSYSTEMS, humanHours } from '../../components/packages/packageUtils';

interface Form {
  name: string;
  description: string;
  enabled: boolean;
  priority: string;
  ecosystems: string[];
  packages: string[];
  group_ids: string[];
  action: PackageRuleAction;
  trigger: PackageRuleTrigger;
  update_types: string[];
  min_age_hours: string;
  max_severity: string;
  max_risk: string;
  require_signature: boolean;
  require_provenance: boolean;
  require_sandbox: boolean;
  allow_install_scripts: boolean;
  licenses: string[];
  exclude_prerelease: boolean;
  exclude_deprecated: boolean;
}

function toForm(r?: PackageRule | null): Form {
  return {
    name: r?.name ?? '',
    description: r?.description ?? '',
    enabled: r?.enabled ?? true,
    priority: String(r?.priority ?? 100),
    ecosystems: r?.ecosystems ?? [],
    packages: r?.packages ?? ['*'],
    group_ids: r?.group_ids ?? ['*'],
    action: r?.action ?? 'auto_approve',
    trigger: r?.trigger ?? 'any',
    update_types: r?.update_types ?? [],
    min_age_hours: String(r?.min_age_hours ?? 72),
    max_severity: r?.max_severity ?? 'none',
    max_risk: r?.max_risk ?? 'low',
    require_signature: r?.require_signature ?? false,
    require_provenance: r?.require_provenance ?? false,
    require_sandbox: r?.require_sandbox ?? true,
    allow_install_scripts: r?.allow_install_scripts ?? false,
    licenses: r?.licenses ?? [],
    exclude_prerelease: r?.exclude_prerelease ?? true,
    exclude_deprecated: r?.exclude_deprecated ?? true,
  };
}

function toPayload(f: Form): Partial<PackageRule> {
  return {
    name: f.name.trim(),
    description: f.description.trim(),
    enabled: f.enabled,
    priority: Number(f.priority) || 0,
    ecosystems: f.ecosystems,
    packages: f.packages.length ? f.packages : ['*'],
    group_ids: f.group_ids.length ? f.group_ids : ['*'],
    action: f.action,
    trigger: f.trigger,
    update_types: f.trigger === 'updates' ? f.update_types : [],
    min_age_hours: Number(f.min_age_hours) || 0,
    max_severity: f.max_severity,
    max_risk: f.max_risk,
    require_signature: f.require_signature,
    require_provenance: f.require_provenance,
    require_sandbox: f.require_sandbox,
    allow_install_scripts: f.allow_install_scripts,
    licenses: f.licenses,
    exclude_prerelease: f.exclude_prerelease,
    exclude_deprecated: f.exclude_deprecated,
  };
}

/** Create / edit a package rule (cooldown, auto-approve, review or block). */
export const RuleFormDrawer: React.FC<{ open: boolean; rule: PackageRule | null; onClose: () => void; onSaved: () => void | Promise<void> }> = ({ open, rule, onClose, onSaved }) => {
  const state = useConsoleState();
  const toast = useToast();
  const [f, setF] = useState<Form>(() => toForm(rule));
  const [attempted, setAttempted] = useState(false);
  const [saving, setSaving] = useState(false);
  useEffect(() => {
    if (open) {
      setF(toForm(rule));
      setAttempted(false);
      setSaving(false);
    }
  }, [open, rule]);
  const set = (p: Partial<Form>) => setF((x) => ({ ...x, ...p }));

  const groupOptions = useMemo(
    () => [{ value: '*', label: 'All groups', description: 'Every client the ecosystem applies to' }, ...state.groups.map((g) => ({ value: g.id, label: g.name, description: g.environment || g.id, color: g.color }))],
    [state.groups]
  );

  const nameErr = attempted && !f.name.trim() ? 'A name is required.' : null;
  const ageNum = Number(f.min_age_hours);
  const ageErr = attempted && (!Number.isInteger(ageNum) || ageNum < 0) ? 'Enter a whole number of hours (0 or more).' : null;
  const isAuto = f.action === 'auto_approve';

  const save = async () => {
    setAttempted(true);
    if (!f.name.trim() || ageErr) return;
    setSaving(true);
    try {
      if (rule) await api.packages.rules.update(rule.id, toPayload(f));
      else await api.packages.rules.create(toPayload(f));
      await onSaved();
      toast.success(rule ? 'Rule saved' : 'Rule created');
      onClose();
    } catch (e) {
      toast.error(e, { title: rule ? 'The rule was not saved' : 'The rule was not created' });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Drawer
      open={open}
      onClose={onClose}
      width="lg"
      title={rule ? 'Edit rule' : 'New rule'}
      description="Rules are evaluated by priority; the first matching rule decides. No match means a package waits for human review."
      dismissible={!saving}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={saving}>Cancel</Button>
          <Button variant="primary" onClick={save} loading={saving}>{rule ? 'Save rule' : 'Create rule'}</Button>
        </>
      }
    >
      <div className="space-y-6">
        <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_120px]">
          <Field label="Name" required error={nameErr}>
            <Input value={f.name} onChange={(e) => set({ name: e.target.value })} placeholder="e.g. Auto-approve vetted npm scopes" data-autofocus />
          </Field>
          <Field label="Priority" hint="Lower first">
            <Input type="number" value={f.priority} onChange={(e) => set({ priority: e.target.value })} />
          </Field>
        </div>
        <Field label="Description" optional>
          <Textarea value={f.description} onChange={(e) => set({ description: e.target.value })} rows={2} />
        </Field>
        <Switch checked={f.enabled} onChange={(v) => set({ enabled: v })} label="Enabled" description="Disabled rules are skipped during evaluation." />

        <Field label="Action">
          {() => (
            <RadioCards<PackageRuleAction>
              aria-label="Rule action"
              value={f.action}
              onChange={(v) => set({ action: v })}
              options={[
                { value: 'auto_approve', title: 'Auto-approve', description: 'Approve without a human when every condition below holds.' },
                { value: 'review', title: 'Force review', description: 'Always send matching packages to a human reviewer.' },
                { value: 'block', title: 'Block', description: 'Reject matching packages outright.' },
              ]}
            />
          )}
        </Field>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Ecosystems" hint="Empty = all ecosystems">
            <MultiSelect value={f.ecosystems} onChange={(v) => set({ ecosystems: v })} options={ECOSYSTEMS.map((e) => ({ value: e, label: ECOSYSTEM_META[e].label }))} placeholder="All ecosystems" />
          </Field>
          <Field label="Group scope" hint="Groups the approvals this rule creates apply to">
            <MultiSelect value={f.group_ids} onChange={(v) => set({ group_ids: v })} options={groupOptions} placeholder="All groups" />
          </Field>
        </div>

        <Field label="Package name globs" hint={'e.g. "*", "@corp/*", "microsoft.extensions.*"'}>
          <TagInput value={f.packages} onChange={(v) => set({ packages: v })} placeholder="Add a glob and press Enter" mono suggestions={['*']} />
        </Field>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Trigger">
            {() => (
              <SegmentedControl<PackageRuleTrigger>
                aria-label="Trigger"
                value={f.trigger}
                onChange={(v) => set({ trigger: v })}
                options={[
                  { value: 'any', label: 'Any version' },
                  { value: 'updates', label: 'Updates only' },
                ]}
              />
            )}
          </Field>
          {f.trigger === 'updates' && (
            <Field label="Update types" hint="Empty = patch, minor and major">
              <MultiSelect
                value={f.update_types}
                onChange={(v) => set({ update_types: v })}
                options={[{ value: 'patch', label: 'Patch' }, { value: 'minor', label: 'Minor' }, { value: 'major', label: 'Major' }]}
                placeholder="All update types"
              />
            </Field>
          )}
        </div>

        {isAuto ? (
          <section className="space-y-4 rounded-lg border border-border bg-surface-2 p-4">
            <h3 className="text-[13px] font-semibold text-fg">Auto-approve conditions</h3>
            <p className="text-[12px] text-fg-muted">A version is approved only when <strong>all</strong> of these hold. Critical advisories and malware always fail.</p>
            <Field label="Cooldown (Karenz)" error={ageErr} hint={ageErr ? undefined : `A version must be public for at least this long — ${humanHours(ageNum)}.`} className="max-w-[260px]">
              <Input type="number" min={0} value={f.min_age_hours} onChange={(e) => set({ min_age_hours: e.target.value })} trailing={<span className="text-[12px] text-fg-subtle">hours</span>} />
            </Field>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Max advisory severity" hint="Highest tolerated advisory severity">
                <Select value={f.max_severity} onChange={(e) => set({ max_severity: e.target.value })} options={[{ value: 'none', label: 'None' }, { value: 'low', label: 'Low' }, { value: 'medium', label: 'Medium' }, { value: 'high', label: 'High' }]} />
              </Field>
              <Field label="Max overall risk" hint="Highest tolerated assessment">
                <Select value={f.max_risk} onChange={(e) => set({ max_risk: e.target.value })} options={[{ value: 'none', label: 'None' }, { value: 'info', label: 'Info' }, { value: 'low', label: 'Low' }, { value: 'medium', label: 'Medium' }, { value: 'high', label: 'High' }]} />
              </Field>
            </div>
            <Field label="Allowed licenses" hint="SPDX identifiers; empty = any license">
              <TagInput value={f.licenses} onChange={(v) => set({ licenses: v })} placeholder="e.g. MIT, Apache-2.0" mono suggestions={['MIT', 'Apache-2.0', 'BSD-3-Clause', 'ISC', 'MPL-2.0']} />
            </Field>
            <div className="space-y-3 border-t border-border pt-3">
              <Switch checked={f.require_signature} onChange={(v) => set({ require_signature: v })} label="Require a verified signature" />
              <Switch checked={f.require_provenance} onChange={(v) => set({ require_provenance: v })} label="Require verified provenance (Sigstore / SLSA)" />
              <Switch checked={f.require_sandbox} onChange={(v) => set({ require_sandbox: v })} label="Require a completed sandbox analysis" />
              <Switch checked={f.allow_install_scripts} onChange={(v) => set({ allow_install_scripts: v })} label="Allow install / build scripts" description="Off: packages with lifecycle or build hooks are held for review." />
              <Switch checked={f.exclude_prerelease} onChange={(v) => set({ exclude_prerelease: v })} label="Exclude prereleases" />
              <Switch checked={f.exclude_deprecated} onChange={(v) => set({ exclude_deprecated: v })} label="Exclude deprecated versions" />
            </div>
          </section>
        ) : (
          <Callout tone="neutral">
            <span className="flex flex-wrap items-center gap-1.5">
              The <Badge tone={f.action === 'block' ? 'danger' : 'warning'} size="sm">{f.action === 'block' ? 'block' : 'review'}</Badge> action ignores the cooldown and auto-approve checks.
            </span>
          </Callout>
        )}
      </div>
    </Drawer>
  );
};
