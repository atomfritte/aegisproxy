import React, { useEffect, useMemo, useState } from 'react';
import { Lightbulb, ShieldCheck, ShieldX } from 'lucide-react';
import type { RuleInput } from '../../types';
import { cn } from '../../lib/cn';
import { usePermissions } from '../../data/AppData';
import { Button, Callout, Drawer, Field, HelpTip, Input, PatternText, SegmentedControl, Switch, TagInput, Textarea } from '../../ui';
import { describeRule, HTTP_METHODS, PATTERN_EXAMPLES, validateCompanion, validateRule } from './policyUtils';

function toLocalInput(iso?: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (!Number.isFinite(d.getTime())) return '';
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export interface RuleFormDrawerProps {
  open: boolean;
  /** Rule to edit; `null` = new rule. */
  rule: RuleInput | null;
  /** Kind of the set (baseline sets usually hold BLOCK guardrails). */
  setKind: string;
  onClose: () => void;
  onSave: (rule: RuleInput) => void;
}

/** Add / edit one rule of a draft (local only — the draft is saved with "Save draft"). */
export const RuleFormDrawer: React.FC<RuleFormDrawerProps> = ({ open, rule, setKind, onClose, onSave }) => {
  const perms = usePermissions();
  const [r, setR] = useState<RuleInput>(rule ?? blank(setKind));
  const [touched, setTouched] = useState(false);

  useEffect(() => {
    if (open) {
      setR(rule ? { ...rule, methods: [...(rule.methods ?? ['GET', 'HEAD'])], companion_rules: [...(rule.companion_rules ?? [])] } : blank(setKind));
      setTouched(false);
    }
  }, [open, rule, setKind]);

  const errors = useMemo(() => validateRule(r, { teamLead: perms.isTeamLead, superAdmin: perms.isSuperAdmin }), [r, perms]);
  const show = (k: keyof typeof errors) => (touched || (k === 'host_pattern' ? r.host_pattern.length > 3 : false) ? errors[k] : undefined);
  const valid = Object.keys(errors).length === 0;
  const anyMethod = (r.methods ?? []).includes('*');
  const blockLocked = !perms.canEditBlockRules && rule?.action === 'BLOCK';

  const submit = () => {
    setTouched(true);
    if (!valid || blockLocked) return;
    const orig = rule;
    const comps = (r.companion_rules ?? []).map((c) => c.trim()).filter(Boolean);
    onSave({
      ...r,
      name: r.name.trim(),
      description: (r.description || '').trim(),
      host_pattern: r.host_pattern.trim().toLowerCase(),
      path_pattern: r.path_pattern.trim() || '/**',
      // keep null vs [] of untouched arrays so the server does not report a modification
      companion_rules: comps.length === 0 && orig && orig.companion_rules === null ? (null as unknown as string[]) : comps,
    });
  };

  return (
    <Drawer
      open={open}
      onClose={onClose}
      width="lg"
      title={rule ? 'Edit rule' : 'Add rule'}
      description="Rules inherit the assignment of their policy set. Changes stay in the draft until you save it."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} disabled={blockLocked}>
            {rule ? 'Apply changes' : 'Add rule'}
          </Button>
        </>
      }
    >
      <form
        className="space-y-6"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        {blockLocked && <Callout tone="warning">This is a BLOCK guardrail. Only InfoSec Approvers and Super Admins can change it.</Callout>}

        <div className="grid gap-5 sm:grid-cols-[1fr_auto]">
          <Field label="Name" required error={show('name')}>
            <Input value={r.name} onChange={(e) => setR({ ...r, name: e.target.value })} placeholder="GitHub: acme organisation" data-autofocus disabled={blockLocked} />
          </Field>
          <Field label="Action" error={errors.action}>
            {({ id }) => (
              <SegmentedControl
                aria-label="Action"
                value={r.action}
                onChange={(v) => setR({ ...r, action: v })}
                options={[
                  { value: 'ALLOW', label: 'Allow', icon: ShieldCheck },
                  {
                    value: 'BLOCK',
                    label: 'Block',
                    icon: ShieldX,
                    disabled: !perms.canEditBlockRules,
                    title: perms.canEditBlockRules ? undefined : 'Only InfoSec Approvers and Super Admins create BLOCK rules',
                  },
                ]}
                className="h-[var(--control-h)] items-center"
                key={id}
              />
            )}
          </Field>
        </div>

        <Field label="Description" optional>
          <Textarea value={r.description} onChange={(e) => setR({ ...r, description: e.target.value })} rows={2} placeholder="Why is this destination needed? Ticket or change number." disabled={blockLocked} />
        </Field>

        <section className="rounded-lg border border-border bg-surface-2 p-4">
          <h3 className="mb-3 text-[13px] font-semibold text-fg">Destination</h3>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field
              label="Host pattern"
              required
              error={show('host_pattern')}
              hint="github.com, *.ubuntu.com or an IP address"
              labelAside={<HelpTip content="A leading *. matches every subdomain. Team Leads cannot use catch-all or top-level wildcards (*.com)." />}
            >
              <Input mono value={r.host_pattern} onChange={(e) => setR({ ...r, host_pattern: e.target.value })} placeholder="github.com" spellCheck={false} autoCapitalize="off" disabled={blockLocked} />
            </Field>
            <Field
              label="Path pattern"
              error={show('path_pattern')}
              hint="/acme/** prefix with sub-paths, /simple/* one level"
              labelAside={<HelpTip content="** matches any number of path segments, * exactly one. Leave /** to match the whole host." />}
            >
              <Input mono value={r.path_pattern} onChange={(e) => setR({ ...r, path_pattern: e.target.value })} placeholder="/**" spellCheck={false} autoCapitalize="off" disabled={blockLocked} />
            </Field>
          </div>
          <div className="mt-4 rounded-md border border-dashed border-border-strong bg-surface px-3 py-2.5">
            <PatternText host={r.host_pattern || 'host'} path={r.path_pattern || '/**'} wrap />
            <p className="mt-1 text-[12.5px] text-fg-muted">{describeRule(r)}</p>
          </div>
          <div className="mt-4">
            <p className="mb-2 flex items-center gap-1.5 text-[12px] font-medium text-fg-muted">
              <Lightbulb className="h-3.5 w-3.5" aria-hidden />
              Examples
            </p>
            <div className="flex flex-wrap gap-1.5">
              {PATTERN_EXAMPLES.filter((x) => perms.canEditBlockRules || x.path !== '/**').map((x) => (
                <button
                  key={x.host + x.path}
                  type="button"
                  disabled={blockLocked}
                  onClick={() =>
                    setR({
                      ...r,
                      host_pattern: x.host,
                      path_pattern: x.path,
                      companion_rules: x.companions ? [...x.companions] : r.companion_rules,
                      follow_redirects: x.follow ?? r.follow_redirects,
                      name: r.name || x.label,
                    })
                  }
                  className="rounded-md border border-border bg-surface px-2 py-1 text-left transition-colors hover:border-accent-border hover:bg-accent-soft disabled:opacity-50"
                >
                  <span className="block font-mono text-[11.5px] text-fg">
                    {x.host}
                    <span className="text-fg-muted">{x.path}</span>
                  </span>
                  <span className="block text-[11px] text-fg-subtle">{x.label}</span>
                </button>
              ))}
            </div>
          </div>
        </section>

        <Field label="Methods" error={show('methods')} hint="Least privilege: GET and HEAD cover downloads and package mirrors.">
          {() => (
            <div className="flex flex-wrap gap-1.5" role="group" aria-label="HTTP methods">
              <button
                type="button"
                aria-pressed={anyMethod}
                disabled={blockLocked}
                onClick={() => setR({ ...r, methods: anyMethod ? ['GET', 'HEAD'] : ['*'] })}
                className={cn(
                  'h-7 rounded-md border px-2.5 text-[12px] font-medium transition-colors',
                  anyMethod ? 'border-accent bg-accent-soft text-accent' : 'border-border-strong text-fg-muted hover:bg-surface-3'
                )}
              >
                Any
              </button>
              {HTTP_METHODS.map((m) => {
                const on = !anyMethod && (r.methods ?? []).includes(m);
                return (
                  <button
                    key={m}
                    type="button"
                    aria-pressed={on}
                    disabled={blockLocked}
                    onClick={() => {
                      const cur = anyMethod ? [] : r.methods ?? [];
                      setR({ ...r, methods: on ? cur.filter((x) => x !== m) : [...cur, m] });
                    }}
                    className={cn(
                      'h-7 rounded-md border px-2.5 font-mono text-[11.5px] font-medium transition-colors',
                      on ? 'border-accent bg-accent-soft text-accent' : 'border-border-strong text-fg-muted hover:bg-surface-3'
                    )}
                  >
                    {m}
                  </button>
                );
              })}
            </div>
          )}
        </Field>

        <Field
          label="Companion rules"
          optional
          error={touched ? errors.companion_rules : undefined}
          hint="Extra host/path patterns that belong to the same purpose, e.g. codeload.github.com/acme/**"
        >
          <TagInput
            mono
            value={r.companion_rules ?? []}
            onChange={(v) => setR({ ...r, companion_rules: v })}
            validate={validateCompanion}
            placeholder="host/path, press Enter"
            max={20}
            disabled={blockLocked}
          />
        </Field>

        <div className="grid gap-5 sm:grid-cols-2">
          <Switch
            checked={r.follow_redirects}
            onChange={(v) => setR({ ...r, follow_redirects: v })}
            disabled={blockLocked}
            label="Follow redirects"
            description="Allows the exact object a matching response redirects to (for example release assets on a CDN) for two minutes."
          />
          <Switch checked={r.enabled} onChange={(v) => setR({ ...r, enabled: v })} disabled={blockLocked} label="Enabled" description="Disabled rules stay in the set but are not enforced." />
        </div>

        <Field label="Expires" optional error={touched ? errors.expires_at : undefined} hint="Temporary rules are ignored by the engine after this time.">
          <Input
            type="datetime-local"
            value={toLocalInput(r.expires_at)}
            onChange={(e) => {
              const v = e.target.value;
              const d = v ? new Date(v) : null;
              setR({ ...r, expires_at: d && Number.isFinite(d.getTime()) ? d.toISOString() : undefined });
            }}
            disabled={blockLocked}
            className="sm:max-w-[260px]"
          />
        </Field>
        <button type="submit" hidden />
      </form>
    </Drawer>
  );
};

function blank(kind: string): RuleInput {
  return {
    id: '',
    name: '',
    description: '',
    action: kind === 'baseline' ? 'BLOCK' : 'ALLOW',
    host_pattern: '',
    path_pattern: '/**',
    methods: kind === 'baseline' ? ['*'] : ['GET', 'HEAD'],
    follow_redirects: false,
    companion_rules: [],
    enabled: true,
  };
}
