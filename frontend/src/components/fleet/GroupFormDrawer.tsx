import React, { useEffect, useId, useMemo, useState } from 'react';
import { Boxes, KeyRound, Lock, Network, Tag } from 'lucide-react';
import { api } from '../../api';
import { useAction, useConsoleState } from '../../data/AppData';
import { navigate } from '../../lib/router';
import type { ServerGroup } from '../../types';
import { Button, Callout, Drawer, Field, Input, Select, Switch, TagInput, Textarea } from '../../ui';
import { ColorPicker } from './ColorPicker';
import { GroupTile, ServerHealthChip } from './FleetChips';
import { cidrContains, ENVIRONMENTS, GROUP_COLORS, labelsMatch, staticGroups, validateCIDR, validateGroupId, validateHexColor } from './fleetUtils';
import { LabelSelectorEditor, rowsToSelector, selectorErrors, SelectorRow, selectorToRows } from './LabelSelectorEditor';

interface FormState {
  id: string;
  name: string;
  description: string;
  environment: string;
  owner_team: string;
  color: string;
  cidrs: string[];
  strict_isolation: boolean;
  require_proxy_token: boolean;
  selector: SelectorRow[];
  block_page_template_id: string;
}

// default colors for new groups (red/pink are left for groups that deserve attention)
const CALM_COLORS = GROUP_COLORS.filter((c) => c !== '#DC2626' && c !== '#BE185D');

function slug(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 56);
}

function toForm(g?: ServerGroup | null, colorSeed = 0): FormState {
  return {
    id: g?.id ?? '',
    name: g?.name ?? '',
    description: g?.description ?? '',
    environment: g?.environment ?? '',
    owner_team: g?.owner_team ?? '',
    color: g?.color || CALM_COLORS[colorSeed % CALM_COLORS.length],
    cidrs: [...(g?.cidrs ?? [])],
    strict_isolation: !!g?.strict_isolation,
    require_proxy_token: !!g?.require_proxy_token,
    selector: selectorToRows(g?.match_labels),
    block_page_template_id: g?.block_page_template_id ?? '',
  };
}

/** Create / edit a server group: CIDRs, label selector with live member preview, block page. */
export const GroupFormDrawer: React.FC<{ open: boolean; onClose: () => void; group?: ServerGroup | null }> = ({ open, onClose, group }) => {
  const state = useConsoleState();
  const { run, pending } = useAction();
  const editing = !!group;
  const [f, setF] = useState<FormState>(() => toForm(group, state.groups.length));
  const [idEdited, setIdEdited] = useState(false);
  const [touched, setTouched] = useState(false);
  const uid = useId();

  useEffect(() => {
    if (open) {
      setF(toForm(group, state.groups.length));
      setIdEdited(false);
      setTouched(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const set = <K extends keyof FormState>(k: K, v: FormState[K]) => setF((p) => ({ ...p, [k]: v }));
  const selector = useMemo(() => rowsToSelector(f.selector), [f.selector]);
  const selErrs = selectorErrors(f.selector);

  const errors = {
    name: !f.name.trim() ? 'Enter a name.' : null,
    id: editing ? null : validateGroupId(f.id) || (state.groups.some((g) => g.id === f.id.trim().toLowerCase()) ? 'A group with this id already exists.' : null),
    color: validateHexColor(f.color),
    selector: selErrs.some(Boolean) ? 'Fix the selector conditions.' : null,
    cidrs: f.require_proxy_token && f.cidrs.length > 0 ? 'Remove the CIDR ranges: a group that requires a proxy token cannot identify sources by address.' : null,
  };
  const blocking = Object.values(errors).some(Boolean);
  const show = (e: string | null) => (touched ? e : null);

  const preview = useMemo(() => {
    const matched = Object.keys(selector).length ? state.servers.filter((s) => labelsMatch(s.labels, selector)) : [];
    const statics = editing ? state.servers.filter((s) => staticGroups(s).includes(group!.id)) : [];
    const byCidr = f.cidrs.length ? state.servers.filter((s) => s.ip && f.cidrs.some((c) => cidrContains(c, s.ip))) : [];
    const withoutToken = [...new Map([...statics, ...matched].filter((s) => !s.has_proxy_token).map((s) => [s.id, s])).values()];
    return { matched, statics, byCidr, withoutToken };
  }, [selector, state.servers, editing, group, f.cidrs]);

  const templates = state.block_pages ?? [];
  const def = templates.find((t) => t.is_default);

  const save = async () => {
    setTouched(true);
    if (blocking) return;
    const body: Partial<ServerGroup> & { id: string; name: string } = {
      ...(group ?? {}),
      id: editing ? group!.id : f.id.trim().toLowerCase(),
      name: f.name.trim(),
      description: f.description.trim(),
      environment: f.environment.trim(),
      owner_team: f.owner_team.trim(),
      color: f.color.trim().toUpperCase(),
      cidrs: f.cidrs,
      strict_isolation: f.strict_isolation,
      require_proxy_token: f.require_proxy_token,
      match_labels: selector,
      block_page_template_id: f.block_page_template_id,
      server_count: group?.server_count ?? 0,
    };
    const res = await run(() => api.groups.upsert(body), {
      key: 'save',
      success: (g) => (editing ? `Saved ${g.name}` : `Created group ${g.name}`),
      errorTitle: editing ? 'The group was not saved' : 'The group was not created',
    });
    if (!res) return;
    onClose();
    if (!editing) navigate(`/groups/${encodeURIComponent(res.id)}`);
  };

  return (
    <Drawer
      open={open}
      onClose={onClose}
      dismissible={pending !== 'save'}
      width="lg"
      title={editing ? `Edit ${group!.name}` : 'New group'}
      titleAside={<GroupTile group={{ color: validateHexColor(f.color) ? '#64748B' : f.color, name: f.name || 'New group' }} size="sm" />}
      description="Groups scope policy sets, approvals, Team Lead permissions and block pages. Servers join statically, by CIDR or by label selector."
      footer={
        <>
          <Button onClick={onClose} disabled={pending === 'save'}>
            Cancel
          </Button>
          <Button variant="primary" onClick={save} loading={pending === 'save'} disabled={touched && blocking}>
            {editing ? 'Save changes' : 'Create group'}
          </Button>
        </>
      }
    >
      <form
        className="space-y-7"
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          save();
        }}
      >
        <section className="space-y-4">
          <SectionTitle icon={Boxes}>Group</SectionTitle>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Name" required error={show(errors.name)}>
              <Input
                value={f.name}
                data-autofocus
                onChange={(e) => {
                  const name = e.target.value;
                  setF((p) => ({ ...p, name, id: !editing && !idEdited ? (slug(name) ? `grp-${slug(name)}` : '') : p.id }));
                }}
                placeholder="Payments platform"
              />
            </Field>
            <Field label="Group id" required={!editing} hint={editing ? 'The id cannot be changed.' : 'Used in the API, CSV imports and policy assignments.'} error={show(errors.id)}>
              <Input
                value={f.id}
                mono
                disabled={editing}
                onChange={(e) => {
                  setIdEdited(true);
                  set('id', e.target.value);
                }}
                placeholder="grp-payments"
                autoComplete="off"
              />
            </Field>
            <Field label="Description" optional className="sm:col-span-2">
              <Textarea value={f.description} onChange={(e) => set('description', e.target.value)} rows={2} placeholder="Which servers belong here and why" />
            </Field>
            <Field label="Environment" optional>
              <Input value={f.environment} onChange={(e) => set('environment', e.target.value)} list={`${uid}-env`} placeholder="prod" autoComplete="off" />
            </Field>
            <Field label="Owner team" optional>
              <Input value={f.owner_team} onChange={(e) => set('owner_team', e.target.value)} list={`${uid}-teams`} placeholder="Payments Platform" autoComplete="off" />
            </Field>
            <Field label="Color" className="sm:col-span-2" error={show(errors.color)}>
              {({ id }) => <ColorPicker id={id} value={f.color} onChange={(v) => set('color', v)} />}
            </Field>
          </div>
          <datalist id={`${uid}-env`}>
            {[...new Set([...ENVIRONMENTS, ...state.groups.map((g) => g.environment).filter(Boolean)])].map((e) => (
              <option key={e} value={e} />
            ))}
          </datalist>
          <datalist id={`${uid}-teams`}>
            {[...new Set(state.groups.map((g) => g.owner_team).filter(Boolean))].sort().map((t) => (
              <option key={t} value={t} />
            ))}
          </datalist>
        </section>

        <section className="space-y-4">
          <SectionTitle icon={Network}>Network</SectionTitle>
          <Field
            label="CIDR ranges"
            optional
            error={show(errors.cidrs)}
            hint="Unregistered sources in these ranges are attributed to the group. Registered servers join through static membership or labels."
          >
            <TagInput
              value={f.cidrs}
              onChange={(v) => set('cidrs', v)}
              validate={validateCIDR}
              mono
              placeholder="10.20.0.0/16, then Enter"
            />
          </Field>
          {preview.byCidr.length > 0 && (
            <p className="-mt-2 text-[12px] text-fg-subtle">
              {preview.byCidr.length} registered server{preview.byCidr.length === 1 ? '' : 's'} have an IP in these ranges.
            </p>
          )}
          <div className="rounded-lg border border-border p-3.5">
            <Switch
              checked={f.strict_isolation}
              onChange={(v) => set('strict_isolation', v)}
              label={
                <span className="inline-flex items-center gap-1.5">
                  <Lock className="h-3.5 w-3.5 text-danger" aria-hidden />
                  Strict isolation (zero-internet tier)
                </span>
              }
              description="For zero-internet tiers: global TLS exceptions do not apply (only exceptions that name the group or server), learning sessions in record & allow mode as well as learning-session access requests are refused, and temporary grants (learning sessions, redirect objects) never open anything for members."
            />
          </div>
          <div className="rounded-lg border border-border p-3.5">
            <Switch
              checked={f.require_proxy_token}
              onChange={(v) => set('require_proxy_token', v)}
              label={
                <span className="inline-flex items-center gap-1.5">
                  <KeyRound className="h-3.5 w-3.5 text-fg-subtle" aria-hidden />
                  Require proxy token
                </span>
              }
              description="Members are identified only by their proxy token. A request from a member's IP address without a token is treated as unregistered (default deny); a proxy user name alone or an invalid token is refused with HTTP 407. Use it for servers behind shared NAT addresses."
            />
            {f.require_proxy_token && preview.withoutToken.length > 0 && (
              <p className="mt-2 text-[12px] text-warning">
                {preview.withoutToken.length} member{preview.withoutToken.length === 1 ? ' has' : 's have'} no proxy token yet (
                {preview.withoutToken
                  .slice(0, 3)
                  .map((s) => s.hostname)
                  .join(', ')}
                {preview.withoutToken.length > 3 ? ', …' : ''}) and will lose access until one is issued (Servers → Onboard).
              </p>
            )}
          </div>
        </section>

        <section className="space-y-4">
          <SectionTitle icon={Tag}>Dynamic membership</SectionTitle>
          <Field label="Label selector" optional hint="Every registered server whose labels match all conditions becomes a member automatically. Leave a value empty or use * to match any value.">
            {() => <LabelSelectorEditor rows={f.selector} onChange={(rows) => set('selector', rows)} servers={state.servers} />}
          </Field>
          <div className="rounded-lg border border-dashed border-border-strong bg-surface-2 p-3.5" aria-live="polite">
            <p className="text-[12.5px] font-medium text-fg">
              {Object.keys(selector).length === 0
                ? 'No selector'
                : `${preview.matched.length} of ${state.servers.length} registered servers match`}
              {editing && preview.statics.length > 0 && <span className="font-normal text-fg-subtle"> · {preview.statics.length} static members</span>}
            </p>
            {preview.matched.length > 0 && (
              <ul className="mt-2 divide-y divide-border rounded-md border border-border bg-surface">
                {preview.matched.slice(0, 8).map((s) => (
                  <li key={s.id} className="flex min-w-0 items-center gap-2 px-2.5 py-1.5 text-[12.5px]">
                    <span className="min-w-0 flex-1 truncate text-fg">{s.hostname}</span>
                    <span className="hidden truncate font-mono text-[11px] text-fg-subtle sm:inline">
                      {Object.keys(selector)
                        .map((k) => `${k}=${s.labels?.[k]}`)
                        .join(', ')}
                    </span>
                    <ServerHealthChip server={s} showHealthy={false} />
                  </li>
                ))}
                {preview.matched.length > 8 && <li className="px-2.5 py-1.5 text-[12px] text-fg-subtle">+{preview.matched.length - 8} more</li>}
              </ul>
            )}
            {Object.keys(selector).length > 0 && preview.matched.length === 0 && (
              <p className="mt-1 text-[12px] text-fg-subtle">No registered server has these labels yet. Servers join as soon as their labels match.</p>
            )}
          </div>
        </section>

        <section className="space-y-4">
          <SectionTitle icon={Boxes}>Block page</SectionTitle>
          <Field label="Block page template" hint="Shown to the group's servers when a request is blocked.">
            <Select
              value={f.block_page_template_id}
              onChange={(e) => set('block_page_template_id', e.target.value)}
              options={[{ value: '', label: `Use the default${def ? ` (${def.name})` : ''}` }, ...templates.map((t) => ({ value: t.id, label: t.is_default ? `${t.name} (default)` : t.name }))]}
            />
          </Field>
        </section>

        {editing && group!.strict_isolation !== f.strict_isolation && (
          <Callout tone="warning" title={f.strict_isolation ? 'Turning on strict isolation' : 'Turning off strict isolation'}>
            {f.strict_isolation
              ? 'Global TLS exceptions stop applying to member servers, and new record & allow learning sessions are refused.'
              : 'Global TLS exceptions apply to member servers again, and learning sessions become possible.'}
          </Callout>
        )}
        <button type="submit" hidden />
      </form>
    </Drawer>
  );
};

const SectionTitle: React.FC<{ icon: React.ComponentType<{ className?: string }>; children: React.ReactNode }> = ({ icon: Icon, children }) => (
  <h3 className="flex items-center gap-2 border-b border-border pb-2 text-[13px] font-semibold text-fg">
    <Icon className="h-4 w-4 text-fg-subtle" aria-hidden />
    {children}
  </h3>
);
