import React, { useEffect, useId, useMemo, useState } from 'react';
import { CheckCircle2, KeyRound, Plus, Server as ServerIcon, Tag } from 'lucide-react';
import { api } from '../../api';
import { useAction, useConsoleState } from '../../data/AppData';
import { navigate } from '../../lib/router';
import type { Server } from '../../types';
import { Button, Callout, Drawer, Field, Input, KeyValueEditor, MultiSelect, Textarea } from '../../ui';
import { MembershipChip } from './FleetChips';
import { matchingGroups, validateCIDR, validateIP, validateProxyUser, validateServerId } from './fleetUtils';

interface FormState {
  id: string;
  hostname: string;
  ip: string;
  subnet_cidr: string;
  proxy_auth_user: string;
  group_ids: string[];
  labels: Record<string, string>;
  os: string;
  department: string;
  owner_team: string;
  description: string;
}

function toForm(s?: Partial<Server> | null): FormState {
  return {
    id: s?.id ?? '',
    hostname: s?.hostname ?? '',
    ip: s?.ip ?? '',
    subnet_cidr: s?.subnet_cidr ?? '',
    proxy_auth_user: s?.proxy_auth_user ?? '',
    group_ids: [...(s?.group_ids ?? [])],
    labels: { ...(s?.labels ?? {}) },
    os: s?.os ?? '',
    department: s?.department ?? '',
    owner_team: s?.owner_team ?? '',
    description: s?.description ?? '',
  };
}

export interface ServerFormDrawerProps {
  open: boolean;
  onClose: () => void;
  /** Existing server (edit) — otherwise a new registration, optionally prefilled. */
  server?: Server | null;
  initial?: Partial<Server> | null;
  /** Offer the onboarding wizard after a new registration. */
  onOnboard?: (server: Server) => void;
}

/** Register / edit a server. The API replaces the whole record, so every field is sent. */
export const ServerFormDrawer: React.FC<ServerFormDrawerProps> = ({ open, onClose, server, initial, onOnboard }) => {
  const state = useConsoleState();
  const { run, pending } = useAction();
  const editing = !!server;
  const [f, setF] = useState<FormState>(() => toForm(server ?? initial));
  const [touched, setTouched] = useState(false);
  const [created, setCreated] = useState<Server | null>(null);
  const uid = useId();

  useEffect(() => {
    if (open) {
      setF(toForm(server ?? initial));
      setTouched(false);
      setCreated(null);
    }
    // reset only when the drawer opens (state polling must not overwrite edits)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const set = <K extends keyof FormState>(k: K, v: FormState[K]) => setF((p) => ({ ...p, [k]: v }));

  const errors = {
    hostname: !f.hostname.trim() ? 'Enter the host name, e.g. app-17.internal.corp.' : null,
    id: editing ? null : validateServerId(f.id) || (state.servers.some((s) => s.id === f.id.trim().toLowerCase()) ? 'A server with this id already exists (saving would update it).' : null),
    ip: validateIP(f.ip) || (f.ip.trim() && state.servers.some((s) => s.ip === f.ip.trim() && s.id !== server?.id) ? `Already registered to ${state.servers.find((s) => s.ip === f.ip.trim())?.hostname}.` : null),
    subnet_cidr: validateCIDR(f.subnet_cidr),
    proxy_auth_user:
      validateProxyUser(f.proxy_auth_user) ||
      (f.proxy_auth_user.trim() && state.servers.some((s) => s.proxy_auth_user?.toLowerCase() === f.proxy_auth_user.trim().toLowerCase() && s.id !== server?.id)
        ? 'Already used by another server.'
        : null),
  };
  const blocking = !!(errors.hostname || errors.ip || errors.subnet_cidr || errors.proxy_auth_user || (errors.id && !errors.id.startsWith('A server with')));
  const show = (e: string | null) => (touched ? e : null);

  const matches = useMemo(() => matchingGroups(f.labels, state.groups).filter((g) => !f.group_ids.includes(g.id)), [f.labels, f.group_ids, state.groups]);
  const groupOptions = state.groups.map((g) => ({ value: g.id, label: g.name, description: g.cidrs?.length ? g.cidrs.join(', ') : g.id, color: g.color }));
  const osValues = useMemo(() => [...new Set(state.servers.map((s) => s.os).filter(Boolean))].sort(), [state.servers]);
  const teams = useMemo(() => [...new Set([...state.servers.map((s) => s.owner_team), ...state.groups.map((g) => g.owner_team)].filter(Boolean) as string[])].sort(), [state.servers, state.groups]);
  const departments = useMemo(() => [...new Set(state.servers.map((s) => s.department).filter(Boolean))].sort(), [state.servers]);

  const save = async () => {
    setTouched(true);
    if (blocking) return;
    const body = {
      ...(server ?? {}),
      id: (editing ? server!.id : f.id.trim().toLowerCase()) || '',
      hostname: f.hostname.trim(),
      ip: f.ip.trim(),
      subnet_cidr: f.subnet_cidr.trim(),
      proxy_auth_user: f.proxy_auth_user.trim().toLowerCase(),
      group_ids: f.group_ids,
      labels: f.labels,
      os: f.os.trim(),
      department: f.department.trim(),
      owner_team: f.owner_team.trim(),
      description: f.description.trim(),
    };
    delete (body as Partial<Server>).effective_group_ids;
    const res = await run(() => api.servers.upsert(body), {
      key: 'save',
      success: (s) => (editing ? `Saved ${s.hostname}` : `Registered ${s.hostname}`),
      errorTitle: editing ? 'The server was not saved' : 'The server was not registered',
    });
    if (!res) return;
    if (editing) onClose();
    else setCreated(res);
  };

  const footer = created ? (
    <>
      <Button
        variant="ghost"
        icon={Plus}
        onClick={() => {
          setF(toForm(null));
          setTouched(false);
          setCreated(null);
        }}
      >
        Register another
      </Button>
      <Button
        onClick={() => {
          onClose();
          navigate(`/servers/${encodeURIComponent(created.id)}`);
        }}
      >
        Open server
      </Button>
      {onOnboard && (
        <Button variant="primary" icon={KeyRound} onClick={() => onOnboard(created)}>
          Issue token and onboard
        </Button>
      )}
    </>
  ) : (
    <>
      <Button variant="secondary" onClick={onClose} disabled={pending === 'save'}>
        Cancel
      </Button>
      <Button variant="primary" onClick={save} loading={pending === 'save'} disabled={touched && blocking}>
        {editing ? 'Save changes' : 'Register server'}
      </Button>
    </>
  );

  return (
    <Drawer
      open={open}
      onClose={onClose}
      dismissible={pending !== 'save'}
      width="lg"
      title={created ? 'Server registered' : editing ? `Edit ${server!.hostname}` : 'Register server'}
      description={
        created
          ? undefined
          : editing
            ? 'Changes apply to policy evaluation within seconds. Quarantine state and the proxy token are not affected.'
            : 'Registered servers get group-based policy, quarantine, onboarding snippets and per-server reports.'
      }
      footer={footer}
    >
      {created ? (
        <div className="space-y-5">
          <div className="flex items-start gap-3 rounded-lg border border-success-border bg-success-soft p-4">
            <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-success" aria-hidden />
            <div className="min-w-0 text-[13px] leading-5">
              <p className="font-semibold text-fg">{created.hostname} is in the inventory</p>
              <p className="text-fg-muted">
                Id <span className="font-mono text-[12px]">{created.id}</span>
                {created.ip ? (
                  <>
                    , IP <span className="font-mono text-[12px]">{created.ip}</span>
                  </>
                ) : null}
                . Policy for its groups applies as soon as it sends traffic through the proxy.
              </p>
            </div>
          </div>
          <div>
            <h3 className="text-[13px] font-semibold text-fg">Next: connect the server</h3>
            <ol className="mt-2 space-y-2 text-[13px] leading-5 text-fg-muted">
              <li className="flex gap-2">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-accent-soft text-[11px] font-semibold text-accent">1</span>
                Issue a proxy token. It is shown once and identifies the server in every request.
              </li>
              <li className="flex gap-2">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-accent-soft text-[11px] font-semibold text-accent">2</span>
                Run the Linux or Windows snippet on the server: it trusts the root CA and sets the proxy.
              </li>
              <li className="flex gap-2">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-accent-soft text-[11px] font-semibold text-accent">3</span>
                Verify: the first request appears live in the onboarding panel.
              </li>
            </ol>
          </div>
        </div>
      ) : (
        <form
          className="space-y-7"
          onSubmit={(e) => {
            e.preventDefault();
            save();
          }}
          noValidate
        >
          <section className="space-y-4">
            <SectionTitle icon={ServerIcon}>Identity</SectionTitle>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Host name" required error={show(errors.hostname)} className="sm:col-span-2">
                <Input value={f.hostname} onChange={(e) => set('hostname', e.target.value)} placeholder="app-17.internal.corp" autoComplete="off" data-autofocus />
              </Field>
              <Field
                label="Server id"
                optional={!editing}
                hint={editing ? 'The id cannot be changed.' : errors.id ?? 'Leave empty to generate one. Lowercase letters, digits and "-".'}
                error={!editing && errors.id && !errors.id.startsWith('A server with') ? show(errors.id) : null}
              >
                <Input value={f.id} onChange={(e) => set('id', e.target.value)} placeholder="srv-app-17" mono disabled={editing} autoComplete="off" />
              </Field>
              <Field label="Proxy user" optional hint={show(errors.proxy_auth_user) ? undefined : 'Proxy-Authorization user name. Derived from the id when a token is issued.'} error={show(errors.proxy_auth_user)}>
                <Input value={f.proxy_auth_user} onChange={(e) => set('proxy_auth_user', e.target.value)} placeholder="svc-app-17" mono autoComplete="off" />
              </Field>
              <Field label="IP address" optional hint={show(errors.ip) ? undefined : 'Used to identify traffic without a proxy token.'} error={show(errors.ip)}>
                <Input value={f.ip} onChange={(e) => set('ip', e.target.value)} placeholder="10.30.12.55" mono autoComplete="off" />
              </Field>
              <Field label="Subnet" optional hint={show(errors.subnet_cidr) ? undefined : 'Accepts the bare proxy user from this range (DHCP, NAT).'} error={show(errors.subnet_cidr)}>
                <Input value={f.subnet_cidr} onChange={(e) => set('subnet_cidr', e.target.value)} placeholder="10.30.12.0/24" mono autoComplete="off" />
              </Field>
            </div>
          </section>

          <section className="space-y-4">
            <SectionTitle icon={Tag}>Groups and labels</SectionTitle>
            <Field label="Static groups" hint="Policy sets assigned to these groups apply to the server. Groups with a label selector add members automatically.">
              <MultiSelect value={f.group_ids} onChange={(v) => set('group_ids', v)} options={groupOptions} placeholder="No static group" searchPlaceholder="Search groups…" />
            </Field>
            <Field label="Labels" hint="Key/value pairs used by dynamic groups (e.g. compliance=pci, env=prod).">
              {() => <KeyValueEditor value={f.labels} onChange={(v) => set('labels', v)} keyPlaceholder="key" valuePlaceholder="value" />}
            </Field>
            <div className="rounded-lg border border-dashed border-border-strong bg-surface-2 px-3.5 py-3 text-[12.5px]">
              <p className="font-medium text-fg">Dynamic memberships from these labels</p>
              {matches.length === 0 ? (
                <p className="mt-0.5 text-fg-subtle">No label selector of another group matches.</p>
              ) : (
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  {matches.map((g) => (
                    <MembershipChip key={g.id} id={g.id} dynamic link={false} />
                  ))}
                </div>
              )}
            </div>
          </section>

          <section className="space-y-4">
            <SectionTitle icon={ServerIcon}>Ownership</SectionTitle>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Operating system" optional>
                <Input value={f.os} onChange={(e) => set('os', e.target.value)} placeholder="Ubuntu 24.04 LTS" list={`${uid}-os`} autoComplete="off" />
              </Field>
              <Field label="Owner team" optional>
                <Input value={f.owner_team} onChange={(e) => set('owner_team', e.target.value)} placeholder="Payments Platform" list={`${uid}-teams`} autoComplete="off" />
              </Field>
              <Field label="Department" optional>
                <Input value={f.department} onChange={(e) => set('department', e.target.value)} placeholder="Engineering" list={`${uid}-dept`} autoComplete="off" />
              </Field>
              <Field label="Description" optional className="sm:col-span-2">
                <Textarea value={f.description} onChange={(e) => set('description', e.target.value)} rows={2} placeholder="What runs on this server, ticket or CMDB reference" />
              </Field>
            </div>
            <datalist id={`${uid}-os`}>
              {osValues.map((v) => (
                <option key={v} value={v} />
              ))}
            </datalist>
            <datalist id={`${uid}-teams`}>
              {teams.map((v) => (
                <option key={v} value={v} />
              ))}
            </datalist>
            <datalist id={`${uid}-dept`}>
              {departments.map((v) => (
                <option key={v} value={v} />
              ))}
            </datalist>
          </section>

          {editing && server?.quarantined && (
            <Callout tone="danger" title="This server is quarantined">
              Saving does not release the quarantine.
            </Callout>
          )}
          <button type="submit" hidden />
        </form>
      )}
    </Drawer>
  );
};

const SectionTitle: React.FC<{ icon: React.ComponentType<{ className?: string }>; children: React.ReactNode }> = ({ icon: Icon, children }) => (
  <h3 className="flex items-center gap-2 border-b border-border pb-2 text-[13px] font-semibold text-fg">
    <Icon className="h-4 w-4 text-fg-subtle" aria-hidden />
    {children}
  </h3>
);
