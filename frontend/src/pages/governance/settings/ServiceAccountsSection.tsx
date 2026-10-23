import React, { useEffect, useMemo, useState } from 'react';
import { Ban, Bot, CheckCircle2, Clock, KeyRound, MoreHorizontal, Pencil, Plus, RefreshCw, RotateCw, Trash2 } from 'lucide-react';
import { api, publicBaseUrl } from '../../../api';
import { useConsoleState, usePermissions } from '../../../data/AppData';
import { ROLE_LABELS } from '../../../data/permissions';
import { useSession } from '../../../data/session';
import { formatDate, formatDateTime, toTime } from '../../../lib/format';
import { useAsync, useNow } from '../../../lib/hooks';
import { useSearchParams } from '../../../lib/router';
import { useUrlFilters } from '../../../lib/useUrlFilters';
import type { Role, ServiceAccount, ServiceAccountInput } from '../../../types';
import {
  Badge,
  Button,
  Callout,
  Card,
  CardHeader,
  CodeBlock,
  Column,
  DataTable,
  Drawer,
  EmptyState,
  Field,
  IconButton,
  Input,
  Menu,
  MultiSelect,
  RadioCards,
  RelativeTime,
  SegmentedControl,
  Skeleton,
  StatTile,
  StatusChip,
  Switch,
  TagInput,
  Textarea,
  Tone,
  Tooltip,
  useConfirm,
  useToast,
} from '../../../ui';
import { ChipList, GroupChip } from '../../../components/common/EntityChips';
import { OneTimeSecretModal } from '../../../components/common/Secrets';
import { RoleBadge } from './IdentitySection';
import { RestrictedSection, SectionTitle } from './shared';

const DAY = 86_400_000;
const WARN_DAYS = 14;
const MAX_DAYS = 730;
const SA_ROLES: Role[] = ['INFOSEC_APPROVER', 'TEAM_LEAD_APPROVER', 'OPERATOR_AUDITOR'];
const ROLE_HELP: Partial<Record<Role, string>> = {
  INFOSEC_APPROVER: 'Fleet, threat protection, policy sets, approvals — e.g. SOAR playbooks that quarantine servers or add indicators.',
  TEAM_LEAD_APPROVER: 'Policy sets and approvals of the selected groups — e.g. CI pipelines that manage a team’s egress rules.',
  OPERATOR_AUDITOR: 'Read-only — e.g. reporting, inventory sync or compliance evidence collection.',
};
const NAME_RE = /^[a-z0-9][a-z0-9._-]{1,63}$/;
const EXPIRY_PRESETS = [30, 90, 180, 365, 730] as const;

type SaState = 'active' | 'expiring' | 'expired' | 'disabled';

function stateOf(a: ServiceAccount, now: number): SaState {
  if (a.disabled) return 'disabled';
  const t = toTime(a.expires_at) ?? 0;
  if (t <= now) return 'expired';
  if (t - now < WARN_DAYS * DAY) return 'expiring';
  return 'active';
}

const STATE_META: Record<SaState, { label: string; tone: Tone }> = {
  active: { label: 'Active', tone: 'success' },
  expiring: { label: 'Expires soon', tone: 'warning' },
  expired: { label: 'Expired', tone: 'danger' },
  disabled: { label: 'Disabled', tone: 'neutral' },
};

/** "in 12 days" / "3 days ago" for expiry dates. */
function expiryText(iso: string, now: number): string {
  const t = toTime(iso);
  if (t === null) return '—';
  const days = Math.round((t - now) / DAY);
  if (t <= now) return days === 0 ? 'Expired today' : `Expired ${-days} ${days === -1 ? 'day' : 'days'} ago`;
  if (days === 0) return 'Expires today';
  return `In ${days} ${days === 1 ? 'day' : 'days'}`;
}

const toDateInput = (t: number) => {
  const d = new Date(t);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
};

function isCidr(v: string): boolean {
  const [ip, bits] = v.split('/');
  const v4 = /^(\d{1,3})(\.\d{1,3}){3}$/.test(ip) && ip.split('.').every((p) => Number(p) <= 255);
  const v6 = ip.includes(':') && /^[0-9a-f:.]+$/i.test(ip);
  if (!v4 && !v6) return false;
  if (bits === undefined) return true;
  const n = Number(bits);
  return /^\d+$/.test(bits) && n >= 0 && n <= (v4 ? 32 : 128);
}

const ExpiryCell: React.FC<{ account: ServiceAccount; now: number }> = ({ account: a, now }) => {
  const st = stateOf(a, now);
  const cls = st === 'expired' ? 'text-danger' : st === 'expiring' ? 'text-warning' : 'text-fg';
  return (
    <Tooltip content={`Expires ${formatDateTime(a.expires_at)}`}>
      <div className="leading-tight">
        <div className={`inline-flex items-center gap-1 whitespace-nowrap text-[13px] ${cls}`}>
          {(st === 'expiring' || st === 'expired') && <Clock className="h-3.5 w-3.5" aria-hidden />}
          {expiryText(a.expires_at, now)}
        </div>
        <div className="mt-0.5 whitespace-nowrap text-[11.5px] text-fg-subtle">{formatDate(a.expires_at)}</div>
      </div>
    </Tooltip>
  );
};

const CidrCell: React.FC<{ cidrs: string[] }> = ({ cidrs }) =>
  cidrs.length === 0 ? (
    <Tooltip content="No source restriction: the key works from any address. Restrict it where possible.">
      <span className="text-[12.5px] text-warning">Any address</span>
    </Tooltip>
  ) : (
    <ChipList max={2}>
      {cidrs.map((c) => (
        <Badge key={c} tone="neutral" className="font-mono">
          {c}
        </Badge>
      ))}
    </ChipList>
  );

/** Settings → Service accounts: API keys for automation (Super Admin manages, InfoSec views). */
export const ServiceAccountsSection: React.FC = () => {
  const perms = usePermissions();
  if (!perms.canManageSystem) {
    return <RestrictedSection title="Service accounts" description="Non-human identities with API keys for SOAR playbooks, CI pipelines, Terraform and scripts." />;
  }
  return <ServiceAccounts />;
};

const ServiceAccounts: React.FC = () => {
  const perms = usePermissions();
  const state = useConsoleState();
  const { meta } = useSession();
  const toast = useToast();
  const confirm = useConfirm();
  const now = useNow();
  const f = useUrlFilters(['state', 'role']);
  const data = useAsync(() => api.serviceAccounts.list(), [state.revision]);
  const [drawer, setDrawer] = useState<{ open: boolean; account: ServiceAccount | null }>({ open: false, account: null });
  const [key, setKey] = useState<{ name: string; key: string; rotated: boolean } | null>(null);
  const canEdit = perms.isSuperAdmin;
  const accounts = useMemo(() => [...(data.data ?? [])].sort((a, b) => a.name.localeCompare(b.name)), [data.data]);
  const base = publicBaseUrl(meta?.public_url);
  const [params, setParams] = useSearchParams();
  // deep link from the command palette: /settings/service-accounts?new=1
  useEffect(() => {
    if (params.get('new') === '1') {
      if (canEdit) setDrawer({ open: true, account: null });
      setParams({ new: null });
    }
  }, [params, setParams, canEdit]);

  const counts = useMemo(() => {
    const c: Record<SaState, number> = { active: 0, expiring: 0, expired: 0, disabled: 0 };
    for (const a of accounts) c[stateOf(a, now)]++;
    return c;
  }, [accounts, now]);

  const inputOf = (a: ServiceAccount, patch: Partial<ServiceAccountInput> = {}): ServiceAccountInput => ({
    name: a.name,
    description: a.description,
    role: a.role,
    allowed_groups: [...(a.allowed_groups ?? [])],
    allowed_cidrs: [...(a.allowed_cidrs ?? [])],
    disabled: a.disabled,
    expires_at: a.expires_at,
    ...patch,
  });

  const toggle = async (a: ServiceAccount) => {
    const disable = !a.disabled;
    if (toTime(a.expires_at)! <= Date.now() && !disable) {
      toast.warning(`${a.name} has expired`, { description: 'Edit the account and choose a new expiry date to use it again.' });
      return;
    }
    await confirm({
      title: disable ? `Disable ${a.name}?` : `Enable ${a.name}?`,
      description: disable ? 'Requests with its API key are rejected immediately. You can enable it again later; the key stays the same.' : 'The existing API key works again.',
      tone: disable ? 'danger' : 'primary',
      confirmLabel: disable ? 'Disable account' : 'Enable account',
      onConfirm: async () => {
        await api.serviceAccounts.update(a.id, inputOf(a, { disabled: disable }));
        toast.success(disable ? `Disabled ${a.name}` : `Enabled ${a.name}`);
        await data.reload();
      },
    });
  };

  const rotate = async (a: ServiceAccount) => {
    const issued = { key: '' };
    const ok = await confirm({
      title: `Rotate the API key of ${a.name}?`,
      description: 'A new key is issued and shown once. The current key stops working immediately — update the automation right away.',
      tone: 'danger',
      confirmLabel: 'Rotate key',
      onConfirm: async () => {
        issued.key = (await api.serviceAccounts.rotate(a.id)).api_key;
      },
    });
    if (ok && issued.key) {
      setKey({ name: a.name, key: issued.key, rotated: true });
      data.reload();
    }
  };

  const remove = async (a: ServiceAccount) => {
    const ok = await confirm({
      title: `Delete ${a.name}?`,
      description: 'The account and its API key are removed permanently. Automation using the key fails from now on. Audit events keep the name.',
      tone: 'danger',
      confirmLabel: 'Delete service account',
      typeToConfirm: a.name,
      onConfirm: () => api.serviceAccounts.remove(a.id),
    });
    if (ok) {
      toast.success(`Deleted ${a.name}`);
      data.reload();
    }
  };

  const menu = (a: ServiceAccount) => {
    if (!canEdit) return null;
    return (
      <Menu
        items={[
          { id: 'edit', label: 'Edit', icon: Pencil, onSelect: () => setDrawer({ open: true, account: a }) },
          { id: 'rotate', label: 'Rotate key…', icon: RotateCw, onSelect: () => rotate(a) },
          { id: 'toggle', label: a.disabled ? 'Enable' : 'Disable…', icon: a.disabled ? CheckCircle2 : Ban, onSelect: () => toggle(a) },
          { id: 'delete', label: 'Delete…', icon: Trash2, danger: true, separator: true, onSelect: () => remove(a) },
        ]}
        trigger={(p) => <IconButton {...p} icon={MoreHorizontal} label={`Actions for ${a.name}`} size="sm" noTooltip />}
      />
    );
  };

  const columns: Column<ServiceAccount>[] = [
    {
      id: 'name',
      header: 'Service account',
      width: '34%',
      sortValue: (a) => a.name.toLowerCase(),
      cell: (a) => (
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-1.5">
            {canEdit ? (
              <button type="button" className="text-left font-medium text-fg hover:text-accent hover:underline" onClick={() => setDrawer({ open: true, account: a })}>
                {a.name}
              </button>
            ) : (
              <span className="font-medium text-fg">{a.name}</span>
            )}
          </div>
          <div className="font-mono text-[11.5px] text-fg-subtle" title="Key prefix">
            {a.key_prefix}…
          </div>
          {a.description && <p className="mt-0.5 line-clamp-1 text-[12px] text-fg-muted" title={a.description}>{a.description}</p>}
        </div>
      ),
    },
    {
      id: 'role',
      header: 'Role',
      width: 170,
      sortValue: (a) => a.role,
      cell: (a) => (
        <div className="space-y-1">
          <RoleBadge role={a.role} />
          {a.role === 'TEAM_LEAD_APPROVER' && (
            <ChipList max={2}>
              {(a.allowed_groups ?? []).map((g) => (
                <GroupChip key={g} id={g} />
              ))}
            </ChipList>
          )}
        </div>
      ),
    },
    { id: 'cidrs', header: 'Allowed sources', width: 150, hideBelow: 'xl', cell: (a) => <CidrCell cidrs={a.allowed_cidrs ?? []} /> },
    { id: 'expires', header: 'Expires', width: 130, sortValue: (a) => a.expires_at, cell: (a) => <ExpiryCell account={a} now={now} /> },
    {
      id: 'state',
      header: 'Status',
      width: 150,
      sortValue: (a) => `${stateOf(a, now)} ${a.last_used_at || ''}`,
      cell: (a) => {
        const m = STATE_META[stateOf(a, now)];
        return (
          <div className="space-y-1 leading-tight">
            <StatusChip tone={m.tone} label={m.label} />
            <div className="text-[11.5px] text-fg-subtle">
              {a.last_used_at ? (
                <Tooltip content={a.last_used_ip ? `Last call from ${a.last_used_ip}` : 'Last call'}>
                  <span>
                    <RelativeTime value={a.last_used_at} prefix="Used" />
                  </span>
                </Tooltip>
              ) : (
                'Never used'
              )}
            </div>
          </div>
        );
      },
    },
    { id: 'actions', header: <span className="sr-only">Actions</span>, width: 48, align: 'right', hideOnMobile: true, cell: menu },
  ];

  const sampleKey = 'aegis_sa_…';

  return (
    <>
      <SectionTitle
        title="Service accounts"
        description="Non-human identities for SOAR playbooks, CI pipelines, Terraform and scripts. Each authenticates with its own API key, is limited to a role, optional source networks and an expiry date, and every call is audited under its name."
        actions={
          <>
            <Button icon={RefreshCw} onClick={() => data.reload()} loading={data.loading && !!data.data}>
              Refresh
            </Button>
            {canEdit && (
              <Button variant="primary" icon={Plus} onClick={() => setDrawer({ open: true, account: null })}>
                New service account
              </Button>
            )}
          </>
        }
      />
      {data.error && !data.data && (
        <Callout tone="danger" title="Service accounts could not be loaded" action={<Button size="sm" onClick={() => data.reload()}>Try again</Button>}>
          {data.error}
        </Callout>
      )}
      {!data.data && !data.error && (
        <div className="space-y-3">
          <Skeleton className="h-20" />
          <Skeleton className="h-48" />
        </div>
      )}
      {data.data && (
        <div className="space-y-5">
          {!canEdit && <Callout tone="neutral">Only Super Admins can create, rotate or delete service accounts. You can review them.</Callout>}
          {accounts.length > 0 && (
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              <StatTile label="Active" value={counts.active + counts.expiring} icon={Bot} tone="success" />
              <StatTile label={`Expiring within ${WARN_DAYS} days`} value={counts.expiring} icon={Clock} tone={counts.expiring ? 'warning' : 'neutral'} attention={counts.expiring > 0} hint="Rotate or extend before they expire" />
              <StatTile label="Expired" value={counts.expired} icon={Clock} tone={counts.expired ? 'danger' : 'neutral'} />
              <StatTile label="Disabled" value={counts.disabled} icon={Ban} />
            </div>
          )}
          <DataTable
            aria-label="Service accounts"
            rows={accounts}
            columns={columns}
            getRowId={(a) => a.id}
            getSearchText={(a) => `${a.name} ${a.description} ${a.key_prefix} ${ROLE_LABELS[a.role]} ${(a.allowed_cidrs ?? []).join(' ')}`}
            searchPlaceholder="Search service accounts…"
            search={f.search}
            onSearchChange={f.setSearch}
            facetValues={f.values}
            onFacetChange={f.onChange}
            facets={[
              { id: 'state', label: 'Status', getValue: (a) => stateOf(a, now), options: (Object.keys(STATE_META) as SaState[]).map((k) => ({ value: k, label: STATE_META[k].label })) },
              { id: 'role', label: 'Role', getValue: (a) => a.role, options: SA_ROLES.map((r) => ({ value: r, label: ROLE_LABELS[r] })) },
            ]}
            rowClassName={(a) => (a.disabled ? 'opacity-70' : undefined)}
            mobileCard={(a) => {
              const m = STATE_META[stateOf(a, now)];
              return (
                <div className="min-w-0 space-y-2">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="truncate font-medium text-fg">{a.name}</div>
                      <div className="font-mono text-[11.5px] text-fg-subtle">{a.key_prefix}…</div>
                    </div>
                    {menu(a)}
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5">
                    <RoleBadge role={a.role} />
                    <StatusChip tone={m.tone} label={m.label} />
                  </div>
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[12px] text-fg-muted">
                    <span>{expiryText(a.expires_at, now)}</span>
                    <span>{a.last_used_at ? <RelativeTime value={a.last_used_at} prefix="used" /> : 'Never used'}</span>
                  </div>
                  <CidrCell cidrs={a.allowed_cidrs ?? []} />
                </div>
              );
            }}
            empty={
              <EmptyState
                icon={Bot}
                title="No service accounts yet"
                description={canEdit ? 'Create one per integration so each gets its own key, role, network restriction and audit identity — never share a personal login with a script.' : 'No automation has API access yet.'}
                action={
                  canEdit && (
                    <Button variant="primary" icon={Plus} onClick={() => setDrawer({ open: true, account: null })}>
                      New service account
                    </Button>
                  )
                }
              />
            }
          />
          <Card>
            <CardHeader icon={KeyRound} title="Using an API key" description="Send the key as a bearer token. Session cookies and CSRF headers are not needed." />
            <div className="space-y-3 p-[var(--card-p)] pt-3">
              <CodeBlock
                title="curl"
                wrap
                code={`curl -sS -H "Authorization: Bearer ${sampleKey}" \\\n  ${base}/api/policy-sets\n\n# who am I?\ncurl -sS -H "Authorization: Bearer ${sampleKey}" ${base}/api/auth/me`}
              />
              <p className="text-[12.5px] leading-5 text-fg-muted">
                Keys never grant Super Admin rights: user management, single sign-on, service accounts and integrations stay with people. Store keys in a secrets manager and
                rotate them at least yearly.
              </p>
            </div>
          </Card>
        </div>
      )}

      <ServiceAccountDrawer
        open={drawer.open}
        account={drawer.account}
        onClose={() => setDrawer({ open: false, account: null })}
        onCreated={(name, k) => {
          setDrawer({ open: false, account: null });
          setKey({ name, key: k, rotated: false });
          data.reload();
        }}
        onSaved={(a) => {
          setDrawer({ open: false, account: null });
          toast.success(`Saved ${a.name}`);
          data.reload();
        }}
      />
      <OneTimeSecretModal
        open={!!key}
        secret={key?.key ?? ''}
        title={key?.rotated ? `New API key for ${key.name}` : `Service account ${key?.name} created`}
        description={key?.rotated ? 'The previous key no longer works. Update the automation with this key now.' : 'Copy the API key now and store it in your secrets manager.'}
        onClose={() => setKey(null)}
      >
        <CodeBlock title="Try it" wrap code={`curl -sS -H "Authorization: Bearer ${key?.key ?? ''}" ${base}/api/auth/me`} />
      </OneTimeSecretModal>
    </>
  );
};

// ---------------------------------------------------------------------------
// Create / edit
// ---------------------------------------------------------------------------

interface Draft {
  name: string;
  description: string;
  role: Role;
  groups: string[];
  cidrs: string[];
  disabled: boolean;
  /** preset days or 'custom' */
  expiryMode: string;
  expiryDate: string;
}

const ServiceAccountDrawer: React.FC<{
  open: boolean;
  account: ServiceAccount | null;
  onClose: () => void;
  onCreated: (name: string, key: string) => void;
  onSaved: (a: ServiceAccount) => void;
}> = ({ open, account, onClose, onCreated, onSaved }) => {
  const state = useConsoleState();
  const toast = useToast();
  const isNew = !account;
  const init = (): Draft => ({
    name: account?.name ?? '',
    description: account?.description ?? '',
    role: account?.role ?? 'OPERATOR_AUDITOR',
    groups: [...(account?.allowed_groups ?? [])].filter((g) => g !== '*'),
    cidrs: [...(account?.allowed_cidrs ?? [])],
    disabled: account?.disabled ?? false,
    expiryMode: account ? 'keep' : '365',
    expiryDate: toDateInput(account ? toTime(account.expires_at) ?? Date.now() + 365 * DAY : Date.now() + 365 * DAY),
  });
  const [d, setD] = useState<Draft>(init);
  const [attempted, setAttempted] = useState(false);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (open) {
      setD(init());
      setAttempted(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, account]);
  const set = (p: Partial<Draft>) => setD((x) => ({ ...x, ...p }));

  const expiresAt = (): string | undefined => {
    if (d.expiryMode === 'keep') return account?.expires_at;
    if (d.expiryMode === 'custom') {
      const t = new Date(`${d.expiryDate}T23:59:00`).getTime();
      return Number.isFinite(t) ? new Date(t).toISOString() : undefined;
    }
    return new Date(Date.now() + Number(d.expiryMode) * DAY).toISOString();
  };
  const exp = expiresAt();
  const expT = toTime(exp ?? null);
  const errors = {
    name: !NAME_RE.test(d.name.trim().toLowerCase()) ? '2–64 characters: letters, digits, . _ - (starting with a letter or digit).' : null,
    groups: d.role === 'TEAM_LEAD_APPROVER' && d.groups.length === 0 ? 'Team Lead service accounts need at least one server group.' : null,
    expiry:
      expT === null
        ? 'Choose a valid date.'
        : expT < Date.now() + 3600_000 && d.expiryMode !== 'keep'
          ? 'The expiry must be at least one hour in the future.'
          : expT > Date.now() + MAX_DAYS * DAY
            ? `At most ${MAX_DAYS} days from now.`
            : null,
    description: d.description.length > 500 ? 'At most 500 characters.' : null,
  };
  const invalid = Object.values(errors).some(Boolean);
  const show = (k: keyof typeof errors) => (attempted || (k === 'name' && d.name) || k === 'expiry' ? errors[k] : null);

  const submit = async () => {
    setAttempted(true);
    if (invalid) return;
    setBusy(true);
    const input: ServiceAccountInput = {
      name: d.name.trim(),
      description: d.description.trim(),
      role: d.role,
      allowed_groups: d.role === 'TEAM_LEAD_APPROVER' ? d.groups : [],
      allowed_cidrs: d.cidrs,
      disabled: d.disabled,
      expires_at: exp,
    };
    try {
      if (isNew) {
        const r = await api.serviceAccounts.create(input);
        onCreated(r.service_account.name, r.api_key);
      } else {
        onSaved(await api.serviceAccounts.update(account!.id, input));
      }
    } catch (e) {
      toast.error(e, { title: isNew ? 'Service account not created' : 'Service account not saved' });
    } finally {
      setBusy(false);
    }
  };

  const expiryOptions = [
    ...(account ? [{ value: 'keep', label: 'Keep' }] : []),
    ...EXPIRY_PRESETS.map((n) => ({ value: String(n), label: n === 365 ? '1 year' : n === 730 ? '2 years' : `${n} days` })),
    { value: 'custom', label: 'Date' },
  ];

  return (
    <Drawer
      open={open}
      onClose={onClose}
      dismissible={!busy}
      width="md"
      title={isNew ? 'New service account' : `Edit ${account?.name}`}
      description={isNew ? 'The API key is shown once after creation.' : `Key ${account?.key_prefix}… · created by ${account?.created_by} ${account ? formatDate(account.created_at) : ''}`}
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" onClick={submit} loading={busy} icon={isNew ? KeyRound : undefined}>
            {isNew ? 'Create and show key' : 'Save changes'}
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
        <Field label="Name" required error={show('name')} hint="Lowercase is recommended, e.g. soar-quarantine or ci-terraform.">
          <Input mono value={d.name} onChange={(e) => set({ name: e.target.value })} placeholder="soar-quarantine" autoComplete="off" spellCheck={false} data-autofocus />
        </Field>
        <Field label="Description" optional error={show('description')} hint="What uses this key and who owns it.">
          <Textarea rows={2} value={d.description} onChange={(e) => set({ description: e.target.value })} placeholder="Cortex XSOAR playbook “Isolate compromised server” — SecOps" />
        </Field>
        <Field label="Role">
          {() => (
            <RadioCards<Role>
              aria-label="Role"
              value={d.role}
              onChange={(role) => set({ role })}
              options={SA_ROLES.map((r) => ({ value: r, title: ROLE_LABELS[r], description: ROLE_HELP[r] }))}
            />
          )}
        </Field>
        {d.role === 'TEAM_LEAD_APPROVER' && (
          <Field label="Server groups" required error={show('groups')} hint="Policy sets and requests of these groups only.">
            <MultiSelect
              value={d.groups}
              onChange={(v) => set({ groups: v })}
              options={state.groups.map((g) => ({ value: g.id, label: g.name, color: g.color, description: g.id }))}
              placeholder="Select groups"
            />
          </Field>
        )}
        <Field label="Allowed source networks" optional hint="IP addresses or CIDRs the key may be used from (press Enter after each). Empty: any address.">
          <TagInput
            value={d.cidrs}
            onChange={(v) => set({ cidrs: v })}
            mono
            placeholder="10.20.0.0/16"
            max={50}
            validate={(t) => (isCidr(t) ? null : `“${t}” is not an IP address or CIDR`)}
          />
        </Field>
        <Field label="Expiry" error={show('expiry')} hint={!show('expiry') && exp ? `Expires ${formatDateTime(exp)}. At most ${MAX_DAYS} days.` : undefined}>
          {() => (
            <div className="space-y-2">
              <SegmentedControl aria-label="Expiry" value={d.expiryMode} onChange={(v) => set({ expiryMode: v })} options={expiryOptions} className="flex-wrap" />
              {d.expiryMode === 'custom' && (
                <Input
                  type="date"
                  aria-label="Expiry date"
                  className="max-w-[220px]"
                  value={d.expiryDate}
                  min={toDateInput(Date.now() + DAY)}
                  max={toDateInput(Date.now() + MAX_DAYS * DAY)}
                  onChange={(e) => set({ expiryDate: e.target.value })}
                />
              )}
            </div>
          )}
        </Field>
        {!isNew && (
          <div className="rounded-md border border-border bg-surface-2 px-3 py-3">
            <Switch checked={d.disabled} onChange={(v) => set({ disabled: v })} label="Disabled" description="Requests with this key are rejected while disabled." />
          </div>
        )}
        <button type="submit" hidden />
      </form>
    </Drawer>
  );
};
