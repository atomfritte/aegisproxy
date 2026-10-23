import React, { useEffect, useMemo, useState } from 'react';
import {
  ArrowRight,
  Ban,
  CheckCircle2,
  KeyRound,
  LogIn,
  MoreHorizontal,
  Pencil,
  RotateCcw,
  ShieldCheck,
  Siren,
  Trash2,
  UserPlus,
  Users,
} from 'lucide-react';
import { api } from '../../../api';
import { useConsole, useConsoleState, usePermissions } from '../../../data/AppData';
import { ROLE_LABELS } from '../../../data/permissions';
import { useSession } from '../../../data/session';
import { cn } from '../../../lib/cn';
import { formatDateTime } from '../../../lib/format';
import { Link } from '../../../lib/router';
import { useUrlFilters } from '../../../lib/useUrlFilters';
import { ChangePasswordDialog } from '../../../shell/ChangePasswordDialog';
import type { Role, User, UserInput } from '../../../types';
import { passwordPolicyError } from '../../../utils';
import {
  Avatar,
  Badge,
  Button,
  ButtonLink,
  Callout,
  Card,
  Column,
  CopyButton,
  DataTable,
  Drawer,
  EmptyState,
  Field,
  IconButton,
  Input,
  Menu,
  Modal,
  MultiSelect,
  RadioCards,
  RelativeTime,
  StatusChip,
  Switch,
  Tone,
  Tooltip,
  useConfirm,
  useToast,
} from '../../../ui';
import { ProviderLogo } from '../../../components/common/ProviderLogo';
import { ssoSummaryLabel } from './SsoSection';
import { ChipList, GroupChip } from '../../../components/common/EntityChips';
import { SaveBar, SectionTitle } from './shared';

export const ROLE_TONE: Record<Role, Tone> = {
  SUPER_ADMIN: 'violet',
  INFOSEC_APPROVER: 'accent',
  TEAM_LEAD_APPROVER: 'info',
  OPERATOR_AUDITOR: 'neutral',
};

const ROLE_DESCRIPTIONS: Record<Role, string> = {
  SUPER_ADMIN: 'Everything, including users and log export destinations.',
  INFOSEC_APPROVER: 'Approves any request; manages fleet, TLS, threat protection, block pages and governance.',
  TEAM_LEAD_APPROVER: 'Approves requests and edits policy sets of the allowed groups. Temporary access only, no BLOCK rules.',
  OPERATOR_AUDITOR: 'Read-only access to everything; can comment on change requests.',
};

const ROLES: Role[] = ['SUPER_ADMIN', 'INFOSEC_APPROVER', 'TEAM_LEAD_APPROVER', 'OPERATOR_AUDITOR'];

// Demo deployments only (AEGIS_DEMO_MODE): the published showcase accounts.
const DEMO_PASSWORDS: Record<string, string> = { admin: 'admin123', infosec: 'infosec123', teamlead: 'teamlead123', auditor: 'auditor123' };

const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{1,63}$/;
const EMAIL_RE = /^[^\s@<>()]+@[^\s@<>()]+\.[^\s@<>()]+$/;

export const RoleBadge: React.FC<{ role: Role }> = ({ role }) =>
  role ? (
    <Tooltip content={ROLE_DESCRIPTIONS[role]}>
      <Badge tone={ROLE_TONE[role] ?? 'neutral'}>{ROLE_LABELS[role] ?? role}</Badge>
    </Tooltip>
  ) : (
    <Tooltip content="Provisioned by SCIM, but none of its SCIM groups is mapped to a role (Settings → Single sign-on → Role mapping). The account stays disabled until one is.">
      <Badge tone="neutral">No role</Badge>
    </Tooltip>
  );

const ScopeChips: React.FC<{ user: User }> = ({ user }) => {
  if (!user.role) return <span className="text-[12.5px] text-fg-subtle">—</span>;
  if (user.role === 'SUPER_ADMIN' || user.role === 'INFOSEC_APPROVER') return <span className="text-[12.5px] text-fg-muted">All groups (role)</span>;
  if (user.role === 'OPERATOR_AUDITOR') return <span className="text-[12.5px] text-fg-subtle">Read-only</span>;
  const g = user.allowed_groups ?? [];
  if (g.length === 0) return <span className="text-[12.5px] text-warning">No groups — cannot approve</span>;
  if (g.includes('*')) return <span className="text-[12.5px] text-fg-muted">All groups</span>;
  return (
    <ChipList max={2}>
      {g.map((id) => (
        <GroupChip key={id} id={id} />
      ))}
    </ChipList>
  );
};

function toInput(u: User): UserInput {
  return {
    id: u.id,
    username: u.username,
    display_name: u.display_name,
    email: u.email || '',
    role: u.role,
    allowed_groups: [...(u.allowed_groups ?? [])],
    department: u.department || '',
    disabled: !!u.disabled,
    break_glass: !!u.break_glass,
  };
}

/** Why an account cannot sign in: locked by an admin, or deprovisioned by the IdP (SSO users without a mapped group). */
export const DisabledChip: React.FC<{ user: User }> = ({ user: u }) => {
  if (!u.disabled) return null;
  if (u.scim && !u.disabled_by_admin) {
    const reason = u.scim.deleted
      ? 'Deleted by the SCIM client (IdP): sessions were revoked and the account is kept disabled for the audit trail. Provisioning the user again re-enables it.'
      : u.scim.active === false
        ? 'Deactivated by the SCIM client (IdP): sessions were revoked. The IdP re-enables it by setting active again.'
        : 'None of its SCIM groups is mapped to a role. It is enabled as soon as the IdP pushes it into a mapped group.';
    return (
      <Tooltip content={reason}>
        <StatusChip tone="warning" label={u.scim.deleted ? 'Deleted by SCIM' : u.scim.active === false ? 'Deactivated by SCIM' : 'No mapped SCIM group'} icon={Ban} />
      </Tooltip>
    );
  }
  if (u.auth_provider === 'oidc' && !u.disabled_by_admin) {
    return (
      <Tooltip content="The user lost every mapped IdP group: the last single sign-on was denied and the account disabled. It is re-enabled automatically when the IdP grants a mapped group again.">
        <StatusChip tone="warning" label="Deprovisioned by IdP" icon={Ban} />
      </Tooltip>
    );
  }
  return (
    <Tooltip content="Locked by an administrator. Single sign-on does not re-enable it; enable the account here.">
      <StatusChip tone="danger" label={u.auth_provider === 'oidc' || u.disabled_by_admin ? 'Disabled by admin' : 'Disabled'} icon={Ban} />
    </Tooltip>
  );
};

/** Sign-in badges of a user: SSO-provisioned, break-glass. */
export const AccountBadges: React.FC<{ user: User }> = ({ user: u }) => (
  <>
    {u.auth_provider === 'oidc' && (
      <Tooltip content="Provisioned by single sign-on: role and scope follow the IdP groups.">
        <Badge tone="info">SSO</Badge>
      </Tooltip>
    )}
    {u.scim && (
      <Tooltip content={`Managed by SCIM provisioning (userName ${u.scim.user_name}): the IdP creates, updates and deactivates it; role and scope follow the pushed groups.`}>
        <Badge tone="violet">SCIM</Badge>
      </Tooltip>
    )}
    {u.break_glass && (
      <Tooltip content="Break-glass account: may sign in with a password even when password sign-in is disabled. Every use raises a security alert.">
        <Badge tone="warning" icon={Siren}>
          Break-glass
        </Badge>
      </Tooltip>
    )}
  </>
);

const emptyInput = (): UserInput => ({
  username: '',
  display_name: '',
  email: '',
  role: 'OPERATOR_AUDITOR',
  allowed_groups: [],
  department: '',
  disabled: false,
  break_glass: false,
  password: '',
});

// ---------------------------------------------------------------------------
// Temporary password (shown once)
// ---------------------------------------------------------------------------

const TempPasswordModal: React.FC<{ value: { username: string; password: string; created: boolean } | null; onClose: () => void }> = ({ value, onClose }) => (
  <Modal
    open={!!value}
    onClose={onClose}
    dismissible={false}
    title={value?.created ? `Account “${value.username}” created` : `Password of “${value?.username}” reset`}
    description="This temporary password is shown only once. Send it over a secure channel; the user changes it after signing in."
    icon={
      <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-warning-soft text-warning">
        <KeyRound className="h-4 w-4" aria-hidden />
      </span>
    }
    footer={
      <Button variant="primary" onClick={onClose}>
        I have stored the password
      </Button>
    }
  >
    {value && (
      <div className="flex items-center gap-2 rounded-lg border border-warning-border bg-warning-soft p-3">
        <code className="min-w-0 flex-1 select-all break-all font-mono text-[15px] font-semibold text-fg" data-testid="temp-password">
          {value.password}
        </code>
        <CopyButton text={value.password} label="Copy password" />
      </div>
    )}
  </Modal>
);

// ---------------------------------------------------------------------------
// Create / edit user
// ---------------------------------------------------------------------------

const UserDrawer: React.FC<{
  open: boolean;
  initial: UserInput | null;
  /** Account provisioned by single sign-on (role and scope are managed by the IdP). */
  sso?: boolean;
  selfId?: string;
  onClose: () => void;
  onSaved: (res: { user: User; temporary_password?: string }, created: boolean) => void;
}> = ({ open, initial, sso, selfId, onClose, onSaved }) => {
  const state = useConsoleState();
  const toast = useToast();
  const [u, setU] = useState<UserInput>(initial ?? emptyInput());
  const [busy, setBusy] = useState(false);
  const [attempted, setAttempted] = useState(false);
  useEffect(() => {
    if (open) {
      setU(initial ?? emptyInput());
      setAttempted(false);
    }
  }, [open, initial]);
  const isNew = !u.id;
  const isSelf = !!u.id && u.id === selfId;
  const isSso = !!sso;

  const errors: Partial<Record<keyof UserInput, string>> = {};
  if (isNew && !USERNAME_RE.test(u.username.trim().toLowerCase())) errors.username = '2–64 characters: lowercase letters, digits, . _ - (starting with a letter or digit).';
  if (!u.display_name.trim()) errors.display_name = 'Enter the person’s name.';
  if (u.email.trim() && !EMAIL_RE.test(u.email.trim())) errors.email = 'Enter a valid e-mail address.';
  if (isNew && u.password) errors.password = passwordPolicyError(u.password) ?? (u.password.toLowerCase().includes(u.username.toLowerCase()) && u.username ? 'The password must not contain the username.' : undefined);
  if (u.role === 'TEAM_LEAD_APPROVER' && u.allowed_groups.length === 0 && !sso) errors.allowed_groups = 'Team Leads need at least one group to approve for.';
  const visible = attempted ? errors : { ...errors, username: u.username ? errors.username : undefined, display_name: undefined, allowed_groups: undefined };
  const invalid = Object.values(errors).some(Boolean);

  const submit = async () => {
    setAttempted(true);
    if (invalid) return;
    setBusy(true);
    try {
      const body: UserInput = {
        ...u,
        username: u.username.trim().toLowerCase(),
        display_name: u.display_name.trim(),
        email: u.email.trim(),
        department: u.department.trim(),
      };
      if (!isNew || !body.password) delete body.password;
      const res = await api.users.upsert(body);
      onSaved(res, isNew);
    } catch (err) {
      toast.error(err, { title: isNew ? 'User not created' : 'User not saved' });
    } finally {
      setBusy(false);
    }
  };

  const groupOptions = [{ value: '*', label: 'All groups', description: 'Including groups created later' }, ...state.groups.map((g) => ({ value: g.id, label: g.name, color: g.color, description: g.id }))];

  return (
    <Drawer
      open={open}
      onClose={onClose}
      dismissible={!busy}
      title={isNew ? 'Add user' : `Edit ${initial?.display_name || initial?.username}`}
      description={isNew ? 'Local account. Leave the password empty to generate a temporary one.' : `@${initial?.username}${isSso ? ' · signs in with single sign-on' : ''}`}
      width="md"
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" onClick={submit} loading={busy} icon={isNew ? UserPlus : undefined}>
            {isNew ? 'Create user' : 'Save user'}
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
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Username" required error={visible.username} hint={isNew ? 'Used to sign in. Cannot be changed later.' : 'Cannot be changed.'}>
            <Input value={u.username} disabled={!isNew} autoComplete="off" spellCheck={false} onChange={(e) => setU({ ...u, username: e.target.value })} mono data-autofocus={isNew || undefined} />
          </Field>
          <Field label="Display name" required error={visible.display_name}>
            <Input value={u.display_name} onChange={(e) => setU({ ...u, display_name: e.target.value })} placeholder="Jane Doe" data-autofocus={!isNew || undefined} />
          </Field>
          <Field label="E-mail" optional error={visible.email}>
            <Input type="email" value={u.email} onChange={(e) => setU({ ...u, email: e.target.value })} placeholder="jane.doe@corp.example" />
          </Field>
          <Field label="Department" optional>
            <Input value={u.department} onChange={(e) => setU({ ...u, department: e.target.value })} placeholder="Platform Engineering" />
          </Field>
        </div>
        {isSso && (
          <Callout tone="info" title="Managed by the identity provider">
            Role and Team Lead scope are synchronized from the IdP groups at every sign-in. Change the group membership in the IdP or the mapping under Single sign-on.
          </Callout>
        )}
        <Field label="Role">
          {() => (
            <RadioCards
              aria-label="Role"
              value={u.role}
              onChange={(role) => setU({ ...u, role })}
              options={ROLES.map((r) => ({
                value: r,
                title: ROLE_LABELS[r],
                description: ROLE_DESCRIPTIONS[r],
                disabled: (isSelf || isSso) && r !== u.role,
                disabledReason: isSso ? 'Managed by the IdP group mapping.' : 'You cannot change your own role.',
              }))}
            />
          )}
        </Field>
        {u.role === 'TEAM_LEAD_APPROVER' && !isSso && (
          <Field label="Approves for groups" required error={visible.allowed_groups} hint="Requests and policy sets of these groups. Choose “All groups” only for deputies of InfoSec.">
            <MultiSelect value={u.allowed_groups} onChange={(v) => setU({ ...u, allowed_groups: v.includes('*') && !u.allowed_groups.includes('*') ? ['*'] : v.filter((x) => x !== '*' || v.length === 1) })} options={groupOptions} placeholder="Select groups" />
          </Field>
        )}
        {isNew && (
          <Field label="Initial password" optional error={visible.password} hint={!visible.password ? 'At least 12 characters and 3 of: lowercase, uppercase, digits, symbols. Empty: a temporary password is generated and shown once.' : undefined}>
            <Input type="password" autoComplete="new-password" value={u.password ?? ''} onChange={(e) => setU({ ...u, password: e.target.value })} />
          </Field>
        )}
        {!isSso && (
          <div className={cn('rounded-md border px-3 py-3', u.break_glass ? 'border-warning-border bg-warning-soft' : 'border-border bg-surface-2')}>
            <Switch
              checked={!!u.break_glass}
              disabled={u.role !== 'SUPER_ADMIN' && !u.break_glass}
              onChange={(v) => setU({ ...u, break_glass: v })}
              label={
                <span className="inline-flex items-center gap-1.5">
                  <Siren className="h-3.5 w-3.5 text-warning" aria-hidden />
                  Break-glass account
                </span>
              }
              description={
                u.role !== 'SUPER_ADMIN'
                  ? 'Only Super Admins can be break-glass accounts.'
                  : 'Emergency access: may sign in with a password even when password sign-in is disabled for single sign-on. Every use is audited and raises a security alert. Keep the password in a vault.'
              }
            />
            {u.break_glass && u.role !== 'SUPER_ADMIN' && <p className="mt-2 text-[12px] text-danger">Break-glass accounts must be Super Admins — turn it off or keep the Super Admin role.</p>}
          </div>
        )}
        {!isNew && (
          <div className="rounded-md border border-border bg-surface-2 px-3 py-3">
            <Switch
              checked={u.disabled}
              disabled={isSelf}
              onChange={(v) => setU({ ...u, disabled: v })}
              label="Account disabled"
              description={
                isSelf
                  ? 'You cannot disable your own account.'
                  : isSso
                    ? 'Locks the account even if the IdP still grants access; sessions end immediately.'
                    : 'Disabled users cannot sign in; their sessions end immediately.'
              }
            />
          </div>
        )}
        <button type="submit" hidden />
      </form>
    </Drawer>
  );
};

// ---------------------------------------------------------------------------
// Single sign-on summary (configured under Settings → Single sign-on)
// ---------------------------------------------------------------------------

const SsoSummaryCard: React.FC = () => {
  const state = useConsoleState();
  const c = state.entra_config;
  const users = state.users ?? [];
  const sso = users.filter((u) => u.auth_provider === 'oidc').length;
  const bg = users.filter((u) => u.break_glass && !u.disabled).length;
  return (
    <Card>
      <div className="flex flex-col gap-4 p-[var(--card-p)] md:flex-row md:items-center">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-border bg-surface-2">
          {c?.enabled ? <ProviderLogo provider={c.provider || 'entra'} className="h-5 w-5" /> : <ShieldCheck className="h-5 w-5 text-fg-subtle" aria-hidden />}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-[14px] font-semibold text-fg">Single sign-on</h2>
            {c?.enabled ? <StatusChip tone="success" label={`Enabled · ${ssoSummaryLabel(c)}`} /> : <StatusChip tone="neutral" label="Not enabled" />}
            {c?.enabled && !c.allow_local_login && <Badge tone="warning">Password sign-in: break-glass only</Badge>}
          </div>
          <p className="mt-0.5 text-[12.5px] leading-5 text-fg-muted">
            {c?.enabled
              ? `${sso} ${sso === 1 ? 'user signs' : 'users sign'} in through the identity provider · ${bg} active break-glass ${bg === 1 ? 'account' : 'accounts'}.`
              : 'Connect Microsoft Entra ID or any OpenID Connect provider so administrators sign in with MFA and IdP groups decide their role.'}
          </p>
        </div>
        <ButtonLink to="/settings/sso" iconRight={ArrowRight}>
          {c?.enabled ? 'Single sign-on settings' : 'Set up single sign-on'}
        </ButtonLink>
      </div>
    </Card>
  );
};

// ---------------------------------------------------------------------------
// Section
// ---------------------------------------------------------------------------

/** Users and roles (Super Admin manages), own account, Microsoft Entra ID. */
export const IdentitySection: React.FC = () => {
  const state = useConsoleState();
  const { refresh, demoMode } = useConsole();
  const perms = usePermissions();
  const { user: me, login } = useSession();
  const toast = useToast();
  const confirm = useConfirm();
  const f = useUrlFilters(['role', 'signin', 'status']);
  const [editing, setEditing] = useState<UserInput | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [temp, setTemp] = useState<{ username: string; password: string; created: boolean } | null>(null);
  const [pwOpen, setPwOpen] = useState(false);
  const canEdit = perms.canManageUsers;
  const users = useMemo(() => [...(state.users ?? [])].sort((a, b) => a.display_name.localeCompare(b.display_name)), [state.users]);
  const meUser = users.find((u) => u.id === me?.id) ?? me;

  const openEdit = (u: User | null) => {
    setEditing(u ? toInput(u) : null);
    setDrawerOpen(true);
  };

  const toggleDisabled = async (u: User) => {
    const disable = !u.disabled;
    const ok = await confirm({
      title: disable ? `Disable ${u.display_name}?` : `Enable ${u.display_name}?`,
      description: disable
        ? `The user is signed out everywhere and cannot sign in until the account is enabled again${u.auth_provider === 'oidc' ? ' — single sign-on does not re-enable it' : ''}.`
        : u.auth_provider === 'oidc'
          ? 'The user can sign in again with single sign-on (if the IdP still grants a mapped group).'
          : 'The user can sign in again with their password.',
      tone: disable ? 'danger' : 'primary',
      confirmLabel: disable ? 'Disable account' : 'Enable account',
      onConfirm: () => api.users.upsert({ ...toInput(u), disabled: disable }),
    });
    if (ok) {
      await refresh();
      toast.success(disable ? `Disabled ${u.username}` : `Enabled ${u.username}`);
    }
  };

  const resetPassword = async (u: User) => {
    let pw = '';
    const ok = await confirm({
      title: `Reset the password of ${u.display_name}?`,
      description: 'A temporary password is generated and shown once. All sessions of this user are signed out.',
      tone: 'danger',
      confirmLabel: 'Reset password',
      onConfirm: async () => {
        pw = (await api.users.resetPassword(u.id)).temporary_password;
      },
    });
    if (ok) {
      setTemp({ username: u.username, password: pw, created: false });
      refresh();
    }
  };

  const remove = async (u: User) => {
    const ok = await confirm({
      title: `Delete ${u.display_name}?`,
      description: 'The account is removed permanently. Audit events keep the username.',
      tone: 'danger',
      confirmLabel: 'Delete user',
      typeToConfirm: u.username,
      onConfirm: () => api.users.remove(u.id),
    });
    if (ok) {
      await refresh();
      toast.success(`Deleted ${u.username}`);
    }
  };

  const switchTo = async (u: User) => {
    const err = await login(u.username, DEMO_PASSWORDS[u.username]);
    if (err) toast.error(err, { title: `Could not sign in as ${u.username}` });
  };

  const statusOf = (u: User) => (!u.disabled ? 'active' : u.auth_provider === 'oidc' && !u.disabled_by_admin ? 'deprovisioned' : 'disabled');

  const columns: Column<User>[] = [
    {
      id: 'user',
      header: 'User',
      sortValue: (u) => u.display_name.toLowerCase(),
      cell: (u) => (
        <div className="flex min-w-0 items-center gap-2.5">
          <Avatar name={u.display_name || u.username} size="md" />
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-x-1.5 gap-y-1">
              <span className="line-clamp-1 font-medium text-fg [overflow-wrap:anywhere]">{u.display_name}</span>
              {u.id === me?.id && <Badge tone="accent">You</Badge>}
              <AccountBadges user={u} />
              <DisabledChip user={u} />
            </div>
            <div className="line-clamp-1 text-[12px] text-fg-subtle [overflow-wrap:anywhere]" title={u.department || undefined}>
              @{u.username}
              {u.email ? ` · ${u.email}` : ''}
            </div>
          </div>
        </div>
      ),
    },
    { id: 'role', header: 'Role', width: 160, sortValue: (u) => ROLES.indexOf(u.role), cell: (u) => <RoleBadge role={u.role} /> },
    { id: 'scope', header: 'Approves for', width: 220, cell: (u) => <ScopeChips user={u} /> },
    {
      id: 'login',
      header: 'Last sign-in',
      width: 120,
      sortValue: (u) => u.last_login_at || '',
      cell: (u) => (u.last_login_at ? <RelativeTime value={u.last_login_at} className="text-fg-muted" /> : <span className="text-fg-subtle">Never</span>),
    },
    {
      id: 'actions',
      header: <span className="sr-only">Actions</span>,
      width: 48,
      align: 'right',
      hideOnMobile: true,
      cell: (u) => userMenu(u),
    },
  ];

  const userMenu = (u: User) => {
    const self = u.id === me?.id;
    const demoPw = demoMode && DEMO_PASSWORDS[u.username];
    const items = [
      { id: 'edit', label: 'Edit', icon: Pencil, onSelect: () => openEdit(u), hidden: !canEdit },
      { id: 'reset', label: 'Reset password…', icon: RotateCcw, onSelect: () => resetPassword(u), hidden: !canEdit || u.auth_provider !== 'local' },
      {
        id: 'disable',
        label: u.disabled ? 'Enable account' : 'Disable account…',
        icon: u.disabled ? CheckCircle2 : Ban,
        onSelect: () => toggleDisabled(u),
        hidden: !canEdit,
        disabled: self,
        description: self ? 'You cannot disable yourself' : undefined,
      },
      { id: 'switch', label: `Sign in as ${u.username}`, icon: LogIn, onSelect: () => switchTo(u), hidden: !demoPw || self, description: 'Demo mode only', separator: canEdit },
      { id: 'delete', label: 'Delete…', icon: Trash2, danger: true, onSelect: () => remove(u), hidden: !canEdit, disabled: self, description: self ? 'You cannot delete yourself' : undefined, separator: true },
    ];
    if (items.every((i) => i.hidden)) return null;
    return <Menu items={items} trigger={(p) => <IconButton {...p} icon={MoreHorizontal} label={`Actions for ${u.username}`} size="sm" noTooltip />} />;
  };

  return (
    <>
      <SectionTitle
        title="Identity & access"
        description="Who can sign in and what they may do. Roles are checked by the server on every request; changing a role or password signs the user out. Automation uses service accounts."
        actions={
          canEdit ? (
            <Button variant="primary" icon={UserPlus} onClick={() => openEdit(null)}>
              Add user
            </Button>
          ) : null
        }
      />
      <div className="space-y-5">
        {meUser && (
          <Card>
            <div className="flex flex-col gap-4 p-[var(--card-p)] sm:flex-row sm:items-center">
              <Avatar name={meUser.display_name || meUser.username} size="lg" />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[14px] font-semibold text-fg">{meUser.display_name}</span>
                  <RoleBadge role={meUser.role} />
                </div>
                <p className="mt-0.5 text-[12.5px] text-fg-muted">
                  Signed in as @{meUser.username}
                  {meUser.password_set_at ? ` · password changed ${formatDateTime(meUser.password_set_at)}` : ''}
                </p>
              </div>
              {meUser.auth_provider === 'local' && (
                <Button icon={KeyRound} onClick={() => setPwOpen(true)}>
                  Change my password
                </Button>
              )}
            </div>
          </Card>
        )}

        {!canEdit && (
          <Callout tone="neutral">Only Super Admins can add users, change roles or reset passwords.</Callout>
        )}

        <DataTable
          rows={users}
          columns={columns}
          getRowId={(u) => u.id}
          onRowClick={canEdit ? (u) => openEdit(u) : undefined}
          getSearchText={(u) => `${u.display_name} ${u.username} ${u.email} ${u.department} ${ROLE_LABELS[u.role]}`}
          searchPlaceholder="Search users…"
          search={f.search}
          onSearchChange={f.setSearch}
          facetValues={f.values}
          onFacetChange={f.onChange}
          facets={[
            { id: 'role', label: 'Role', getValue: (u) => u.role, options: ROLES.map((r) => ({ value: r, label: ROLE_LABELS[r] })) },
            {
              id: 'signin',
              label: 'Sign-in',
              getValue: (u) => [u.auth_provider === 'oidc' ? 'sso' : 'local', ...(u.break_glass ? ['break_glass'] : [])],
              options: [
                { value: 'local', label: 'Local password' },
                { value: 'sso', label: 'Single sign-on' },
                { value: 'break_glass', label: 'Break-glass' },
              ],
            },
            {
              id: 'status',
              label: 'Status',
              getValue: statusOf,
              options: [
                { value: 'active', label: 'Active' },
                { value: 'disabled', label: 'Disabled' },
                { value: 'deprovisioned', label: 'Deprovisioned by IdP' },
              ],
            },
          ]}
          mobileCard={(u) => (
            <div className="flex min-w-0 items-start gap-3">
              <Avatar name={u.display_name || u.username} size="md" />
              <div className="min-w-0 flex-1 space-y-1.5">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="truncate font-medium text-fg">{u.display_name}</div>
                    <div className="truncate text-[12px] text-fg-subtle">@{u.username}</div>
                  </div>
                  {userMenu(u)}
                </div>
                <div className="flex flex-wrap items-center gap-1.5">
                  <RoleBadge role={u.role} />
                  <AccountBadges user={u} />
                  <DisabledChip user={u} />
                  {u.id === me?.id && <Badge tone="accent">You</Badge>}
                </div>
                <ScopeChips user={u} />
              </div>
            </div>
          )}
          empty={<EmptyState size="sm" icon={Users} title="No users" />}
        />

        <SsoSummaryCard />
      </div>

      <UserDrawer
        open={drawerOpen}
        initial={editing}
        sso={!!editing?.id && users.find((x) => x.id === editing.id)?.auth_provider === 'oidc'}
        selfId={me?.id}
        onClose={() => setDrawerOpen(false)}
        onSaved={async (res, created) => {
          setDrawerOpen(false);
          await refresh();
          if (res.temporary_password) setTemp({ username: res.user.username, password: res.temporary_password, created });
          else toast.success(created ? `Created ${res.user.username}` : `Saved ${res.user.username}`);
        }}
      />
      <TempPasswordModal value={temp} onClose={() => setTemp(null)} />
      <ChangePasswordDialog open={pwOpen} onClose={() => setPwOpen(false)} authProvider={meUser?.auth_provider} />
    </>
  );
};
