import React, { useState } from 'react';
import { ArrowUpRight, Lock, Plus, RefreshCw, RotateCw, Trash2, UsersRound } from 'lucide-react';
import { api } from '../../../api';
import { formatDate, toTime } from '../../../lib/format';
import { useAsync } from '../../../lib/hooks';
import { cn } from '../../../lib/cn';
import type { ScimToken, SsoProvider } from '../../../types';
import { Badge, Button, Callout, Card, CardHeader, CodeBlock, CopyButton, HelpTip, IconButton, RelativeTime, Skeleton, StatusChip, Switch, useConfirm, useToast } from '../../../ui';
import { OneTimeSecretModal } from '../../../components/common/Secrets';

const DAY = 86_400_000;

const Stat: React.FC<{ label: string; children: React.ReactNode; hint?: string }> = ({ label, children, hint }) => (
  <div className="min-w-0 rounded-md border border-border bg-surface-2 px-3 py-2">
    <div className="text-[11.5px] font-medium uppercase tracking-wide text-fg-subtle">{label}</div>
    <div className="mt-0.5 truncate text-[14px] font-semibold text-fg" title={hint}>
      {children}
    </div>
  </div>
);

/**
 * Settings → Single sign-on → Provisioning (SCIM): Entra ID / Okta create, update, deactivate and delete
 * console accounts and push groups; roles come from the pushed groups through the SSO role mapping.
 */
export const ScimCard: React.FC<{ provider: SsoProvider; mappedGroups: number }> = ({ provider, mappedGroups }) => {
  const toast = useToast();
  const confirm = useConfirm();
  const data = useAsync(() => api.settings.scim(), []);
  const [issued, setIssued] = useState<{ name: string; secret: string; rotated: boolean } | null>(null);
  const [toggling, setToggling] = useState(false);
  const st = data.data?.status;
  const canEdit = !!data.data?.can_edit;
  const base = data.data?.base_url ?? '';
  const tokens = st?.tokens ?? [];

  const setEnabled = async (enabled: boolean) => {
    const run = async () => {
      setToggling(true);
      try {
        await api.settings.updateScim(enabled);
        toast.success(enabled ? 'SCIM provisioning enabled' : 'SCIM provisioning disabled');
        await data.reload();
      } catch (e) {
        toast.error(e, { title: 'SCIM setting not saved' });
      } finally {
        setToggling(false);
      }
    };
    if (enabled) return run();
    await confirm({
      title: 'Disable SCIM provisioning?',
      description: 'The IdP’s provisioning requests are rejected (403) until you enable it again. Provisioned accounts keep their current state and role.',
      tone: 'danger',
      confirmLabel: 'Disable provisioning',
      onConfirm: run,
    });
  };

  const create = async () => {
    const out = { name: '', secret: '' };
    const stem = provider === 'entra' ? 'entra-provisioning' : 'okta-provisioning';
    const taken = new Set(tokens.map((t) => t.name.toLowerCase()));
    let suggested = stem;
    for (let i = 2; taken.has(suggested); i++) suggested = `${stem}-${i}`;
    const ok = await confirm({
      title: 'Generate a SCIM token',
      description: 'The token is shown once. Enter it in the IdP’s provisioning settings. It is valid for one year and only for the SCIM endpoints.',
      tone: 'primary',
      confirmLabel: 'Generate token',
      reason: { label: 'Token name', placeholder: stem, required: true, defaultValue: suggested },
      onConfirm: async (name) => {
        const r = await api.settings.createScimToken(name.trim());
        out.name = r.token.name;
        out.secret = r.secret;
      },
    });
    if (ok && out.secret) {
      setIssued({ name: out.name, secret: out.secret, rotated: false });
      data.reload();
    }
  };

  const rotate = async (t: ScimToken) => {
    const out = { secret: '' };
    const ok = await confirm({
      title: `Rotate “${t.name}”?`,
      description: 'A new value is issued and shown once. The current value stops working immediately — provisioning fails until you update the IdP.',
      tone: 'danger',
      confirmLabel: 'Rotate token',
      onConfirm: async () => {
        out.secret = (await api.settings.rotateScimToken(t.id)).secret;
      },
    });
    if (ok && out.secret) {
      setIssued({ name: t.name, secret: out.secret, rotated: true });
      data.reload();
    }
  };

  const revoke = async (t: ScimToken) => {
    const ok = await confirm({
      title: `Revoke “${t.name}”?`,
      description: 'The IdP can no longer provision with this token. Accounts already provisioned are not changed.',
      tone: 'danger',
      confirmLabel: 'Revoke token',
      typeToConfirm: t.name,
      onConfirm: () => api.settings.revokeScimToken(t.id),
    });
    if (ok) {
      toast.success(`Revoked ${t.name}`);
      data.reload();
    }
  };

  return (
    <Card>
      <CardHeader
        icon={UsersRound}
        title="Provisioning (SCIM)"
        description="Entra ID and Okta create, update, deactivate and delete console accounts and push groups over SCIM 2.0 — offboarding takes effect at once instead of at the next sign-in."
        actions={st ? st.enabled ? <StatusChip tone="success" label="Enabled" /> : <StatusChip tone="neutral" label="Off" /> : null}
        divider
      />
      <div className="space-y-5 p-[var(--card-p)]" data-testid="scim-card">
        {data.loading && !data.data ? (
          <Skeleton className="h-24" />
        ) : data.error ? (
          <Callout tone="danger" title="Provisioning status could not be loaded">
            {data.error}
          </Callout>
        ) : st ? (
          <>
            {!canEdit && (
              <Callout tone="neutral" icon={Lock}>
                Only Super Admins can configure provisioning.
              </Callout>
            )}
            <Switch
              checked={st.enabled}
              disabled={!canEdit || toggling}
              onChange={setEnabled}
              label="Enable SCIM provisioning"
              description="SCIM is authoritative for the accounts it manages: their role and Team Lead scope come from the pushed groups via the role mapping above (group display name or object ID). Local and break-glass accounts are never touched."
            />

            <div>
              <div className="mb-1.5 flex items-center gap-1.5">
                <span className="label">SCIM base URL</span>
                <HelpTip content="Entra ID: Enterprise application → Provisioning → Tenant URL. Okta: SCIM connector base URL." />
              </div>
              <div className="flex items-center gap-1 rounded-md border border-border bg-surface-2 py-1 pl-3 pr-1">
                <code className="min-w-0 flex-1 font-mono text-[12.5px] text-fg [overflow-wrap:anywhere]" data-testid="scim-base-url">
                  {base}
                </code>
                <CopyButton text={base} label="Copy SCIM base URL" />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
              <Stat label="Accounts" hint="Enabled of all provisioned accounts">
                {st.active_users} <span className="text-[12.5px] font-normal text-fg-muted">enabled of {st.users}</span>
              </Stat>
              <Stat label="Groups">{st.groups}</Stat>
              <Stat label="Last change">{st.last_sync_at ? <RelativeTime value={st.last_sync_at} /> : <span className="font-normal text-fg-subtle">never</span>}</Stat>
              <Stat label="Last request">{st.last_request_at ? <RelativeTime value={st.last_request_at} /> : <span className="font-normal text-fg-subtle">never</span>}</Stat>
            </div>

            {st.enabled && mappedGroups === 0 && (
              <Callout tone="warning" title="No role mapping">
                Provisioned accounts stay disabled until a pushed group is mapped to a role in “Role mapping” above.
              </Callout>
            )}
            {st.enabled && tokens.length === 0 && (
              <Callout tone="info" title="Connect the identity provider">
                Generate a token and enter it with the base URL in the IdP’s provisioning settings.
              </Callout>
            )}

            <div>
              <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                <span className="label">Tokens</span>
                {canEdit && (
                  <Button size="sm" icon={Plus} onClick={create} disabled={tokens.length >= 5}>
                    Generate token
                  </Button>
                )}
              </div>
              {tokens.length === 0 ? (
                <p className="rounded-md border border-dashed border-border-strong px-3 py-3 text-[12.5px] text-fg-subtle">No tokens. The SCIM endpoints reject every request.</p>
              ) : (
                <ul className="divide-y divide-border rounded-md border border-border">
                  {tokens.map((t) => {
                    const left = (toTime(t.expires_at) ?? 0) - Date.now();
                    return (
                      <li key={t.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-[12.5px]">
                        <span className="min-w-0 font-medium text-fg">{t.name}</span>
                        <code className="font-mono text-fg-subtle">{t.prefix}…</code>
                        <Badge tone={left <= 0 ? 'danger' : left < 14 * DAY ? 'warning' : 'neutral'}>{left <= 0 ? 'expired' : `expires ${formatDate(t.expires_at)}`}</Badge>
                        <span className={cn('text-fg-subtle')}>
                          {t.last_used_at ? (
                            <>
                              <RelativeTime value={t.last_used_at} prefix="used" />
                              {t.last_used_ip ? ` from ${t.last_used_ip}` : ''}
                            </>
                          ) : (
                            'never used'
                          )}
                        </span>
                        {canEdit && (
                          <span className="ml-auto flex items-center gap-1">
                            <IconButton icon={RotateCw} label={`Rotate ${t.name}`} size="sm" variant="ghost" onClick={() => rotate(t)} />
                            <IconButton icon={Trash2} label={`Revoke ${t.name}`} size="sm" variant="danger-ghost" onClick={() => revoke(t)} />
                          </span>
                        )}
                      </li>
                    );
                  })}
                </ul>
              )}
              <p className="mt-2 text-[12px] leading-5 text-fg-subtle">
                Tokens work only for SCIM — never for the console or the API. To replace one without downtime: generate a new token, update the IdP, then revoke the old one.
              </p>
            </div>

            <ol className="list-decimal space-y-1.5 pl-5 text-[12.5px] leading-5 text-fg-muted marker:text-fg-subtle">
              {provider === 'entra' ? (
                <>
                  <li>
                    Entra admin center → <span className="text-fg">Enterprise applications → AegisProxy → Provisioning</span>: mode <span className="text-fg">Automatic</span>, Tenant URL =
                    base URL, Secret Token = a token from here, <span className="text-fg">Test Connection</span>.
                  </li>
                  <li>
                    Mappings: keep userName ← userPrincipalName; map <code className="font-mono text-fg">externalId</code> ← <code className="font-mono text-fg">objectId</code> (required):
                    the first single sign-on links by the immutable ID (oid) only, never by user name. Groups are matched by display name or object ID.
                  </li>
                  <li>Assign the groups that are mapped to roles to the application, set the scope to “assigned users and groups” and start provisioning.</li>
                </>
              ) : (
                <>
                  <li>
                    Okta: application → <span className="text-fg">Provisioning → Integration</span>: SCIM connector base URL = base URL, unique identifier field{' '}
                    <code className="font-mono text-fg">userName</code>, actions Push New Users, Push Profile Updates, Push Groups, authentication mode <span className="text-fg">HTTP Header</span>{' '}
                    with the token.
                  </li>
                  <li>
                    <span className="text-fg">To App</span>: enable Create Users, Update User Attributes and Deactivate Users; then <span className="text-fg">Push Groups</span> for every group mapped
                    to a role. Other IdPs: send the user’s immutable ID (the token’s <code className="font-mono text-fg">sub</code>) as <code className="font-mono text-fg">externalId</code> — accounts are
                    never linked by user name.
                  </li>
                </>
              )}
            </ol>
            {data.data?.docs_url && (
              <a href={data.data.docs_url} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 text-[12.5px] font-medium text-accent hover:underline">
                Setup guide and security notes <ArrowUpRight className="h-3.5 w-3.5" aria-hidden />
              </a>
            )}
          </>
        ) : null}
      </div>

      <OneTimeSecretModal
        open={!!issued}
        secret={issued?.secret ?? ''}
        secretLabel="SCIM token"
        confirmLabel="Close — I have stored the token"
        title={issued?.rotated ? `New value for ${issued.name}` : `SCIM token ${issued?.name} created`}
        description={issued?.rotated ? 'The previous value no longer works. Update the IdP’s provisioning settings now.' : 'Enter it in the IdP’s provisioning settings now.'}
        onClose={() => setIssued(null)}
      >
        <CodeBlock
          title="Check it"
          wrap
          code={`curl -sS -H "Authorization: Bearer ${issued?.secret ?? ''}" \\\n  "${base}/Users?filter=userName%20eq%20%22nobody%22"`}
        />
        <p className="flex items-center gap-1.5 text-[12px] text-fg-muted">
          <RefreshCw className="h-3.5 w-3.5" aria-hidden /> Entra ID: Secret Token · Okta: HTTP Header “Authorization: Bearer &lt;token&gt;”
        </p>
      </OneTimeSecretModal>
    </Card>
  );
};
