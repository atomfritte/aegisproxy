import React, { useState } from 'react';
import { CheckCircle2, Download, KeyRound, Plus, Trash2 } from 'lucide-react';
import { api } from '../../../api';
import { formatDate, formatDateTime, toTime } from '../../../lib/format';
import { useAsync } from '../../../lib/hooks';
import { cn } from '../../../lib/cn';
import type { SsoClientKey, SsoProvider } from '../../../types';
import { Badge, Button, Callout, CopyButton, HelpTip, IconButton, Select, Skeleton, StatusChip, Tooltip, buttonClass, useConfirm, useToast } from '../../../ui';

const ALG_LABEL: Record<SsoClientKey['alg'], string> = { RS256: 'RSA 3072 · RS256', ES256: 'EC P-256 · ES256' };
const DAY = 86_400_000;

/** base64url SHA-1 thumbprint (x5t) → upper-case hex, as Entra ID displays certificate thumbprints. */
export function thumbprintHex(x5t: string): string {
  try {
    const b64 = x5t.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
    return Array.from(bin, (c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('').toUpperCase();
  } catch {
    return '';
  }
}

const statusChip = (k: SsoClientKey) =>
  k.status === 'active' ? (
    <StatusChip tone="success" label="Active" icon={CheckCircle2} />
  ) : k.status === 'next' ? (
    <Tooltip content="Published in the JWKS and downloadable, not used for signing yet. Register it at the IdP, then activate it.">
      <StatusChip tone="info" label="Staged" />
    </Tooltip>
  ) : (
    <Tooltip content="Replaced by a newer key. Its private key was erased; the public key stays in the JWKS until the grace period ends.">
      <StatusChip tone="neutral" label={k.published_until ? `Retired · published until ${formatDate(k.published_until)}` : 'Retired'} />
    </Tooltip>
  );

/**
 * private_key_jwt: the control plane authenticates to the IdP's token endpoint with a JWT signed by its
 * own key pair (no shared secret). Keys are generated server-side; IdPs get the public key as JWKS URL
 * (Keycloak, Okta, Ping) or as certificate upload (Entra ID).
 */
export const SsoClientKeysPanel: React.FC<{ provider: SsoProvider; ro: boolean; inUse: boolean }> = ({ provider, ro, inUse }) => {
  const toast = useToast();
  const confirm = useConfirm();
  const data = useAsync(() => api.settings.ssoClientKeys(), []);
  const [alg, setAlg] = useState<SsoClientKey['alg']>('RS256');
  const [busy, setBusy] = useState(false);
  const keys = data.data?.keys ?? [];
  const active = keys.find((k) => k.status === 'active');
  const staged = keys.find((k) => k.status === 'next');
  const canEdit = !ro && !!data.data?.can_edit;
  const jwks = data.data?.jwks_uri ?? '';
  const graceDays = Math.round((data.data?.grace_period_hours ?? 168) / 24);

  const generate = async () => {
    setBusy(true);
    try {
      const r = await api.settings.generateSsoClientKey(alg);
      toast.success(r.key.status === 'active' ? 'Client key generated — it signs the client assertions' : 'New key staged', {
        description:
          r.key.status === 'active'
            ? provider === 'entra'
              ? 'Download the certificate and upload it to the app registration.'
              : 'Register the JWKS URL at the IdP.'
            : provider === 'entra'
              ? 'Upload its certificate to the app registration, then activate it.'
              : 'IdPs with the JWKS URL see it already. Activate it to rotate.',
      });
      await data.reload();
    } catch (e) {
      toast.error(e, { title: 'Client key not generated' });
    } finally {
      setBusy(false);
    }
  };

  const activate = (k: SsoClientKey) =>
    confirm({
      title: 'Activate the staged key?',
      description:
        provider === 'entra'
          ? 'From now on sign-ins use this key. Upload its certificate to the Entra app registration first — otherwise Entra ID rejects the sign-in (AADSTS700027).'
          : `From now on sign-ins use this key. The current key is retired and stays in the JWKS for ${graceDays} days.`,
      tone: 'primary',
      confirmLabel: 'Activate key',
      onConfirm: async () => {
        await api.settings.activateSsoClientKey(k.kid);
        toast.success('Key rotated', { description: `The previous key is retired and published for ${graceDays} more days.` });
        await data.reload();
      },
    });

  const remove = (k: SsoClientKey) =>
    confirm({
      title: k.status === 'active' ? 'Delete the active key?' : `Delete the ${k.status === 'next' ? 'staged' : 'retired'} key?`,
      description: 'It disappears from the JWKS immediately. IdPs that still use it reject assertions signed with it.',
      tone: 'danger',
      confirmLabel: 'Delete key',
      onConfirm: async () => {
        await api.settings.deleteSsoClientKey(k.kid);
        toast.success('Client key deleted');
        await data.reload();
      },
    });

  return (
    <div className="space-y-4 rounded-lg border border-border bg-surface-2 p-4" data-testid="sso-client-keys">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5">
            <KeyRound className="h-4 w-4 text-fg-muted" aria-hidden />
            <span className="text-[13px] font-semibold text-fg">Client key (private_key_jwt)</span>
            <HelpTip content="The control plane proves its identity to the token endpoint with a short-lived JWT (RFC 7523) signed by this key. The private key never leaves the control plane and is stored encrypted." />
          </div>
          <p className="mt-0.5 text-[12.5px] leading-5 text-fg-muted">No client secret to rotate or leak. Rotation: stage a new key, register it at the IdP, then activate it.</p>
        </div>
      </div>

      <div>
        <div className="mb-1.5 flex items-center gap-1.5">
          <span className="label">JWKS URL</span>
          <HelpTip content="Keycloak: Credentials → Client authenticator “Signed JWT”, Keys → Use JWKS URL. Okta: Client authentication “Public key / Private key”, “Use a URL to fetch keys dynamically”." />
        </div>
        <div className="flex items-center gap-1 rounded-md border border-border bg-surface py-1 pl-3 pr-1">
          <code className="min-w-0 flex-1 font-mono text-[12px] text-fg [overflow-wrap:anywhere]" data-testid="sso-jwks-uri">
            {jwks || '…'}
          </code>
          {jwks && <CopyButton text={jwks} label="Copy JWKS URL" />}
        </div>
      </div>

      {data.loading && !data.data ? (
        <Skeleton className="h-16" />
      ) : data.error ? (
        <Callout tone="danger" title="Client keys could not be loaded">
          {data.error}
        </Callout>
      ) : keys.length === 0 ? (
        <Callout tone={inUse ? 'danger' : 'warning'} title="No client key yet">
          Generate a key{provider === 'entra' ? ', upload its certificate to the app registration' : ' and register the JWKS URL at the IdP'} before saving with private_key_jwt.
        </Callout>
      ) : (
        <ul className="divide-y divide-border rounded-md border border-border bg-surface">
          {keys.map((k) => {
            const expiresSoon = (toTime(k.not_after) ?? 0) - Date.now() < 30 * DAY;
            const hex = thumbprintHex(k.x5t);
            return (
              <li key={k.kid} className="space-y-2 px-3 py-2.5 text-[12.5px]">
                <div className="flex flex-wrap items-center gap-2">
                  {statusChip(k)}
                  <Badge tone="neutral">{ALG_LABEL[k.alg] ?? k.alg}</Badge>
                  <span className={cn('text-fg-muted', expiresSoon && 'font-medium text-warning')}>
                    certificate valid until {formatDate(k.not_after)}
                  </span>
                  <div className="ml-auto flex flex-wrap items-center gap-1">
                    <a className={buttonClass('ghost', 'xs')} href={api.settings.ssoClientCertificateUrl(k.kid, 'pem')} download>
                      <Download className="h-3.5 w-3.5" aria-hidden /> .pem
                    </a>
                    <a className={buttonClass('ghost', 'xs')} href={api.settings.ssoClientCertificateUrl(k.kid, 'cer')} download>
                      <Download className="h-3.5 w-3.5" aria-hidden /> .cer
                    </a>
                    {canEdit && k.status === 'next' && (
                      <Button size="xs" variant="primary" onClick={() => activate(k)}>
                        Activate
                      </Button>
                    )}
                    {canEdit && (k.status !== 'active' || !inUse) && <IconButton icon={Trash2} label="Delete key" size="xs" variant="danger-ghost" onClick={() => remove(k)} />}
                  </div>
                </div>
                <dl className="grid gap-x-4 gap-y-1 sm:grid-cols-[auto_minmax(0,1fr)]">
                  <dt className="text-fg-subtle">Key ID (kid)</dt>
                  <dd className="min-w-0 font-mono text-fg [overflow-wrap:anywhere]">{k.kid}</dd>
                  <dt className="text-fg-subtle">Thumbprint (SHA-1)</dt>
                  <dd className="flex min-w-0 items-center gap-1 font-mono text-fg [overflow-wrap:anywhere]" title="Entra ID shows this thumbprint after the certificate upload">
                    {hex}
                    {hex && <CopyButton text={hex} label="Copy thumbprint" />}
                  </dd>
                  <dt className="text-fg-subtle">Created</dt>
                  <dd className="text-fg-muted">
                    {formatDateTime(k.created_at)} by {k.created_by}
                  </dd>
                </dl>
              </li>
            );
          })}
        </ul>
      )}

      {canEdit && (
        <div className="flex flex-wrap items-center gap-2">
          <Select
            aria-label="Key algorithm"
            className="w-[190px]"
            value={alg}
            onChange={(e) => setAlg(e.target.value as SsoClientKey['alg'])}
            options={[
              { value: 'RS256', label: 'RSA 3072 (RS256)' },
              { value: 'ES256', label: 'EC P-256 (ES256)' },
            ]}
          />
          <Button icon={Plus} loading={busy} onClick={generate} disabled={!!staged && !!active}>
            {active ? 'Stage new key' : 'Generate key'}
          </Button>
          {staged && active && <span className="text-[12px] text-fg-subtle">Activate or delete the staged key first.</span>}
          {provider === 'entra' && alg === 'ES256' && (
            <span className="text-[12px] text-warning">Entra ID requires RSA certificates for client assertions — use RS256.</span>
          )}
        </div>
      )}

      <ol className="list-decimal space-y-1 pl-5 text-[12px] leading-5 text-fg-muted marker:text-fg-subtle">
        {provider === 'entra' ? (
          <>
            <li>
              Entra admin center → <span className="text-fg">App registrations → AegisProxy → Certificates &amp; secrets → Certificates → Upload certificate</span>: the
              .pem or .cer file above. Entra ID shows the SHA-1 thumbprint listed here.
            </li>
            <li>Remove the client secret from the app registration once sign-in works with the certificate.</li>
          </>
        ) : (
          <>
            <li>
              Keycloak: client → Credentials → Client authenticator <span className="text-fg">Signed JWT</span>; Keys → <span className="text-fg">Use JWKS URL</span> = the URL
              above.
            </li>
            <li>
              Okta: application → General → Client authentication <span className="text-fg">Public key / Private key</span>, “Use a URL to fetch keys dynamically” = the URL above
              (or add the key as JWK).
            </li>
          </>
        )}
      </ol>
    </div>
  );
};
