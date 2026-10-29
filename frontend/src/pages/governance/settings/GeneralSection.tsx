import React from 'react';
import { FlaskConical, Globe, Monitor, Moon, Network, Palette, Rows3, Rows4, Sun } from 'lucide-react';
import { API_BASE } from '../../../api';
import { useConsole, useConsoleState, usePermissions } from '../../../data/AppData';
import { ROLE_LABELS } from '../../../data/permissions';
import { useSession } from '../../../data/session';
import { shellQuote } from '../../../lib/shell';
import { useTheme } from '../../../lib/theme';
import { Badge, ButtonLink, Card, CardHeader, CodeBlock, CopyButton, DescriptionList, SegmentedControl } from '../../../ui';
import { installCommands } from '../../security/tls/ca';
import { MonoValue, SectionTitle } from './shared';

const Copyable: React.FC<{ value?: string; empty?: string }> = ({ value, empty = 'Not configured' }) =>
  value ? (
    <span className="inline-flex max-w-full items-center gap-1">
      <MonoValue>{value}</MonoValue>
      <CopyButton text={value} size="xs" label="Copy" />
    </span>
  ) : (
    <span className="text-fg-subtle">{empty}</span>
  );

/** Product information, endpoints, onboarding snippet and per-browser appearance. */
export const GeneralSection: React.FC = () => {
  const state = useConsoleState();
  const { version, demoMode } = useConsole();
  const { meta, user } = useSession();
  const perms = usePermissions();
  const { theme, setTheme, density, setDensity } = useTheme();
  const publicUrl = (meta?.public_url || '').replace(/\/+$/, '');
  const consoleUrl = state.notify_config?.dashboard_base_url || '';
  const apiBase = API_BASE || window.location.origin;
  const proxy = state.proxy_address || '';
  const caBase = publicUrl || apiBase;

  const onboarding = [
    '# Route outbound traffic of a server through AegisProxy',
    `export HTTP_PROXY=${proxy ? shellQuote(`http://${proxy}`) : 'http://<proxy-host>:8080'}`,
    `export HTTPS_PROXY=${proxy ? shellQuote(`http://${proxy}`) : 'http://<proxy-host>:8080'}`,
    'export NO_PROXY=localhost,127.0.0.1,.corp.example',
    '',
    '# Trust the enterprise root CA (fingerprint-pinned installer; the verified one-liner is on TLS & CA)',
    installCommands(caBase).linux,
  ].join('\n');

  return (
    <>
      <SectionTitle title="General" description="Product information and the addresses servers and integrations use." />
      <div className="space-y-5">
        <Card>
          <CardHeader icon={Globe} title="Product" divider />
          <div className="p-[var(--card-p)]">
            <DescriptionList
              columns={3}
              items={[
                { label: 'Product', value: meta?.product || 'AegisProxy Enterprise' },
                { label: 'Control-plane version', value: <MonoValue>{version || '—'}</MonoValue> },
                { label: 'Configuration revision', value: <MonoValue>{state.revision ?? '—'}</MonoValue> },
                {
                  label: 'Demo mode',
                  value: demoMode ? (
                    <Badge tone="warning" icon={FlaskConical}>
                      On — never use in production
                    </Badge>
                  ) : (
                    <Badge tone="success">Off</Badge>
                  ),
                },
                { label: 'Sign-in', value: [meta?.local_login_enabled !== false && 'Local accounts', meta?.entra_enabled && 'Microsoft Entra ID'].filter(Boolean).join(' · ') || '—' },
                { label: 'You', value: user ? `${user.display_name || user.username} · ${perms.role ? ROLE_LABELS[perms.role] : ''}` : '—' },
              ]}
            />
          </div>
        </Card>

        <Card>
          <CardHeader icon={Network} title="Endpoints" description="Set by the control-plane configuration (AEGIS_PUBLIC_URL, proxy address)." divider />
          <div className="p-[var(--card-p)]">
            <DescriptionList
              columns={2}
              items={[
                { label: 'Proxy address for servers', value: <Copyable value={proxy} /> },
                { label: 'Public URL (CA, installers, request API)', value: <Copyable value={publicUrl} /> },
                { label: 'Console API', value: <Copyable value={apiBase} /> },
                {
                  label: 'Console links in notifications',
                  value: (
                    <span className="inline-flex flex-wrap items-center gap-2">
                      <Copyable value={consoleUrl} empty="Not set — messages have no console links" />
                      <ButtonLink to="/settings/notifications" size="xs" variant="ghost">
                        Change
                      </ButtonLink>
                    </span>
                  ),
                },
              ]}
            />
            <CodeBlock className="mt-5" title="Server onboarding (Linux)" code={onboarding} wrap />
            <p className="mt-2 text-[12px] text-fg-subtle">
              Servers authenticate with a proxy token (see the server page). Root CA details and Windows installers are on the TLS & CA page.
            </p>
          </div>
        </Card>

        <Card>
          <CardHeader icon={Palette} title="Appearance" description="Stored in this browser only." divider />
          <div className="grid gap-5 p-[var(--card-p)] sm:grid-cols-2">
            <div>
              <div className="label mb-1.5">Theme</div>
              <SegmentedControl
                aria-label="Theme"
                value={theme}
                onChange={setTheme}
                options={[
                  { value: 'light', label: 'Light', icon: Sun },
                  { value: 'dark', label: 'Dark', icon: Moon },
                  { value: 'system', label: 'System', icon: Monitor },
                ]}
              />
            </div>
            <div>
              <div className="label mb-1.5">Density</div>
              <SegmentedControl
                aria-label="Density"
                value={density}
                onChange={setDensity}
                options={[
                  { value: 'comfortable', label: 'Comfortable', icon: Rows3 },
                  { value: 'compact', label: 'Compact', icon: Rows4 },
                ]}
              />
              <p className="mt-1.5 text-[12px] text-fg-subtle">Compact fits more rows into tables.</p>
            </div>
          </div>
        </Card>
      </div>
    </>
  );
};
