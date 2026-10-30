import React from 'react';
import type { LucideIcon } from 'lucide-react';
import { Bell, Bot, Lock, Fingerprint, Gavel, Info, PackageCheck, ScrollText, ServerCog, ShieldHalf, Users } from 'lucide-react';
import { Button } from '../../../ui';

export type SettingsSectionId = 'general' | 'governance' | 'notifications' | 'identity' | 'sso' | 'service-accounts' | 'data-planes' | 'log-export' | 'defender' | 'packages';

export interface SettingsSectionMeta {
  id: SettingsSectionId;
  label: string;
  icon: LucideIcon;
  description: string;
  path: string;
  /** Extra search terms (command palette). */
  keywords?: string;
  /** Only InfoSec Approvers and Super Admins can open it (others see a restricted notice). */
  systemOnly?: boolean;
}

/** Sub-navigation of /settings (also a good source for command palette entries). */
export const SETTINGS_SECTIONS: SettingsSectionMeta[] = [
  { id: 'general', label: 'General', icon: Info, path: '/settings', description: 'Version, endpoints and appearance', keywords: 'appearance theme dark light density version endpoints proxy' },
  { id: 'governance', label: 'Governance', icon: Gavel, path: '/settings/governance', description: 'Four-eyes review, SLAs, recertification, digest', keywords: 'four-eyes review sla recertification digest prune' },
  { id: 'notifications', label: 'Notifications', icon: Bell, path: '/settings/notifications', description: 'Teams and Slack webhooks, delivery log', keywords: 'teams slack webhook alerts' },
  { id: 'identity', label: 'Identity & access', icon: Users, path: '/settings/identity', description: 'Users, roles, break-glass accounts', keywords: 'users rbac roles password reset break-glass' },
  {
    id: 'sso',
    label: 'Single sign-on',
    icon: Fingerprint,
    path: '/settings/sso',
    description: 'Entra ID or OpenID Connect, group mapping',
    keywords: 'sso oidc entra azure ad okta keycloak ping adfs saml mfa groups login identity provider idp',
  },
  {
    id: 'service-accounts',
    label: 'Service accounts',
    icon: Bot,
    path: '/settings/service-accounts',
    description: 'API keys for automation',
    keywords: 'api key token bearer automation soar terraform ci scripts machine',
    systemOnly: true,
  },
  { id: 'data-planes', label: 'Data-plane workers', icon: ServerCog, path: '/settings/data-planes', description: 'Proxy workers, versions and health', keywords: 'mitmproxy workers clamav yara icap heartbeat' },
  {
    id: 'log-export',
    label: 'Log export',
    icon: ScrollText,
    path: '/settings/log-export',
    description: 'SIEM and observability destinations',
    keywords: 'siem syslog splunk sentinel elastic datadog loki otlp webhook',
    systemOnly: true,
  },
  {
    id: 'defender',
    label: 'Microsoft Defender',
    icon: ShieldHalf,
    path: '/settings/defender',
    description: 'Endpoint risk, isolation and indicators',
    keywords: 'mde defender for endpoint integration edr device risk isolation quarantine indicators microsoft',
    systemOnly: true,
  },
  {
    id: 'packages',
    label: 'Package firewall',
    icon: PackageCheck,
    path: '/settings/packages',
    description: 'Ecosystems, cooldown, sandbox and advisory sources',
    keywords: 'package firewall npm pypi nuget powershell gallery registry cooldown karenz sandbox advisory osv snyk socket ossindex depsdev supply chain',
    systemOnly: true,
  },
];

/** Title block of a settings section. */
export const SectionTitle: React.FC<{ title: string; description?: React.ReactNode; actions?: React.ReactNode }> = ({ title, description, actions }) => (
  <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
    <div className="min-w-0">
      <h2 className="text-[17px] font-semibold leading-7 text-fg">{title}</h2>
      {description && <p className="mt-0.5 max-w-3xl text-[13px] leading-5 text-fg-muted">{description}</p>}
    </div>
    {actions && <div className="flex shrink-0 flex-wrap gap-2">{actions}</div>}
  </div>
);

/** Shown instead of a section the signed-in role may not open (the server enforces it too). */
export const RestrictedSection: React.FC<{ title: string; description: React.ReactNode; who?: string }> = ({ title, description, who = 'InfoSec Approvers and Super Admins' }) => (
  <>
    <SectionTitle title={title} description={description} />
    <div className="rounded-lg border border-border bg-surface shadow-card">
      <div className="flex flex-col items-center justify-center px-6 py-14 text-center">
        <span className="mb-3 flex h-12 w-12 items-center justify-center rounded-full border border-border bg-surface-2 text-fg-subtle">
          <Lock className="h-5 w-5" aria-hidden />
        </span>
        <p className="text-[14px] font-semibold text-fg">Restricted</p>
        <p className="mt-1 max-w-md text-[13px] leading-5 text-fg-muted">Only {who} can view this section.</p>
      </div>
    </div>
  </>
);

/** Floating "unsaved changes" bar for settings forms. */
export const SaveBar: React.FC<{ dirty: boolean; saving: boolean; onSave: () => void; onReset: () => void; label?: string; disabled?: boolean; note?: React.ReactNode }> = ({
  dirty,
  saving,
  onSave,
  onReset,
  label = 'Save changes',
  disabled,
  note,
}) =>
  dirty ? (
    <div className="sticky bottom-3 z-20 mt-5 flex flex-wrap items-center gap-3 rounded-lg border border-border-strong bg-surface px-4 py-2.5 shadow-pop animate-toast-in">
      <span className="text-[13px] font-medium text-fg">Unsaved changes</span>
      {note && <span className="text-[12px] text-danger">{note}</span>}
      <div className="ml-auto flex gap-2">
        <Button size="sm" variant="ghost" onClick={onReset} disabled={saving}>
          Discard
        </Button>
        <Button size="sm" variant="primary" onClick={onSave} loading={saving} disabled={disabled}>
          {label}
        </Button>
      </div>
    </div>
  ) : null;

/** Small "label: value" row with a mono value. */
export const MonoValue: React.FC<{ children: React.ReactNode; className?: string }> = ({ children, className }) => (
  <span className={`break-all font-mono text-[12.5px] text-fg ${className ?? ''}`}>{children}</span>
);
