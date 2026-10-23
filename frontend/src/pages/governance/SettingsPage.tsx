import React, { useEffect, useRef } from 'react';
import { usePermissions } from '../../data/AppData';
import { cn } from '../../lib/cn';
import { useDocumentTitle } from '../../lib/hooks';
import { NavLink, Redirect, useParams } from '../../lib/router';
import { PageHeader } from '../../ui';
import { NotFoundPage } from '../system/NotFoundPage';
import { DataPlanesSection } from './settings/DataPlanesSection';
import { DefenderSection } from './settings/DefenderSection';
import { GeneralSection } from './settings/GeneralSection';
import { GovernanceSection } from './settings/GovernanceSection';
import { IdentitySection } from './settings/IdentitySection';
import { LogExportSection } from './settings/logexport/LogExportSection';
import { NotificationsSection } from './settings/NotificationsSection';
import { ServiceAccountsSection } from './settings/ServiceAccountsSection';
import { SsoSection } from './settings/SsoSection';
import { SETTINGS_SECTIONS, type SettingsSectionId } from './settings/shared';

const SECTION_COMPONENTS: Record<SettingsSectionId, React.FC> = {
  general: GeneralSection,
  governance: GovernanceSection,
  notifications: NotificationsSection,
  identity: IdentitySection,
  sso: SsoSection,
  'service-accounts': ServiceAccountsSection,
  'data-planes': DataPlanesSection,
  'log-export': LogExportSection,
  defender: DefenderSection,
};

/** Routes /settings (general) and /settings/:tab with a section sub-navigation. */
export const SettingsPage: React.FC = () => {
  const { tab } = useParams<{ tab?: string }>();
  const perms = usePermissions();
  const id = (tab || 'general') as SettingsSectionId;
  const meta = SETTINGS_SECTIONS.find((s) => s.id === id);
  useDocumentTitle(meta ? (meta.id === 'general' ? 'Settings' : `${meta.label} · Settings`) : null);
  const navRef = useRef<HTMLUListElement>(null);
  // phones: keep the active section visible in the horizontally scrolling sub-navigation
  useEffect(() => {
    const ul = navRef.current;
    const a = ul?.querySelector<HTMLElement>('[aria-current="page"]');
    if (ul && a && ul.scrollWidth > ul.clientWidth) ul.scrollLeft += a.getBoundingClientRect().left - ul.getBoundingClientRect().left - (ul.clientWidth - a.offsetWidth) / 2;
  }, [id]);

  if (tab === 'access' || tab === 'users') return <Redirect to="/settings/identity" />;
  if (tab === 'entra' || tab === 'single-sign-on') return <Redirect to="/settings/sso" />;
  if (tab === 'integrations') return <Redirect to="/settings/defender" />;
  if (tab === 'general') return <Redirect to="/settings" />;
  if (!meta) return <NotFoundPage title="Settings section not found" backTo="/settings" backLabel="Open settings" />;
  const Section = SECTION_COMPONENTS[id];

  return (
    <>
      <PageHeader title="Settings" description="Product, governance, notifications, identity and single sign-on, automation, data-plane workers and integrations." />
      <div className="grid gap-6 lg:grid-cols-[220px_minmax(0,1fr)] xl:gap-8">
        <nav aria-label="Settings sections" className="min-w-0">
          <ul ref={navRef} className="scroll-thin -mx-1 flex gap-1 overflow-x-auto px-1 pb-1 lg:sticky lg:top-[72px] lg:mx-0 lg:flex-col lg:overflow-visible lg:px-0 lg:pb-0">
            {SETTINGS_SECTIONS.map((s) => {
              const Icon = s.icon;
              const locked = !!s.systemOnly && !perms.canManageSystem;
              return (
                <li key={s.id} className="shrink-0">
                  <NavLink
                    to={s.path}
                    end
                    className={(active) =>
                      cn(
                        'group flex items-center gap-2.5 whitespace-nowrap rounded-md px-3 py-2 text-[13px] font-medium transition-colors lg:items-start lg:whitespace-normal',
                        active ? 'bg-surface text-fg shadow-card ring-1 ring-border' : 'text-fg-muted hover:bg-surface-3 hover:text-fg'
                      )
                    }
                  >
                    <Icon className="h-4 w-4 shrink-0 text-fg-subtle group-aria-[current=page]:text-accent lg:mt-0.5" aria-hidden />
                    <span className="min-w-0">
                      <span className="block">{s.label}</span>
                      <span className="hidden text-[11.5px] font-normal leading-4 text-fg-subtle lg:block">{locked ? 'InfoSec and Super Admins' : s.description}</span>
                    </span>
                  </NavLink>
                </li>
              );
            })}
          </ul>
        </nav>
        <section aria-label={meta.label} className="min-w-0">
          <Section />
        </section>
      </div>
    </>
  );
};
