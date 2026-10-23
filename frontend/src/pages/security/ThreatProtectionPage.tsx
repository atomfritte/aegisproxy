import React from 'react';
import { Ban, Database, FileCheck2, FileCode2, LayoutDashboard, ScanSearch, ShieldAlert, SlidersHorizontal } from 'lucide-react';
import { useDocumentTitle } from '../../lib/hooks';
import { navigate, useLocation, useParams } from '../../lib/router';
import { PageHeader, TabPanel, Tabs } from '../../ui';
import { NotFoundPage } from '../system/NotFoundPage';
import { ModeBadge } from './threats/components';
import { EventsTab } from './threats/EventsTab';
import { ExceptionsTab } from './threats/ExceptionsTab';
import { FeedsTab } from './threats/FeedsTab';
import { IocsTab } from './threats/IocsTab';
import { LookupTab } from './threats/LookupTab';
import { tabPath, THREAT_TABS, ThreatTab } from './threats/meta';
import { OverviewTab } from './threats/OverviewTab';
import { PolicyTab } from './threats/PolicyTab';
import { useThreatData } from './threats/useThreatData';
import { YaraTab } from './threats/YaraTab';

const TITLES: Record<ThreatTab, string> = {
  overview: 'Threat protection',
  events: 'Security events',
  feeds: 'Threat feeds',
  iocs: 'Custom indicators',
  exceptions: 'Exceptions',
  yara: 'YARA rules',
  policy: 'Protection policy',
  lookup: 'Threat lookup',
};

/**
 * Threat protection: overview, security events (/threats/events/:id deep links from Teams/Slack),
 * threat-intel feeds, custom IOCs, false-positive exceptions, the protection policy and lookup.
 */
export const ThreatProtectionPage: React.FC = () => {
  const { tab: rawTab, id } = useParams<{ tab?: string; id?: string }>();
  const { search } = useLocation();
  const d = useThreatData();
  const tab = (rawTab ?? 'overview') as ThreatTab;
  const valid = (THREAT_TABS as readonly string[]).includes(tab) && (!id || tab === 'events' || tab === 'yara') && rawTab !== 'overview';
  useDocumentTitle(valid ? TITLES[tab] : 'Threat protection');
  // keep the active tab visible in the horizontally scrolling tab bar (phones)

  if (!valid) {
    return <NotFoundPage title="Page not found" description="This threat protection page does not exist." backTo="/threats" backLabel="Threat protection" />;
  }

  const p = d.policy;
  const openCount = d.openEvents.length;
  const hasCritical = d.openEvents.some((e) => e.severity === 'critical' || e.severity === 'high');

  return (
    <>
      <PageHeader
        title="Threat protection"
        description="Threat intelligence, antivirus (ClamAV, ICAP engines), YARA, data loss prevention and download control — enforced by every data-plane worker, also for allowed destinations."
        meta={
          p && (
            <>
              <ModeBadge mode={p.threat_intel_mode} prefix="Threat intel" />
              <ModeBadge mode={p.av_enabled ? p.av_mode : 'off'} prefix="Antivirus" />
              <ModeBadge mode={p.dlp_mode} prefix="DLP" />
              {p.icap_respmod_url || p.icap_reqmod_url ? <ModeBadge mode={p.icap_mode} prefix="ICAP" /> : null}
              <ModeBadge mode={p.yara_mode || 'off'} prefix="YARA" />
            </>
          )
        }
      />
      <Tabs<ThreatTab>
        idPrefix="threats"
        aria-label="Threat protection sections"
        className="mb-6"
        value={tab}
        onChange={(t) => navigate(tabPath(t) + (t === tab ? search : ''), { preserveScroll: true })}
        tabs={[
          { id: 'overview', label: 'Overview', icon: LayoutDashboard },
          { id: 'events', label: 'Events', icon: ShieldAlert, count: openCount || null, countTone: hasCritical ? 'danger' : 'warning' },
          { id: 'feeds', label: 'Feeds', icon: Database, count: d.feeds.filter((f) => f.enabled).length },
          { id: 'iocs', label: 'Indicators', icon: Ban, count: d.indicators.length },
          { id: 'exceptions', label: 'Exceptions', icon: FileCheck2, count: d.exceptions.length },
          { id: 'yara', label: 'YARA', icon: FileCode2 },
          { id: 'policy', label: 'Policy', icon: SlidersHorizontal },
          { id: 'lookup', label: 'Lookup', icon: ScanSearch },
        ]}
      />
      <TabPanel id={tab} idPrefix="threats">
        {tab === 'overview' && <OverviewTab />}
        {tab === 'events' && <EventsTab eventId={id} />}
        {tab === 'feeds' && <FeedsTab />}
        {tab === 'iocs' && <IocsTab />}
        {tab === 'exceptions' && <ExceptionsTab />}
        {tab === 'yara' && <YaraTab id={id} />}
        {tab === 'policy' && <PolicyTab />}
        {tab === 'lookup' && <LookupTab />}
      </TabPanel>
    </>
  );
};

