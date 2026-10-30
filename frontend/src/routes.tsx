// Route table of the signed-in console. Order matters: first match wins.
// To add a page: create src/pages/<area>/<Name>Page.tsx, add it here, and (for top-level pages)
// add a navigation entry in src/shell/nav.ts. See ARCHITECTURE.md.
import { lazy, type ComponentType } from 'react';
import type { RouteDef } from './lib/router';
import { OverviewPage } from './pages/overview/OverviewPage';

// Larger pages (and pages that still host legacy 2.0 views) are code-split and loaded on first visit.
const page = <K extends string>(load: () => Promise<Record<K, ComponentType>>, name: K) =>
  lazy(() => load().then((m) => ({ default: m[name] })));
// Only the Overview (landing route) is eager. The policy / change-request authoring suite is large and
// off the landing path, so it is code-split like everything else — keeping it out of the initial bundle.
const PolicySetsPage = page(() => import('./pages/policies/PolicySetsPage'), 'PolicySetsPage');
const PolicySetCreatePage = page(() => import('./pages/policies/PolicySetCreatePage'), 'PolicySetCreatePage');
const PolicySetDetailPage = page(() => import('./pages/policies/PolicySetDetailPage'), 'PolicySetDetailPage');
const ChangeRequestsPage = page(() => import('./pages/changes/ChangeRequestsPage'), 'ChangeRequestsPage');
const ChangeRequestDetailPage = page(() => import('./pages/changes/ChangeRequestDetailPage'), 'ChangeRequestDetailPage');
const LoginRedirect = page(() => import('./pages/auth/LoginRedirect'), 'LoginRedirect');
const AccessRequestsPage = page(() => import('./pages/requests/AccessRequestsPage'), 'AccessRequestsPage');
const AccessRequestDetailPage = page(() => import('./pages/requests/AccessRequestDetailPage'), 'AccessRequestDetailPage');
const LearningSessionsPage = page(() => import('./pages/learning/LearningSessionsPage'), 'LearningSessionsPage');
const ServersPage = page(() => import('./pages/servers/ServersPage'), 'ServersPage');
const ServerDetailPage = page(() => import('./pages/servers/ServerDetailPage'), 'ServerDetailPage');
const GroupsPage = page(() => import('./pages/groups/GroupsPage'), 'GroupsPage');
const GroupDetailPage = page(() => import('./pages/groups/GroupDetailPage'), 'GroupDetailPage');
const LiveTrafficPage = page(() => import('./pages/traffic/LiveTrafficPage'), 'LiveTrafficPage');
const BandwidthPage = page(() => import('./pages/traffic/BandwidthPage'), 'BandwidthPage');
const ThreatProtectionPage = page(() => import('./pages/security/ThreatProtectionPage'), 'ThreatProtectionPage');
const TlsCaPage = page(() => import('./pages/security/TlsCaPage'), 'TlsCaPage');
const AuditTrailPage = page(() => import('./pages/governance/AuditTrailPage'), 'AuditTrailPage');
const SettingsPage = page(() => import('./pages/governance/SettingsPage'), 'SettingsPage');
const BlockPagesPage = page(() => import('./pages/security/BlockPagesPage'), 'BlockPagesPage');
const BlockPageEditorPage = page(() => import('./pages/security/BlockPageEditorPage'), 'BlockPageEditorPage');
const PosturePage = page(() => import('./pages/governance/PosturePage'), 'PosturePage');
const PackagesOverviewPage = page(() => import('./pages/packages/PackagesOverviewPage'), 'PackagesOverviewPage');
const PackageRequestsPage = page(() => import('./pages/packages/PackageRequestsPage'), 'PackageRequestsPage');
const PackageRequestDetailPage = page(() => import('./pages/packages/PackageRequestDetailPage'), 'PackageRequestDetailPage');
const PackageApprovalsPage = page(() => import('./pages/packages/PackageApprovalsPage'), 'PackageApprovalsPage');
const PackageRulesPage = page(() => import('./pages/packages/PackageRulesPage'), 'PackageRulesPage');
const PackageBlocksPage = page(() => import('./pages/packages/PackageBlocksPage'), 'PackageBlocksPage');
const PackageReceiversPage = page(() => import('./pages/packages/PackageReceiversPage'), 'PackageReceiversPage');

export const ROUTES: RouteDef[] = [
  { path: '/', component: OverviewPage },
  // Policy
  { path: '/policies', component: PolicySetsPage },
  { path: '/policies/new', component: PolicySetCreatePage },
  { path: '/policies/:id/:tab?', component: PolicySetDetailPage },
  { path: '/changes', component: ChangeRequestsPage },
  { path: '/changes/:id', component: ChangeRequestDetailPage },
  { path: '/requests', component: AccessRequestsPage },
  { path: '/requests/:id', component: AccessRequestDetailPage },
  { path: '/learning', component: LearningSessionsPage },
  // Fleet
  { path: '/servers', component: ServersPage },
  { path: '/servers/:id/:tab?', component: ServerDetailPage },
  { path: '/groups', component: GroupsPage },
  { path: '/groups/:id/:tab?', component: GroupDetailPage },
  // Traffic
  { path: '/traffic', component: LiveTrafficPage },
  { path: '/bandwidth', component: BandwidthPage },
  // Packages (package firewall)
  { path: '/packages', component: PackagesOverviewPage },
  { path: '/packages/requests', component: PackageRequestsPage },
  { path: '/packages/requests/:id', component: PackageRequestDetailPage },
  { path: '/packages/approvals', component: PackageApprovalsPage },
  { path: '/packages/rules', component: PackageRulesPage },
  { path: '/packages/blocks', component: PackageBlocksPage },
  { path: '/packages/receivers', component: PackageReceiversPage },
  // Security
  { path: '/threats/:tab?/:id?', component: ThreatProtectionPage }, // yara/:id = rule set editor
  { path: '/tls', component: TlsCaPage },
  { path: '/block-pages', component: BlockPagesPage },
  { path: '/block-pages/:id', component: BlockPageEditorPage },
  // Governance
  { path: '/audit', component: AuditTrailPage },
  { path: '/posture', component: PosturePage },
  { path: '/settings/:tab?', component: SettingsPage },
  // The SSO callback redirects to /login?sso_error=… — once signed in, continue to the overview.
  { path: '/login', component: LoginRedirect },
];
