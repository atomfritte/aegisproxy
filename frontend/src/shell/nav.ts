// Sidebar navigation (also used by the command palette). Add a page here AND in src/routes.tsx.
import type { LucideIcon } from 'lucide-react';
import {
  Activity,
  Ban,
  BarChart3,
  CheckCircle2,
  FileWarning,
  GitPullRequestArrow,
  History,
  Inbox,
  LayoutDashboard,
  Layers,
  Lock,
  PackageCheck,
  PackageSearch,
  Radar,
  ScrollText,
  Server,
  ServerCog,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Boxes,
} from 'lucide-react';
import type { Permissions } from '../data/permissions';
import type { DashboardState } from '../types';
import type { Tone } from '../ui';

export interface NavBadge {
  count: number;
  tone: Tone;
  /** Accessible description, e.g. "2 pending, 1 overdue". */
  label: string;
}

export interface NavItem {
  id: string;
  label: string;
  to: string;
  icon: LucideIcon;
  /** Pattern used for the active state (prefix match). Defaults to `to`. */
  match?: string;
  /** Exact-match the active state (no prefix) — for a section landing page like /packages. */
  end?: boolean;
  /** Short description (command palette). */
  description: string;
  /** Extra search terms for the command palette. */
  keywords?: string;
  badge?: (state: DashboardState) => NavBadge | null;
  /** Hide the entry for roles that cannot open the page (the server enforces it anyway). */
  visible?: (perms: Permissions) => boolean;
}

export interface NavSection {
  id: string;
  title?: string;
  items: NavItem[];
}

const n = (v: number | undefined) => v ?? 0;

export const NAV: NavSection[] = [
  {
    id: 'home',
    items: [
      {
        id: 'overview',
        label: 'Overview',
        to: '/',
        icon: LayoutDashboard,
        description: 'Work queues, policy and fleet health',
        keywords: 'home dashboard',
      },
    ],
  },
  {
    id: 'policy',
    title: 'Policy',
    items: [
      {
        id: 'policies',
        label: 'Policy sets',
        to: '/policies',
        icon: Layers,
        description: 'Versioned rule sets, drafts, recertification',
        keywords: 'rules whitelist allow block baseline',
        badge: (s) => {
          const overdue = n(s.overview?.recertification_overdue);
          return overdue > 0 ? { count: overdue, tone: 'danger', label: `${overdue} overdue for recertification` } : null;
        },
      },
      {
        id: 'changes',
        label: 'Change requests',
        to: '/changes',
        icon: GitPullRequestArrow,
        description: 'Four-eyes review of policy changes',
        keywords: 'review approve cr',
        badge: (s) => {
          const c = n(s.overview?.changes_to_review);
          return c > 0 ? { count: c, tone: 'warning', label: `${c} to review` } : null;
        },
      },
      {
        id: 'requests',
        label: 'Access requests',
        to: '/requests',
        icon: Inbox,
        description: 'Requests from blocked servers',
        keywords: 'approvals queue sla assign extend revoke bulk',
        badge: (s) => {
          const p = n(s.overview?.pending_requests);
          const o = n(s.overview?.overdue_requests);
          return p > 0 ? { count: p, tone: o > 0 ? 'danger' : 'warning', label: `${p} pending${o ? `, ${o} overdue` : ''}` } : null;
        },
      },
      {
        id: 'learning',
        label: 'Learning sessions',
        to: '/learning',
        icon: Radar,
        description: 'Record traffic and turn it into rules',
        keywords: 'record session studio candidates publish',
      },
    ],
  },
  {
    id: 'fleet',
    title: 'Fleet',
    items: [
      {
        id: 'servers',
        label: 'Servers',
        to: '/servers',
        icon: Server,
        description: 'Inventory, labels, quarantine, onboarding',
        keywords: 'hosts inventory import export quarantine discovered onboarding register token labels',
        badge: (s) => {
          const q = n(s.overview?.quarantined_servers);
          return q > 0 ? { count: q, tone: 'danger', label: `${q} quarantined` } : null;
        },
      },
      {
        id: 'groups',
        label: 'Groups',
        to: '/groups',
        icon: Boxes,
        description: 'Server groups and dynamic label selectors',
        keywords: 'cidr labels dynamic selector strict isolation',
      },
    ],
  },
  {
    id: 'traffic',
    title: 'Traffic',
    items: [
      {
        id: 'traffic',
        label: 'Live traffic',
        to: '/traffic',
        icon: Activity,
        description: 'Live flows and policy simulator',
        keywords: 'flows tracing stream simulate',
      },
      {
        id: 'bandwidth',
        label: 'Bandwidth',
        to: '/bandwidth',
        icon: BarChart3,
        description: 'Throughput and top talkers',
        keywords: 'volume mbps',
      },
    ],
  },
  {
    id: 'packages',
    title: 'Packages',
    items: [
      {
        id: 'packages-overview',
        label: 'Package firewall',
        to: '/packages',
        end: true,
        icon: PackageCheck,
        description: 'Ecosystems, work queues, sandbox health and recent decisions',
        keywords: 'package firewall npm pypi nuget powershell gallery registry supply chain overview',
      },
      {
        id: 'packages-requests',
        label: 'Requests',
        to: '/packages/requests',
        icon: PackageSearch,
        description: 'Request and review packages with the dependency graph',
        keywords: 'request review dependency graph assessment sandbox approve reject karenz cooldown',
      },
      {
        id: 'packages-approvals',
        label: 'Approvals',
        to: '/packages/approvals',
        icon: CheckCircle2,
        description: 'Approved versions, pinned files, revoke and extend',
        keywords: 'approved versions pins sha256 sha512 revoke extend expiry',
      },
      {
        id: 'packages-rules',
        label: 'Rules',
        to: '/packages/rules',
        icon: ScrollText,
        description: 'Cooldown, auto-approve, review and block rules',
        keywords: 'rules cooldown karenz auto approve review block priority glob severity risk signature provenance',
      },
      {
        id: 'packages-blocks',
        label: 'Block list',
        to: '/packages/blocks',
        icon: Ban,
        description: 'Versions denied regardless of approvals',
        keywords: 'block list deny malicious banned versions',
      },
      {
        id: 'packages-receivers',
        label: 'Receivers',
        to: '/packages/receivers',
        icon: ServerCog,
        description: 'Which servers obtained a package',
        keywords: 'receivers incident who downloaded servers investigation forensics telemetry',
      },
    ],
  },
  {
    id: 'security',
    title: 'Security',
    items: [
      {
        id: 'threats',
        label: 'Threat protection',
        to: '/threats',
        icon: ShieldAlert,
        description: 'Threat intel, antivirus, ICAP, YARA, DLP, security events',
        keywords: 'ioc feeds malware events yara icap taxii misp dlp antivirus clamav sandbox',
        badge: (s) => {
          const e = n(s.stats?.open_security_events);
          return e > 0 ? { count: e, tone: 'danger', label: `${e} unacknowledged events` } : null;
        },
      },
      {
        id: 'tls',
        label: 'TLS & CA',
        to: '/tls',
        icon: Lock,
        description: 'TLS inspection exceptions and the root CA',
        keywords: 'certificate bypass ssl',
      },
      {
        id: 'block-pages',
        label: 'Block pages',
        to: '/block-pages',
        icon: FileWarning,
        description: 'Branded block page templates',
        keywords: 'branding template designer preview logo self-service',
      },
    ],
  },
  {
    id: 'governance',
    title: 'Governance',
    items: [
      {
        id: 'audit',
        label: 'Audit trail',
        to: '/audit',
        icon: History,
        description: 'Hash-chained audit log',
        keywords: 'log compliance export jsonl',
      },
      {
        id: 'posture',
        label: 'Security posture',
        to: '/posture',
        icon: ShieldCheck,
        description: 'Hardening checks with remediation',
        keywords: 'score hardening compliance checklist cis best practice',
        visible: (p) => p.canManageSystem,
      },
      {
        id: 'settings',
        label: 'Settings',
        to: '/settings',
        icon: Settings,
        description: 'Users, SSO, service accounts, notifications, governance, integrations',
        keywords: 'configuration preferences admin appearance theme',
      },
    ],
  },
];

export const NAV_ITEMS: NavItem[] = NAV.flatMap((s) => s.items);

/** Navigation entries the given role may open. */
export const navItemVisible = (item: NavItem, perms: Permissions) => !item.visible || item.visible(perms);
