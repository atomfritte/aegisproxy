import React, { useEffect, useMemo, useRef, useState } from 'react';
import type { LucideIcon } from 'lucide-react';
import {
  Boxes,
  CornerDownLeft,
  Database,
  ExternalLink,
  FileCode2,
  FileUp,
  FileWarning,
  GitPullRequestArrow,
  Radar,
  ShieldAlert,
  SlidersHorizontal,
  Inbox,
  KeyRound,
  Layers,
  LogOut,
  Monitor,
  Moon,
  PackagePlus,
  Plus,
  RefreshCw,
  Rows3,
  Search,
  Server,
  Sun,
} from 'lucide-react';
import { cn } from '../lib/cn';
import { useFocusTrap, useScrollLock } from '../lib/hooks';
import { navigate } from '../lib/router';
import { useTheme } from '../lib/theme';
import { useConsole } from '../data/AppData';
import { useSession } from '../data/session';
import { Kbd, Portal } from '../ui';
import { NAV_ITEMS, navItemVisible } from './nav';
import { SETTINGS_SECTIONS } from '../pages/governance/settings/shared';

interface PaletteItem {
  id: string;
  group: string;
  label: string;
  sub?: string;
  icon: LucideIcon;
  keywords?: string;
  run: () => void;
}

function score(item: PaletteItem, terms: string[]): number {
  if (terms.length === 0) return 1;
  const label = item.label.toLowerCase();
  const hay = `${label} ${(item.sub || '').toLowerCase()} ${(item.keywords || '').toLowerCase()} ${item.group.toLowerCase()}`;
  const words = new Set((item.keywords || '').toLowerCase().split(/\s+/));
  let s = 0;
  for (const t of terms) {
    if (!hay.includes(t)) return 0;
    s += label.startsWith(t) ? 4 : label.includes(t) ? 2 : words.has(t) ? 2 : 1;
  }
  return s;
}

/** Ctrl/Cmd+K: jump to pages and entities, run quick actions. */
export const CommandPalette: React.FC<{ open: boolean; onClose: () => void; onChangePassword: () => void }> = ({ open, onClose, onChangePassword }) => {
  const { state, perms, refresh } = useConsole();
  const { logout } = useSession();
  const { setTheme, density, setDensity } = useTheme();
  const [q, setQ] = useState('');
  const [active, setActive] = useState(0);
  const panelRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  useScrollLock(open);
  useFocusTrap(panelRef, open);

  useEffect(() => {
    if (open) {
      setQ('');
      setActive(0);
    }
  }, [open]);

  const items = useMemo<PaletteItem[]>(() => {
    const go = (to: string) => () => navigate(to);
    const out: PaletteItem[] = [];
    const pages: PaletteItem[] = NAV_ITEMS.filter((n) => navItemVisible(n, perms)).map((n) => ({
      id: `nav-${n.id}`,
      group: 'Pages',
      label: n.label,
      sub: n.description,
      icon: n.icon,
      keywords: n.keywords,
      run: go(n.to),
    }));
    // deep pages that are tabs of a top-level page
    pages.push(
      { id: 'nav-threat-events', group: 'Pages', label: 'Security events', sub: 'Threat protection', icon: ShieldAlert, keywords: 'alerts incidents acknowledge', run: go('/threats/events') },
      { id: 'nav-threat-feeds', group: 'Pages', label: 'Threat feeds', sub: 'Threat protection · lists, TAXII, MISP, Defender', icon: Database, keywords: 'taxii misp stix blocklist intel', run: go('/threats/feeds') },
      { id: 'nav-yara', group: 'Pages', label: 'YARA rules', sub: 'Threat protection · rule sets and compile status', icon: FileCode2, keywords: 'yara-x malware signatures detection', run: go('/threats/yara') },
      { id: 'nav-threat-policy', group: 'Pages', label: 'Protection policy', sub: 'Threat protection · antivirus, ICAP, YARA, DLP', icon: SlidersHorizontal, keywords: 'icap clamav dlp download control hygiene', run: go('/threats/policy') }
    );
    const navCount = pages.length;
    out.push(...pages);
    const actions: PaletteItem[] = [];
    if (!perms.isReadOnly) {
      actions.push(
        { id: 'act-new-set', group: 'Actions', label: 'Create policy set', icon: Plus, keywords: 'new add rule', run: go('/policies/new') },
        { id: 'act-import-sets', group: 'Actions', label: 'Import policy sets', icon: FileUp, keywords: 'policy as code json bundle gitops', run: go('/policies?import=1') },
        { id: 'act-request-package', group: 'Actions', label: 'Request a package', icon: PackagePlus, keywords: 'npm pypi nuget powershell gallery package firewall dependency new', run: go('/packages/requests?new=1') }
      );
    }
    if (perms.canManageSystem) actions.push({ id: 'act-new-yara', group: 'Actions', label: 'Create YARA rule set', icon: FileCode2, keywords: 'new add yara', run: go('/threats/yara/new') });
    if (perms.isSuperAdmin) actions.push({ id: 'act-new-sa', group: 'Actions', label: 'Create service account', icon: KeyRound, keywords: 'api key token automation new', run: go('/settings/service-accounts?new=1') });
    actions.push(
      { id: 'act-refresh', group: 'Actions', label: 'Refresh data', icon: RefreshCw, keywords: 'reload', run: () => void refresh() },
      { id: 'act-light', group: 'Actions', label: 'Use light theme', icon: Sun, keywords: 'appearance', run: () => setTheme('light') },
      { id: 'act-dark', group: 'Actions', label: 'Use dark theme', icon: Moon, keywords: 'appearance', run: () => setTheme('dark') },
      { id: 'act-system', group: 'Actions', label: 'Use system theme', icon: Monitor, keywords: 'appearance auto', run: () => setTheme('system') },
      {
        id: 'act-density',
        group: 'Actions',
        label: density === 'compact' ? 'Use comfortable density' : 'Use compact density',
        icon: Rows3,
        keywords: 'spacing rows',
        run: () => setDensity(density === 'compact' ? 'comfortable' : 'compact'),
      },
      { id: 'act-portal', group: 'Actions', label: 'Open block page portal', icon: ExternalLink, keywords: 'public ca certificate', run: go('/?portal=block') },
      { id: 'act-password', group: 'Actions', label: 'Change password', icon: KeyRound, run: onChangePassword },
      { id: 'act-logout', group: 'Actions', label: 'Sign out', icon: LogOut, keywords: 'logout', run: () => void logout() }
    );
    for (const sec of SETTINGS_SECTIONS) {
      if (sec.systemOnly && !perms.canManageSystem) continue;
      out.push({ id: `set-${sec.id}`, group: 'Settings', label: sec.label, sub: sec.description, icon: sec.icon, keywords: `settings ${sec.keywords ?? ''}`, run: go(sec.path) });
    }
    if (state) {
      for (const b of state.block_pages ?? []) {
        out.push({
          id: `bp-${b.id}`,
          group: 'Block pages',
          label: b.name,
          sub: `${b.is_default ? 'Default template · ' : ''}${b.company_name || b.id}`,
          icon: FileWarning,
          keywords: `${b.id} block page template branding ${b.title}`,
          run: go(`/block-pages/${encodeURIComponent(b.id)}`),
        });
      }
      for (const ls of state.sessions ?? []) {
        out.push({
          id: `ls-${ls.id}`,
          group: 'Learning sessions',
          label: ls.name,
          sub: `${ls.server_hostname || ls.server_ip} · ${ls.status} · ${ls.captured_flow_count} requests`,
          icon: Radar,
          keywords: `${ls.id} learning recording ${ls.server_id}`,
          run: go(`/learning?session=${encodeURIComponent(ls.id)}`),
        });
      }
      for (const s of state.policy_sets ?? []) {
        out.push({ id: `ps-${s.id}`, group: 'Policy sets', label: s.name, sub: `${s.kind} · v${s.version} · ${(s.rules ?? []).length} rules`, icon: Layers, keywords: `${s.id} ${(s.tags ?? []).join(' ')} ${s.owner_team}`, run: go(`/policies/${encodeURIComponent(s.id)}`) });
      }
      for (const c of state.change_requests ?? []) {
        out.push({ id: `cr-${c.id}`, group: 'Change requests', label: c.title, sub: `${c.policy_set_name} · ${c.status} · by ${c.submitted_by}`, icon: GitPullRequestArrow, keywords: c.id, run: go(`/changes/${encodeURIComponent(c.id)}`) });
      }
      for (const r of state.requests ?? []) {
        out.push({ id: `rq-${r.id}`, group: 'Access requests', label: `${r.host}${r.path ? r.path.slice(0, 40) : ''}`, sub: `${r.server_hostname || r.server_ip} · ${r.status}`, icon: Inbox, keywords: `${r.id} ${r.requester}`, run: go(`/requests/${encodeURIComponent(r.id)}`) });
      }
      for (const s of state.servers ?? []) {
        out.push({ id: `srv-${s.id}`, group: 'Servers', label: s.hostname, sub: `${s.ip} · ${s.id}`, icon: Server, keywords: Object.entries(s.labels || {}).map(([k, v]) => `${k}=${v}`).join(' '), run: go(`/servers/${encodeURIComponent(s.id)}`) });
      }
      for (const g of state.groups ?? []) {
        out.push({ id: `grp-${g.id}`, group: 'Groups', label: g.name, sub: g.id, icon: Boxes, keywords: g.environment, run: go(`/groups/${encodeURIComponent(g.id)}`) });
      }
    }
    return [...out.slice(0, navCount), ...actions, ...out.slice(navCount)];
  }, [state, perms, refresh, setTheme, density, setDensity, onChangePassword, logout]);

  const results = useMemo(() => {
    const terms = q.trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (terms.length === 0) {
      const pending = items.filter((i) => i.id.startsWith('cr-') || i.id.startsWith('rq-')).filter((i) => /open|pending/.test(i.sub || ''));
      return [
        ...items.filter((i) => i.group === 'Pages' && i.id.startsWith('nav-') && !['nav-threat-events', 'nav-threat-feeds', 'nav-yara', 'nav-threat-policy'].includes(i.id)),
        ...pending.slice(0, 5).map((i) => ({ ...i, group: 'Needs attention' })),
        ...items.filter((i) => i.group === 'Actions'),
      ];
    }
    const scored = items.map((i) => ({ i, s: score(i, terms) })).filter((x) => x.s > 0);
    const byGroup = new Map<string, Array<{ i: PaletteItem; s: number }>>();
    for (const x of scored) {
      const arr = byGroup.get(x.i.group) || [];
      arr.push(x);
      byGroup.set(x.i.group, arr);
    }
    const groups = [...byGroup.entries()]
      .map(([g, arr]) => ({ g, arr: arr.sort((a, b) => b.s - a.s).slice(0, 6), best: Math.max(...arr.map((a) => a.s)) }))
      .sort((a, b) => b.best - a.best);
    return groups.flatMap((g) => g.arr.map((a) => a.i));
  }, [items, q]);

  useEffect(() => setActive(0), [q]);
  useEffect(() => {
    listRef.current?.querySelector(`[data-idx="${active}"]`)?.scrollIntoView({ block: 'nearest' });
  }, [active]);

  if (!open) return null;

  const runItem = (it: PaletteItem) => {
    onClose();
    window.setTimeout(it.run, 0);
  };

  let lastGroup = '';
  return (
    <Portal>
      <div className="fixed inset-0 z-[95] flex items-start justify-center px-3 pt-[10vh]">
        <div className="absolute inset-0 bg-black/45 animate-fade-in" onClick={onClose} aria-hidden />
        <div
          ref={panelRef}
          role="dialog"
          aria-modal="true"
          aria-label="Command palette"
          className="relative flex max-h-[70vh] w-full max-w-[620px] flex-col overflow-hidden rounded-xl border border-border bg-surface shadow-pop animate-pop-in"
          onKeyDown={(e) => {
            if (e.key === 'Escape') {
              e.preventDefault();
              onClose();
            } else if (e.key === 'ArrowDown') {
              e.preventDefault();
              setActive((a) => Math.min(results.length - 1, a + 1));
            } else if (e.key === 'ArrowUp') {
              e.preventDefault();
              setActive((a) => Math.max(0, a - 1));
            } else if (e.key === 'Enter') {
              e.preventDefault();
              const it = results[active];
              if (it) runItem(it);
            }
          }}
        >
          <div className="flex items-center gap-3 border-b border-border px-4">
            <Search className="h-4 w-4 shrink-0 text-fg-subtle" aria-hidden />
            <input
              data-autofocus
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search pages, settings, policy sets, servers, requests…"
              aria-label="Search commands"
              aria-controls="palette-list"
              aria-activedescendant={results[active] ? `pal-${results[active].id}` : undefined}
              className="h-12 min-w-0 flex-1 bg-transparent text-[14px] text-fg outline-hidden placeholder:text-fg-subtle"
            />
            <Kbd>Esc</Kbd>
          </div>
          <div ref={listRef} id="palette-list" role="listbox" className="scroll-thin min-h-0 flex-1 overflow-y-auto p-2">
            {results.length === 0 && <div className="px-3 py-10 text-center text-[13px] text-fg-subtle">No results for “{q}”.</div>}
            {results.map((it, idx) => {
              const header = it.group !== lastGroup ? it.group : null;
              lastGroup = it.group;
              const Icon = it.icon;
              return (
                <React.Fragment key={`${it.group}-${it.id}`}>
                  {header && <div className="px-2.5 pb-1 pt-3 text-[11.5px] font-medium text-fg-subtle first:pt-1">{header}</div>}
                  <div
                    id={`pal-${it.id}`}
                    role="option"
                    aria-selected={idx === active}
                    data-idx={idx}
                    onPointerMove={() => setActive(idx)}
                    onClick={() => runItem(it)}
                    className={cn('flex cursor-pointer items-center gap-3 rounded-lg px-2.5 py-2', idx === active ? 'bg-accent-soft' : '')}
                  >
                    <span className={cn('flex h-7 w-7 shrink-0 items-center justify-center rounded-md border', idx === active ? 'border-accent-border bg-surface text-accent' : 'border-border bg-surface-2 text-fg-muted')}>
                      <Icon className="h-4 w-4" aria-hidden />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-[13px] font-medium text-fg">{it.label}</span>
                      {it.sub && <span className="block truncate text-[12px] text-fg-subtle">{it.sub}</span>}
                    </span>
                    {idx === active && <CornerDownLeft className="h-3.5 w-3.5 shrink-0 text-fg-subtle" aria-hidden />}
                  </div>
                </React.Fragment>
              );
            })}
          </div>
          <div className="hidden items-center gap-4 border-t border-border bg-surface-2 px-4 py-2 text-[12px] text-fg-subtle sm:flex">
            <span className="inline-flex items-center gap-1.5">
              <Kbd>↑</Kbd>
              <Kbd>↓</Kbd> navigate
            </span>
            <span className="inline-flex items-center gap-1.5">
              <Kbd>Enter</Kbd> open
            </span>
            <span className="inline-flex items-center gap-1.5">
              <Kbd>Esc</Kbd> close
            </span>
          </div>
        </div>
      </div>
    </Portal>
  );
};
