import React from 'react';
import { ChevronsLeft, ChevronsRight } from 'lucide-react';
import { cn } from '../lib/cn';
import { NavLink } from '../lib/router';
import { useConsole, useFlows } from '../data/AppData';
import { Tooltip } from '../ui';
import { LogoMark, Wordmark } from './Logo';
import { NAV, NavBadge, NavItem, navItemVisible } from './nav';

const badgeTone: Record<string, string> = {
  danger: 'bg-danger-solid text-white',
  warning: 'bg-warning-solid text-white',
  neutral: 'bg-sidebar-active text-sidebar-fg',
  accent: 'bg-primary text-white',
  info: 'bg-info-solid text-white',
  success: 'bg-success-solid text-white',
  violet: 'bg-violet-solid text-white',
};

const NavEntry: React.FC<{ item: NavItem; collapsed: boolean; badge: NavBadge | null; live?: boolean; onNavigate?: () => void }> = ({
  item,
  collapsed,
  badge,
  live,
  onNavigate,
}) => {
  const Icon = item.icon;
  const link = (
    <NavLink
      to={item.to}
      match={item.match}
      end={item.end}
      onClick={onNavigate}
      aria-label={collapsed ? `${item.label}${badge ? ` (${badge.label})` : ''}` : undefined}
      className={(active) =>
        cn(
          'group relative flex h-9 items-center gap-3 rounded-md text-[13px] font-medium outline-hidden transition-colors focus-visible:ring-2 focus-visible:ring-ring/70',
          collapsed ? 'w-9 justify-center' : 'px-2.5',
          active ? 'bg-sidebar-active text-white' : 'text-sidebar-fg/80 hover:bg-sidebar-hover hover:text-white'
        )
      }
    >
      <Icon className="h-[18px] w-[18px] shrink-0 opacity-90" aria-hidden />
      {!collapsed && <span className="min-w-0 flex-1 truncate">{item.label}</span>}
      {!collapsed && live && <span className="h-1.5 w-1.5 rounded-full bg-success-solid" title="Live stream connected" />}
      {badge &&
        (collapsed ? (
          <span className={cn('absolute right-1 top-1 h-2 w-2 rounded-full ring-2 ring-sidebar', badge.tone === 'danger' ? 'bg-danger-solid' : 'bg-warning-solid')} aria-hidden />
        ) : (
          <span
            title={badge.label}
            className={cn('inline-flex h-[18px] min-w-[20px] items-center justify-center rounded-full px-1.5 text-[11px] font-semibold tabular', badgeTone[badge.tone])}
          >
            {badge.count > 99 ? '99+' : badge.count}
          </span>
        ))}
    </NavLink>
  );
  return collapsed ? (
    <Tooltip content={badge ? `${item.label} — ${badge.label}` : item.label} className="w-full justify-center">
      {link}
    </Tooltip>
  ) : (
    link
  );
};

/** Grouped navigation. Used in the desktop sidebar and the mobile off-canvas menu. */
export const SidebarNav: React.FC<{ collapsed?: boolean; onNavigate?: () => void }> = ({ collapsed = false, onNavigate }) => {
  const { state, perms } = useConsole();
  const { connected } = useFlows();
  return (
    <nav aria-label="Main" className={cn('flex flex-col gap-5', collapsed && 'items-center')}>
      {NAV.map((section) => (
        <div key={section.id} className={cn('flex flex-col gap-0.5', collapsed && 'items-center')}>
          {section.title &&
            (collapsed ? (
              <div className="mx-auto mb-1 h-px w-5 bg-sidebar-border" aria-hidden />
            ) : (
              <div className="mb-1 px-2.5 text-[11.5px] font-medium text-sidebar-muted">{section.title}</div>
            ))}
          {section.items.filter((item) => navItemVisible(item, perms)).map((item) => (
            <NavEntry
              key={item.id}
              item={item}
              collapsed={collapsed}
              badge={state && item.badge ? item.badge(state) : null}
              live={item.id === 'traffic' && connected}
              onNavigate={onNavigate}
            />
          ))}
        </div>
      ))}
    </nav>
  );
};

/** Desktop sidebar (≥ lg). Collapsible to an icon rail. */
export const Sidebar: React.FC<{ collapsed: boolean; onToggle: () => void }> = ({ collapsed, onToggle }) => {
  const { version } = useConsole();
  return (
    <aside
      className={cn(
        'fixed inset-y-0 left-0 z-40 hidden flex-col border-r border-sidebar-border bg-sidebar text-sidebar-fg transition-[width] duration-200 lg:flex',
        collapsed ? 'w-[64px]' : 'w-[248px]'
      )}
    >
      <div className={cn('flex h-14 shrink-0 items-center gap-2.5 border-b border-sidebar-border', collapsed ? 'justify-center px-0' : 'px-4')}>
        <LogoMark className="h-8 w-8 shrink-0" />
        {!collapsed && <Wordmark className="text-white" sub={version ? `Enterprise ${version.replace(/-dev$/, '')}` : 'Enterprise'} />}
      </div>
      <div className={cn('scroll-thin min-h-0 flex-1 overflow-y-auto py-4', collapsed ? 'px-0' : 'px-3')}>
        <SidebarNav collapsed={collapsed} />
      </div>
      <div className={cn('flex shrink-0 items-center border-t border-sidebar-border py-2', collapsed ? 'justify-center' : 'justify-between px-3')}>
        {!collapsed && <span className="truncate text-[11.5px] text-sidebar-muted">{version ? `Control plane ${version}` : ''}</span>}
        <Tooltip content={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}>
          <button
            type="button"
            onClick={onToggle}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            className="flex h-8 w-8 items-center justify-center rounded-md text-sidebar-muted hover:bg-sidebar-hover hover:text-white"
          >
            {collapsed ? <ChevronsRight className="h-4 w-4" /> : <ChevronsLeft className="h-4 w-4" />}
          </button>
        </Tooltip>
      </div>
    </aside>
  );
};
