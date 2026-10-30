import React from 'react';
import { Check, KeyRound, LogOut, Menu as MenuIcon, Monitor, Moon, Rows3, Search, Sun } from 'lucide-react';
import { cn } from '../lib/cn';
import { useTheme } from '../lib/theme';
import { useConsole, useFlows, useLastUpdated } from '../data/AppData';
import { ROLE_LABELS } from '../data/permissions';
import { useSession } from '../data/session';
import { Avatar, IconButton, Kbd, Menu, modKey, Tooltip } from '../ui';
import { LogoMark } from './Logo';

export const Topbar: React.FC<{ onOpenPalette: () => void; onOpenMobileNav: () => void; onChangePassword: () => void }> = ({
  onOpenPalette,
  onOpenMobileNav,
  onChangePassword,
}) => {
  const { user, logout } = useSession();
  const { connected } = useFlows();
  const { error } = useConsole();
  const lastUpdated = useLastUpdated();
  const { theme, setTheme, resolvedTheme, density, setDensity } = useTheme();
  const ThemeIcon = theme === 'system' ? Monitor : resolvedTheme === 'dark' ? Moon : Sun;

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-2 border-b border-border bg-surface/90 px-3 backdrop-blur-sm supports-[backdrop-filter]:bg-surface/75 sm:px-5">
      <IconButton icon={MenuIcon} label="Open navigation" onClick={onOpenMobileNav} className="lg:hidden" noTooltip />
      <LogoMark className="h-7 w-7 lg:hidden" />

      <button
        type="button"
        onClick={onOpenPalette}
        className="ml-1 flex h-9 min-w-0 flex-1 items-center gap-2.5 rounded-md border border-border bg-surface-2 px-3 text-left text-[13px] text-fg-subtle transition-colors hover:border-border-strong hover:text-fg-muted sm:max-w-[420px]"
        aria-label="Search or jump to (command palette)"
      >
        <Search className="h-4 w-4 shrink-0" aria-hidden />
        <span className="min-w-0 flex-1 truncate">Search or jump to…</span>
        <span className="hidden items-center gap-1 sm:flex">
          <Kbd>{modKey()}</Kbd>
          <Kbd>K</Kbd>
        </span>
      </button>

      <div className="ml-auto flex items-center gap-1">
        <Tooltip
          content={
            error
              ? `Console data could not be refreshed: ${error}`
              : connected
              ? 'Live traffic stream connected'
              : 'Live traffic stream reconnecting'
          }
        >
          <span
            className={cn(
              'mr-1 hidden h-7 items-center gap-1.5 rounded-full border px-2.5 text-[12px] font-medium sm:inline-flex',
              error ? 'border-danger-border bg-danger-soft text-danger' : connected ? 'border-success-border bg-success-soft text-success' : 'border-warning-border bg-warning-soft text-warning'
            )}
          >
            <span className={cn('h-1.5 w-1.5 rounded-full', error ? 'bg-danger-solid' : connected ? 'bg-success-solid' : 'bg-warning-solid')} />
            {error ? 'Offline' : connected ? 'Live' : 'Connecting'}
            {lastUpdated === null && !error && <span className="sr-only">loading</span>}
          </span>
        </Tooltip>

        <Menu
          align="end"
          items={[
            { id: 'light', label: 'Light', icon: theme === 'light' ? Check : Sun, onSelect: () => setTheme('light') },
            { id: 'dark', label: 'Dark', icon: theme === 'dark' ? Check : Moon, onSelect: () => setTheme('dark') },
            { id: 'system', label: 'System', icon: theme === 'system' ? Check : Monitor, onSelect: () => setTheme('system') },
            {
              id: 'density',
              separator: true,
              label: density === 'compact' ? 'Comfortable density' : 'Compact density',
              icon: Rows3,
              onSelect: () => setDensity(density === 'compact' ? 'comfortable' : 'compact'),
            },
          ]}
          trigger={(p) => (
            <Tooltip content="Appearance">
              <button
                {...p}
                type="button"
                aria-label="Appearance"
                className="flex h-9 w-9 items-center justify-center rounded-md text-fg-muted transition-colors hover:bg-surface-3 hover:text-fg"
              >
                <ThemeIcon className="h-[18px] w-[18px]" />
              </button>
            </Tooltip>
          )}
        />

        {user && (
          <Menu
            align="end"
            header={
              <div className="min-w-0 py-0.5">
                <div className="truncate text-[13px] font-semibold text-fg">{user.display_name || user.username}</div>
                <div className="truncate text-[12px] text-fg-subtle">
                  @{user.username}, {ROLE_LABELS[user.role]}
                </div>
                {user.role === 'TEAM_LEAD_APPROVER' && (
                  <div className="mt-1 truncate text-[12px] text-fg-subtle">Groups: {(user.allowed_groups ?? []).join(', ') || 'none'}</div>
                )}
              </div>
            }
            items={[
              { id: 'pw', label: 'Change password', icon: KeyRound, onSelect: onChangePassword },
              { id: 'logout', label: 'Sign out', icon: LogOut, onSelect: () => void logout(), separator: true },
            ]}
            trigger={(p) => (
              <button
                {...p}
                type="button"
                aria-label="Account menu"
                className="ml-1 flex h-9 items-center gap-2 rounded-md px-1.5 transition-colors hover:bg-surface-3"
              >
                <Avatar name={user.display_name || user.username} size="sm" />
                <span className="hidden min-w-0 text-left leading-tight md:block">
                  <span className="block max-w-[160px] truncate text-[12.5px] font-medium text-fg">{user.username}</span>
                  <span className="block max-w-[160px] truncate text-[11.5px] text-fg-subtle">{ROLE_LABELS[user.role]}</span>
                </span>
              </button>
            )}
          />
        )}
      </div>
    </header>
  );
};
