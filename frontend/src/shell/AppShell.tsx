import React, { Suspense, useCallback, useEffect, useRef, useState } from 'react';
import { CloudOff, FlaskConical, X } from 'lucide-react';
import { cn } from '../lib/cn';
import { useFocusTrap, useHotkey, useScrollLock } from '../lib/hooks';
import { useLocation } from '../lib/router';
import { readStorage, writeStorage } from '../lib/storage';
import { useConsole } from '../data/AppData';
import { useSession } from '../data/session';
import { Button, EmptyState, PageSkeleton, Portal } from '../ui';
import { ChangePasswordDialog } from './ChangePasswordDialog';
import { CommandPalette } from './CommandPalette';
import { LogoMark, Wordmark } from './Logo';
import { Sidebar, SidebarNav } from './Sidebar';
import { Topbar } from './Topbar';

const SIDEBAR_KEY = 'aegis.sidebar.collapsed';

const MobileNav: React.FC<{ open: boolean; onClose: () => void }> = ({ open, onClose }) => {
  const ref = useRef<HTMLDivElement>(null);
  useScrollLock(open);
  useFocusTrap(ref, open);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <Portal>
      <div className="fixed inset-0 z-[75] lg:hidden">
        <div className="absolute inset-0 bg-black/50 animate-fade-in" onClick={onClose} aria-hidden />
        <div
          ref={ref}
          role="dialog"
          aria-modal="true"
          aria-label="Navigation"
          className="absolute inset-y-0 left-0 flex w-[280px] max-w-[85vw] flex-col bg-sidebar text-sidebar-fg shadow-drawer"
          style={{ animation: 'fade-in .15s ease-out' }}
        >
          <div className="flex h-14 shrink-0 items-center gap-2.5 border-b border-sidebar-border px-4">
            <LogoMark className="h-8 w-8" />
            <Wordmark className="flex-1 text-white" />
            <button type="button" onClick={onClose} aria-label="Close navigation" className="flex h-8 w-8 items-center justify-center rounded-md text-sidebar-muted hover:bg-sidebar-hover hover:text-white">
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="scroll-thin min-h-0 flex-1 overflow-y-auto px-3 py-4">
            <SidebarNav onNavigate={onClose} />
          </div>
        </div>
      </div>
    </Portal>
  );
};

const DemoBanner: React.FC = () => (
  <div className="flex items-center gap-2 border-b border-warning-border bg-warning-soft px-4 py-1.5 text-[12.5px] text-warning sm:px-6">
    <FlaskConical className="h-3.5 w-3.5 shrink-0" aria-hidden />
    <span className="min-w-0">
      <span className="font-semibold">Demo mode.</span>{' '}
      <span className="text-fg-muted">Seeded data, simulated traffic and public demo accounts. Never run demo mode in production.</span>
    </span>
  </div>
);

/** Signed-in layout: sidebar, top bar, demo banner, command palette and the routed page. */
export const AppShell: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { state, error, refresh, demoMode } = useConsole();
  const { user } = useSession();
  const [collapsed, setCollapsed] = useState(() => readStorage(SIDEBAR_KEY) === '1');
  const [mobileOpen, setMobileOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [pwOpen, setPwOpen] = useState(false);
  const { pathname } = useLocation();

  useHotkey('mod+k', (e) => {
    e.preventDefault();
    setPaletteOpen((o) => !o);
  });
  useHotkey('/', (e) => {
    e.preventDefault();
    setPaletteOpen(true);
  });

  useEffect(() => setMobileOpen(false), [pathname]);

  const toggleCollapsed = useCallback(() => {
    setCollapsed((c) => {
      writeStorage(SIDEBAR_KEY, c ? '0' : '1');
      return !c;
    });
  }, []);

  let content: React.ReactNode;
  if (!state && error) {
    content = (
      <EmptyState
        icon={CloudOff}
        title="The control plane cannot be reached"
        description={error}
        action={
          <Button variant="primary" onClick={() => refresh()}>
            Try again
          </Button>
        }
      />
    );
  } else if (!state) {
    content = <PageSkeleton />;
  } else {
    content = <Suspense fallback={<PageSkeleton />}>{children}</Suspense>;
  }

  return (
    <div className="min-h-screen">
      <a href="#main" className="sr-only z-[200] rounded bg-primary px-3 py-2 text-primary-fg focus:not-sr-only focus:fixed focus:left-3 focus:top-3">
        Skip to content
      </a>
      <Sidebar collapsed={collapsed} onToggle={toggleCollapsed} />
      <MobileNav open={mobileOpen} onClose={() => setMobileOpen(false)} />
      <div className={cn('flex min-h-screen min-w-0 flex-col transition-[padding] duration-200', collapsed ? 'lg:pl-[64px]' : 'lg:pl-[248px]')}>
        <Topbar onOpenPalette={() => setPaletteOpen(true)} onOpenMobileNav={() => setMobileOpen(true)} onChangePassword={() => setPwOpen(true)} />
        {demoMode && <DemoBanner />}
        <main id="main" className="mx-auto w-full min-w-0 max-w-[1440px] flex-1 px-4 pb-16 pt-6 sm:px-6 lg:px-8">
          {content}
        </main>
      </div>
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} onChangePassword={() => setPwOpen(true)} />
      <ChangePasswordDialog open={pwOpen} onClose={() => setPwOpen(false)} authProvider={user?.auth_provider} />
    </div>
  );
};
