import React from 'react';
import { Loader2 } from 'lucide-react';
import { DataProvider } from './data/AppData';
import { SessionProvider, useSession } from './data/session';
import { navigate, RouterProvider, Routes, useLocation } from './lib/router';
import { ThemeProvider } from './lib/theme';
import { LoginPage } from './pages/auth/LoginPage';
import { PublicBlockPortal } from './pages/public/PublicBlockPortal';
import { NotFoundPage } from './pages/system/NotFoundPage';
import { ROUTES } from './routes';
import { AppShell } from './shell/AppShell';
import { ConfirmProvider, ToastProvider } from './ui';

/** Decides between the public block portal, the login page and the signed-in console. */
const Gate: React.FC = () => {
  const { search } = useLocation();
  const { user, ready, meta } = useSession();

  // Legacy public portal URL: /?portal=block&bt=<token> (also ?url=&ip=&trace=). Works signed out.
  if (new URLSearchParams(search).get('portal') === 'block') {
    return (
      <PublicBlockPortal
        meta={meta}
        onSwitchToAdmin={() => navigate('/')}
      />
    );
  }

  if (!ready) {
    return (
      <div className="flex min-h-screen items-center justify-center gap-2 text-[13px] text-fg-muted">
        <Loader2 className="h-4 w-4 animate-spin text-accent" />
        Restoring session…
      </div>
    );
  }

  if (!user) return <LoginPage />;

  return (
    <DataProvider key={user.id}>
      <AppShell>
        <Routes routes={ROUTES} fallback={<NotFoundPage />} />
      </AppShell>
    </DataProvider>
  );
};

export const App: React.FC = () => (
  <ThemeProvider>
    <RouterProvider>
      <ToastProvider>
        <ConfirmProvider>
          <SessionProvider>
            <Gate />
          </SessionProvider>
        </ConfirmProvider>
      </ToastProvider>
    </RouterProvider>
  </ThemeProvider>
);
