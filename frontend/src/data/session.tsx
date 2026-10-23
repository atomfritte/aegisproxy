// Authentication state: public metadata, the signed-in user (cookie session), login/logout.
// Any API call that returns 401 (expired / revoked session) signs the user out locally and
// shows a message on the login page.

import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { api, errorMessage, onUnauthorized } from '../api';
import type { PublicMeta, User } from '../types';

interface SessionContextValue {
  meta: PublicMeta | null;
  user: User | null;
  /** false until /api/auth/me answered (avoid flashing the login page). */
  ready: boolean;
  /** Message for the login page (session expired, failed login, throttling). */
  loginError: string | null;
  loggingIn: boolean;
  /** Returns an error message or null. */
  login: (username: string, password: string) => Promise<string | null>;
  logout: () => Promise<void>;
  /** Replace the cached user (e.g. live role changes from /api/state). */
  updateUser: (u: User) => void;
  clearLoginError: () => void;
}

const SessionContext = createContext<SessionContextValue | null>(null);

export const SessionProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [meta, setMeta] = useState<PublicMeta | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [ready, setReady] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [loggingIn, setLoggingIn] = useState(false);
  const userRef = useRef<User | null>(null);

  const apply = useCallback((u: User | null) => {
    userRef.current = u;
    setUser(u);
  }, []);

  useEffect(
    () =>
      onUnauthorized(() => {
        const was = userRef.current !== null;
        apply(null);
        if (was) setLoginError('Your session has expired or was revoked. Please sign in again.');
      }),
    [apply]
  );

  useEffect(() => {
    api.public.meta().then(setMeta).catch(() => {});
    api.auth
      .me()
      .then((d) => apply(d.user))
      .catch(() => {})
      .finally(() => setReady(true));
  }, [apply]);

  const login = useCallback(
    async (username: string, password: string) => {
      setLoginError(null);
      setLoggingIn(true);
      try {
        const res = await api.auth.login(username, password);
        apply(res.user);
        return null;
      } catch (err) {
        // 401 = bad credentials, 429 = throttled (message includes the retry delay)
        const msg = errorMessage(err, 'Authentication failed');
        setLoginError(msg);
        return msg;
      } finally {
        setLoggingIn(false);
      }
    },
    [apply]
  );

  const logout = useCallback(async () => {
    try {
      await api.auth.logout();
    } catch {
      // local session is cleared regardless
    }
    apply(null);
    setLoginError(null);
  }, [apply]);

  const updateUser = useCallback(
    (u: User) => {
      const cur = userRef.current;
      if (
        cur &&
        u.id === cur.id &&
        (u.role !== cur.role || u.display_name !== cur.display_name || JSON.stringify(u.allowed_groups) !== JSON.stringify(cur.allowed_groups))
      ) {
        apply(u);
      }
    },
    [apply]
  );

  const value = useMemo(
    () => ({ meta, user, ready, loginError, loggingIn, login, logout, updateUser, clearLoginError: () => setLoginError(null) }),
    [meta, user, ready, loginError, loggingIn, login, logout, updateUser]
  );
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
};

export function useSession(): SessionContextValue {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error('useSession must be used inside <SessionProvider>');
  return ctx;
}
