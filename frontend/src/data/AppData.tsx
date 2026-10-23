// Console data layer.
//
//   <DataProvider>            (inside the signed-in shell)
//     useConsole()  -> { state, refresh, perms, me, demoMode, error, lastUpdated }
//     useFlows()    -> { flows, connected }      live flows (SSE /api/flows/stream)
//     useAction()   -> { run, pending }          mutation helper: toast + refresh
//     useLookups()  -> maps for ids -> names (groups, servers, users, policy sets)
//
// /api/state?exclude_flows=1 is polled every 30 s (only while the tab is visible) and after
// every mutation (`refresh()`). The first load includes recent flows to seed the live view.

import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { api, apiFetch } from '../api';
import type { DashboardState, TrafficFlow } from '../types';
import { useToast } from '../ui/Toast';
import { permissionsFor, Permissions } from './permissions';
import { useSession } from './session';

const STATE_POLL_MS = 30_000;
const MAX_FLOWS = 300;

interface ConsoleContextValue {
  /** null until the first /api/state response. `state.flows` is not kept current — use useFlows(). */
  state: DashboardState | null;
  error: string | null;
  lastUpdated: number | null;
  /** Re-fetches /api/state (resolves when done; never throws). */
  refresh: () => Promise<void>;
  perms: Permissions;
  demoMode: boolean;
  version: string;
}

interface FlowsContextValue {
  flows: TrafficFlow[];
  connected: boolean;
}

const ConsoleContext = createContext<ConsoleContextValue | null>(null);
const FlowsContext = createContext<FlowsContextValue>({ flows: [], connected: false });

export const DataProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { user, meta, updateUser } = useSession();
  const [state, setState] = useState<DashboardState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);
  const [flows, setFlows] = useState<TrafficFlow[]>([]);
  const [connected, setConnected] = useState(false);
  const [sseEpoch, setSseEpoch] = useState(0);
  const loadedFlows = useRef(false);
  const pending = useRef<TrafficFlow[]>([]);
  const inflight = useRef<Promise<void> | null>(null);
  const userId = user?.id;
  const lastUpdatedRef = useRef<number | null>(null);
  lastUpdatedRef.current = lastUpdated;

  const refresh = useCallback(async () => {
    if (inflight.current) return inflight.current;
    const p = (async () => {
      try {
        const data = await api.state.get({ excludeFlows: loadedFlows.current });
        if (!loadedFlows.current && data.flows) {
          setFlows((prev) => mergeFlows(prev, data.flows));
        }
        loadedFlows.current = true;
        setState({ ...data, flows: [] });
        setError(null);
        setLastUpdated(Date.now());
        if (data.me) updateUser(data.me);
      } catch (err) {
        // 401 is handled globally (session listener); keep the last good state otherwise
        setError(err instanceof Error ? err.message : 'Failed to load console state');
      } finally {
        inflight.current = null;
      }
    })();
    inflight.current = p;
    return p;
  }, [updateUser]);

  // polling
  useEffect(() => {
    if (!userId) return;
    refresh();
    const t = window.setInterval(() => {
      if (document.visibilityState === 'visible') refresh();
    }, STATE_POLL_MS);
    const onVisible = () => {
      if (document.visibilityState === 'visible' && lastUpdatedRef.current && Date.now() - lastUpdatedRef.current > STATE_POLL_MS) refresh();
    };
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      window.clearInterval(t);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [userId, refresh]);

  // live flows: buffered SSE stream, flushed at most 4x per second
  useEffect(() => {
    if (!userId) return;
    let disposed = false;
    let retry: number | undefined;
    const es = new EventSource(api.state.flowStreamUrl(), { withCredentials: true });
    es.addEventListener('connected', () => setConnected(true));
    es.addEventListener('session_expired', () => {
      es.close();
      setConnected(false);
      // a probe returns 401 and triggers the global sign-out
      apiFetch('/api/auth/me').catch(() => {});
    });
    es.onmessage = (ev) => {
      setConnected(true);
      try {
        pending.current.push(JSON.parse(ev.data) as TrafficFlow);
      } catch {
        // ignore malformed frames
      }
    };
    es.onerror = () => {
      setConnected(false);
      if (es.readyState === EventSource.CLOSED && !disposed) {
        // The browser gave up (HTTP 401/503): probe the session, then retry later.
        apiFetch('/api/auth/me')
          .then((res) => {
            if (res.ok && !disposed) retry = window.setTimeout(() => setSseEpoch((n) => n + 1), 10_000);
          })
          .catch(() => {
            if (!disposed) retry = window.setTimeout(() => setSseEpoch((n) => n + 1), 10_000);
          });
      }
    };
    const flush = window.setInterval(() => {
      if (pending.current.length === 0) return;
      const batch = pending.current.splice(0, pending.current.length);
      setFlows((prev) => mergeFlows(prev, batch.reverse()));
    }, 250);
    return () => {
      disposed = true;
      window.clearInterval(flush);
      if (retry) window.clearTimeout(retry);
      es.close();
    };
  }, [userId, sseEpoch]);

  // reset on sign-out
  useEffect(() => {
    if (!userId) {
      setState(null);
      setFlows([]);
      loadedFlows.current = false;
      pending.current = [];
    }
  }, [userId]);

  const perms = useMemo(() => permissionsFor(user), [user]);
  const value = useMemo<ConsoleContextValue>(
    () => ({
      state,
      error,
      lastUpdated,
      refresh,
      perms,
      demoMode: state?.demo_mode ?? meta?.demo_mode ?? false,
      version: state?.version || meta?.version || '',
    }),
    [state, error, lastUpdated, refresh, perms, meta]
  );
  const flowsValue = useMemo(() => ({ flows, connected }), [flows, connected]);

  return (
    <ConsoleContext.Provider value={value}>
      <FlowsContext.Provider value={flowsValue}>{children}</FlowsContext.Provider>
    </ConsoleContext.Provider>
  );
};

/** Newest first, de-duplicated, capped. `incoming` is newest-first. */
function mergeFlows(prev: TrafficFlow[], incoming: TrafficFlow[]): TrafficFlow[] {
  if (incoming.length === 0) return prev;
  const seen = new Set(prev.map((f) => f.id));
  const fresh = incoming.filter((f) => {
    if (seen.has(f.id)) return false;
    seen.add(f.id);
    return true;
  });
  if (fresh.length === 0) return prev;
  return [...fresh, ...prev].slice(0, MAX_FLOWS);
}

export function useConsole(): ConsoleContextValue {
  const ctx = useContext(ConsoleContext);
  if (!ctx) throw new Error('useConsole must be used inside <DataProvider>');
  return ctx;
}

/** Console state, asserting it has loaded (use inside pages rendered after the shell's loading gate). */
export function useConsoleState(): DashboardState {
  const { state } = useConsole();
  if (!state) throw new Error('console state not loaded yet');
  return state;
}

export function useFlows(): FlowsContextValue {
  return useContext(FlowsContext);
}

export function usePermissions(): Permissions {
  return useConsole().perms;
}

export interface RunOptions<R> {
  /** Toast on success (string or derived from the result). */
  success?: string | ((r: R) => string | null);
  /** Error toast title (the server message becomes the description). */
  errorTitle?: string;
  /** Re-fetch /api/state afterwards (default true). */
  refresh?: boolean;
  /** Identifies the action for `pending` (e.g. 'publish'). */
  key?: string;
}

/**
 * Mutation helper: runs `fn`, toasts success / the server error, refreshes the console state.
 * Returns the result, or undefined when it failed.
 *
 *   const { run, pending } = useAction();
 *   <Button loading={pending === 'publish'} onClick={() => run(() => api.policySets.publish(id, {...}), { key: 'publish', success: 'Published' })}>
 */
export function useAction() {
  const toast = useToast();
  const { refresh } = useConsole();
  const [pending, setPending] = useState<string | null>(null);
  const run = useCallback(
    async <R,>(fn: () => Promise<R>, opts: RunOptions<R> = {}): Promise<R | undefined> => {
      const key = opts.key ?? 'action';
      setPending(key);
      try {
        const r = await fn();
        const msg = typeof opts.success === 'function' ? opts.success(r) : opts.success;
        if (msg) toast.success(msg);
        if (opts.refresh !== false) await refresh();
        return r;
      } catch (err) {
        toast.error(err, opts.errorTitle ? { title: opts.errorTitle } : undefined);
        return undefined;
      } finally {
        setPending((p) => (p === key ? null : p));
      }
    },
    [toast, refresh]
  );
  return { run, pending };
}
