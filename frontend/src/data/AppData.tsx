// Console data layer.
//
//   <DataProvider>            (inside the signed-in shell)
//     useConsole()      -> { state, refresh, perms, me, demoMode, error }
//     useLastUpdated()  -> number | null         freshness tick, isolated so it re-renders only its readers
//     useFlows()        -> { flows, connected }   live flows (SSE /api/flows/stream)
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
// Isolated from ConsoleContext so the freshness tick (every poll) re-renders only its readers
// (the Topbar status pill), not all ~78 console-state consumers.
const LastUpdatedContext = createContext<number | null>(null);

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
  const lastSig = useRef<string | null>(null);
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
        // Skip the state update (and the re-render of all ~78 consumers) when the polled payload is
        // unchanged. Otherwise every 30 s tick replaced `state` with a brand-new object, re-deriving
        // every DataTable even on a byte-identical response. `stateSignature` ignores volatile fields
        // (see its doc), so an unchanged signature is a genuine no-op.
        const sig = stateSignature(data);
        if (sig !== lastSig.current) {
          lastSig.current = sig;
          setState({ ...data, flows: [] });
        }
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
      lastSig.current = null;
      pending.current = [];
    }
  }, [userId]);

  const perms = useMemo(() => permissionsFor(user), [user]);
  const value = useMemo<ConsoleContextValue>(
    () => ({
      state,
      error,
      refresh,
      perms,
      demoMode: state?.demo_mode ?? meta?.demo_mode ?? false,
      version: state?.version || meta?.version || '',
    }),
    [state, error, refresh, perms, meta]
  );
  const flowsValue = useMemo(() => ({ flows, connected }), [flows, connected]);

  return (
    <ConsoleContext.Provider value={value}>
      <LastUpdatedContext.Provider value={lastUpdated}>
        <FlowsContext.Provider value={flowsValue}>{children}</FlowsContext.Provider>
      </LastUpdatedContext.Provider>
    </ConsoleContext.Provider>
  );
};

/**
 * Cheap change signal for a polled /api/state payload, used to skip no-op state updates.
 * Excludes two fields that change regardless of real activity:
 *   - `flows`: carried by the live SSE stream and always stored as [] here, not part of `state`.
 *   - `bandwidth`: a rolling 24 h summary recomputed against now() on every request (its 15-minute
 *     buckets, time labels and current_mbps slide every minute), so it is never byte-stable. Any
 *     real traffic change also moves `stats`/`overview` (and streams in live via SSE), so those
 *     remain in the signal and still trigger a full state update that carries the fresh bandwidth.
 * Returns `length:checksum` (cyrb53) so we retain a short string, never the whole payload.
 */
function stateSignature(data: DashboardState): string {
  const { flows: _flows, bandwidth: _bandwidth, ...rest } = data;
  const json = JSON.stringify(rest);
  let h1 = 0xdeadbeef;
  let h2 = 0x41c6ce57;
  for (let i = 0; i < json.length; i++) {
    const ch = json.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
  h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
  h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  const checksum = 4294967296 * (2097151 & h2) + (h1 >>> 0);
  return `${json.length}:${checksum}`;
}

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

/** Timestamp (ms) of the last successful /api/state refresh, or null before the first load. */
export function useLastUpdated(): number | null {
  return useContext(LastUpdatedContext);
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
