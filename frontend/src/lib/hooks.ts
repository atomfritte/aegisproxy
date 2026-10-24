import { DependencyList, RefObject, useCallback, useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { errorMessage } from '../api/http';

/** Value that follows `value` after `delay` ms without changes. */
export function useDebouncedValue<T>(value: T, delay = 200): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = window.setTimeout(() => setV(value), delay);
    return () => window.clearTimeout(t);
  }, [value, delay]);
  return v;
}

export function useMediaQuery(query: string): boolean {
  const subscribe = useCallback(
    (cb: () => void) => {
      const mql = window.matchMedia(query);
      mql.addEventListener('change', cb);
      return () => mql.removeEventListener('change', cb);
    },
    [query]
  );
  return useSyncExternalStore(
    subscribe,
    () => window.matchMedia(query).matches,
    () => false
  );
}

/** Phone layout (< 768px): tables render as cards, sidebar becomes off-canvas. */
export function useIsMobile(): boolean {
  return useMediaQuery('(max-width: 767px)');
}

// One shared ticker for relative times / countdowns.
const nowListeners = new Set<() => void>();
let nowValue = Date.now();
let nowTimer: number | undefined;
function subscribeNow(cb: () => void) {
  nowListeners.add(cb);
  if (nowTimer === undefined) {
    nowTimer = window.setInterval(() => {
      nowValue = Date.now();
      nowListeners.forEach((l) => l());
    }, 15_000);
  }
  return () => {
    nowListeners.delete(cb);
    if (nowListeners.size === 0 && nowTimer !== undefined) {
      window.clearInterval(nowTimer);
      nowTimer = undefined;
    }
  };
}

/** Current time, refreshed every 15 s (shared by all subscribers). */
export function useNow(): number {
  return useSyncExternalStore(subscribeNow, () => nowValue, () => nowValue);
}

/** Calls handler when a pointer down happens outside all given elements. */
export function useOnClickOutside(refs: Array<RefObject<HTMLElement | null>>, handler: () => void, enabled = true) {
  const handlerRef = useRef(handler);
  handlerRef.current = handler;
  useEffect(() => {
    if (!enabled) return;
    const onDown = (e: PointerEvent) => {
      const target = e.target as Node;
      if (refs.some((r) => r.current && r.current.contains(target))) return;
      handlerRef.current();
    };
    document.addEventListener('pointerdown', onDown, true);
    return () => document.removeEventListener('pointerdown', onDown, true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled]);
}

/**
 * Global keyboard shortcut. `combo` like "mod+k", "shift+?", "escape", "/".
 * "mod" = Cmd on macOS, Ctrl elsewhere. Ignored while typing in inputs unless `allowInInputs`.
 */
export function useHotkey(
  combo: string,
  handler: (e: KeyboardEvent) => void,
  opts: { enabled?: boolean; allowInInputs?: boolean } = {}
) {
  const { enabled = true, allowInInputs = false } = opts;
  const handlerRef = useRef(handler);
  handlerRef.current = handler;
  useEffect(() => {
    if (!enabled) return;
    const parts = combo.toLowerCase().split('+');
    const key = parts[parts.length - 1];
    const needMod = parts.includes('mod');
    const needShift = parts.includes('shift');
    const onKey = (e: KeyboardEvent) => {
      const isMac = /mac|iphone|ipad/i.test(navigator.platform || navigator.userAgent);
      const mod = isMac ? e.metaKey : e.ctrlKey;
      if (needMod !== mod) return;
      if (needShift && !e.shiftKey) return;
      if (e.key.toLowerCase() !== key) return;
      const el = e.target as HTMLElement | null;
      const typing = !!el && (el.isContentEditable || /^(input|textarea|select)$/i.test(el.tagName));
      if (typing && !allowInInputs && !needMod) return;
      handlerRef.current(e);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [combo, enabled, allowInInputs]);
}

export interface AsyncState<T> {
  data: T | undefined;
  error: string | null;
  loading: boolean;
  /** Re-runs the loader; keeps the previous data while loading. */
  reload: () => Promise<void>;
  setData: (d: T | undefined) => void;
}

/**
 * Loads data with `fn` whenever deps change. Errors are exposed as a message (not toasted).
 * Use for detail endpoints that are not part of /api/state.
 */
export function useAsync<T>(fn: () => Promise<T>, deps: DependencyList): AsyncState<T> {
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const seq = useRef(0);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  const run = useCallback(async () => {
    const my = ++seq.current;
    setLoading(true);
    try {
      const d = await fnRef.current();
      if (my === seq.current) {
        setData(d);
        setError(null);
      }
    } catch (err) {
      if (my === seq.current) setError(errorMessage(err));
    } finally {
      if (my === seq.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    run();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, error, loading, reload: run, setData };
}

/** Locks body scroll while `active` (overlays). Nested locks are counted. */
let scrollLocks = 0;
export function useScrollLock(active: boolean) {
  useEffect(() => {
    if (!active) return;
    scrollLocks++;
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      scrollLocks--;
      if (scrollLocks === 0) document.body.style.overflow = prev === 'hidden' ? '' : prev;
    };
  }, [active]);
}

/** Keeps keyboard focus inside `ref` while active; restores focus on close. */
export function useFocusTrap(ref: RefObject<HTMLElement | null>, active: boolean) {
  useEffect(() => {
    if (!active) return;
    const previous = document.activeElement as HTMLElement | null;
    const node = ref.current;
    const selector =
      'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';
    const focusFirst = () => {
      if (!node) return;
      const auto = node.querySelector<HTMLElement>('[data-autofocus]');
      const first = auto || node.querySelector<HTMLElement>(selector);
      (first || node).focus({ preventScroll: true });
    };
    const t = window.setTimeout(focusFirst, 10);
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Tab' || !node) return;
      const items = Array.from(node.querySelectorAll<HTMLElement>(selector)).filter(
        (el) => el.offsetParent !== null || el === document.activeElement
      );
      if (items.length === 0) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => {
      window.clearTimeout(t);
      document.removeEventListener('keydown', onKey);
      if (previous && typeof previous.focus === 'function') previous.focus({ preventScroll: true });
    };
  }, [active, ref]);
}

/** Stable unique id for aria attributes. */
let idCounter = 0;
export function useStableId(prefix = 'id'): string {
  const ref = useRef<string | undefined>(undefined);
  if (!ref.current) ref.current = `${prefix}-${++idCounter}`;
  return ref.current;
}

/** Sets document.title to "<title> | AegisProxy" (null/undefined leaves it unchanged). */
export function useDocumentTitle(title: string | null | undefined) {
  useEffect(() => {
    if (title === null || title === undefined) return;
    document.title = title ? `${title} | AegisProxy` : 'AegisProxy Enterprise';
  }, [title]);
}
