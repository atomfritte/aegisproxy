// Tiny history-API router (no dependency).
//
//   <RouterProvider>                       top level, listens to popstate
//   <Routes routes={[{ path: '/policies/:id/:tab?', component: X }]} fallback={<NotFound/>} />
//   <Link to="/policies/ps-1">…</Link>      client-side navigation (modifier clicks open new tabs)
//   navigate('/changes?tab=mine', { replace: true })   usable anywhere (also outside React)
//   useParams<{ id: string }>(), useLocation(), useSearchParams(), useQueryParam('q')
//   useNavigationBlocker(dirty, 'Discard unsaved changes?')
//
// Patterns: literal segments, `:param`, optional `:param?` (last segments only) and a trailing `*`
// (splat, available as params['*']). Matching is case-sensitive and ignores a trailing slash.
// Deep links work on reload because the Go server and nginx serve index.html for unknown paths.

import React, {
  AnchorHTMLAttributes,
  createContext,
  forwardRef,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';

export interface RouterLocation {
  pathname: string;
  search: string;
  hash: string;
}

export interface NavigateOptions {
  replace?: boolean;
  /** Keep the scroll position (default: scroll to top when the pathname changes). */
  preserveScroll?: boolean;
}

const NAV_EVENT = 'aegis:navigate';

function readLocation(): RouterLocation {
  return {
    pathname: window.location.pathname || '/',
    search: window.location.search,
    hash: window.location.hash,
  };
}

// ---------------------------------------------------------------------------
// Navigation blockers (unsaved changes)
// ---------------------------------------------------------------------------

const blockers = new Map<number, (next: URL) => string | null>();
let blockerSeq = 0;

function blockMessage(next: URL): string | null {
  for (const fn of blockers.values()) {
    const msg = fn(next);
    if (msg) return msg;
  }
  return null;
}

function confirmLeave(next: URL): boolean {
  const msg = blockMessage(next);
  if (!msg) return true;
  return window.confirm(msg);
}

/** Navigates within the console. Absolute URLs to other origins fall back to a full page load. */
export function navigate(to: string, opts: NavigateOptions = {}): void {
  const url = new URL(to, window.location.href);
  if (url.origin !== window.location.origin) {
    window.location.assign(url.toString());
    return;
  }
  const next = url.pathname + url.search + url.hash;
  const current = window.location.pathname + window.location.search + window.location.hash;
  if (next === current) return;
  if (!confirmLeave(url)) return;
  const samePath = url.pathname === window.location.pathname;
  if (opts.replace) window.history.replaceState(null, '', next);
  else window.history.pushState(null, '', next);
  window.dispatchEvent(
    new CustomEvent(NAV_EVENT, { detail: { preserveScroll: opts.preserveScroll ?? samePath } })
  );
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

export type Params = Record<string, string>;

const compiled = new Map<string, { re: RegExp; keys: string[] }>();

function compile(pattern: string) {
  let c = compiled.get(pattern);
  if (c) return c;
  const keys: string[] = [];
  const segs = pattern.replace(/\/+$/, '').split('/').filter(Boolean);
  let src = '^';
  for (const s of segs) {
    if (s === '*') {
      keys.push('*');
      src += '(?:/(.*))?';
    } else if (s.startsWith(':')) {
      const optional = s.endsWith('?');
      keys.push(optional ? s.slice(1, -1) : s.slice(1));
      src += optional ? '(?:/([^/]+))?' : '/([^/]+)';
    } else {
      src += '/' + s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
  }
  src += '/?$';
  if (segs.length === 0) src = '^/?$';
  c = { re: new RegExp(src), keys };
  compiled.set(pattern, c);
  return c;
}

/** Returns the params when `pathname` matches `pattern`, otherwise null. */
export function matchPath(pattern: string, pathname: string, opts: { end?: boolean } = {}): Params | null {
  const { end = true } = opts;
  if (!end) {
    const base = pattern.replace(/\/+$/, '');
    if (base === '' ) return pathname === '/' ? {} : null;
    return pathname === base || pathname.startsWith(base + '/') ? {} : null;
  }
  const { re, keys } = compile(pattern);
  const m = re.exec(pathname);
  if (!m) return null;
  const params: Params = {};
  keys.forEach((k, i) => {
    const v = m[i + 1];
    if (v !== undefined) {
      try {
        params[k] = decodeURIComponent(v);
      } catch {
        params[k] = v;
      }
    }
  });
  return params;
}

/** Builds a path from a pattern: buildPath('/policies/:id', { id: 'ps 1' }) === '/policies/ps%201' */
export function buildPath(pattern: string, params: Params = {}): string {
  const out = pattern
    .split('/')
    .map((s) => {
      if (!s.startsWith(':')) return s;
      const key = s.replace(/^:/, '').replace(/\?$/, '');
      const v = params[key];
      return v === undefined || v === '' ? '' : encodeURIComponent(v);
    })
    .filter((s, i) => i === 0 || s !== '')
    .join('/');
  return out || '/';
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

interface RouterContextValue {
  location: RouterLocation;
}

const RouterContext = createContext<RouterContextValue | null>(null);
const ParamsContext = createContext<{ params: Params; pattern: string }>({ params: {}, pattern: '' });

export const RouterProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [location, setLocation] = useState<RouterLocation>(readLocation);
  const lastUrl = useRef(window.location.pathname + window.location.search + window.location.hash);

  useEffect(() => {
    const onNav = (e: Event) => {
      const loc = readLocation();
      const preserve = (e as CustomEvent).detail?.preserveScroll;
      lastUrl.current = loc.pathname + loc.search + loc.hash;
      setLocation(loc);
      if (!preserve) window.scrollTo(0, 0);
    };
    const onPop = () => {
      if (blockers.size > 0 && !confirmLeave(new URL(window.location.href))) {
        // restore the URL we were on
        window.history.pushState(null, '', lastUrl.current);
        return;
      }
      const loc = readLocation();
      lastUrl.current = loc.pathname + loc.search + loc.hash;
      setLocation(loc);
    };
    window.addEventListener(NAV_EVENT, onNav);
    window.addEventListener('popstate', onPop);
    return () => {
      window.removeEventListener(NAV_EVENT, onNav);
      window.removeEventListener('popstate', onPop);
    };
  }, []);

  const value = useMemo(() => ({ location }), [location]);
  return <RouterContext.Provider value={value}>{children}</RouterContext.Provider>;
};

export function useLocation(): RouterLocation {
  const ctx = useContext(RouterContext);
  if (!ctx) throw new Error('useLocation must be used inside <RouterProvider>');
  return ctx.location;
}

export function useNavigate(): typeof navigate {
  return navigate;
}

/** Params of the closest matched <Routes> entry. */
export function useParams<T extends Params = Params>(): T {
  return useContext(ParamsContext).params as T;
}

/** True when the current pathname matches `pattern` (end=false: prefix match). */
export function useMatch(pattern: string, opts: { end?: boolean } = {}): Params | null {
  const { pathname } = useLocation();
  return matchPath(pattern, pathname, opts);
}

export type SearchUpdate =
  | Record<string, string | number | boolean | null | undefined>
  | ((prev: URLSearchParams) => URLSearchParams);

/**
 * Query string as URLSearchParams plus a setter that merges values (null/undefined/'' removes a key).
 * Updates replace the history entry by default (filters should not spam the back button).
 */
export function useSearchParams(): [URLSearchParams, (update: SearchUpdate, opts?: NavigateOptions) => void] {
  const { search, pathname, hash } = useLocation();
  const params = useMemo(() => new URLSearchParams(search), [search]);
  const set = useCallback(
    (update: SearchUpdate, opts: NavigateOptions = {}) => {
      let next: URLSearchParams;
      const current = new URLSearchParams(window.location.search);
      if (typeof update === 'function') next = update(current);
      else {
        next = current;
        for (const [k, v] of Object.entries(update)) {
          if (v === null || v === undefined || v === '' || v === false) next.delete(k);
          else next.set(k, String(v));
        }
      }
      const s = next.toString();
      navigate(`${window.location.pathname}${s ? `?${s}` : ''}${hash}`, {
        replace: opts.replace ?? true,
        preserveScroll: true,
      });
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [pathname, hash]
  );
  return [params, set];
}

/** One query parameter as state: const [q, setQ] = useQueryParam('q'). */
export function useQueryParam(name: string, fallback = ''): [string, (v: string | null) => void] {
  const [params, set] = useSearchParams();
  const value = params.get(name) ?? fallback;
  const setValue = useCallback((v: string | null) => set({ [name]: v === fallback ? null : v }), [name, fallback, set]);
  return [value, setValue];
}

/**
 * Asks for confirmation before leaving the page (in-app navigation, back button, tab close).
 * `allow(next)` exempts targets, e.g. switching tabs of the same entity.
 */
export function useNavigationBlocker(
  when: boolean,
  message = 'You have unsaved changes. Leave this page?',
  allow?: (next: URL) => boolean
) {
  const msgRef = useRef(message);
  msgRef.current = message;
  const allowRef = useRef(allow);
  allowRef.current = allow;
  useEffect(() => {
    if (!when) return;
    const id = ++blockerSeq;
    blockers.set(id, (next) => (allowRef.current?.(next) ? null : msgRef.current));
    const onBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', onBeforeUnload);
    return () => {
      blockers.delete(id);
      window.removeEventListener('beforeunload', onBeforeUnload);
    };
  }, [when]);
}

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

export interface RouteDef {
  path: string;
  /** Page component (may be React.lazy — the shell renders routes inside <Suspense>). */
  component: React.ComponentType | React.LazyExoticComponent<React.ComponentType>;
}

/** Renders the first route whose pattern matches the current pathname, else `fallback`. */
export const Routes: React.FC<{ routes: RouteDef[]; fallback?: React.ReactNode }> = ({ routes, fallback = null }) => {
  const { pathname } = useLocation();
  for (const r of routes) {
    const params = matchPath(r.path, pathname);
    if (params) {
      const C = r.component;
      return (
        <ParamsContext.Provider value={{ params, pattern: r.path }}>
          <C key={r.path} />
        </ParamsContext.Provider>
      );
    }
  }
  return <>{fallback}</>;
};

function isModifiedEvent(e: React.MouseEvent) {
  return e.metaKey || e.altKey || e.ctrlKey || e.shiftKey || e.button !== 0;
}

export interface LinkProps extends Omit<AnchorHTMLAttributes<HTMLAnchorElement>, 'href'> {
  to: string;
  replace?: boolean;
  preserveScroll?: boolean;
}

/** Anchor with client-side navigation; Ctrl/Cmd/middle click keep native "open in new tab". */
export const Link = forwardRef<HTMLAnchorElement, LinkProps>(function Link(
  { to, replace, preserveScroll, onClick, target, ...rest },
  ref
) {
  return (
    <a
      ref={ref}
      href={to}
      target={target}
      onClick={(e) => {
        onClick?.(e);
        if (e.defaultPrevented || isModifiedEvent(e) || (target && target !== '_self')) return;
        const url = new URL(to, window.location.href);
        if (url.origin !== window.location.origin) return;
        e.preventDefault();
        navigate(to, { replace, preserveScroll });
      }}
      {...rest}
    />
  );
});

/** Link that sets aria-current="page" when active (prefix match unless `end`). */
export const NavLink = forwardRef<
  HTMLAnchorElement,
  Omit<LinkProps, 'className'> & { end?: boolean; match?: string; className?: string | ((active: boolean) => string) }
>(function NavLink({ end, match, className, ...rest }, ref) {
  const { pathname } = useLocation();
  const pattern = match ?? rest.to.split('?')[0];
  const active = !!matchPath(pattern, pathname, { end: end ?? pattern === '/' });
  return (
    <Link
      ref={ref}
      aria-current={active ? 'page' : undefined}
      className={typeof className === 'function' ? className(active) : className}
      {...rest}
    />
  );
});

/** Redirects on mount (replace). */
export const Redirect: React.FC<{ to: string }> = ({ to }) => {
  useEffect(() => {
    navigate(to, { replace: true });
  }, [to]);
  return null;
};
