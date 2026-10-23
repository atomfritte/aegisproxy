// Low-level HTTP helpers for the AegisProxy console (typed endpoints live in ./client.ts).
//
// Authentication is carried exclusively by the HttpOnly, SameSite=Strict `aegis_session`
// cookie set by POST /api/auth/login — the browser never sees the session token. Every
// state-changing request must carry the `X-Requested-With` header, otherwise the control-plane
// rejects it as a potential CSRF attempt.
//
// All paths are resolved against the runtime API base URL (public/config.js), and requests use
// `credentials: 'include'` so the session cookie also works when the API lives on a separate
// same-site origin (e.g. console.corp.example -> aegis-api.corp.example).

import { API_BASE, API_IS_CROSS_ORIGIN } from '../config';

export { API_BASE, apiUrl, publicBaseUrl } from '../config';

export class ApiError extends Error {
  status: number;
  data: any;

  constructor(message: string, status: number, data?: any) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

type UnauthorizedListener = () => void;
const unauthorizedListeners = new Set<UnauthorizedListener>();

/**
 * Registers a callback that fires whenever an authenticated API call returns 401
 * (session expired, revoked or signed out elsewhere). Returns an unsubscribe function.
 */
export function onUnauthorized(listener: UnauthorizedListener): () => void {
  unauthorizedListeners.add(listener);
  return () => {
    unauthorizedListeners.delete(listener);
  };
}

export function notifyUnauthorized(): void {
  unauthorizedListeners.forEach((fn) => {
    try {
      fn();
    } catch {
      // listeners must never break the request flow
    }
  });
}

// Endpoints where a 401 does not mean "your session expired" (wrong credentials, public routes).
const NO_SESSION_PATHS = ['/api/auth/login', '/api/auth/logout', '/api/public/'];

function signalsExpiredSession(path: string): boolean {
  return !NO_SESSION_PATHS.some((p) => path.startsWith(p));
}

// Anonymous endpoints that the control-plane exposes with `Access-Control-Allow-Origin: *`
// (and only `Content-Type` as an allowed request header). Credentialed requests or custom
// headers would fail the CORS check when the API runs on another origin.
const WILDCARD_CORS_PATHS = ['/api/public/requests', '/api/public/ca/'];

export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const anonymousCrossOrigin =
    API_IS_CROSS_ORIGIN && WILDCARD_CORS_PATHS.some((p) => path.startsWith(p));
  const headers = new Headers(init.headers || {});
  if (!anonymousCrossOrigin) {
    headers.set('X-Requested-With', 'aegis-ui');
  }
  if (init.body !== undefined && init.body !== null && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
    credentials: anonymousCrossOrigin ? 'omit' : 'include',
  });
  if (res.status === 401 && signalsExpiredSession(path)) {
    notifyUnauthorized();
  }
  return res;
}

async function parseBody(res: Response): Promise<any> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

/** Performs a request and returns the parsed JSON body; throws ApiError on non-2xx. */
export async function apiJSON<T = any>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await apiFetch(path, init);
  const data = await parseBody(res);
  if (!res.ok) {
    const msg =
      (data && typeof data === 'object' && data.error) ||
      (typeof data === 'string' && data.trim()) ||
      res.statusText ||
      `HTTP ${res.status}`;
    throw new ApiError(String(msg), res.status, data);
  }
  return data as T;
}

/** POST with an optional JSON body. */
export function apiPost<T = any>(path: string, body?: unknown): Promise<T> {
  return apiJSON<T>(path, {
    method: 'POST',
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

/** PUT with a JSON body. */
export function apiPut<T = any>(path: string, body?: unknown): Promise<T> {
  return apiJSON<T>(path, {
    method: 'PUT',
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

/** DELETE request. */
export function apiDelete<T = any>(path: string): Promise<T> {
  return apiJSON<T>(path, { method: 'DELETE' });
}

/** Builds a query string from defined values: qs({a: 1, b: undefined}) === '?a=1'. */
export function qs(params: Record<string, string | number | boolean | null | undefined>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue;
    sp.set(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : '';
}

/** Encodes a single path segment (ids coming from the API). */
export function seg(id: string): string {
  return encodeURIComponent(id);
}

/** Extracts a human readable message from anything thrown by the helpers above. */
export function errorMessage(err: unknown, fallback = 'Request failed'): string {
  if (err instanceof Error && err.message) return err.message;
  if (typeof err === 'string' && err) return err;
  return fallback;
}
