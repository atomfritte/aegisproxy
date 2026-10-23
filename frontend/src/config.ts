// Runtime configuration (NOT build-time). `public/config.js` is loaded by index.html before the
// application bundle and can be replaced per deployment (nginx/IIS/S3) without rebuilding:
//
//   window.__AEGIS_CONFIG__ = { apiBaseUrl: "https://aegis-api.corp.example" };
//
// An empty apiBaseUrl means "same origin" (default; also used by the Vite dev proxy).

export interface AegisRuntimeConfig {
  apiBaseUrl?: string;
}

declare global {
  interface Window {
    __AEGIS_CONFIG__?: AegisRuntimeConfig;
  }
}

export const API_BASE: string = (
  (typeof window !== 'undefined' && window.__AEGIS_CONFIG__?.apiBaseUrl) ||
  ''
)
  .trim()
  .replace(/\/+$/, '');

/** True when the API is served from a different origin than the console. */
export const API_IS_CROSS_ORIGIN: boolean = (() => {
  if (!API_BASE || typeof window === 'undefined') return false;
  try {
    return new URL(API_BASE, window.location.href).origin !== window.location.origin;
  } catch {
    return true;
  }
})();

/** Absolute (or same-origin relative) URL for an API path, e.g. apiUrl('/api/audit/export'). */
export function apiUrl(path: string): string {
  return `${API_BASE}${path}`;
}

/**
 * Base URL that *servers* should use to reach the public endpoints (CA download, install
 * scripts, access requests). Prefers the control-plane's configured AEGIS_PUBLIC_URL, then the
 * runtime API base, then the current origin.
 */
export function publicBaseUrl(publicUrl?: string | null): string {
  const fromMeta = (publicUrl || '').trim().replace(/\/+$/, '');
  if (fromMeta) return fromMeta;
  if (API_BASE) return API_BASE;
  return typeof window !== 'undefined' ? window.location.origin : '';
}
