# Hosting the console separately

The console is a static single-page application. By default it is bundled with the control-plane
(`ghcr.io/atomfritte/aegisproxy-control-plane` image, `AEGIS_UI_DIR`). It can also be hosted on its own — e.g. to serve it from a
DMZ web tier, a CDN or IIS while the API stays in an internal zone.

The console reads its API location at **runtime** from `/config.js`:

```js
window.__AEGIS_CONFIG__ = { apiBaseUrl: "" };   // "" = same origin
```

## Option A — same origin through a reverse proxy (recommended)

The console host proxies `/api/` to the control-plane. No CORS, the session cookie stays first-party.

- Container: `ghcr.io/atomfritte/aegisproxy-console` with `AEGIS_API_UPSTREAM=http://control-plane:8081`.
  The control-plane must trust the console as a proxy, either by a name only the console resolves to
  (`AEGIS_TRUSTED_PROXY_HOSTS=console`) or, when its address is shared (a Docker bridge gateway, host
  networking), with the same `AEGIS_TRUSTED_PROXY_SECRET` (`_FILE`) on both sides — see
  [trusted proxies](../configuration.md#trusted-proxies-and-sign-in-throttling).
- Kubernetes: `console.enabled=true` (default proxies to the control-plane service).
- nginx: see `frontend/docker/nginx.conf` and `deploy/nginx/aegis-console.conf` (disable response buffering for
  `/api/flows/stream`; on the control-plane host send the proxy secret).
- IIS: `Install-AegisConsole-IIS.ps1 -ApiProxyTarget http://127.0.0.1:8081` adds the ARR rule, disables response
  buffering and sends the proxy secret that the control-plane installer creates for a loopback
  `-TrustedProxies` ([Windows guide](windows.md#7-web-console-hosting)).

## Option B — API on its own origin

Example: console `https://console.corp.example`, API `https://aegis-api.corp.example` (same *site*).

1. Console: `AEGIS_API_BASE_URL=https://aegis-api.corp.example` (container) or edit `config.js`.
   The container also adds the API origin to the CSP `connect-src`.
2. Control-plane:
   ```
   AEGIS_PUBLIC_URL=https://aegis-api.corp.example
   AEGIS_DASHBOARD_URL=https://console.corp.example
   AEGIS_CORS_ORIGINS=https://console.corp.example
   ```
3. Different *sites* (e.g. `console.example.net` and `api.corp.example`): additionally
   `AEGIS_COOKIE_SAMESITE=none` (HTTPS required). Prefer option A or same-site host names.

## Static hosting without a container

```bash
npm --prefix frontend ci && npm --prefix frontend run build
# upload frontend/dist/* to the web root; set config.js; configure:
#   - SPA fallback: unknown paths -> /index.html
#   - /assets/*   : Cache-Control: public, max-age=31536000, immutable
#   - /config.js, /index.html : Cache-Control: no-cache
#   - security headers (CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy)
```

Reference header set: `frontend/docker/40-aegis-config.sh`.
