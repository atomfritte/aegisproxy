// AegisProxy console runtime configuration.
// Replace this file per deployment (no rebuild required).
//   apiBaseUrl: ""                                  -> API on the same origin as the console (default)
//   apiBaseUrl: "https://aegis-api.corp.example"    -> API on a separate (same-site) origin
// When the API runs on another origin, add the console origin to the control-plane's CORS
// allow-list (AEGIS_CORS_ORIGINS) so credentialed requests and the session cookie are accepted.
window.__AEGIS_CONFIG__ = { apiBaseUrl: "" };
