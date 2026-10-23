// Public surface of the API layer:
//   - `api` (typed client for every endpoint, ./client.ts)
//   - low-level helpers (apiJSON/apiPost/apiPut/apiDelete/apiFetch, ApiError, errorMessage, seg, qs)
//   - runtime config helpers (API_BASE, apiUrl, publicBaseUrl)
export * from './http';
export { api } from './client';
export type { Api, DiffRef } from './client';
