import { api, apiFetch } from '../../../api';
import { API_IS_CROSS_ORIGIN } from '../../../config';

export type PreviewOpts = { locale?: string; variant?: 'request' | 'threat'; format?: 'html' | 'cli' };

/** URL of GET /api/block-pages/{id}/preview (the server disables scripts with its own CSP). */
export const savedPreviewUrl = (id: string, opts: PreviewOpts) => api.blockPages.previewUrl(id, opts);

/**
 * Opens the standalone preview of a saved template in a new tab. Same origin: a plain navigation
 * carries the session cookie. Cross-origin API: fetch with credentials and open a blob URL.
 */
export async function openSavedPreview(id: string, opts: PreviewOpts): Promise<void> {
  const url = savedPreviewUrl(id, opts);
  if (!API_IS_CROSS_ORIGIN) {
    window.open(url, '_blank', 'noopener');
    return;
  }
  const win = window.open('', '_blank');
  try {
    const res = await apiFetch(url.slice(url.indexOf('/api/')));
    if (!res.ok) throw new Error(`The preview could not be loaded (HTTP ${res.status}).`);
    const blobUrl = URL.createObjectURL(await res.blob());
    if (win) win.location.href = blobUrl;
    window.setTimeout(() => URL.revokeObjectURL(blobUrl), 60_000);
  } catch (err) {
    win?.close();
    throw err;
  }
}
