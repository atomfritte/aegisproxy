import { useEffect, useRef, useState } from 'react';
import { api, errorMessage } from '../../../api';
import type { BlockPagePreview } from '../../../types';
import { toPayload, type Locale, type TemplateDraft, type Variant } from './model';

// Rendered previews by payload; shared by the list thumbnails and the editor (bounded).
const cache = new Map<string, BlockPagePreview>();
function remember(key: string, value: BlockPagePreview) {
  cache.set(key, value);
  if (cache.size > 80) cache.delete(cache.keys().next().value as string);
}

export interface PreviewState {
  html: string;
  cli: string;
  /** Validation / render error of the latest attempt (the last good render stays visible). */
  error: string | null;
  loading: boolean;
}

/**
 * Renders a (possibly unsaved) template with sample data via POST /api/block-pages/preview,
 * debounced while the user types. Out-of-order responses are discarded.
 */
export function usePreview(draft: TemplateDraft | null, locale: Locale, variant: Variant, delay = 400): PreviewState {
  // the name is console-only; a new template without one should still render
  const payload = draft ? JSON.stringify(toPayload({ ...draft, name: draft.name.trim() || 'Untitled template' })) : '';
  const key = `${locale}|${variant}|${payload}`;
  const cached = cache.get(key);
  const [state, setState] = useState<PreviewState>(() => ({ html: cached?.html ?? '', cli: cached?.cli ?? '', error: null, loading: !cached && !!draft }));
  const seq = useRef(0);
  const first = useRef(true);

  useEffect(() => {
    if (!payload) return;
    const hit = cache.get(key);
    if (hit) {
      seq.current++;
      setState({ html: hit.html, cli: hit.cli, error: null, loading: false });
      first.current = false;
      return;
    }
    const my = ++seq.current;
    setState((s) => ({ ...s, loading: true }));
    const run = async () => {
      try {
        const res = await api.blockPages.preview(JSON.parse(payload), locale, variant);
        remember(key, res);
        if (my === seq.current) setState({ html: res.html, cli: res.cli, error: null, loading: false });
      } catch (err) {
        if (my === seq.current) setState((s) => ({ ...s, error: errorMessage(err, 'Preview failed'), loading: false }));
      }
    };
    // render immediately the first time, debounce while editing
    const t = window.setTimeout(run, first.current ? 0 : delay);
    first.current = false;
    return () => window.clearTimeout(t);
  }, [key, payload, locale, variant, delay]);

  return state;
}
