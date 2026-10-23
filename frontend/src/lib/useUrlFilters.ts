import { useCallback, useMemo } from 'react';
import { useSearchParams } from './router';

/**
 * DataTable filter state stored in the query string (?q=…&kind=a,b), so filtered lists are
 * deep-linkable (e.g. overview tiles link to /policies?review=overdue).
 *
 *   const f = useUrlFilters(['kind', 'review']);
 *   <DataTable search={f.search} onSearchChange={f.setSearch} facetValues={f.values} onFacetChange={f.onChange} … />
 */
export function useUrlFilters(ids: string[]) {
  const [params, set] = useSearchParams();
  const key = ids.map((id) => `${id}=${params.get(id) || ''}`).join('&');
  const values = useMemo(() => {
    const out: Record<string, string[]> = {};
    for (const id of ids) out[id] = (params.get(id) || '').split(',').filter(Boolean);
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  const onChange = useCallback((id: string, vals: string[]) => set({ [id]: vals.join(',') || null }), [set]);
  const search = params.get('q') || '';
  const setSearch = useCallback((v: string) => set({ q: v || null }), [set]);
  return { values, onChange, search, setSearch };
}
