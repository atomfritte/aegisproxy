import React, { useEffect, useMemo, useRef, useState } from 'react';
import { ArrowDown, ArrowUp, ChevronsUpDown, Filter, SearchX, X } from 'lucide-react';
import { cn } from '../lib/cn';
import { useDebouncedValue, useIsMobile } from '../lib/hooks';
import { navigate } from '../lib/router';
import { Button } from './Button';
import { EmptyState } from './EmptyState';
import { Checkbox, SearchInput } from './Form';
import { Popover } from './Popover';
import { Skeleton } from './Skeleton';

export interface Column<T> {
  id: string;
  header: React.ReactNode;
  cell: (row: T) => React.ReactNode;
  /** Enables sorting on this column. */
  sortValue?: (row: T) => string | number | null | undefined;
  align?: 'left' | 'right' | 'center';
  /** CSS width (e.g. '30%', 120). */
  width?: string | number;
  className?: string;
  /** Hide the column in the table layout below this breakpoint. */
  hideBelow?: 'lg' | 'xl';
  /** Hide in the phone card layout. */
  hideOnMobile?: boolean;
  /** Label in the card layout (defaults to `header` when it is a string). */
  mobileLabel?: string;
}

export interface FacetDef<T> {
  id: string;
  label: string;
  /** Value(s) of a row for this facet. */
  getValue: (row: T) => string | string[] | null | undefined;
  /** Fixed option list; otherwise derived from the rows (with counts). */
  options?: Array<{ value: string; label: string }>;
  /** Label for derived values. */
  optionLabel?: (value: string) => string;
}

export interface DataTableProps<T> {
  rows: T[];
  columns: Column<T>[];
  getRowId: (row: T) => string;
  /** Free-text filter over getSearchText(row). */
  getSearchText?: (row: T) => string;
  searchPlaceholder?: string;
  /** Controlled search (e.g. synced with ?q=). */
  search?: string;
  onSearchChange?: (v: string) => void;
  facets?: FacetDef<T>[];
  /** Controlled facet selection. */
  facetValues?: Record<string, string[]>;
  onFacetChange?: (id: string, values: string[]) => void;
  /** Row selection with a bulk-action bar. Function form: which rows are selectable. */
  selectable?: boolean | ((row: T) => boolean);
  bulkActions?: (selected: T[], clear: () => void) => React.ReactNode;
  initialSort?: { id: string; dir: 'asc' | 'desc' };
  onRowClick?: (row: T) => void;
  /** Row navigates to this path on click (primary cell should still contain a Link for keyboard users). */
  rowHref?: (row: T) => string;
  rowClassName?: (row: T) => string | undefined;
  /** Custom phone card; default renders all columns as label/value pairs. */
  mobileCard?: (row: T) => React.ReactNode;
  /** Shown when `rows` is empty. */
  empty?: React.ReactNode;
  /** Extra controls right of the search box. */
  toolbar?: React.ReactNode;
  loading?: boolean;
  /** Client-side "Show more" page size (default 50). */
  pageSize?: number;
  /** Scroll inside the table with a sticky header (px). Without it the header sticks below the top bar. */
  maxHeight?: number;
  /** Hide toolbar entirely. */
  hideToolbar?: boolean;
  /** Section header rows between groups of consecutive rows (only while no column sort is active). */
  groupBy?: { key: (row: T) => string; label: (key: string, rows: T[]) => React.ReactNode };
  className?: string;
  'aria-label'?: string;
}

function asArray(v: string | string[] | null | undefined): string[] {
  if (v === null || v === undefined || v === '') return [];
  return Array.isArray(v) ? v : [v];
}

const alignCls = { left: 'text-left', right: 'text-right', center: 'text-center' };
const hideCls = { lg: 'hidden lg:table-cell', xl: 'hidden xl:table-cell' };

/**
 * Data table: sortable columns, search, faceted filters, row selection + bulk bar, empty states,
 * sticky header, "show more" paging and a card layout on phones.
 */
export function DataTable<T>(props: DataTableProps<T>) {
  const {
    rows,
    columns,
    getRowId,
    getSearchText,
    searchPlaceholder = 'Filter…',
    facets = [],
    selectable,
    bulkActions,
    initialSort,
    onRowClick,
    rowHref,
    rowClassName,
    mobileCard,
    empty,
    toolbar,
    loading,
    pageSize = 50,
    maxHeight,
    hideToolbar,
    groupBy,
    className,
  } = props;
  const isMobile = useIsMobile();

  const [searchState, setSearchState] = useState('');
  // `search` is the committed value that drives filtering (and, when controlled, the ?q= URL).
  const search = props.search ?? searchState;
  const setSearch = props.onSearchChange ?? setSearchState;
  // The input itself is held locally so typing stays instant; only the debounced value is committed
  // (one URL write per pause instead of per keystroke, and one re-filter instead of per keystroke).
  // Filter *results* are unchanged — only when they recompute.
  const [typed, setTyped] = useState(search);
  const debouncedTyped = useDebouncedValue(typed, 200);
  useEffect(() => {
    if (debouncedTyped !== search) setSearch(debouncedTyped);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedTyped]);
  // Adopt external changes to the committed value (deep links, "Clear filters", the clear button).
  useEffect(() => {
    setTyped(search);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search]);

  const [facetState, setFacetState] = useState<Record<string, string[]>>({});
  const facetValues = props.facetValues ?? facetState;
  const setFacet = (id: string, values: string[]) => {
    if (props.onFacetChange) props.onFacetChange(id, values);
    else setFacetState((s) => ({ ...s, [id]: values }));
  };

  const [sort, setSort] = useState<{ id: string; dir: 'asc' | 'desc' } | null>(initialSort ?? null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [limit, setLimit] = useState(pageSize);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return rows.filter((r) => {
      if (q && getSearchText && !getSearchText(r).toLowerCase().includes(q)) return false;
      for (const f of facets) {
        const sel = facetValues[f.id];
        if (!sel || sel.length === 0) continue;
        const vals = asArray(f.getValue(r));
        if (!vals.some((v) => sel.includes(v))) return false;
      }
      return true;
    });
  }, [rows, search, facets, facetValues, getSearchText]);

  const sorted = useMemo(() => {
    if (!sort) return filtered;
    const col = columns.find((c) => c.id === sort.id);
    if (!col?.sortValue) return filtered;
    const dir = sort.dir === 'asc' ? 1 : -1;
    return [...filtered].sort((a, b) => {
      const va = col.sortValue!(a);
      const vb = col.sortValue!(b);
      if (va === vb) return 0;
      if (va === null || va === undefined || va === '') return 1;
      if (vb === null || vb === undefined || vb === '') return -1;
      if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * dir;
      return String(va).localeCompare(String(vb), 'en', { numeric: true, sensitivity: 'base' }) * dir;
    });
  }, [filtered, sort, columns]);

  // reset paging when filters change
  useEffect(() => setLimit(pageSize), [search, facetValues, pageSize]);

  // drop selections that disappeared
  const rowIds = useMemo(() => new Set(rows.map(getRowId)), [rows, getRowId]);
  useEffect(() => {
    setSelected((s) => {
      const next = new Set([...s].filter((id) => rowIds.has(id)));
      return next.size === s.size ? s : next;
    });
  }, [rowIds]);

  const canSelect = (r: T) => (typeof selectable === 'function' ? selectable(r) : !!selectable);
  const visible = sorted.slice(0, limit);
  const selectableVisible = sorted.filter(canSelect);
  const allSelected = selectableVisible.length > 0 && selectableVisible.every((r) => selected.has(getRowId(r)));
  const someSelected = selectableVisible.some((r) => selected.has(getRowId(r)));
  const selectedRows = rows.filter((r) => selected.has(getRowId(r)));
  const clearSel = () => setSelected(new Set());
  const toggleRow = (id: string) =>
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  const activeFilters = facets.filter((f) => (facetValues[f.id] || []).length > 0).length + (search ? 1 : 0);
  const clearFilters = () => {
    setSearch('');
    facets.forEach((f) => setFacet(f.id, []));
  };

  const onRow = (e: React.MouseEvent, r: T) => {
    if (!onRowClick && !rowHref) return;
    // clicks inside portals (menus, dialogs opened from a cell) bubble through React; ignore them
    if (!(e.currentTarget as HTMLElement).contains(e.target as Node)) return;
    const t = e.target as HTMLElement;
    if (t.closest('a,button,input,label,select,textarea,[role="button"],[role="checkbox"]')) return;
    if (window.getSelection()?.toString()) return;
    if (rowHref) {
      const href = rowHref(r);
      if (e.metaKey || e.ctrlKey) window.open(href, '_blank');
      else navigate(href);
    } else onRowClick?.(r);
  };

  const showSelect = !!selectable;
  const hasToolbar = !hideToolbar && (getSearchText || facets.length > 0 || toolbar);

  const header = hasToolbar ? (
    <div className="flex flex-col gap-2 pb-3 sm:flex-row sm:flex-wrap sm:items-center">
      {getSearchText && (
        <SearchInput value={typed} onChange={setTyped} placeholder={searchPlaceholder} className="sm:max-w-[280px]" inputSize="sm" />
      )}
      {facets.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          {facets.map((f) => (
            <FacetButton key={f.id} facet={f} rows={rows} value={facetValues[f.id] || []} onChange={(v) => setFacet(f.id, v)} />
          ))}
          {activeFilters > 0 && (
            <Button size="sm" variant="ghost" icon={X} onClick={clearFilters}>
              Clear filters
            </Button>
          )}
        </div>
      )}
      {toolbar && <div className="flex flex-wrap items-center gap-2 sm:ml-auto">{toolbar}</div>}
    </div>
  ) : null;

  const bulkBar =
    showSelect && bulkActions && selected.size > 0 ? (
      <div className="sticky bottom-3 z-20 mt-3 flex flex-wrap items-center gap-3 rounded-lg border border-border-strong bg-surface px-4 py-2.5 shadow-pop animate-toast-in">
        <span className="text-[13px] font-medium text-fg">{selected.size} selected</span>
        <div className="flex flex-wrap items-center gap-2">{bulkActions(selectedRows, clearSel)}</div>
        <Button size="sm" variant="ghost" onClick={clearSel} className="ml-auto">
          Clear selection
        </Button>
      </div>
    ) : null;

  let content: React.ReactNode;
  if (loading && rows.length === 0) {
    content = (
      <div className="space-y-2 p-4">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-9" />
        ))}
      </div>
    );
  } else if (rows.length === 0) {
    content = empty ?? <EmptyState title="Nothing here yet" size="sm" />;
  } else if (sorted.length === 0) {
    content = (
      <EmptyState
        icon={SearchX}
        size="sm"
        title="No results match your filters"
        description="Try a different search term or remove a filter."
        action={
          <Button size="sm" onClick={clearFilters}>
            Clear filters
          </Button>
        }
      />
    );
  } else if (isMobile) {
    content = (
      <ul className="divide-y divide-border">
        {visible.map((r, idx) => {
          const id = getRowId(r);
          const [primary, ...rest] = columns.filter((c) => !c.hideOnMobile);
          const gk = groupBy && !sort ? groupBy.key(r) : null;
          const showGroup = gk !== null && (idx === 0 || groupBy!.key(visible[idx - 1]) !== gk);
          return (
            <React.Fragment key={id}>
            {showGroup && (
              <li className="bg-surface-2 px-4 py-1.5 text-[12px] font-medium text-fg-muted">
                {groupBy!.label(gk!, sorted.filter((x) => groupBy!.key(x) === gk))}
              </li>
            )}
            <li
              onClick={(e) => onRow(e, r)}
              className={cn('flex gap-3 px-4 py-3', (rowHref || onRowClick) && 'cursor-pointer active:bg-surface-2', rowClassName?.(r))}
            >
              {showSelect && (
                <Checkbox
                  aria-label="Select row"
                  checked={selected.has(id)}
                  disabled={!canSelect(r)}
                  onChange={() => toggleRow(id)}
                  className="mt-0.5"
                />
              )}
              <div className="min-w-0 flex-1">
                {mobileCard ? (
                  mobileCard(r)
                ) : (
                  <>
                    {primary && <div className="min-w-0 text-[13px]">{primary.cell(r)}</div>}
                    {rest.length > 0 && (
                      <dl className="mt-2 grid grid-cols-2 gap-x-3 gap-y-2">
                        {rest.map((c) => (
                          <div key={c.id} className="min-w-0">
                            <dt className="text-[11.5px] text-fg-subtle">{c.mobileLabel ?? (typeof c.header === 'string' ? c.header : c.id)}</dt>
                            <dd className="mt-0.5 min-w-0 break-words text-[12.5px] text-fg">{c.cell(r)}</dd>
                          </div>
                        ))}
                      </dl>
                    )}
                  </>
                )}
              </div>
            </li>
            </React.Fragment>
          );
        })}
      </ul>
    );
  } else {
    content = (
      <table className="w-full border-separate border-spacing-0 text-[13px]" aria-label={props['aria-label']}>
        <thead>
          <tr>
            {showSelect && (
              <th
                className={cn('w-10 rounded-tl-lg border-b border-border bg-surface-2 py-2 pl-4 pr-1', 'sticky z-10', maxHeight ? 'top-0' : 'top-[var(--sticky-top,56px)]')}
              >
                <Checkbox
                  aria-label="Select all rows"
                  checked={allSelected}
                  indeterminate={!allSelected && someSelected}
                  disabled={selectableVisible.length === 0}
                  onChange={() => (allSelected ? clearSel() : setSelected(new Set(selectableVisible.map(getRowId))))}
                />
              </th>
            )}
            {columns.map((c) => {
              const sorting = sort?.id === c.id ? sort.dir : null;
              return (
                <th
                  key={c.id}
                  scope="col"
                  aria-sort={sorting === 'asc' ? 'ascending' : sorting === 'desc' ? 'descending' : undefined}
                  style={{ width: c.width }}
                  className={cn(
                    'sticky z-10 whitespace-nowrap border-b border-border bg-surface-2 py-2 text-[12px] font-medium text-fg-muted first:rounded-tl-lg first:pl-4 last:rounded-tr-lg last:pr-4',
                    maxHeight ? 'top-0' : 'top-[var(--sticky-top,56px)]',
                    'px-[var(--cell-px)]',
                    alignCls[c.align || 'left'],
                    c.hideBelow && hideCls[c.hideBelow]
                  )}
                >
                  {c.sortValue ? (
                    <button
                      type="button"
                      onClick={() =>
                        setSort((s) => (s?.id !== c.id ? { id: c.id, dir: 'asc' } : s.dir === 'asc' ? { id: c.id, dir: 'desc' } : null))
                      }
                      className={cn('-mx-1 inline-flex items-center gap-1 rounded px-1 hover:text-fg', sorting && 'text-fg', c.align === 'right' && 'flex-row-reverse')}
                    >
                      {c.header}
                      {sorting === 'asc' ? (
                        <ArrowUp className="h-3.5 w-3.5" aria-hidden />
                      ) : sorting === 'desc' ? (
                        <ArrowDown className="h-3.5 w-3.5" aria-hidden />
                      ) : (
                        <ChevronsUpDown className="h-3.5 w-3.5 opacity-40" aria-hidden />
                      )}
                    </button>
                  ) : (
                    c.header
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {visible.map((r, idx) => {
            const id = getRowId(r);
            const isSel = selected.has(id);
            const gk = groupBy && !sort ? groupBy.key(r) : null;
            const showGroup = gk !== null && (idx === 0 || groupBy!.key(visible[idx - 1]) !== gk);
            return (
              <React.Fragment key={id}>
              {showGroup && (
                <tr>
                  <td colSpan={columns.length + (showSelect ? 1 : 0)} className="border-b border-border bg-surface-2/70 px-4 py-1.5 text-[12px] font-medium text-fg-muted">
                    {groupBy!.label(gk!, sorted.filter((x) => groupBy!.key(x) === gk))}
                  </td>
                </tr>
              )}
              <tr
                onClick={(e) => onRow(e, r)}
                className={cn(
                  'group/row transition-colors',
                  (rowHref || onRowClick) && 'cursor-pointer',
                  isSel ? 'bg-accent-soft/60' : 'hover:bg-surface-2',
                  rowClassName?.(r)
                )}
              >
                {showSelect && (
                  <td className="border-b border-border py-[var(--cell-py)] pl-4 pr-1 align-top">
                    <Checkbox aria-label="Select row" checked={isSel} disabled={!canSelect(r)} onChange={() => toggleRow(id)} className="mt-0.5" />
                  </td>
                )}
                {columns.map((c) => (
                  <td
                    key={c.id}
                    className={cn(
                      'border-b border-border px-[var(--cell-px)] py-[var(--cell-py)] align-middle text-fg first:pl-4 last:pr-4',
                      alignCls[c.align || 'left'],
                      c.hideBelow && hideCls[c.hideBelow],
                      c.className
                    )}
                  >
                    {c.cell(r)}
                  </td>
                ))}
              </tr>
              </React.Fragment>
            );
          })}
        </tbody>
      </table>
    );
  }

  return (
    <div className={cn('min-w-0', className)}>
      {header}
      <div
        className={cn('rounded-lg border border-border bg-surface shadow-card', maxHeight ? 'scroll-thin overflow-auto' : 'overflow-x-clip')}
        style={maxHeight ? { maxHeight } : undefined}
      >
        {content}
        {sorted.length > limit && (
          <div className="flex items-center justify-center gap-3 border-t border-border px-4 py-2.5 text-[12.5px] text-fg-muted">
            Showing {visible.length} of {sorted.length}
            <Button size="sm" variant="ghost" onClick={() => setLimit((l) => l + pageSize)}>
              Show more
            </Button>
          </div>
        )}
      </div>
      {bulkBar}
    </div>
  );
}

function FacetButton<T>({ facet, rows, value, onChange }: { facet: FacetDef<T>; rows: T[]; value: string[]; onChange: (v: string[]) => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLButtonElement>(null);
  const options = useMemo(() => {
    const counts = new Map<string, number>();
    for (const r of rows) for (const v of asArray(facet.getValue(r))) counts.set(v, (counts.get(v) || 0) + 1);
    const base = facet.options ?? [...counts.keys()].sort().map((v) => ({ value: v, label: facet.optionLabel?.(v) ?? v }));
    return base.map((o) => ({ ...o, count: counts.get(o.value) || 0 }));
  }, [rows, facet]);
  const labelOf = (v: string) => options.find((o) => o.value === v)?.label ?? v;
  const active = value.length > 0;
  return (
    <>
      <button
        ref={ref}
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className={cn(
          'inline-flex h-[var(--control-h-sm)] max-w-[280px] items-center gap-1.5 rounded-md border px-2.5 text-[12.5px] font-medium transition-colors',
          active ? 'border-accent-border bg-accent-soft text-accent' : 'border-dashed border-border-strong text-fg-muted hover:bg-surface-3 hover:text-fg'
        )}
      >
        <Filter className="h-3.5 w-3.5 shrink-0" aria-hidden />
        <span className="shrink-0">{facet.label}</span>
        {active && (
          <span className="truncate font-normal">
            : {value.length <= 2 ? value.map(labelOf).join(', ') : `${value.length} selected`}
          </span>
        )}
      </button>
      <Popover open={open} onClose={() => setOpen(false)} anchorRef={ref} className="w-[240px]">
        <div role="listbox" aria-multiselectable aria-label={facet.label}>
          {options.length === 0 && <div className="px-3 py-4 text-center text-[12.5px] text-fg-subtle">No values</div>}
          {options.map((o) => {
            const sel = value.includes(o.value);
            return (
              <label key={o.value} className="flex cursor-pointer items-center gap-2.5 rounded-md px-2.5 py-1.5 text-[13px] hover:bg-surface-3">
                <Checkbox checked={sel} onChange={() => onChange(sel ? value.filter((v) => v !== o.value) : [...value, o.value])} />
                <span className="min-w-0 flex-1 truncate text-fg">{o.label}</span>
                <span className="text-[12px] tabular text-fg-subtle">{o.count}</span>
              </label>
            );
          })}
        </div>
        {active && (
          <div className="mt-1 border-t border-border px-2.5 pb-1 pt-2">
            <button type="button" className="text-[12.5px] font-medium text-accent hover:underline" onClick={() => onChange([])}>
              Clear
            </button>
          </div>
        )}
      </Popover>
    </>
  );
}
