import React, { useId, useMemo } from 'react';
import { Plus, Trash2 } from 'lucide-react';
import type { Server } from '../../types';
import { Button, IconButton } from '../../ui';
import { validateLabelKey } from './fleetUtils';

export interface SelectorRow {
  key: string;
  value: string;
}

export function rowsToSelector(rows: SelectorRow[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const r of rows) {
    const k = r.key.trim().toLowerCase();
    if (k) out[k] = r.value.trim() || '*';
  }
  return out;
}

export function selectorToRows(sel?: Record<string, string> | null): SelectorRow[] {
  return Object.entries(sel ?? {}).map(([key, value]) => ({ key, value }));
}

export function selectorErrors(rows: SelectorRow[]): string[] {
  const seen = new Set<string>();
  return rows.map((r) => {
    const k = r.key.trim().toLowerCase();
    if (!k) return r.value.trim() ? 'Enter a key.' : '';
    const e = validateLabelKey(r.key.trim());
    if (e) return e;
    if (seen.has(k)) return 'Duplicate key.';
    seen.add(k);
    return '';
  });
}

/**
 * Label selector builder: key/value rows (all must match), `*` matches any value of the key.
 * Keys and values are suggested from the labels of registered servers.
 */
export const LabelSelectorEditor: React.FC<{ rows: SelectorRow[]; onChange: (rows: SelectorRow[]) => void; servers: Server[]; disabled?: boolean }> = ({
  rows,
  onChange,
  servers,
  disabled,
}) => {
  const uid = useId();
  const known = useMemo(() => {
    const m = new Map<string, Set<string>>();
    for (const s of servers) for (const [k, v] of Object.entries(s.labels ?? {})) (m.get(k) ?? m.set(k, new Set()).get(k)!).add(v);
    return m;
  }, [servers]);
  const errors = selectorErrors(rows);
  const update = (i: number, patch: Partial<SelectorRow>) => onChange(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));

  return (
    <div className="space-y-2">
      {rows.length === 0 && <p className="text-[12.5px] text-fg-subtle">No selector: membership is static or by CIDR only.</p>}
      {rows.map((r, i) => {
        const values = [...(known.get(r.key.trim().toLowerCase()) ?? [])].sort();
        return (
          <div key={i} className="flex items-start gap-2">
            {i > 0 && <span className="mt-2 w-7 shrink-0 text-center text-[11.5px] font-medium text-fg-subtle">and</span>}
            {i === 0 && <span className="mt-2 w-7 shrink-0 text-center text-[11.5px] font-medium text-fg-subtle">if</span>}
            <div className="min-w-0 flex-1">
              <input
                aria-label={`Selector key ${i + 1}`}
                value={r.key}
                disabled={disabled}
                list={`${uid}-keys`}
                placeholder="key"
                aria-invalid={!!errors[i] || undefined}
                onChange={(e) => update(i, { key: e.target.value })}
                className="control px-2.5 font-mono text-[12.5px]"
              />
              {errors[i] && <p className="mt-1 text-[11.5px] text-danger">{errors[i]}</p>}
            </div>
            <span className="mt-2 text-fg-subtle">=</span>
            <div className="min-w-0 flex-1">
              <input
                aria-label={`Selector value ${i + 1}`}
                value={r.value}
                disabled={disabled}
                list={`${uid}-v${i}`}
                placeholder="value or *"
                onChange={(e) => update(i, { value: e.target.value })}
                className="control px-2.5 font-mono text-[12.5px]"
              />
              <datalist id={`${uid}-v${i}`}>
                <option value="*">any value</option>
                {values.map((v) => (
                  <option key={v} value={v} />
                ))}
              </datalist>
            </div>
            <IconButton icon={Trash2} label="Remove condition" disabled={disabled} onClick={() => onChange(rows.filter((_, j) => j !== i))} />
          </div>
        );
      })}
      <datalist id={`${uid}-keys`}>
        {[...known.keys()].sort().map((k) => (
          <option key={k} value={k} />
        ))}
      </datalist>
      <Button size="sm" variant="ghost" icon={Plus} disabled={disabled} onClick={() => onChange([...rows, { key: '', value: '' }])}>
        Add condition
      </Button>
    </div>
  );
};
