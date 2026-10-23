import React from 'react';
import { Plus, Trash2 } from 'lucide-react';
import { cn } from '../lib/cn';
import { Button, IconButton } from './Button';

const KEY_RE = /^[a-z0-9]([a-z0-9._/-]{0,61}[a-z0-9])?$/i;

export interface KeyValueEditorProps {
  value: Record<string, string>;
  onChange: (v: Record<string, string>) => void;
  keyPlaceholder?: string;
  valuePlaceholder?: string;
  /** Explain that `*` matches any value (dynamic group selectors). */
  allowWildcard?: boolean;
  disabled?: boolean;
  addLabel?: string;
  className?: string;
}

/**
 * Edits labels / selectors (key=value). Keeps rows in insertion order; empty keys are dropped
 * from the emitted value. Keys: letters, digits, '.', '_', '/', '-'.
 */
export const KeyValueEditor: React.FC<KeyValueEditorProps> = ({
  value,
  onChange,
  keyPlaceholder = 'key',
  valuePlaceholder = 'value',
  allowWildcard,
  disabled,
  addLabel = 'Add label',
  className,
}) => {
  const [rows, setRows] = React.useState<Array<[string, string]>>(() => Object.entries(value || {}));
  const lastEmitted = React.useRef(JSON.stringify(value || {}));

  // follow external changes
  React.useEffect(() => {
    const s = JSON.stringify(value || {});
    if (s !== lastEmitted.current) {
      lastEmitted.current = s;
      setRows(Object.entries(value || {}));
    }
  }, [value]);

  const emit = (next: Array<[string, string]>) => {
    setRows(next);
    const obj: Record<string, string> = {};
    for (const [k, v] of next) if (k.trim()) obj[k.trim()] = v.trim();
    lastEmitted.current = JSON.stringify(obj);
    onChange(obj);
  };

  const dupKeys = new Set(rows.map((r) => r[0].trim()).filter((k, i, a) => k && a.indexOf(k) !== i));

  return (
    <div className={cn('space-y-2', className)}>
      {rows.length === 0 && <p className="text-[12.5px] text-fg-subtle">No labels.</p>}
      {rows.map(([k, v], i) => {
        const keyErr = k.trim() && !KEY_RE.test(k.trim()) ? 'Use letters, digits, . _ / -' : dupKeys.has(k.trim()) ? 'Duplicate key' : null;
        return (
          <div key={i} className="flex items-start gap-2">
            <div className="min-w-0 flex-1">
              <input
                aria-label={`Label key ${i + 1}`}
                value={k}
                disabled={disabled}
                placeholder={keyPlaceholder}
                aria-invalid={!!keyErr || undefined}
                onChange={(e) => emit(rows.map((r, j) => (j === i ? [e.target.value, r[1]] : r)))}
                className="control px-2.5 font-mono text-[12.5px]"
              />
              {keyErr && <p className="mt-1 text-[11.5px] text-danger">{keyErr}</p>}
            </div>
            <span className="mt-2 text-fg-subtle">=</span>
            <input
              aria-label={`Label value ${i + 1}`}
              value={v}
              disabled={disabled}
              placeholder={allowWildcard ? `${valuePlaceholder} or *` : valuePlaceholder}
              onChange={(e) => emit(rows.map((r, j) => (j === i ? [r[0], e.target.value] : r)))}
              className="control min-w-0 flex-1 px-2.5 font-mono text-[12.5px]"
            />
            <IconButton icon={Trash2} label="Remove label" disabled={disabled} onClick={() => emit(rows.filter((_, j) => j !== i))} />
          </div>
        );
      })}
      <div className="flex items-center gap-3">
        <Button size="sm" variant="ghost" icon={Plus} disabled={disabled} onClick={() => setRows([...rows, ['', '']])}>
          {addLabel}
        </Button>
        {allowWildcard && <span className="text-[12px] text-fg-subtle">Value * matches any value of that key.</span>}
      </div>
    </div>
  );
};
