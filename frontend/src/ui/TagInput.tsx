import React, { useState } from 'react';
import { X } from 'lucide-react';
import { cn } from '../lib/cn';

export interface TagInputProps {
  value: string[];
  onChange: (v: string[]) => void;
  placeholder?: string;
  /** Returns an error message for an invalid tag (shown inline, tag not added). */
  validate?: (tag: string) => string | null;
  /** Normalizes input (default: trim). */
  normalize?: (tag: string) => string;
  suggestions?: string[];
  max?: number;
  mono?: boolean;
  disabled?: boolean;
  id?: string;
  className?: string;
  'aria-describedby'?: string;
  'aria-invalid'?: boolean;
}

/** Free-text chips: Enter / comma / Tab adds, Backspace removes the last chip, paste splits on commas. */
export const TagInput: React.FC<TagInputProps> = ({
  value,
  onChange,
  placeholder = 'Type and press Enter',
  validate,
  normalize = (t) => t.trim(),
  suggestions = [],
  max,
  mono,
  disabled,
  id,
  className,
  ...aria
}) => {
  const [text, setText] = useState('');
  const [error, setError] = useState<string | null>(null);

  const add = (raw: string) => {
    const parts = raw.split(/[,\n]/).map(normalize).filter(Boolean);
    if (parts.length === 0) return true;
    const next = [...value];
    for (const p of parts) {
      if (next.includes(p)) continue;
      const err = validate?.(p);
      if (err) {
        setError(err);
        return false;
      }
      if (max && next.length >= max) {
        setError(`At most ${max} entries`);
        return false;
      }
      next.push(p);
    }
    setError(null);
    onChange(next);
    return true;
  };

  const unused = suggestions.filter((s) => !value.includes(s) && (!text || s.toLowerCase().includes(text.toLowerCase()))).slice(0, 8);

  return (
    <div className={className}>
      <div
        className={cn('control flex min-h-[var(--control-h)] flex-wrap items-center gap-1 px-1.5 py-1', disabled && 'bg-surface-2')}
        aria-disabled={disabled || undefined}
        onClick={(e) => (e.currentTarget.querySelector('input') as HTMLInputElement | null)?.focus()}
      >
        {value.map((t) => (
          <span key={t} className={cn('inline-flex max-w-full items-center gap-1 rounded bg-surface-3 py-0.5 pl-1.5 pr-0.5 text-[12px] text-fg', mono && 'font-mono')}>
            <span className="truncate">{t}</span>
            {!disabled && (
              <button
                type="button"
                aria-label={`Remove ${t}`}
                onClick={(e) => {
                  e.stopPropagation();
                  onChange(value.filter((x) => x !== t));
                }}
                className="rounded p-0.5 text-fg-subtle hover:bg-surface hover:text-fg"
              >
                <X className="h-3 w-3" />
              </button>
            )}
          </span>
        ))}
        <input
          id={id}
          value={text}
          disabled={disabled}
          placeholder={value.length === 0 ? placeholder : ''}
          onChange={(e) => {
            setText(e.target.value);
            setError(null);
          }}
          onPaste={(e) => {
            const data = e.clipboardData.getData('text');
            if (/[,\n]/.test(data)) {
              e.preventDefault();
              if (add(data)) setText('');
            }
          }}
          onKeyDown={(e) => {
            if ((e.key === 'Enter' || e.key === ',' || (e.key === 'Tab' && text)) && text.trim()) {
              e.preventDefault();
              if (add(text)) setText('');
            } else if (e.key === 'Backspace' && !text && value.length > 0) {
              onChange(value.slice(0, -1));
            }
          }}
          onBlur={() => {
            if (text.trim() && add(text)) setText('');
          }}
          className={cn('min-w-[120px] flex-1 bg-transparent px-1.5 py-1 text-[13px] outline-hidden placeholder:text-fg-subtle', mono && 'font-mono text-[12.5px]')}
          {...aria}
        />
      </div>
      {error && <p className="mt-1.5 text-[12px] text-danger">{error}</p>}
      {unused.length > 0 && !disabled && (
        <div className="mt-1.5 flex flex-wrap gap-1">
          {unused.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => add(s)}
              className="rounded border border-dashed border-border-strong px-1.5 py-0.5 text-[12px] text-fg-muted hover:border-accent hover:text-accent"
            >
              + {s}
            </button>
          ))}
        </div>
      )}
    </div>
  );
};
