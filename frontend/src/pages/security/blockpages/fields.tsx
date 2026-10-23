import React, { useCallback, useRef, useState } from 'react';
import type { LucideIcon } from 'lucide-react';
import { ArrowDown, ArrowUp, Braces, ImagePlus, Plus, Trash2, Upload } from 'lucide-react';
import { cn } from '../../../lib/cn';
import { formatBytes } from '../../../lib/format';
import type { LinkItem } from '../../../types';
import { Button, Checkbox, Field, IconButton, Input, Tooltip, useToast } from '../../../ui';
import { LIMITS, LOGO_TYPES, VARIABLES } from './model';

// ---------------------------------------------------------------------------
// Section card with an anchor id (the editor's section nav scrolls to it)
// ---------------------------------------------------------------------------

export const FormSection: React.FC<{
  id: string;
  title: string;
  description?: React.ReactNode;
  icon: LucideIcon;
  aside?: React.ReactNode;
  children: React.ReactNode;
}> = ({ id, title, description, icon: Icon, aside, children }) => (
  <section id={id} aria-labelledby={`${id}-title`} className="scroll-mt-[124px] rounded-lg border border-border bg-surface shadow-card">
    <header className="flex items-start justify-between gap-3 border-b border-border px-[var(--card-p)] py-3.5">
      <div className="flex min-w-0 items-start gap-2.5">
        <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-surface-3 text-fg-muted">
          <Icon className="h-4 w-4" aria-hidden />
        </span>
        <div className="min-w-0">
          <h2 id={`${id}-title`} className="text-[14px] font-semibold leading-6 text-fg">
            {title}
          </h2>
          {description && <p className="text-[12.5px] leading-5 text-fg-muted">{description}</p>}
        </div>
      </div>
      {aside}
    </header>
    <div className="space-y-5 p-[var(--card-p)]">{children}</div>
  </section>
);

/** "12 / 120" counter for text fields. */
export const Counter: React.FC<{ value: string; max: number }> = ({ value, max }) => (
  <span className={cn('text-[11.5px] tabular', value.length > max ? 'text-danger' : 'text-fg-subtle')}>
    {value.length} / {max}
  </span>
);

// ---------------------------------------------------------------------------
// Colors
// ---------------------------------------------------------------------------

const HEX = /^#[0-9A-Fa-f]{6}$/;

export const ColorField: React.FC<{
  label: string;
  hint?: React.ReactNode;
  value: string;
  onChange: (v: string) => void;
  error?: string;
  disabled?: boolean;
  presets: string[];
}> = ({ label, hint, value, onChange, error, disabled, presets }) => {
  const [text, setText] = useState(value);
  React.useEffect(() => setText(value), [value]);
  return (
    <Field label={label} hint={hint} error={error}>
      {({ id, describedBy, invalid }) => (
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <label
              className={cn('relative h-[var(--control-h)] w-11 shrink-0 cursor-pointer overflow-hidden rounded-md border border-border-strong shadow-xs', disabled && 'cursor-not-allowed opacity-60')}
              style={{ background: HEX.test(value) ? value : 'transparent' }}
            >
              <span className="sr-only">Pick {label.toLowerCase()}</span>
              <input
                type="color"
                value={HEX.test(value) ? value : '#000000'}
                disabled={disabled}
                onChange={(e) => onChange(e.target.value.toUpperCase())}
                className="absolute inset-0 h-full w-full cursor-pointer opacity-0"
              />
            </label>
            <Input
              id={id}
              aria-describedby={describedBy}
              aria-invalid={invalid || undefined}
              mono
              value={text}
              disabled={disabled}
              maxLength={7}
              spellCheck={false}
              onChange={(e) => {
                let v = e.target.value.trim();
                if (v && !v.startsWith('#')) v = `#${v}`;
                setText(v);
                onChange(HEX.test(v) ? v.toUpperCase() : v);
              }}
              className="max-w-[130px]"
            />
          </div>
          {!disabled && (
            <div className="flex flex-wrap gap-1.5" role="group" aria-label={`${label} presets`}>
              {presets.map((c) => (
                <button
                  key={c}
                  type="button"
                  title={c}
                  aria-label={`Use ${c}`}
                  aria-pressed={value.toUpperCase() === c}
                  onClick={() => onChange(c)}
                  className={cn(
                    'h-5 w-5 rounded-full border border-black/10 transition-transform hover:scale-110',
                    value.toUpperCase() === c && 'ring-2 ring-accent ring-offset-2 ring-offset-surface'
                  )}
                  style={{ background: c }}
                />
              ))}
            </div>
          )}
        </div>
      )}
    </Field>
  );
};

// ---------------------------------------------------------------------------
// Logo upload (data URL, ≤ 200 KB)
// ---------------------------------------------------------------------------

function dataUrlBytes(url: string): number {
  const i = url.indexOf(',');
  if (i < 0) return 0;
  const b64 = url.slice(i + 1);
  return Math.floor((b64.length * 3) / 4) - (b64.endsWith('==') ? 2 : b64.endsWith('=') ? 1 : 0);
}

export const LogoField: React.FC<{ value: string; onChange: (v: string) => void; disabled?: boolean }> = ({ value, onChange, disabled }) => {
  const toast = useToast();
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  const accept = useCallback(
    (file: File | undefined) => {
      if (!file) return;
      if (!LOGO_TYPES.includes(file.type)) {
        toast.error('Use a PNG, JPEG, GIF, WebP or SVG image.', { title: 'Logo not supported' });
        return;
      }
      if (file.size > LIMITS.logoBytes) {
        toast.error(`The file has ${formatBytes(file.size)}; the limit is 200 KB. Export a smaller version (an SVG or a 2x PNG of the logo height).`, {
          title: 'Logo too large',
        });
        return;
      }
      const reader = new FileReader();
      reader.onload = () => {
        const url = String(reader.result || '');
        if (!/^data:image\/(png|jpeg|gif|webp|svg\+xml);base64,/.test(url)) {
          toast.error('The image could not be read as a base64 data URL.', { title: 'Logo not supported' });
          return;
        }
        onChange(url);
      };
      reader.onerror = () => toast.error('The file could not be read.', { title: 'Logo upload failed' });
      reader.readAsDataURL(file);
    },
    [onChange, toast]
  );

  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between gap-2">
        <span className="label">Logo</span>
        <span className="text-[11.5px] text-fg-subtle">PNG, JPEG, GIF, WebP or SVG · max 200 KB</span>
      </div>
      <div
        onDragOver={(e) => {
          if (disabled) return;
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          if (!disabled) accept(e.dataTransfer.files?.[0]);
        }}
        className={cn(
          'flex flex-col gap-3 rounded-lg border border-dashed p-3 sm:flex-row sm:items-center',
          dragging ? 'border-accent bg-accent-soft' : 'border-border-strong bg-surface-2'
        )}
      >
        <div
          className="flex h-16 w-full shrink-0 items-center justify-center overflow-hidden rounded-md border border-border sm:w-40"
          style={{
            backgroundImage:
              'linear-gradient(45deg, rgb(var(--c-surface-3)) 25%, transparent 25%), linear-gradient(-45deg, rgb(var(--c-surface-3)) 25%, transparent 25%), linear-gradient(45deg, transparent 75%, rgb(var(--c-surface-3)) 75%), linear-gradient(-45deg, transparent 75%, rgb(var(--c-surface-3)) 75%)',
            backgroundSize: '12px 12px',
            backgroundPosition: '0 0, 0 6px, 6px -6px, -6px 0',
          }}
        >
          {value ? (
            <img src={value} alt="Logo preview" className="max-h-12 max-w-[90%] object-contain" />
          ) : (
            <ImagePlus className="h-5 w-5 text-fg-subtle" aria-hidden />
          )}
        </div>
        <div className="min-w-0 flex-1 text-[12.5px] text-fg-muted">
          {value ? (
            <>
              <span className="font-medium text-fg">Logo embedded</span> · {formatBytes(dataUrlBytes(value))}
              <span className="block text-[12px] text-fg-subtle">Shown above the card, next to the company name.</span>
            </>
          ) : (
            <>
              <span className="font-medium text-fg">No logo</span>
              <span className="block text-[12px] text-fg-subtle">Drop an image here or choose a file. It is embedded in the page — no external requests.</span>
            </>
          )}
        </div>
        {!disabled && (
          <div className="flex shrink-0 gap-2">
            <Button size="sm" icon={Upload} onClick={() => inputRef.current?.click()}>
              {value ? 'Replace' : 'Choose file'}
            </Button>
            {value && (
              <Button size="sm" variant="danger-ghost" icon={Trash2} onClick={() => onChange('')}>
                Remove
              </Button>
            )}
          </div>
        )}
        <input
          ref={inputRef}
          type="file"
          accept={LOGO_TYPES.join(',')}
          className="sr-only"
          tabIndex={-1}
          aria-label="Logo file"
          onChange={(e) => {
            accept(e.target.files?.[0]);
            e.target.value = '';
          }}
        />
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Variable chips: insert {variable} at the cursor of the last focused text field
// ---------------------------------------------------------------------------

type TextEl = HTMLInputElement | HTMLTextAreaElement;

export interface TextTargets {
  /** Props to spread on a text field: ref + focus tracking. */
  bind: (field: string) => { ref: (el: TextEl | null) => void; onFocus: () => void };
  active: string;
  insert: (variable: string) => void;
}

/**
 * Tracks the text fields of a card and inserts variables at the caret of the last focused one.
 * `setValue(field, next)` must update the draft.
 */
export function useTextTargets(fields: string[], getValue: (field: string) => string, setValue: (field: string, v: string) => void): TextTargets {
  const els = useRef(new Map<string, TextEl>());
  const [active, setActive] = useState(fields[0]);
  const bind = useCallback(
    (field: string) => ({
      ref: (el: TextEl | null) => {
        if (el) els.current.set(field, el);
        else els.current.delete(field);
      },
      onFocus: () => setActive(field),
    }),
    []
  );
  const insert = (variable: string) => {
    const el = els.current.get(active);
    const cur = getValue(active);
    const token = `{${variable}}`;
    const start = el?.selectionStart ?? cur.length;
    const end = el?.selectionEnd ?? cur.length;
    const next = cur.slice(0, start) + token + cur.slice(end);
    setValue(active, next);
    window.requestAnimationFrame(() => {
      if (!el) return;
      el.focus();
      const pos = start + token.length;
      el.setSelectionRange(pos, pos);
    });
  };
  return { bind, active, insert };
}

export const VariableToolbar: React.FC<{ targets: TextTargets; labels: Record<string, string>; disabled?: boolean }> = ({ targets, labels, disabled }) => (
  <div className="rounded-lg border border-border bg-surface-2 px-3 py-2.5">
    <div className="mb-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-[12px] text-fg-muted">
      <Braces className="h-3.5 w-3.5 text-fg-subtle" aria-hidden />
      <span>
        Insert a variable into <span className="font-medium text-fg">{labels[targets.active] ?? targets.active}</span>
      </span>
      <span className="text-fg-subtle">· click a field first to choose where</span>
    </div>
    <div className="flex flex-wrap gap-1.5">
      {VARIABLES.map((v) => (
        <Tooltip key={v.name} content={`${v.label} — e.g. ${v.sample}`}>
          <button
            type="button"
            disabled={disabled}
            // keep the caret in the text field
            onMouseDown={(e) => e.preventDefault()}
            onClick={() => targets.insert(v.name)}
            className="rounded-md border border-border-strong bg-surface px-1.5 py-0.5 font-mono text-[11.5px] text-accent transition-colors hover:border-accent hover:bg-accent-soft disabled:cursor-not-allowed disabled:opacity-50"
          >
            {`{${v.name}}`}
          </button>
        </Tooltip>
      ))}
    </div>
  </div>
);

// ---------------------------------------------------------------------------
// Help links (≤ 6, ordered)
// ---------------------------------------------------------------------------

export const LinksEditor: React.FC<{
  value: LinkItem[];
  onChange: (v: LinkItem[]) => void;
  errors: Partial<Record<string, string>>;
  disabled?: boolean;
}> = ({ value, onChange, errors, disabled }) => {
  const set = (i: number, patch: Partial<LinkItem>) => onChange(value.map((l, j) => (j === i ? { ...l, ...patch } : l)));
  const move = (i: number, d: -1 | 1) => {
    const next = [...value];
    const [x] = next.splice(i, 1);
    next.splice(i + d, 0, x);
    onChange(next);
  };
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <span className="label">Links</span>
        <span className="text-[11.5px] text-fg-subtle">
          {value.length} / {LIMITS.links} · e.g. egress policy, service desk, request status
        </span>
      </div>
      {value.length === 0 && <p className="rounded-md border border-dashed border-border-strong px-3 py-3 text-[12.5px] text-fg-subtle">No links. They appear as buttons under the help section.</p>}
      {value.map((l, i) => (
        <div key={i} className="flex items-start gap-2 rounded-md border border-border bg-surface-2 p-2">
          <div className="grid min-w-0 flex-1 gap-2 sm:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
            <div className="min-w-0">
              <Input
                aria-label={`Link ${i + 1} label`}
                placeholder="Label"
                value={l.label}
                disabled={disabled}
                maxLength={LIMITS.link_label + 10}
                aria-invalid={!!errors[`links.${i}.label`] || undefined}
                onChange={(e) => set(i, { label: e.target.value })}
              />
              {errors[`links.${i}.label`] && <p className="mt-1 text-[11.5px] text-danger">{errors[`links.${i}.label`]}</p>}
            </div>
            <div className="min-w-0">
              <Input
                aria-label={`Link ${i + 1} URL`}
                placeholder="https://"
                mono
                type="url"
                value={l.url}
                disabled={disabled}
                aria-invalid={!!errors[`links.${i}.url`] || undefined}
                onChange={(e) => set(i, { url: e.target.value })}
              />
              {errors[`links.${i}.url`] && <p className="mt-1 text-[11.5px] text-danger">{errors[`links.${i}.url`]}</p>}
            </div>
          </div>
          {!disabled && (
            <div className="flex shrink-0 items-center">
              <IconButton icon={ArrowUp} label="Move up" size="sm" disabled={i === 0} onClick={() => move(i, -1)} />
              <IconButton icon={ArrowDown} label="Move down" size="sm" disabled={i === value.length - 1} onClick={() => move(i, 1)} />
              <IconButton icon={Trash2} label="Remove link" size="sm" variant="danger-ghost" onClick={() => onChange(value.filter((_, j) => j !== i))} />
            </div>
          )}
        </div>
      ))}
      {!disabled && (
        <Button size="sm" variant="ghost" icon={Plus} disabled={value.length >= LIMITS.links} onClick={() => onChange([...value, { label: '', url: '' }])}>
          Add link
        </Button>
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Checkbox group with explanations (scopes, durations)
// ---------------------------------------------------------------------------

export const ChoiceGroup: React.FC<{
  label: string;
  hint?: React.ReactNode;
  options: Array<{ value: string; label: string; description: string }>;
  value: string[];
  onChange: (v: string[]) => void;
  error?: string;
  disabled?: boolean;
  columns?: 1 | 2;
}> = ({ label, hint, options, value, onChange, error, disabled, columns = 1 }) => (
  <fieldset className="min-w-0">
    <legend className="label mb-1.5">{label}</legend>
    {hint && <p className="-mt-0.5 mb-2 text-[12px] text-fg-subtle">{hint}</p>}
    <div className={cn('grid gap-2', columns === 2 && 'sm:grid-cols-2')}>
      {options.map((o) => {
        const on = value.includes(o.value);
        return (
          <label
            key={o.value}
            className={cn(
              'flex cursor-pointer items-start gap-2.5 rounded-md border px-3 py-2.5 transition-colors',
              on ? 'border-accent-border bg-accent-soft' : 'border-border bg-surface hover:border-border-strong',
              disabled && 'cursor-not-allowed opacity-70'
            )}
          >
            <Checkbox checked={on} disabled={disabled} onChange={() => onChange(on ? value.filter((v) => v !== o.value) : [...value, o.value])} className="mt-0.5" />
            <span className="min-w-0 text-[13px] leading-5">
              <span className="font-medium text-fg">{o.label}</span>
              <span className="block text-[12px] text-fg-muted">{o.description}</span>
            </span>
          </label>
        );
      })}
    </div>
    {error && <p className="mt-1.5 text-[12px] text-danger">{error}</p>}
  </fieldset>
);
