import React from 'react';
import { Check } from 'lucide-react';
import { cn } from '../../lib/cn';
import { GROUP_COLORS, validateHexColor } from './fleetUtils';

/** Preset swatches + hex input + native color picker. */
export const ColorPicker: React.FC<{ value: string; onChange: (v: string) => void; id?: string; disabled?: boolean }> = ({ value, onChange, id, disabled }) => {
  const valid = !validateHexColor(value);
  const norm = value.trim().toUpperCase();
  return (
    <div className="space-y-2.5">
      <div role="radiogroup" aria-label="Preset colors" className="flex flex-wrap gap-1.5">
        {GROUP_COLORS.map((c) => {
          const active = norm === c.toUpperCase();
          return (
            <button
              key={c}
              type="button"
              role="radio"
              aria-checked={active}
              aria-label={c}
              title={c}
              disabled={disabled}
              onClick={() => onChange(c)}
              className={cn(
                'flex h-7 w-7 items-center justify-center rounded-md shadow-xs ring-offset-2 ring-offset-surface transition focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring/60',
                active && 'ring-2 ring-fg/70'
              )}
              style={{ background: c }}
            >
              {active && <Check className="h-3.5 w-3.5 text-white" strokeWidth={3} aria-hidden />}
            </button>
          );
        })}
      </div>
      <div className="flex items-center gap-2">
        <label className="relative flex h-[var(--control-h)] w-[var(--control-h)] shrink-0 cursor-pointer overflow-hidden rounded-md border border-border-strong" title="Pick a custom color">
          <span className="absolute inset-0" style={{ background: valid ? value : 'transparent' }} aria-hidden />
          <input
            type="color"
            value={valid ? value : '#64748B'}
            disabled={disabled}
            onChange={(e) => onChange(e.target.value.toUpperCase())}
            className="absolute inset-0 h-full w-full cursor-pointer opacity-0"
            aria-label="Custom color"
          />
        </label>
        <input
          id={id}
          value={value}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value)}
          aria-invalid={!valid || undefined}
          className="control w-32 px-2.5 font-mono text-[12.5px]"
          placeholder="#2563EB"
          spellCheck={false}
        />
        {!valid && <span className="text-[12px] text-danger">Use #RRGGBB</span>}
      </div>
    </div>
  );
};
