import React, { forwardRef, useCallback, useImperativeHandle, useLayoutEffect, useMemo, useRef } from 'react';
import { cn } from '../lib/cn';

export interface CodeEditorProps extends Omit<React.TextareaHTMLAttributes<HTMLTextAreaElement>, 'value' | 'onChange'> {
  value: string;
  onChange: (value: string) => void;
  /** Visible height in lines before the editor scrolls (default 22). */
  rows?: number;
  /** 1-based line numbers to highlight (e.g. compiler errors). */
  errorLines?: number[];
  /** Spaces inserted by Tab (default 2). Shift+Tab outdents; Esc then Tab leaves the editor. */
  tabSize?: number;
}

const LINE_PX = 20;

/**
 * Monospace source editor: textarea with a line-number gutter, Tab indentation and highlighted
 * error lines. Plain text (no syntax highlighting) — keeps the bundle small and CSP-friendly.
 * Pressing Esc releases Tab so keyboard users can leave the editor.
 */
export const CodeEditor = forwardRef<HTMLTextAreaElement, CodeEditorProps>(function CodeEditor(
  { value, onChange, rows = 22, errorLines, tabSize = 2, className, disabled, readOnly, onKeyDown, onScroll, ...rest },
  ref
) {
  const ta = useRef<HTMLTextAreaElement>(null);
  const gutter = useRef<HTMLDivElement>(null);
  const tabTrap = useRef(true);
  useImperativeHandle(ref, () => ta.current as HTMLTextAreaElement);
  const lines = useMemo(() => Math.max(1, value.split('\n').length), [value]);
  const errors = useMemo(() => new Set(errorLines ?? []), [errorLines]);

  const sync = useCallback(() => {
    if (gutter.current && ta.current) gutter.current.scrollTop = ta.current.scrollTop;
  }, []);
  useLayoutEffect(sync, [value, sync]);

  const replaceSelection = (el: HTMLTextAreaElement, start: number, end: number, text: string, selStart: number, selEnd: number) => {
    const next = el.value.slice(0, start) + text + el.value.slice(end);
    onChange(next);
    requestAnimationFrame(() => {
      el.selectionStart = selStart;
      el.selectionEnd = selEnd;
    });
  };

  const handleKey = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    onKeyDown?.(e);
    if (e.defaultPrevented || disabled || readOnly) return;
    if (e.key === 'Escape') {
      tabTrap.current = false;
      return;
    }
    if (e.key !== 'Tab' || !tabTrap.current || e.ctrlKey || e.metaKey || e.altKey) return;
    e.preventDefault();
    const el = e.currentTarget;
    const { selectionStart: s, selectionEnd: t, value: v } = el;
    const indent = ' '.repeat(tabSize);
    const lineStart = v.lastIndexOf('\n', s - 1) + 1;
    if (!e.shiftKey && s === t) {
      replaceSelection(el, s, t, indent, s + indent.length, s + indent.length);
      return;
    }
    // indent / outdent every selected line
    const blockEnd = t > s && v[t - 1] === '\n' ? t - 1 : t;
    const block = v.slice(lineStart, blockEnd);
    const out = block
      .split('\n')
      .map((l) => (e.shiftKey ? l.replace(new RegExp(`^ {1,${tabSize}}`), '') : indent + l))
      .join('\n');
    const delta = out.length - block.length;
    const firstDelta = e.shiftKey ? out.split('\n')[0].length - block.split('\n')[0].length : indent.length;
    replaceSelection(el, lineStart, blockEnd, out, Math.max(lineStart, s + firstDelta), t + delta);
  };

  return (
    <div
      className={cn(
        'control relative flex overflow-hidden p-0 font-mono text-[12.5px]',
        (disabled || readOnly) && 'bg-surface-2',
        className
      )}
      aria-disabled={disabled || undefined}
      style={{ height: rows * LINE_PX + 18 }}
    >
      <div
        ref={gutter}
        aria-hidden
        className="pointer-events-none w-12 shrink-0 select-none overflow-hidden border-r border-border bg-surface-2 py-2 pr-2 text-right tabular text-fg-subtle"
      >
        {Array.from({ length: lines }, (_, i) => (
          <div key={i} style={{ height: LINE_PX, lineHeight: `${LINE_PX}px` }} className={cn(errors.has(i + 1) && 'bg-danger-soft font-semibold text-danger')}>
            {i + 1}
          </div>
        ))}
        <div style={{ height: 40 }} />
      </div>
      <textarea
        ref={ta}
        value={value}
        disabled={disabled}
        readOnly={readOnly}
        spellCheck={false}
        autoCapitalize="off"
        autoComplete="off"
        autoCorrect="off"
        wrap="off"
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={handleKey}
        onFocus={() => (tabTrap.current = true)}
        onScroll={(e) => {
          sync();
          onScroll?.(e);
        }}
        className="scroll-thin h-full min-w-0 flex-1 resize-none whitespace-pre bg-transparent px-3 py-2 text-fg outline-hidden placeholder:text-fg-subtle disabled:cursor-not-allowed"
        style={{ lineHeight: `${LINE_PX}px`, tabSize }}
        {...rest}
      />
    </div>
  );
});
