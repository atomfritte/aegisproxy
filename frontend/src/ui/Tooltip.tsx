import React, { useCallback, useId, useLayoutEffect, useRef, useState } from 'react';
import { cn } from '../lib/cn';
import { Portal } from './Portal';

export interface TooltipProps {
  content: React.ReactNode;
  children: React.ReactNode;
  side?: 'top' | 'bottom';
  /** Wrapper class (the trigger is wrapped in an inline-flex span). */
  className?: string;
  delay?: number;
  disabled?: boolean;
}

/** Hover/focus tooltip rendered in a portal (never clipped by scroll containers). */
export const Tooltip: React.FC<TooltipProps> = ({ content, children, side = 'top', className, delay = 250, disabled }) => {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number; side: 'top' | 'bottom' } | null>(null);
  const triggerRef = useRef<HTMLSpanElement>(null);
  const tipRef = useRef<HTMLDivElement>(null);
  const timer = useRef<number | undefined>(undefined);
  const id = useId();

  const show = useCallback(() => {
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setOpen(true), delay);
  }, [delay]);
  const hide = useCallback(() => {
    window.clearTimeout(timer.current);
    setOpen(false);
    setPos(null);
  }, []);

  useLayoutEffect(() => {
    if (!open || !triggerRef.current || !tipRef.current) return;
    const r = triggerRef.current.getBoundingClientRect();
    const t = tipRef.current.getBoundingClientRect();
    let s = side;
    if (s === 'top' && r.top - t.height - 8 < 4) s = 'bottom';
    if (s === 'bottom' && r.bottom + t.height + 8 > window.innerHeight - 4) s = 'top';
    const top = s === 'top' ? r.top - t.height - 6 : r.bottom + 6;
    let left = r.left + r.width / 2 - t.width / 2;
    left = Math.max(6, Math.min(left, window.innerWidth - t.width - 6));
    setPos({ top, left, side: s });
  }, [open, side, content]);

  if (disabled || content === null || content === undefined || content === '') return <>{children}</>;

  return (
    <>
      <span
        ref={triggerRef}
        className={cn('inline-flex max-w-full', className)}
        onPointerEnter={show}
        onPointerLeave={hide}
        onFocusCapture={show}
        onBlurCapture={hide}
        onKeyDown={(e) => e.key === 'Escape' && hide()}
        aria-describedby={open ? id : undefined}
      >
        {children}
      </span>
      {open && (
        <Portal>
          <div
            ref={tipRef}
            id={id}
            role="tooltip"
            style={{ top: pos?.top ?? -9999, left: pos?.left ?? -9999 }}
            className={cn(
              'pointer-events-none fixed z-[100] max-w-[320px] rounded-md bg-fg px-2 py-1 text-[12px] font-medium leading-snug text-bg shadow-pop',
              pos ? 'animate-fade-in' : 'opacity-0'
            )}
          >
            {content}
          </div>
        </Portal>
      )}
    </>
  );
};
