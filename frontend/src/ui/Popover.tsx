import React, { RefObject, useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { cn } from '../lib/cn';
import { useOnClickOutside } from '../lib/hooks';
import { Portal } from './Portal';

export interface PopoverProps {
  open: boolean;
  onClose: () => void;
  anchorRef: RefObject<HTMLElement>;
  children: React.ReactNode;
  align?: 'start' | 'end';
  /** Match the anchor's width (select-like popovers). */
  matchWidth?: boolean;
  className?: string;
  /** Max height of the panel in px (content scrolls). */
  maxHeight?: number;
}

/** Floating panel anchored to an element (portal, flips upwards, closes on outside click / Esc). */
export const Popover: React.FC<PopoverProps> = ({ open, onClose, anchorRef, children, align = 'start', matchWidth, className, maxHeight = 360 }) => {
  const panelRef = useRef<HTMLDivElement>(null);
  const [style, setStyle] = useState<React.CSSProperties>({ top: -9999, left: -9999 });

  const place = useCallback(() => {
    const a = anchorRef.current;
    const p = panelRef.current;
    if (!a || !p) return;
    const r = a.getBoundingClientRect();
    const ph = Math.min(p.scrollHeight, maxHeight);
    const pw = matchWidth ? Math.max(r.width, p.offsetWidth) : p.offsetWidth;
    const below = window.innerHeight - r.bottom;
    const up = below < ph + 12 && r.top > below;
    let left = align === 'end' ? r.right - pw : r.left;
    left = Math.max(8, Math.min(left, window.innerWidth - pw - 8));
    setStyle({
      top: up ? Math.max(8, r.top - ph - 6) : r.bottom + 6,
      left,
      minWidth: matchWidth ? r.width : undefined,
      maxHeight,
    });
  }, [anchorRef, align, matchWidth, maxHeight]);

  useLayoutEffect(() => {
    if (open) place();
  }, [open, place, children]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onClose();
        anchorRef.current?.focus();
      }
    };
    window.addEventListener('resize', place);
    window.addEventListener('scroll', place, true);
    document.addEventListener('keydown', onKey, true);
    return () => {
      window.removeEventListener('resize', place);
      window.removeEventListener('scroll', place, true);
      document.removeEventListener('keydown', onKey, true);
    };
  }, [open, place, onClose, anchorRef]);

  useOnClickOutside([panelRef, anchorRef as RefObject<HTMLElement>], onClose, open);

  if (!open) return null;
  return (
    <Portal>
      <div
        ref={panelRef}
        style={style}
        className={cn(
          'scroll-thin fixed z-[90] overflow-auto rounded-lg border border-border bg-surface p-1 shadow-pop animate-pop-in',
          className
        )}
      >
        {children}
      </div>
    </Portal>
  );
};
