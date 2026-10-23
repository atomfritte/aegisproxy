import React, { useLayoutEffect, useRef, useState } from 'react';
import { cn } from '../../../lib/cn';

/**
 * Sandboxed iframe that renders `html` at a logical viewport width (1280 = desktop, 390 = phone)
 * and scales it down to fit its container. No scripts, forms, popups or same-origin access.
 */
export const ScaledFrame: React.FC<{
  html: string;
  title: string;
  /** Logical viewport width in CSS px. */
  logicalWidth: number;
  /** Fixed container height in px; omit to fill the parent (parent needs a height). */
  height?: number;
  /** Thumbnails: no pointer events, not focusable, lazy. */
  thumbnail?: boolean;
  /** Draws a rounded device frame around phone previews. */
  device?: boolean;
  className?: string;
}> = ({ html, title, logicalWidth, height, thumbnail, device, className }) => {
  const ref = useRef<HTMLDivElement>(null);
  const [box, setBox] = useState({ w: 0, h: height ?? 0 });

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const measure = () => setBox({ w: el.clientWidth, h: height ?? el.clientHeight });
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [height]);

  // Scripts never run in the sandbox anyway; dropping them avoids console noise.
  const doc = React.useMemo(() => html.replace(/<script\b[\s\S]*?<\/script>/gi, ''), [html]);
  const pad = device ? 20 : 0;
  const scale = box.w > 0 ? Math.min(1, (box.w - pad * 2) / logicalWidth) : 0;
  const frameH = box.h > 0 && scale > 0 ? (box.h - pad * 2) / scale : 0;

  return (
    <div ref={ref} className={cn('relative w-full overflow-hidden', !height && 'h-full', className)} style={height ? { height } : undefined}>
      {scale > 0 && (
        <div
          className={cn('absolute left-1/2 -translate-x-1/2', device ? 'top-5 overflow-hidden rounded-[22px] border-[6px] border-sidebar bg-surface shadow-pop' : 'top-0')}
          style={{ width: logicalWidth * scale + (device ? 12 : 0), height: frameH * scale + (device ? 12 : 0) }}
        >
          <iframe
            title={title}
            sandbox=""
            srcDoc={doc}
            referrerPolicy="no-referrer"
            loading={thumbnail ? 'lazy' : undefined}
            tabIndex={thumbnail ? -1 : undefined}
            aria-hidden={thumbnail || undefined}
            className={cn('block origin-top-left border-0 bg-surface', thumbnail && 'pointer-events-none')}
            style={{ width: logicalWidth, height: frameH, transform: `scale(${scale})` }}
          />
        </div>
      )}
    </div>
  );
};
