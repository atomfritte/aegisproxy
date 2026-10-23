import React, { useEffect, useRef } from 'react';
import { X } from 'lucide-react';
import { cn } from '../lib/cn';
import { useFocusTrap, useScrollLock } from '../lib/hooks';
import { IconButton } from './Button';
import { Portal } from './Portal';

// Stack of open overlays so Esc only closes the top-most one.
const stack: number[] = [];
let seq = 0;

function useOverlay(open: boolean, onClose: () => void, dismissible: boolean) {
  const idRef = useRef(0);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useEffect(() => {
    if (!open) return;
    const id = ++seq;
    idRef.current = id;
    stack.push(id);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && stack[stack.length - 1] === id && dismissible) {
        e.preventDefault();
        closeRef.current();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
      const i = stack.indexOf(id);
      if (i >= 0) stack.splice(i, 1);
    };
  }, [open, dismissible]);
}

export interface DrawerProps {
  open: boolean;
  onClose: () => void;
  title: React.ReactNode;
  description?: React.ReactNode;
  /** sm 420px · md 560px · lg 720px · xl 900px (full width on phones) */
  width?: 'sm' | 'md' | 'lg' | 'xl';
  footer?: React.ReactNode;
  children: React.ReactNode;
  /** Prevent closing via Esc / backdrop (e.g. while saving). */
  dismissible?: boolean;
  /** Element rendered next to the title (badges). */
  titleAside?: React.ReactNode;
}

const widths = { sm: 'sm:max-w-[420px]', md: 'sm:max-w-[560px]', lg: 'sm:max-w-[720px]', xl: 'sm:max-w-[900px]' };

/** Right side panel for create/edit forms and details. Esc / backdrop click closes. */
export const Drawer: React.FC<DrawerProps> = ({ open, onClose, title, description, width = 'md', footer, children, dismissible = true, titleAside }) => {
  const ref = useRef<HTMLDivElement>(null);
  useOverlay(open, onClose, dismissible);
  useScrollLock(open);
  useFocusTrap(ref, open);
  if (!open) return null;
  return (
    <Portal>
      <div className="fixed inset-0 z-[70] flex justify-end">
        <div className="absolute inset-0 bg-black/40 animate-fade-in" onClick={() => dismissible && onClose()} aria-hidden />
        <div
          ref={ref}
          role="dialog"
          aria-modal="true"
          aria-label={typeof title === 'string' ? title : undefined}
          tabIndex={-1}
          className={cn('relative flex h-full w-full flex-col bg-surface shadow-drawer outline-hidden animate-slide-in-right', widths[width])}
        >
          <div className="flex items-start justify-between gap-3 border-b border-border px-5 py-4">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-[16px] font-semibold leading-6 text-fg">{title}</h2>
                {titleAside}
              </div>
              {description && <p className="mt-0.5 text-[13px] leading-5 text-fg-muted">{description}</p>}
            </div>
            <IconButton icon={X} label="Close" onClick={onClose} disabled={!dismissible} className="-mr-2 -mt-1" noTooltip />
          </div>
          <div className="scroll-thin min-h-0 flex-1 overflow-y-auto px-5 py-5">{children}</div>
          {footer && <div className="flex flex-wrap items-center justify-end gap-2 border-t border-border bg-surface-2 px-5 py-3">{footer}</div>}
        </div>
      </div>
    </Portal>
  );
};

export interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: React.ReactNode;
  description?: React.ReactNode;
  size?: 'sm' | 'md' | 'lg';
  footer?: React.ReactNode;
  children?: React.ReactNode;
  dismissible?: boolean;
  /** Icon tile left of the title. */
  icon?: React.ReactNode;
}

const modalSizes = { sm: 'max-w-[420px]', md: 'max-w-[540px]', lg: 'max-w-[760px]' };

/** Centered dialog. Esc / backdrop click closes (unless dismissible=false). */
export const Modal: React.FC<ModalProps> = ({ open, onClose, title, description, size = 'md', footer, children, dismissible = true, icon }) => {
  const ref = useRef<HTMLDivElement>(null);
  useOverlay(open, onClose, dismissible);
  useScrollLock(open);
  useFocusTrap(ref, open);
  if (!open) return null;
  return (
    <Portal>
      <div className="fixed inset-0 z-[80] flex items-end justify-center p-0 sm:items-center sm:p-6">
        <div className="absolute inset-0 bg-black/45 animate-fade-in" onClick={() => dismissible && onClose()} aria-hidden />
        <div
          ref={ref}
          role="dialog"
          aria-modal="true"
          aria-label={typeof title === 'string' ? title : undefined}
          tabIndex={-1}
          className={cn(
            'relative flex max-h-[92vh] w-full flex-col rounded-t-xl border border-border bg-surface shadow-pop outline-hidden animate-pop-in sm:rounded-xl',
            modalSizes[size]
          )}
        >
          <div className="flex items-start gap-3 px-5 pb-2 pt-5">
            {icon}
            <div className="min-w-0 flex-1">
              <h2 className="text-[16px] font-semibold leading-6 text-fg">{title}</h2>
              {description && <div className="mt-1 text-[13px] leading-5 text-fg-muted">{description}</div>}
            </div>
            <IconButton icon={X} label="Close" onClick={onClose} disabled={!dismissible} size="sm" className="-mr-2 -mt-1" noTooltip />
          </div>
          {children && <div className="scroll-thin min-h-0 overflow-y-auto px-5 py-3">{children}</div>}
          {footer && <div className="flex flex-wrap items-center justify-end gap-2 px-5 pb-5 pt-3">{footer}</div>}
        </div>
      </div>
    </Portal>
  );
};
