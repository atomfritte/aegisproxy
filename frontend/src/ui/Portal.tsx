import React from 'react';
import { createPortal } from 'react-dom';

/** Renders children into document.body (overlays, tooltips, toasts). */
export const Portal: React.FC<{ children: React.ReactNode }> = ({ children }) =>
  typeof document === 'undefined' ? null : createPortal(children, document.body);
