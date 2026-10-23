// Theme (light / dark / system) and density (comfortable / compact), persisted in localStorage.
// Applied as `class="dark"` + `data-theme` + `data-density` on <html>; tokens live in index.css.

import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { readStorage, writeStorage } from './storage';

export type ThemePreference = 'light' | 'dark' | 'system';
export type Density = 'comfortable' | 'compact';

const THEME_KEY = 'aegis.theme';
const DENSITY_KEY = 'aegis.density';

function readTheme(): ThemePreference {
  const v = readStorage(THEME_KEY);
  return v === 'light' || v === 'dark' || v === 'system' ? v : 'system';
}

function readDensity(): Density {
  return readStorage(DENSITY_KEY) === 'compact' ? 'compact' : 'comfortable';
}

function systemDark(): boolean {
  try {
    return window.matchMedia('(prefers-color-scheme: dark)').matches;
  } catch {
    return false;
  }
}

function apply(pref: ThemePreference, density: Density): 'light' | 'dark' {
  const resolved = pref === 'system' ? (systemDark() ? 'dark' : 'light') : pref;
  const root = document.documentElement;
  root.classList.toggle('dark', resolved === 'dark');
  root.dataset.theme = resolved;
  root.dataset.density = density;
  return resolved;
}

/** Call once before the first render to avoid a theme flash (CSP forbids inline scripts). */
export function applyInitialTheme(): void {
  apply(readTheme(), readDensity());
}

interface ThemeContextValue {
  theme: ThemePreference;
  resolvedTheme: 'light' | 'dark';
  density: Density;
  setTheme: (t: ThemePreference) => void;
  setDensity: (d: Density) => void;
  /** light -> dark -> system */
  cycleTheme: () => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [theme, setThemeState] = useState<ThemePreference>(readTheme);
  const [density, setDensityState] = useState<Density>(readDensity);
  const [resolvedTheme, setResolved] = useState<'light' | 'dark'>(() => apply(readTheme(), readDensity()));

  useEffect(() => {
    setResolved(apply(theme, density));
    if (theme !== 'system') return;
    let mql: MediaQueryList;
    try {
      mql = window.matchMedia('(prefers-color-scheme: dark)');
    } catch {
      return;
    }
    const onChange = () => setResolved(apply('system', density));
    mql.addEventListener('change', onChange);
    return () => mql.removeEventListener('change', onChange);
  }, [theme, density]);

  const setTheme = useCallback((t: ThemePreference) => {
    writeStorage(THEME_KEY, t);
    setThemeState(t);
  }, []);
  const setDensity = useCallback((d: Density) => {
    writeStorage(DENSITY_KEY, d);
    setDensityState(d);
  }, []);
  const cycleTheme = useCallback(() => {
    setTheme(theme === 'light' ? 'dark' : theme === 'dark' ? 'system' : 'light');
  }, [theme, setTheme]);

  const value = useMemo(
    () => ({ theme, resolvedTheme, density, setTheme, setDensity, cycleTheme }),
    [theme, resolvedTheme, density, setTheme, setDensity, cycleTheme]
  );
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
};

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error('useTheme must be used inside <ThemeProvider>');
  return ctx;
}
