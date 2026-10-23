import React from 'react';
import ReactDOM from 'react-dom/client';
import { App } from './App';
import { applyInitialTheme } from './lib/theme';
import './index.css';

// Apply the stored theme before the first paint (CSP forbids inline scripts in index.html).
applyInitialTheme();

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
