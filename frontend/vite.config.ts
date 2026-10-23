import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// Dev proxy target for /api (control-plane). Override with AEGIS_DEV_API, e.g.
//   AEGIS_DEV_API=http://127.0.0.1:18281 npm run dev
const devApi = process.env.AEGIS_DEV_API || 'http://localhost:8081';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    rolldownOptions: {
      output: {
        // Long-term cacheable vendor chunks (React, icons) separate from the application code.
        codeSplitting: {
          groups: [
            { name: 'react', test: /node_modules[\\/](react|react-dom|scheduler)[\\/]/ },
            { name: 'icons', test: /node_modules[\\/]lucide-react[\\/]/ },
          ],
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: devApi,
        changeOrigin: true,
        configure: (proxy) => {
          // The control-plane's CSRF check compares Origin with Host; changeOrigin rewrites Host
          // to the target, so present the browser's request as same-origin to the API.
          proxy.on('proxyReq', (proxyReq) => {
            if (proxyReq.getHeader('origin')) proxyReq.setHeader('origin', new URL(devApi).origin);
          });
          // keep the SSE stream unbuffered
          proxy.on('proxyRes', (res) => {
            if (String(res.headers['content-type'] || '').includes('text/event-stream')) {
              res.headers['cache-control'] = 'no-cache';
            }
          });
        },
      },
    },
  },
});
