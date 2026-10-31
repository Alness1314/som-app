import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
export default defineConfig(({ command }) => ({
  plugins: [tailwindcss(), react(), {
    name: 'som-dev-style-csp',
    transformIndexHtml(html) {
      // Vite injects HMR styles in development. Keep the relaxed style rule out of packaged builds.
      return command === 'serve'
        ? html.replace("style-src 'self';", "style-src 'self' 'unsafe-inline';").replace("connect-src 'self';", "connect-src 'self' ws://127.0.0.1:5173;")
        : html;
    },
  }],
  root: '.',
  server: { host: '127.0.0.1', port: 5173, strictPort: true },
  build: { outDir: 'dist', emptyOutDir: true },
}));
