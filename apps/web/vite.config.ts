import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// 端口可被 E2E 覆盖（独立于开发实例：Web 14273 / API 14274）
const webPort = Number(process.env.MIMA_WEB_PORT ?? '4173');
const apiPort = Number(process.env.MIMA_API_PORT ?? '4174');
const apiHost = process.env.MIMA_API_PROXY_HOST ?? '127.0.0.1';
const apiUrlHost = apiHost.includes(':') ? `[${apiHost}]` : apiHost;

const apiProxy = {
  '/api': {
    target: `http://${apiUrlHost}:${apiPort}`,
    changeOrigin: false,
  },
};

export default defineConfig({
  plugins: [react()],
  server: {
    port: webPort,
    strictPort: true,
    proxy: apiProxy,
  },
  preview: {
    port: webPort,
    strictPort: true,
    proxy: apiProxy,
  },
  build: {
    sourcemap: process.env.NODE_ENV === 'production' ? false : 'hidden',
  },
});
