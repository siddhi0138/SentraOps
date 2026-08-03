import path from 'node:path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    // Vite's default output dir is "assets" - collides with this app's own
    // /assets route (Asset Inventory page). Any real HTTP GET to /assets
    // (a hard refresh, a bookmark, a direct link) hit nginx's real static
    // directory instead of the SPA, breaking the page outright. Renamed so
    // no app route can ever collide with the build output again.
    assetsDir: '_build',
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        ws: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
})
