import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// relative base so the build works from any sub-path; in development /api goes to the local API
// (uv run uvicorn api.app:app --port 8787), in production nginx proxies it the same way
export default defineConfig({
  base: './',
  plugins: [react(), tailwindcss()],
  server: { proxy: { '/api': 'http://127.0.0.1:8787' } },
})
