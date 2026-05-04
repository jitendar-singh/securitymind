/* global process */
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Backend (Flask) origin. Override via VITE_API_TARGET in .env when the
// backend runs somewhere other than localhost:5001.
const API_TARGET = process.env.VITE_API_TARGET || 'http://localhost:5001'

// All Flask routes proxied so the frontend can use same-origin relative URLs
// (`/auth/login`, `/chat`, etc.). This sidesteps SameSite=Lax cookie issues
// when the dev server is reached over the LAN (192.168.x.y:5173) rather than
// localhost.
const PROXY_PREFIXES = [
  '/auth',
  '/chat',
  '/integrations',
  '/settings',
  '/reports',
  '/conversations',
]

const proxy = Object.fromEntries(
  PROXY_PREFIXES.map((p) => [p, { target: API_TARGET, changeOrigin: true }])
)

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy,
  },
})
