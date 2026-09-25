// SPDX-License-Identifier: AGPL-3.0-or-later
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The dashboard is served same-origin with varlatchd in production; in dev,
// /auth, /v1 and /.well-known are proxied so cookies stay first-party.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      "/auth": "http://localhost:8686",
      "/v1": "http://localhost:8686",
      "/.well-known": "http://localhost:8686",
      "/enroll": "http://localhost:8686",
      "/enroll.js": "http://localhost:8686",
    },
  },
  preview: {
    port: 5173,
    proxy: {
      "/auth": "http://localhost:8686",
      "/v1": "http://localhost:8686",
      "/.well-known": "http://localhost:8686",
      "/enroll": "http://localhost:8686",
      "/enroll.js": "http://localhost:8686",
    },
  },
});
