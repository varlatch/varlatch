// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The dashboard is served same-origin with varlatchd in production; in dev,
// /auth, /v1 and /.well-known are proxied so cookies stay first-party.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  // The tests render the providers as against the TypeScript server
  // (lib/backend.ts chooses at start in the app).
  test: { setupFiles: ["./test/setup.ts"] },
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
