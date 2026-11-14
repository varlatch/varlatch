// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { createRoot } from "react-dom/client";
import { detectBackend } from "./lib/backend";
import "./styles.css";

// The server's capabilities choose the session and realtime clients before
// the app (and any Convex client) is loaded (lib/backend.ts).
void detectBackend().then(async () => {
  const { App } = await import("./app");
  createRoot(document.getElementById("root") as HTMLElement).render(<App />);
});
