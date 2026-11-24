// SPDX-License-Identifier: AGPL-3.0-or-later
import "./features/oauth/arrive";
import React from "react";
import { createRoot } from "react-dom/client";
import { detectBackend } from "./lib/backend";
import { ConnectingScreen, MaintenanceScreen } from "./shell/CenteredCard";
import "./styles.css";

// The server's capabilities choose the session and realtime clients before
// the app (and any Convex client) is loaded (lib/backend.ts). Until
// /v1/meta answers, a screen says why the dashboard waits.
const root = createRoot(document.getElementById("root") as HTMLElement);
void detectBackend({
  onWaiting: (why) => root.render(why === "maintenance" ? <MaintenanceScreen /> : <ConnectingScreen />),
}).then(async () => {
  const { App } = await import("./app");
  root.render(<App />);
});
