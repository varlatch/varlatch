// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { createRoot } from "react-dom/client";
import { App } from "./app";
import "./styles.css";

createRoot(document.getElementById("root") as HTMLElement).render(<App />);
