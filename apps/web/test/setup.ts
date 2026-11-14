// SPDX-License-Identifier: AGPL-3.0-or-later
import { chooseBackend } from "../src/lib/backend";

// The app chooses its session and realtime clients from /v1/meta before it
// loads (src/main.tsx); tests render its providers directly, as against
// the TypeScript server. A test of the Go server's clients chooses again.
chooseBackend({ session: "better-auth", realtime: "convex" });
