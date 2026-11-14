// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Which server the dashboard talks to, read from /v1/meta before anything
 * else loads (ADR-0059 step 3; varlatchd-core decision 1). The dashboard
 * works with both servers while the Go server is written:
 *
 * - session: "varlatchd" when /v1/meta lists auth.session, the Go server's
 *   own browser session (/auth/session and the paths beside it, a CSRF
 *   token on every POST); "better-auth" otherwise, the TypeScript server's
 *   Better Auth client, as before.
 * - realtime: "convex" on the TypeScript server, as before; "none" on the
 *   Go server until it serves events (realtime.sse, step 3.5): no Convex
 *   client is ever created, the live-updates indicator says updates are
 *   unavailable, and pages refresh by polling.
 *
 * A /v1/meta that fails or does not answer in time leaves the TypeScript
 * server's clients, as today.
 */

export interface Backend {
  session: "better-auth" | "varlatchd";
  realtime: "convex" | "none";
}

const TYPESCRIPT_SERVER: Backend = { session: "better-auth", realtime: "convex" };

let current: Backend = TYPESCRIPT_SERVER;

/** The clients /v1/meta's capabilities choose. */
export function backendOf(capabilities: readonly string[] | null | undefined): Backend {
  if (!Array.isArray(capabilities) || !capabilities.includes("auth.session")) return TYPESCRIPT_SERVER;
  return { session: "varlatchd", realtime: "none" };
}

/** Reads /v1/meta once, at start, before the app module loads. */
export async function detectBackend(timeoutMs = 4000): Promise<Backend> {
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), timeoutMs);
  try {
    const res = await fetch("/v1/meta", { headers: { Accept: "application/json" }, signal: abort.signal });
    const body = res.ok ? ((await res.json()) as { capabilities?: unknown }) : null;
    current = backendOf(Array.isArray(body?.capabilities) ? (body.capabilities as string[]) : null);
  } catch {
    current = TYPESCRIPT_SERVER;
  } finally {
    clearTimeout(timer);
  }
  return current;
}

/** The backend chosen at start. */
export function backend(): Backend {
  return current;
}
