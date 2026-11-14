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
 * Only a successful /v1/meta answer chooses. Until one arrives the choice
 * stays open and /v1/meta is asked again: a failure, a timeout or an
 * error status says nothing about which server answers, so the dashboard
 * never falls back to a guess. While the installation answers MAINTENANCE
 * the dashboard shows the maintenance screen and asks again after its
 * Retry-After.
 */

export interface Backend {
  session: "better-auth" | "varlatchd";
  realtime: "convex" | "none";
}

/** The clients a successful /v1/meta's capabilities choose. */
export function backendOf(capabilities: readonly string[]): Backend {
  if (!capabilities.includes("auth.session")) return { session: "better-auth", realtime: "convex" };
  return { session: "varlatchd", realtime: "none" };
}

/** One /v1/meta request's outcome. */
export type MetaAttempt =
  | { kind: "answered"; backend: Backend }
  | { kind: "maintenance"; retryAfterMs: number }
  | { kind: "failed" };

/** Asks /v1/meta once. */
export async function readMeta(fetchMeta: typeof fetch, timeoutMs: number): Promise<MetaAttempt> {
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), timeoutMs);
  try {
    const res = await fetchMeta("/v1/meta", { headers: { Accept: "application/json" }, signal: abort.signal });
    const body = (await res.json().catch(() => null)) as { capabilities?: unknown; error?: { code?: unknown } } | null;
    if (res.ok && Array.isArray(body?.capabilities) && body.capabilities.every((c) => typeof c === "string")) {
      return { kind: "answered", backend: backendOf(body.capabilities as string[]) };
    }
    if (res.status === 503 && body?.error?.code === "MAINTENANCE") {
      const after = Number(res.headers.get("Retry-After"));
      return { kind: "maintenance", retryAfterMs: (Number.isFinite(after) && after > 0 ? after : 5) * 1000 };
    }
    return { kind: "failed" };
  } catch {
    return { kind: "failed" };
  } finally {
    clearTimeout(timer);
  }
}

let current: Backend | null = null;

export interface DetectOptions {
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  /** Told while the choice is still open: why it waits. */
  onWaiting?: (why: "connecting" | "maintenance") => void;
  timeoutMs?: number;
}

/**
 * Asks /v1/meta until it answers, then keeps its choice for the page's
 * lifetime. Failures back off from 1 to 10 seconds; MAINTENANCE waits its
 * Retry-After.
 */
export async function detectBackend(options: DetectOptions = {}): Promise<Backend> {
  const fetchMeta = options.fetch ?? globalThis.fetch.bind(globalThis);
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  for (let failures = 0; ; ) {
    const attempt = await readMeta(fetchMeta, options.timeoutMs ?? 4000);
    if (attempt.kind === "answered") {
      current = attempt.backend;
      return attempt.backend;
    }
    if (attempt.kind === "maintenance") {
      options.onWaiting?.("maintenance");
      await sleep(attempt.retryAfterMs);
      continue;
    }
    options.onWaiting?.("connecting");
    await sleep(Math.min(1000 * 2 ** failures, 10_000));
    failures++;
  }
}

/**
 * Sets the choice without asking /v1/meta: for tests that render the app's
 * providers, which run as against the TypeScript server unless they say
 * otherwise (test/setup.ts).
 */
export function chooseBackend(choice: Backend): void {
  current = choice;
}

/** The backend chosen at start; the app loads only after detectBackend chose it. */
export function backend(): Backend {
  if (!current) throw new Error("backend(): /v1/meta has not answered yet");
  return current;
}
